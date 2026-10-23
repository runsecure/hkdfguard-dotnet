using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HkdfGuard.KeyWrapping.AzureKeyVault;

/// <summary>
/// The wrapped-DEK format <see cref="AzureKeyVaultKeyWrapper"/> writes and reads:
/// <code>
/// offset  length  field
/// 0       4       magic "HGKV"
/// 4       1       format version (1)
/// 5       16      wrapping key version (Key Vault's 32 hex digits, as bytes)
/// 21      2       n, the RSA-OAEP-256 ciphertext's length (big-endian)
/// 23      n       the DEK, wrapped under that version of the wrapping key
/// 23+n    16      signing key version
/// 39+n    64      ES256 signature (r || s) by that version of the signing key
/// </code>
/// Only key versions are stored: the vault and key names are the wrapper's own, so a key file can
/// never point it at another key. The signature covers <see cref="SignedData"/>: a domain string,
/// the wrapper's context, and every byte before the signing key version.
/// </summary>
internal static class WrappedDekEnvelope
{
    internal static ReadOnlySpan<byte> Magic => "HGKV"u8;

    internal const byte FormatVersion = 1;
    internal const int KeyVersionLength = 16;
    internal const int SignatureLength = 64;

    // Magic, format version, wrapping key version and ciphertext length.
    internal const int HeaderLength = 4 + 1 + KeyVersionLength + 2;

    /// <summary>Everything besides the RSA ciphertext.</summary>
    internal const int Overhead = HeaderLength + KeyVersionLength + SignatureLength;

    private static ReadOnlySpan<byte> Domain => "HkdfGuard-AzureKeyVault-wrap-v1\0"u8;

    /// <summary>A parsed envelope: the parts and where the signed part ends.</summary>
    internal readonly record struct Parts(string WrappingKeyVersion, byte[] WrappedDek, string SigningKeyVersion, byte[] Signature, int UnsignedLength);

    /// <summary>The header and ciphertext: everything the signature covers besides the domain and context.</summary>
    /// <exception cref="CryptographicException">The version isn't Key Vault's form, or the ciphertext is empty or too long to encode.</exception>
    internal static byte[] BuildUnsigned(string wrappingKeyVersion, ReadOnlySpan<byte> wrappedDek)
    {
        if (wrappedDek.IsEmpty || wrappedDek.Length > ushort.MaxValue)
            throw new CryptographicException($"Azure Key Vault returned a {wrappedDek.Length}-byte wrapped key.");

        var unsigned = new byte[HeaderLength + wrappedDek.Length];
        Magic.CopyTo(unsigned);
        unsigned[4] = FormatVersion;
        WriteVersion(wrappingKeyVersion, unsigned.AsSpan(5, KeyVersionLength));
        BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(21), (ushort)wrappedDek.Length);
        wrappedDek.CopyTo(unsigned.AsSpan(HeaderLength));
        return unsigned;
    }

    /// <summary>What the signing key signs: the domain, the length-prefixed context, then <paramref name="unsigned"/>.</summary>
    internal static byte[] SignedData(ReadOnlySpan<byte> unsigned, byte[] context)
    {
        var data = new byte[Domain.Length + 2 + context.Length + unsigned.Length];
        Domain.CopyTo(data);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(Domain.Length), (ushort)context.Length);
        context.CopyTo(data.AsSpan(Domain.Length + 2));
        unsigned.CopyTo(data.AsSpan(Domain.Length + 2 + context.Length));
        return data;
    }

    /// <summary>Writes the complete envelope into <paramref name="result"/>.</summary>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">result is too small.</exception>
    /// <exception cref="CryptographicException">The version or signature isn't the expected form.</exception>
    internal static int Write(ReadOnlySpan<byte> unsigned, string signingKeyVersion, ReadOnlySpan<byte> signature, Span<byte> result)
    {
        if (signature.Length != SignatureLength)
            throw new CryptographicException(
                $"Azure Key Vault returned a {signature.Length}-byte signature; an ES256 signature is {SignatureLength}. The signing key must be an EC P-256 key.");

        var length = unsigned.Length + KeyVersionLength + SignatureLength;
        if (length > result.Length)
            throw new ArgumentException($"The wrapped DEK is {length} bytes; result holds {result.Length}.", nameof(result));

        unsigned.CopyTo(result);
        WriteVersion(signingKeyVersion, result.Slice(unsigned.Length, KeyVersionLength));
        signature.CopyTo(result[(unsigned.Length + KeyVersionLength)..]);
        return length;
    }

    /// <summary>Splits an envelope into its parts, refusing anything that isn't exactly one.</summary>
    /// <exception cref="CryptographicException">It isn't.</exception>
    internal static Parts Parse(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < Overhead + 1 || !envelope.StartsWith(Magic))
            throw new CryptographicException("This is not a wrapped DEK written by AzureKeyVaultKeyWrapper.");
        if (envelope[4] != FormatVersion)
            throw new CryptographicException($"This wrapped DEK is format version {envelope[4]}; only version {FormatVersion} is supported.");

        var wrappedLength = BinaryPrimitives.ReadUInt16BigEndian(envelope[21..]);
        if (wrappedLength == 0 || envelope.Length != Overhead + wrappedLength)
            throw new CryptographicException($"This wrapped DEK is {envelope.Length} bytes, but its header describes {Overhead + wrappedLength}.");

        var unsignedLength = HeaderLength + wrappedLength;
        return new Parts(
            Convert.ToHexStringLower(envelope.Slice(5, KeyVersionLength)),
            envelope.Slice(HeaderLength, wrappedLength).ToArray(),
            Convert.ToHexStringLower(envelope.Slice(unsignedLength, KeyVersionLength)),
            envelope[(unsignedLength + KeyVersionLength)..].ToArray(),
            unsignedLength);
    }

    /// <summary>The UTF-8 bytes of a context, refusing one too long to length-prefix.</summary>
    internal static byte[] EncodeContext(string? context)
    {
        var bytes = context is null ? [] : Encoding.UTF8.GetBytes(context);
        if (bytes.Length > ushort.MaxValue)
            throw new ArgumentException($"The context is {bytes.Length} bytes in UTF-8; at most {ushort.MaxValue} are allowed.", nameof(context));
        return bytes;
    }

    // Key Vault key versions are 32 lowercase hex digits; stored as the 16 bytes they spell.
    private static void WriteVersion(string version, Span<byte> destination)
    {
        // 32 characters that all decode fill the 16 bytes exactly.
        if (version.Length != KeyVersionLength * 2
            || Convert.FromHexString(version, destination, out _, out _) != System.Buffers.OperationStatus.Done)
            throw new CryptographicException($"Azure Key Vault returned key version '{version}', not 32 hex digits.");
    }
}
