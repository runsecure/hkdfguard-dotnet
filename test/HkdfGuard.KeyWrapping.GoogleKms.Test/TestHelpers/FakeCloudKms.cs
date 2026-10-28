using System.Security.Cryptography;
using System.Text;
using Google.Api.Gax.Grpc;
using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Grpc.Core;

namespace HkdfGuard.KeyWrapping.GoogleKms.Test.TestHelpers;

/// <summary>
/// An in-process stand-in for Cloud KMS, implementing only the two calls GoogleKmsKeyWrapper makes
/// (any other member throws). By default it behaves like a set of symmetric keys, each with a
/// primary version: ciphertext is AES-GCM under a local key, binding the key name, the version and
/// the additional authenticated data, so Decrypt fails unless all three match. It checks request
/// checksums and sets response ones as Cloud KMS does. Each call can be replaced with a handler to
/// return or throw what a test needs. Every request is recorded; Encrypt's plaintext is copied when
/// it arrives, since the wrapper zeroes it afterwards.
/// </summary>
public sealed class FakeCloudKms : KeyManagementServiceClient
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, int> _primaryVersions = [];

    public Func<EncryptRequest, EncryptResponse>? OnEncrypt { get; set; }
    public Func<DecryptRequest, DecryptResponse>? OnDecrypt { get; set; }

    public List<EncryptRequest> EncryptRequests { get; } = [];
    public List<byte[]> EncryptPlaintexts { get; } = [];
    public List<DecryptRequest> DecryptRequests { get; } = [];

    /// <summary>The plaintext of every Decrypt response returned, to check it was zeroed.</summary>
    public List<ByteString> DecryptPlaintexts { get; } = [];

    /// <summary>Makes a new version of the key its primary, as rotating it in Cloud KMS does.</summary>
    public void Rotate(string keyName) => _primaryVersions[keyName] = PrimaryVersion(keyName) + 1;

    public override Task<EncryptResponse> EncryptAsync(EncryptRequest request, CallSettings? callSettings = null)
        => Run(callSettings, () =>
        {
            EncryptRequests.Add(request);
            EncryptPlaintexts.Add(request.Plaintext.ToByteArray());
            return OnEncrypt?.Invoke(request) ?? Encrypt(request);
        });

    public override Task<DecryptResponse> DecryptAsync(DecryptRequest request, CallSettings? callSettings = null)
        => Run(callSettings, () =>
        {
            DecryptRequests.Add(request);
            var response = OnDecrypt?.Invoke(request) ?? Decrypt(request);
            DecryptPlaintexts.Add(response.Plaintext);
            return response;
        });

    /// <summary>An exception shaped like the one gRPC raises for a Cloud KMS error response.</summary>
    public static RpcException Error(StatusCode status, string detail) => new(new Status(status, detail));

    private EncryptResponse Encrypt(EncryptRequest request)
    {
        CheckCrc32C(request.Plaintext, request.PlaintextCrc32C, "plaintext");
        CheckCrc32C(request.AdditionalAuthenticatedData, request.AdditionalAuthenticatedDataCrc32C, "additional_authenticated_data");

        var version = PrimaryVersion(request.Name);
        var plaintext = request.Plaintext.Span;
        var ciphertext = new byte[1 + 12 + 16 + plaintext.Length];
        ciphertext[0] = (byte)version;
        RandomNumberGenerator.Fill(ciphertext.AsSpan(1, 12));
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(ciphertext.AsSpan(1, 12), plaintext, ciphertext.AsSpan(29), ciphertext.AsSpan(13, 16),
            Aad(request.Name, version, request.AdditionalAuthenticatedData));

        return new EncryptResponse
        {
            Name = $"{request.Name}/cryptoKeyVersions/{version}",
            Ciphertext = ByteString.CopyFrom(ciphertext),
            CiphertextCrc32C = GoogleKmsKeyWrapper.Crc32C(ciphertext),
            VerifiedPlaintextCrc32C = request.PlaintextCrc32C is not null,
            VerifiedAdditionalAuthenticatedDataCrc32C = request.AdditionalAuthenticatedDataCrc32C is not null,
            ProtectionLevel = ProtectionLevel.Software,
        };
    }

    private DecryptResponse Decrypt(DecryptRequest request)
    {
        CheckCrc32C(request.Ciphertext, request.CiphertextCrc32C, "ciphertext");
        CheckCrc32C(request.AdditionalAuthenticatedData, request.AdditionalAuthenticatedDataCrc32C, "additional_authenticated_data");

        var ciphertext = request.Ciphertext.Span;
        if (ciphertext.Length < 29)
            throw InvalidCiphertext();

        var plaintext = new byte[ciphertext.Length - 29];
        try
        {
            using var aes = new AesGcm(_key, 16);
            aes.Decrypt(ciphertext.Slice(1, 12), ciphertext[29..], ciphertext.Slice(13, 16), plaintext,
                Aad(request.Name, ciphertext[0], request.AdditionalAuthenticatedData));
        }
        catch (AuthenticationTagMismatchException)
        {
            // Cloud KMS gives the same answer for another key, another AAD, and tampering.
            throw InvalidCiphertext();
        }

        return new DecryptResponse
        {
            Plaintext = ByteString.CopyFrom(plaintext),
            PlaintextCrc32C = GoogleKmsKeyWrapper.Crc32C(plaintext),
            UsedPrimary = ciphertext[0] == PrimaryVersion(request.Name),
            ProtectionLevel = ProtectionLevel.Software,
        };
    }

    private int PrimaryVersion(string keyName) => _primaryVersions.GetValueOrDefault(keyName, 1);

    private static Task<T> Run<T>(CallSettings? callSettings, Func<T> call)
    {
        // gRPC reports cancellation as an RpcException, not an OperationCanceledException.
        if (callSettings?.CancellationToken is { IsCancellationRequested: true })
            return Task.FromException<T>(Error(StatusCode.Cancelled, "Call canceled by the client."));
        try
        {
            return Task.FromResult(call());
        }
        catch (Exception e)
        {
            return Task.FromException<T>(e);
        }
    }

    private static void CheckCrc32C(ByteString data, long? crc32C, string field)
    {
        if (crc32C is not null && crc32C != GoogleKmsKeyWrapper.Crc32C(data.Span))
            throw Error(StatusCode.InvalidArgument, $"The checksum in field {field}_crc32c did not match the data in field {field}.");
    }

    private static RpcException InvalidCiphertext() => Error(StatusCode.InvalidArgument, "Decryption failed: the ciphertext is invalid.");

    private static byte[] Aad(string keyName, int version, ByteString aad)
        => [.. Encoding.UTF8.GetBytes($"{keyName}\0{version}\0"), .. aad.Span];
}
