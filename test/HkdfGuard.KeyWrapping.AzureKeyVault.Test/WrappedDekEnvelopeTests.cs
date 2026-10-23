using System.Security.Cryptography;

namespace HkdfGuard.KeyWrapping.AzureKeyVault.Test;

public class WrappedDekEnvelopeTests
{
    private const string WrapVersion = "0123456789abcdef0123456789abcdef";
    private const string SignVersion = "fedcba9876543210fedcba9876543210";

    private static byte[] Envelope(int wrappedLength = 256)
    {
        var unsigned = WrappedDekEnvelope.BuildUnsigned(WrapVersion, RandomNumberGenerator.GetBytes(wrappedLength));
        var envelope = new byte[unsigned.Length + WrappedDekEnvelope.KeyVersionLength + WrappedDekEnvelope.SignatureLength];
        Assert.Equal(envelope.Length, WrappedDekEnvelope.Write(unsigned, SignVersion, RandomNumberGenerator.GetBytes(64), envelope));
        return envelope;
    }

    [Fact]
    public void WriteThenParse_RoundTripsEveryPart()
    {
        var wrapped = RandomNumberGenerator.GetBytes(256);
        var signature = RandomNumberGenerator.GetBytes(64);
        var unsigned = WrappedDekEnvelope.BuildUnsigned(WrapVersion.ToUpperInvariant(), wrapped);
        var envelope = new byte[512];
        var length = WrappedDekEnvelope.Write(unsigned, SignVersion, signature, envelope);

        var parts = WrappedDekEnvelope.Parse(envelope.AsSpan(0, length));

        Assert.Equal(256 + WrappedDekEnvelope.Overhead, length);
        Assert.Equal(WrapVersion, parts.WrappingKeyVersion);
        Assert.Equal(wrapped, parts.WrappedDek);
        Assert.Equal(SignVersion, parts.SigningKeyVersion);
        Assert.Equal(signature, parts.Signature);
        Assert.Equal(unsigned.Length, parts.UnsignedLength);
        Assert.Equal("HGKV"u8.ToArray(), envelope[..4]);
    }

    [Fact]
    public void Parse_RefusesWhatIsNotAnEnvelope()
    {
        Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.Parse(new byte[WrappedDekEnvelope.Overhead]));
        Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.Parse(RandomNumberGenerator.GetBytes(300)));
    }

    [Fact]
    public void Parse_RefusesAnotherFormatVersion()
    {
        var envelope = Envelope();
        envelope[4] = 2;

        var ex = Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.Parse(envelope));
        Assert.Contains("format version 2", ex.Message);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void Parse_RefusesALengthThatDisagreesWithTheHeader(int delta)
    {
        var envelope = Envelope();
        var altered = new byte[envelope.Length + delta];
        envelope.AsSpan(0, Math.Min(envelope.Length, altered.Length)).CopyTo(altered);

        Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.Parse(altered));
    }

    [Fact]
    public void Parse_RefusesAnEmptyCiphertext()
    {
        var envelope = Envelope(wrappedLength: 1);
        envelope[21] = 0;
        envelope[22] = 0;

        Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.Parse(envelope));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(ushort.MaxValue + 1)]
    public void BuildUnsigned_RefusesACiphertextItCanNotEncode(int length)
    {
        Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.BuildUnsigned(WrapVersion, new byte[length]));
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcde")]   // 31 digits
    [InlineData("0123456789abcdef0123456789abcdef0")] // 33
    [InlineData("0123456789abcdef0123456789abcdeg")]  // not hex
    public void BuildUnsignedAndWrite_RefuseAVersionThatIsNotKeyVaults(string version)
    {
        Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.BuildUnsigned(version, new byte[256]));

        var unsigned = WrappedDekEnvelope.BuildUnsigned(WrapVersion, new byte[256]);
        Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.Write(unsigned, version, new byte[64], new byte[512]));
    }

    [Theory]
    [InlineData(63)]
    [InlineData(72)]
    public void Write_RefusesASignatureThatIsNotES256(int length)
    {
        var unsigned = WrappedDekEnvelope.BuildUnsigned(WrapVersion, new byte[256]);

        var ex = Assert.Throws<CryptographicException>(() => WrappedDekEnvelope.Write(unsigned, SignVersion, new byte[length], new byte[512]));
        Assert.Contains("EC P-256", ex.Message);
    }

    [Fact]
    public void Write_RefusesAResultTooSmall()
    {
        var unsigned = WrappedDekEnvelope.BuildUnsigned(WrapVersion, new byte[256]);

        Assert.Throws<ArgumentException>(() => WrappedDekEnvelope.Write(unsigned, SignVersion, new byte[64], new byte[unsigned.Length + 79]));
    }

    [Fact]
    public void SignedData_BindsTheDomainContextAndEnvelope()
    {
        var unsigned = WrappedDekEnvelope.BuildUnsigned(WrapVersion, new byte[256]);

        var none = WrappedDekEnvelope.SignedData(unsigned, WrappedDekEnvelope.EncodeContext(null));
        var empty = WrappedDekEnvelope.SignedData(unsigned, WrappedDekEnvelope.EncodeContext(""));
        var app = WrappedDekEnvelope.SignedData(unsigned, WrappedDekEnvelope.EncodeContext("com.example.myapp"));

        Assert.Equal(none, empty);
        Assert.NotEqual(none, app);
        var domain = "HkdfGuard-AzureKeyVault-wrap-v1\0"u8.ToArray();
        Assert.Equal(domain, app[..domain.Length]);
        Assert.Equal(unsigned, app[^unsigned.Length..]);
    }

    [Fact]
    public void EncodeContext_RefusesOneTooLongToLengthPrefix()
    {
        Assert.Throws<ArgumentException>(() => WrappedDekEnvelope.EncodeContext(new string('x', ushort.MaxValue + 1)));
    }
}
