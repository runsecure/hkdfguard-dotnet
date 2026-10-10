using System.Text;

namespace HkdfGuard.Abstractions.Test;

public class ProtectedConfigurationPurposeTests
{
    [Fact]
    public void For_PrefixesAndUpperCasesTheFullKeyPath()
    {
        Assert.Equal("HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:ADMIN",
            ProtectedConfigurationPurpose.For("ConnectionStrings:Admin"));
    }

    [Fact]
    public void For_KeysDifferingOnlyByCase_GiveTheSamePurpose()
    {
        Assert.Equal(ProtectedConfigurationPurpose.For("connectionstrings:admin"),
            ProtectedConfigurationPurpose.For("ConnectionStrings:Admin"));
    }

    [Fact]
    public void For_DifferentKeys_GiveDifferentPurposes()
    {
        Assert.NotEqual(ProtectedConfigurationPurpose.For("ConnectionStrings:Admin"),
            ProtectedConfigurationPurpose.For("ConnectionStrings:Reporting"));
    }

    [Fact]
    public void AadFor_IsTheUtf8BytesOfThePurpose()
    {
        Assert.Equal(Encoding.UTF8.GetBytes(ProtectedConfigurationPurpose.For("Database:Password")),
            ProtectedConfigurationPurpose.AadFor("Database:Password"));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void For_WithAnEmptyKey_Throws(string? key)
    {
        Assert.ThrowsAny<ArgumentException>(() => ProtectedConfigurationPurpose.For(key!));
        Assert.ThrowsAny<ArgumentException>(() => ProtectedConfigurationPurpose.AadFor(key!));
    }

    [Theory]
    [InlineData("ConnectionStrings:Admin")]
    [InlineData("héllo:ünïcode")]
    public void AadFor_TheSpanOverload_MatchesTheStringOverload(string key)
    {
        Assert.Equal(ProtectedConfigurationPurpose.AadFor(key), ProtectedConfigurationPurpose.AadFor(key.AsSpan()));
    }

    [Fact]
    public void AadFor_AKeyTooLongForTheStack_StillMatchesFor()
    {
        var longKey = string.Join(':', Enumerable.Range(0, 60).Select(i => $"Section{i}"));

        Assert.Equal(Encoding.UTF8.GetBytes(ProtectedConfigurationPurpose.For(longKey)),
            ProtectedConfigurationPurpose.AadFor(longKey.AsSpan()));
    }

    [Fact]
    public void AadFor_AnEmptySpan_Throws()
    {
        Assert.Throws<ArgumentException>(() => ProtectedConfigurationPurpose.AadFor(ReadOnlySpan<char>.Empty));
    }

    [Theory]
    [InlineData("secret", "SECRET")]
    [InlineData("Secret", "secret")]
    [InlineData("Connection_Strings:Admin-1", "connection_strings:ADMIN-1")]
    public void For_KeysDifferingOnlyInAsciiCase_ShareAPurpose(string first, string second)
    {
        Assert.Equal(ProtectedConfigurationPurpose.For(first), ProtectedConfigurationPurpose.For(second));
        Assert.Equal(ProtectedConfigurationPurpose.AadFor(first), ProtectedConfigurationPurpose.AadFor(second));
    }

    [Theory]
    [InlineData("caf\u00E9", "CAF\u00C9")]        // non-ASCII case: configuration merges them, the purpose doesn't
    [InlineData("\u017Fecret", "Secret")]         // 'ſ' upper-cases to 'S' under Unicode rules, never here
    [InlineData("\u0131d", "ID")]                 // dotless i
    [InlineData("stra\u00DFe", "STRASSE")]        // ß
    public void For_NonAsciiCaseVariants_NeverShareAPurpose(string first, string second)
    {
        Assert.NotEqual(ProtectedConfigurationPurpose.For(first), ProtectedConfigurationPurpose.For(second));
    }

    [Fact]
    public void For_UpperCasesOnlyAsciiLetters_AndCopiesEveryOtherCodeUnitAsIs()
    {
        Assert.Equal($"{ProtectedConfigurationPurpose.Prefix}:CAF\u00E9:\u00FCBER-1_\u4E2D",
            ProtectedConfigurationPurpose.For("caf\u00E9:\u00FCber-1_\u4E2D"));
    }

    [Fact]
    public void For_NeverMergesKeysConfigurationKeepsApart_ForAnyCodePoint()
    {
        // The safety half of the rule, checked exhaustively: equal purposes imply that .NET
        // configuration would also treat the keys as the same key.
        var byPurpose = new Dictionary<string, string>();
        for (var cp = 0; cp <= 0x10FFFF; cp++)
        {
            if (cp is >= 0xD800 and <= 0xDFFF)
                continue;

            var key = char.ConvertFromUtf32(cp);
            var purpose = ProtectedConfigurationPurpose.For(key);
            if (byPurpose.TryGetValue(purpose, out var other))
                Assert.True(string.Equals(key, other, StringComparison.OrdinalIgnoreCase), $"U+{cp:X4} shares a purpose with '{other}'");
            else
                byPurpose[purpose] = key;
        }
    }

    [Fact]
    public void ForAndAadFor_RejectAnUnpairedSurrogate()
    {
        // Encoding one would substitute U+FFFD, so "Key\uD800Tail" and "Key\uD801Tail" would share an
        // AAD. Built here rather than in InlineData, which replaces lone surrogates when serializing.
        string[] keys = ["Key\uD800Tail", "Key\uDC00Tail", "Key\uD800"]; // lone high, lone low, high at the end
        foreach (var key in keys)
        {
            Assert.ThrowsAny<ArgumentException>(() => ProtectedConfigurationPurpose.For(key));
            Assert.ThrowsAny<ArgumentException>(() => ProtectedConfigurationPurpose.AadFor(key));
            Assert.ThrowsAny<ArgumentException>(() => ProtectedConfigurationPurpose.AadFor(key.AsSpan()));
        }
    }

    [Fact]
    public void ForAndAadFor_AcceptASurrogatePair()
    {
        var key = "Key😀Tail"; // U+1F600

        Assert.Equal($"{ProtectedConfigurationPurpose.Prefix}:KEY😀TAIL", ProtectedConfigurationPurpose.For(key));
        Assert.Equal(Encoding.UTF8.GetBytes(ProtectedConfigurationPurpose.For(key)), ProtectedConfigurationPurpose.AadFor(key));
    }

    [Fact]
    public void AadFor_KnownVector_ForCrossLanguagePorts()
    {
        // Every port must produce exactly these bytes for this key.
        Assert.Equal("HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:CAF\u00E9"u8.ToArray(),
            ProtectedConfigurationPurpose.AadFor("ConnectionStrings:caf\u00E9"));
    }
}
