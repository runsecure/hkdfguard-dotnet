using System.Text.Json;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>Go durations, and how leniently responses are read where Vault strays from its spec.</summary>
public class GoDurationAndJsonTests
{
    [Theory]
    [InlineData("0", 0)]
    [InlineData("-0", 0)]
    [InlineData("300ms", 3_000_000)]
    [InlineData("1.5s", 15_000_000)]
    [InlineData(".5s", 5_000_000)]
    [InlineData("1h30m", 54_000_000_000)]
    [InlineData("-1m", -600_000_000)]
    [InlineData("+2s", 20_000_000)]
    [InlineData("1h2m3.5s", 37_235_000_000)]
    [InlineData("100ns", 1)]
    [InlineData("1us", 10)]
    [InlineData("1µs", 10)]
    [InlineData("1μs", 10)]
    [InlineData("2h45m", 99_000_000_000)]
    public void Parse_ReadsGoDurations(string value, long ticks) => Assert.Equal(TimeSpan.FromTicks(ticks), GoDuration.Parse(value));

    [Theory]
    [InlineData("")]
    [InlineData("-")]
    [InlineData("60")]
    [InlineData("1x")]
    [InlineData("s")]
    [InlineData(".s")]
    [InlineData("1.2.3s")]
    public void Parse_RefusesWhatIsntOne(string value) => Assert.Throws<FormatException>(() => GoDuration.Parse(value));

    [Fact]
    public void Parse_RefusesWhatATimeSpanCantHold() => Assert.Throws<OverflowException>(() => GoDuration.Parse("9999999999h"));

    [Theory]
    [InlineData(0, "0s")]
    [InlineData(1, "100ns")]
    [InlineData(15, "1.5µs")]
    [InlineData(15_000, "1.5ms")]
    [InlineData(3_000_000, "300ms")]
    [InlineData(10_000_000, "1s")]
    [InlineData(3_000_000_000, "5m0s")]
    [InlineData(37_235_000_000, "1h2m3.5s")]
    [InlineData(36_000_000_000, "1h0m0s")]
    [InlineData(-600_000_000, "-1m0s")]
    public void Format_WritesGoDurations(long ticks, string expected) => Assert.Equal(expected, GoDuration.Format(TimeSpan.FromTicks(ticks)));

    [Fact]
    public async Task AStringProperty_TakesWhateverJsonStandsInItsPlace_AsText()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(System.Net.HttpStatusCode.OK, """
            {"data":{"token_ttl":768,"token_max_ttl":"24h","token_type":true,"token_period":false,
                     "token_policies":["a",1],"bind_secret_id":true,"token_num_uses":"5","secret_id_ttl":null,
                     "secret_id_bound_cidrs":[{"x":1}],"not_in_the_spec":{"nested":[1]}}}
            """);

        var role = (await t.Client.SendAsync<AppRoleShapedResponse>(HttpMethod.Get, "/v1/auth/approle/role/r", null, null, null, default))!.Data!;

        Assert.Equal(("768", "24h", "true", "false"), (role.TokenTtl, role.TokenMaxTtl, role.TokenType, role.TokenPeriod));
        Assert.Equal(["a", "1"], role.TokenPolicies!);
        Assert.Equal((true, 5), (role.BindSecretId, role.TokenNumUses));
        Assert.Null(role.SecretIdTtl);
        Assert.Equal("""{"x":1}""", Assert.Single(role.SecretIdBoundCidrs!));
    }

    [Theory]
    [InlineData("\"2024-05-06T07:08:09Z\"", 0)]
    [InlineData("\"2024-05-06T07:08:09.5+02:00\"", 5_000_000)]
    [InlineData("\"2024-05-06T07:08:09.123456789Z\"", 1_234_567)]
    [InlineData("\"2024-05-06T07:08:09.123456789\"", 1_234_567)]
    public void DateTimes_KeepWhatPrecisionTheyCan(string json, long fractionTicks)
    {
        var info = JsonSerializer.Deserialize<VaultResponseWrapInfo>($$"""{"creation_time":{{json}}}""", VaultJson.Options)!;
        var direct = JsonSerializer.Deserialize<DateTimeOffset>(json, VaultJson.Options);

        Assert.Equal(fractionTicks, info.CreationTime!.Value.Ticks % TimeSpan.TicksPerSecond);
        Assert.Equal(info.CreationTime.Value, direct);
    }

    [Theory]
    [InlineData("\"\"")]
    [InlineData("null")]
    public void AnEmptyDateTime_IsNone(string json)
    {
        Assert.Null(JsonSerializer.Deserialize<VaultResponseWrapInfo>($$"""{"creation_time":{{json}}}""", VaultJson.Options)!.CreationTime);
        Assert.Equal(default, JsonSerializer.Deserialize<DateTimeOffset>("\"\"", VaultJson.Options));
    }

    [Theory]
    [InlineData("\"yesterday\"")]
    [InlineData("12")]
    public void ADateTimeThatIsntOne_FailsTheResponse(string json)
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<VaultResponseWrapInfo>($$"""{"creation_time":{{json}}}""", VaultJson.Options));

    [Fact]
    public void Writing_LeavesOutNullProperties_AndWritesTimesAndTokensAsTheyAre()
    {
        var json = JsonSerializer.Serialize(new VaultResponseWrapInfo
        {
            Token = new StaticVaultToken("protected-form"),
            CreationTime = new DateTimeOffset(2024, 5, 6, 7, 8, 9, TimeSpan.Zero),
        }, VaultJson.Options);

        Assert.Equal("""{"token":"protected-form","ttl":0,"creation_time":"2024-05-06T07:08:09+00:00"}""", json);
        Assert.Equal("{\"creation_time\":null}", JsonSerializer.Serialize(new NullableTime(), VaultJson.Options));
        Assert.Equal("\"2024-05-06T07:08:09+00:00\"", JsonSerializer.Serialize(new DateTimeOffset(2024, 5, 6, 7, 8, 9, TimeSpan.Zero), VaultJson.Options));
        Assert.Equal("{\"a\":\"b\"}", JsonSerializer.Serialize(new Dictionary<string, string> { ["a"] = "b" }, VaultJson.Options));
    }

    [Fact]
    public void AStringPropertyGivenSomethingElse_FailsTheResponse()
        => Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Dictionary<string, string>>("""{"a":}""", VaultJson.Options));

    [Fact]
    public void ATokenReadOutsideAClient_Fails()
        => Assert.Throws<InvalidOperationException>(() => JsonSerializer.Deserialize<VaultResponseWrapInfo>("""{"token":"hvs.x"}""", VaultJson.Options));

    [Fact]
    public void SecureBufferWriter_Grows_AndIsZeroedWhenDisposed()
    {
        var writer = new SecureBufferWriter(4);
        "0123456789"u8.CopyTo(writer.GetSpan(10));
        writer.Advance(10);
        writer.GetMemory(1000);
        var memory = writer.WrittenMemory;

        Assert.Equal("0123456789"u8.ToArray(), memory.ToArray());
        Assert.Throws<ArgumentOutOfRangeException>(() => writer.Advance(-1));
        Assert.Throws<InvalidOperationException>(() => writer.Advance(1_000_000));

        writer.Dispose();
        Assert.All(memory.ToArray(), b => Assert.Equal(0, b));
        Assert.Equal(0, writer.WrittenMemory.Length);
    }

    // The shape of a generated response model (AppRoleReadRoleResponse's): strings where Vault sends
    // durations as numbers, nullable values throughout.
    private sealed class AppRoleShapedResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("bind_secret_id")]
        public bool? BindSecretId { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("secret_id_bound_cidrs")]
        public List<string>? SecretIdBoundCidrs { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("secret_id_ttl")]
        public string? SecretIdTtl { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_max_ttl")]
        public string? TokenMaxTtl { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_num_uses")]
        public int? TokenNumUses { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_period")]
        public string? TokenPeriod { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_policies")]
        public List<string>? TokenPolicies { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_ttl")]
        public string? TokenTtl { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
    }

    private sealed class NullableTime
    {
        [System.Text.Json.Serialization.JsonPropertyName("creation_time")]
        [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.Never)]
        public DateTimeOffset? CreationTime { get; set; }
    }
}
