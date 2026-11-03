using System.Net;
using System.Text;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>vault-client-go's replication_consistency tests.</summary>
public class VaultReplicationTests
{
    [Theory]
    [InlineData("v1:my-cluster:12345:54321:", null)]
    [InlineData("v1:my-cluster:12345:54321:1B9144F5EC067A2A6D6099F16418A3AFD2E5CDA5C9EC318C92D00ED8DD8207E4", "my-hmac-key")]
    public void Parse_ReadsTheState_VerifyingAnHmac(string raw, string? hmacKey)
    {
        var state = VaultReplicationState.Parse(Encode(raw), hmacKey is null ? default : Encoding.UTF8.GetBytes(hmacKey));

        Assert.Equal(new VaultReplicationState("my-cluster", 12345, 54321), state);
    }

    [Theory]
    [InlineData("v1:my-cluster:12345:54321:1B9144F5EC067A2A6D6099F16418A3AFD2E5CDA5C9EC318C92D00ED8DD8207E4", "bad-key")]
    [InlineData("bad-format", null)]
    [InlineData("v1:my-cluster:12345:54321:not-hex", null)]
    [InlineData("v2:my-cluster:1:2:", null)]
    [InlineData("v1::1:2:", null)]
    [InlineData("v1:c:x:2:", null)]
    [InlineData("v1:c:1:-2:", null)]
    [InlineData("v1:c:1:", null)]
    public void Parse_RefusesWhatIsntAState(string raw, string? hmacKey)
        => Assert.Throws<FormatException>(() => VaultReplicationState.Parse(Encode(raw), hmacKey is null ? default : Encoding.UTF8.GetBytes(hmacKey)));

    [Fact]
    public void Parse_RefusesWhatIsntBase64() => Assert.Throws<FormatException>(() => VaultReplicationState.Parse("not base64!"));

    [Theory]
    [InlineData(new string[0], "v1:cid:1:0:", new[] { "v1:cid:1:0:" })]
    [InlineData(new[] { "v1:cid:1:0:" }, "v1:cid:2:0:", new[] { "v1:cid:2:0:" })]
    [InlineData(new[] { "v1:cid:2:0:" }, "v1:cid:1:0:", new[] { "v1:cid:2:0:" })]
    [InlineData(new[] { "v1:cid:1:0:" }, "v1:cid:0:1:", new[] { "v1:cid:0:1:", "v1:cid:1:0:" })]
    [InlineData(new[] { "v1:cid:0:1:" }, "v1:cid:1:0:", new[] { "v1:cid:0:1:", "v1:cid:1:0:" })]
    [InlineData(new[] { "v1:cid:0:1:", "v1:cid:1:0:" }, "v1:cid:2:0:", new[] { "v1:cid:0:1:", "v1:cid:2:0:" })]
    [InlineData(new[] { "v1:cid:0:1:", "v1:cid:1:0:" }, "v1:cid:2:1:", new[] { "v1:cid:2:1:" })]
    [InlineData(new[] { "v1:a:1:0:", "v1:a:2:0:", "v1:a:3:0:" }, "v1:a:0:0:", new[] { "v1:a:0:0:" })]
    [InlineData(new[] { "v1:other:9:9:" }, "v1:cid:1:0:", new[] { "v1:cid:1:0:" })]
    [InlineData(new[] { "garbage" }, "v1:cid:1:0:", new[] { "v1:cid:1:0:" })]
    public void Merge_KeepsTheNewestStates(string[] oldStates, string newState, string[] expected)
    {
        var merged = VaultReplication.MergeReplicationStates(oldStates.Select(Encode).ToArray(), Encode(newState));

        Assert.Equal(expected, merged.Select(Decode));
    }

    [Fact]
    public void RecordAndRequire_CarryAStateFromAResponseToARequest()
    {
        string? recorded = "unset";
        var record = VaultReplication.RecordReplicationState(s => recorded = s);
        using var response = new HttpResponseMessage(HttpStatusCode.OK);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://vault.test/v1/a");

        record(request, response);
        Assert.Null(recorded);

        response.Headers.Add("X-Vault-Index", "state-1");
        record(request, response);
        VaultReplication.RequireReplicationStates(recorded!, "state-2")(request);

        Assert.Equal("state-1", recorded);
        Assert.Equal(["state-1", "state-2"], request.Headers.GetValues("X-Vault-Index"));
    }

    [Fact]
    public void TheCache_IgnoresResponsesWithoutAState()
    {
        var cache = new ReplicationStateCache();
        using var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Headers.TryAddWithoutValidation("X-Vault-Index", "");

        cache.Record(response);

        Assert.Empty(cache.Snapshot());
    }

    private static string Encode(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    private static string Decode(string s) => Encoding.UTF8.GetString(Convert.FromBase64String(s));
}
