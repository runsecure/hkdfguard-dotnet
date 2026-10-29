using System.Text.Json;
using System.Text.Json.Nodes;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.HashiCorpVault.Test.TestHelpers;

/// <summary>
/// The value an integration test's secret is expected to hold - a JSON object, read from an
/// environment variable - and the checks against what a cache reveals: the whole value (compared as
/// JSON, so whitespace the store added or removed doesn't matter) and each member as "name#key",
/// as the cache caches it (a string as its text, a number, true or false as its JSON text).
/// </summary>
internal static class ExpectedSecret
{
    /// <summary>The variable's JSON object; null if it isn't set.</summary>
    public static JsonObject? Read(string variable)
        => Environment.GetEnvironmentVariable(variable) is { Length: > 0 } json
            ? JsonNode.Parse(json) as JsonObject ?? throw new InvalidOperationException($"{variable} isn't a JSON object.")
            : null;

    /// <summary>Each member as the cache reveals it under "name#key".</summary>
    public static IEnumerable<(string Key, string Value)> Members(JsonObject expected)
        => expected
            .Where(member => member.Value is JsonValue)
            .Select(member => (member.Key, member.Value!.GetValueKind() == JsonValueKind.String
                ? member.Value.GetValue<string>()
                : member.Value.ToJsonString()));

    /// <summary>The value stored under name, as text; fails the test if there is none.</summary>
    public static string Decrypt(IProtectedReadOnlyCache cache, string name)
    {
        Assert.True(cache.TryGetMaxDecryptedLength(name, out var max), $"Nothing is stored under '{name}'.");
        var chars = new char[max];
        return new string(chars, 0, cache.Decrypt(name, chars.AsSpan()));
    }

    /// <summary><see cref="Decrypt"/>, through DecryptAsync.</summary>
    public static async Task<string> DecryptAsync(IProtectedReadOnlyCache cache, string name)
    {
        var max = await cache.GetMaxDecryptedLengthAsync(name);
        Assert.True(max > 0, $"Nothing is stored under '{name}'.");
        var chars = new char[max];
        return new string(chars, 0, await cache.DecryptAsync(name, chars.AsMemory()));
    }

    /// <summary>Asserts whole is the expected object, compared as JSON.</summary>
    public static void AssertWholeValue(JsonObject expected, string whole)
        => Assert.True(JsonNode.DeepEquals(expected, JsonNode.Parse(whole)), "The secret's whole value isn't the expected JSON object.");
}
