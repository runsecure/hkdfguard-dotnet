using System.Collections.Concurrent;
using HkdfGuard.Abstractions;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.Test.TestHelpers;

/// <summary>
/// A RemoteSecretCache over an in-memory dictionary, matched as <c>matching</c> says. Names are valid
/// unless they are empty or hold a ':'. Every fetch is recorded, and <see cref="OnFetch"/> can replace one.
/// </summary>
internal sealed class FakeRemoteSecretCache(IKeyRing keyRing, SecretNameMatching matching, ILogger? logger = null)
    : RemoteSecretCache(keyRing, matching, logger)
{
    private readonly ConcurrentDictionary<string, string> _secrets =
        new(matching == SecretNameMatching.Exact ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);

    /// <summary>Every name Fetch was called with, in order.</summary>
    public ConcurrentQueue<string> Fetches { get; } = new();

    /// <summary>When set, runs in place of the default fetch.</summary>
    public Action<string, SecretValueSink>? OnFetch { get; set; }

    /// <summary>What a name without a key reads; null for the whole value.</summary>
    public string? DefaultKeyToRead { get; set; }

    public void Set(string name, string value) => _secrets[name] = value;

    protected override string? DefaultKey => DefaultKeyToRead ?? base.DefaultKey;

    protected override bool IsValidName(string name) => name.Length > 0 && !name.Contains(':');

    /// <summary>Every name FetchAsync was called with, in order - whether or not it went on to Fetch.</summary>
    public ConcurrentQueue<string> AsyncFetches { get; } = new();

    /// <summary>When set, runs in place of FetchAsync's default, which calls Fetch.</summary>
    public Func<string, SecretValueSink, CancellationToken, ValueTask>? OnFetchAsync { get; set; }

    protected override void Fetch(string name, SecretValueSink value)
    {
        Fetches.Enqueue(name);
        if (OnFetch is not null)
            OnFetch(name, value);
        else if (_secrets.TryGetValue(name, out var secret))
            value.SetText(secret);
    }

    protected override ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        AsyncFetches.Enqueue(name);
        return OnFetchAsync?.Invoke(name, value, cancellationToken) ?? base.FetchAsync(name, value, cancellationToken);
    }
}
