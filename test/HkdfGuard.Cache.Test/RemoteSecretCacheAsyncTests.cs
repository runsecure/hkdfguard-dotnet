using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.Cache.Test;

/// <summary>RemoteSecretCache's asynchronous lookups: FetchAsync, and fetches shared between callers.</summary>
public class RemoteSecretCacheAsyncTests
{
    private static async Task<FakeRemoteSecretCache> CreateAsync(SecretNameMatching matching = SecretNameMatching.Exact)
        => new(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))), matching);

    private static async Task<string> DecryptStringAsync(FakeRemoteSecretCache cache, string name, CancellationToken cancellationToken = default)
    {
        var result = new char[64];
        return new string(result, 0, await cache.DecryptAsync(name, result.AsMemory(), cancellationToken));
    }

    private static string DecryptString(FakeRemoteSecretCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    // A FetchAsync that waits for release, then hands over value; started completes once it is running.
    private static (TaskCompletionSource Started, TaskCompletionSource Release) Gate(FakeRemoteSecretCache cache, string value)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        cache.OnFetchAsync = async (_, sink, cancellationToken) =>
        {
            started.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
            sink.SetText(value);
        };
        return (started, release);
    }

    [Fact]
    public async Task AMiss_FetchesThroughFetchAsync_ThenEveryOverloadIsServedFromTheCache()
    {
        var cache = await CreateAsync();
        cache.Set("item", "value");

        Assert.True(await cache.GetMaxDecryptedLengthAsync("item") >= 5);
        Assert.Equal("value", await DecryptStringAsync(cache, "item"));
        var bytes = new byte[16];
        Assert.Equal("value"u8.ToArray(), bytes[..await cache.DecryptAsync("item", bytes.AsMemory())]);
        Assert.Equal("value", DecryptString(cache, "item"));

        // FetchAsync's default calls Fetch.
        Assert.Equal(["item"], cache.AsyncFetches);
        Assert.Equal(["item"], cache.Fetches);
    }

    [Fact]
    public async Task AnOverriddenFetchAsync_IsUsed_AndFetchIsNot()
    {
        var cache = await CreateAsync();
        cache.OnFetchAsync = async (name, sink, _) =>
        {
            await Task.Yield();
            sink.SetText($"async {name}");
        };

        Assert.Equal("async item", await DecryptStringAsync(cache, "item"));
        Assert.Empty(cache.Fetches);
    }

    [Fact]
    public async Task KeysHandedOverAsynchronously_AreCachedFromOneFetch()
    {
        var cache = await CreateAsync();
        cache.OnFetchAsync = async (_, sink, _) =>
        {
            await Task.Yield();
            sink.SetBytesWithJsonKeys("""{"user":"app","pass":"s3cret"}"""u8.ToArray());
        };

        Assert.Equal("s3cret", await DecryptStringAsync(cache, "db#pass"));
        Assert.Equal("app", await DecryptStringAsync(cache, "db#user"));
        Assert.Single(cache.AsyncFetches);
    }

    [Fact]
    public async Task AMissingSecret_ReturnsZero_AndIsFetchedAgain()
    {
        var cache = await CreateAsync();

        Assert.Equal(0, await cache.DecryptAsync("later", new byte[16].AsMemory()));
        Assert.Equal(0, await cache.GetMaxDecryptedLengthAsync("later"));
        cache.Set("later", "now here");
        Assert.Equal("now here", await DecryptStringAsync(cache, "later"));
        Assert.Equal(3, cache.AsyncFetches.Count);
    }

    [Theory]
    [InlineData("in:valid")]
    [InlineData("s#bad key")]
    [InlineData("#key")]
    public async Task AnInvalidName_IsMissing_WithoutAFetch(string name)
    {
        var cache = await CreateAsync();

        Assert.Equal(0, await cache.DecryptAsync(name, new byte[16].AsMemory()));
        Assert.Equal(0, await cache.DecryptAsync(name, new char[16].AsMemory()));
        Assert.Equal(0, await cache.GetMaxDecryptedLengthAsync(name));
        Assert.Empty(cache.AsyncFetches);
    }

    [Fact]
    public async Task ANullName_Throws()
    {
        var cache = await CreateAsync();

        await Assert.ThrowsAsync<ArgumentNullException>(() => cache.DecryptAsync(null!, new byte[16].AsMemory()).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(() => cache.DecryptAsync(null!, new char[16].AsMemory()).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(() => cache.GetMaxDecryptedLengthAsync(null!).AsTask());
    }

    [Fact]
    public async Task AFetchFailure_Propagates_AndIsRetriedOnTheNextLookup()
    {
        var cache = await CreateAsync();
        cache.OnFetchAsync = async (_, _, _) =>
        {
            await Task.Yield();
            throw new TimeoutException("unreachable");
        };

        await Assert.ThrowsAsync<TimeoutException>(() => DecryptStringAsync(cache, "item"));

        cache.OnFetchAsync = null;
        cache.Set("item", "value");
        Assert.Equal("value", await DecryptStringAsync(cache, "item"));
    }

    [Fact]
    public async Task AFetchsOwnCancellation_IsAFailure_NotTheCallersCancellation()
    {
        var cache = await CreateAsync();
        cache.OnFetchAsync = (_, _, _) => throw new OperationCanceledException("A timeout inside the fetch.");

        var e = await Assert.ThrowsAsync<OperationCanceledException>(() => DecryptStringAsync(cache, "item"));
        Assert.Equal("A timeout inside the fetch.", e.Message);
    }

    [Fact]
    public async Task ConcurrentSyncAndAsyncLookups_ShareOneFetch()
    {
        var cache = await CreateAsync();
        var (started, release) = Gate(cache, "value");

        var first = DecryptStringAsync(cache, "shared");
        await started.Task;
        var others = new[]
        {
            DecryptStringAsync(cache, "shared"),
            Task.Run(() => DecryptString(cache, "shared")),
            Task.Run(() => DecryptString(cache, "shared")),
        };
        await Task.Delay(100);
        release.SetResult();

        Assert.Equal("value", await first);
        Assert.Equal(["value", "value", "value"], await Task.WhenAll(others));
        Assert.Single(cache.AsyncFetches);
        Assert.Empty(cache.Fetches);
    }

    [Fact]
    public async Task ASyncLookupStartingTheFetch_IsJoinedByAsyncOnes()
    {
        var cache = await CreateAsync();
        using var release = new ManualResetEventSlim();
        cache.OnFetch = (_, sink) =>
        {
            release.Wait(TimeSpan.FromSeconds(10));
            sink.SetText("value");
        };

        var sync = Task.Run(() => DecryptString(cache, "shared"));
        while (cache.Fetches.IsEmpty)
            await Task.Delay(10);
        var asynchronous = DecryptStringAsync(cache, "shared");
        await Task.Delay(100);
        release.Set();

        Assert.Equal(["value", "value"], await Task.WhenAll(sync, asynchronous));
        Assert.Single(cache.Fetches);
        Assert.Empty(cache.AsyncFetches);
    }

    [Fact]
    public async Task AJoinerCancellingItsWait_LeavesTheFetchRunningForTheOthers()
    {
        var cache = await CreateAsync();
        var (started, release) = Gate(cache, "value");

        var owner = DecryptStringAsync(cache, "shared");
        await started.Task;
        using var cancel = new CancellationTokenSource();
        var joiner = DecryptStringAsync(cache, "shared", cancel.Token);
        await Task.Delay(50);
        await cancel.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => joiner);
        release.SetResult();
        Assert.Equal("value", await owner);
        Assert.Single(cache.AsyncFetches);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WhenTheCallerThatStartedAFetchCancelsIt_AJoinerFetchesAgain(bool synchronousJoiner)
    {
        var cache = await CreateAsync();
        var (started, _) = Gate(cache, "never");

        using var cancel = new CancellationTokenSource();
        var owner = DecryptStringAsync(cache, "shared", cancel.Token);
        await started.Task;
        var joiner = synchronousJoiner ? Task.Run(() => DecryptString(cache, "shared")) : DecryptStringAsync(cache, "shared");
        await Task.Delay(100);

        // The fetch the joiner starts once the first is cancelled answers at once.
        cache.OnFetchAsync = (_, sink, _) =>
        {
            sink.SetText("second fetch");
            return ValueTask.CompletedTask;
        };
        cache.OnFetch = (_, sink) => sink.SetText("second fetch");
        await cancel.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner);
        Assert.Equal("second fetch", await joiner);
    }

    [Fact]
    public async Task ACancelledLookupOfACachedName_StillAnswers()
    {
        var cache = await CreateAsync();
        cache.Set("item", "value");
        Assert.Equal("value", await DecryptStringAsync(cache, "item"));

        Assert.Equal("value", await DecryptStringAsync(cache, "item", new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task AnUncachedLookup_WithACancelledToken_IsCancelled_WithoutAFetch()
    {
        var cache = await CreateAsync();
        cache.Set("item", "value");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DecryptStringAsync(cache, "item", new CancellationToken(canceled: true)));
        Assert.Empty(cache.Fetches);
    }

    [Fact]
    public async Task InACollection_ARemoteSourceIsAskedAsynchronously()
    {
        var remote = await CreateAsync();
        remote.OnFetchAsync = async (_, sink, _) =>
        {
            await Task.Yield();
            sink.SetText("remote value");
        };
        var local = new ProtectedCache(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))));
        local.Add("local", "local value"u8.ToArray());
        var collection = new ProtectedCacheCollection().Add(local).Add(remote);

        var chars = new char[32];
        Assert.Equal("local value", new string(chars, 0, await collection.DecryptAsync("local", chars.AsMemory())));
        Assert.Equal("remote value", new string(chars, 0, await collection.DecryptAsync("remote", chars.AsMemory())));
        Assert.Equal(["remote"], remote.AsyncFetches);
        Assert.Empty(remote.Fetches);
        Assert.True(await collection.GetMaxDecryptedLengthAsync("remote") >= Encoding.UTF8.GetByteCount("remote value"));
        Assert.True(await collection.GetMaxDecryptedLengthAsync("local") >= Encoding.UTF8.GetByteCount("local value"));
        Assert.Equal(0, await collection.GetMaxDecryptedLengthAsync("in:valid"));
    }
}
