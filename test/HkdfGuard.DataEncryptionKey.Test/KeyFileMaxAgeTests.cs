using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// The key-file maximum age: a DataEncryptionKey with a deadline stops encrypting once it passes,
/// announcing a warning and then its expiry once each, while decryption never stops; KeyRingBuilder
/// gives every key-file key a deadline from the file's last write time, and reports a current key
/// file nearing or past its age at startup.
/// </summary>
public sealed class KeyFileMaxAgeTests : IDisposable
{
    private readonly List<string> _paths = [];

    public void Dispose()
    {
        foreach (var path in _paths)
            File.Delete(path);
    }

    private string KeyFile(int ageDays = 0)
    {
        var path = Path.GetTempFileName();
        _paths.Add(path);
        File.WriteAllBytes(path, "wrapped"u8.ToArray());
        if (ageDays != 0)
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow - TimeSpan.FromDays(ageDays));
        return path;
    }

    private static KeyRingBuilder Builder() => new KeyRingBuilder()
        .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
        .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
        .WithKeyRefreshInterval(60);

    private static async Task<ICryptoProvider> NewProviderAsync()
        => await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60);

    private static string Unprotect(IDataProtector protector, string formatted)
    {
        Span<char> result = new char[formatted.Length];
        return new string(result[..protector.Decrypt(formatted, result)]);
    }

    private static int[] EventIds(RecordingLogger<KeyRing> logger) => [.. logger.Entries.Select(e => e.EventId)];

    // --- DataEncryptionKey ------------------------------------------------------------------

    [Fact]
    public async Task Encrypt_StopsAtTheDeadline_ZeroingThePlaintext_ButDecryptKeepsWorking()
    {
        var calls = new List<string>();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var now = clock.GetUtcNow();
        var deadline = new EncryptionDeadline
        {
            WarnAt = now.AddSeconds(1),
            RefuseAt = now.AddSeconds(2),
            Reason = "rotate me",
            OnWarning = () => calls.Add("warn"),
            OnExpired = () => calls.Add("expired"),
        };
        using var key = new DataEncryptionKey(await NewProviderAsync(), deadline, clock);
        var ciphertext = key.Encrypt("before"u8.ToArray());
        Assert.False(key.CheckDeadline(now));
        Assert.Empty(calls);

        clock.Now = now.AddMilliseconds(1500);
        key.Encrypt("warned"u8.ToArray());
        key.Encrypt("warned again"u8.ToArray());
        Assert.Equal(["warn"], calls);

        clock.Now = now.AddSeconds(2);
        var plaintext = "refused"u8.ToArray();
        var refused = Assert.Throws<EncryptionLimitReachedException>(() => key.Encrypt(plaintext));
        Assert.Equal("rotate me", refused.Message);
        Assert.All(plaintext, b => Assert.Equal(0, b));
        Assert.Throws<EncryptionLimitReachedException>(() => key.Encrypt("refused again"u8.ToArray(), "aad"u8));
        Assert.Equal(["warn", "expired"], calls);

        var result = new byte[6];
        key.Decrypt(ciphertext, result);
        Assert.Equal("before"u8.ToArray(), result);
    }

    [Fact]
    public async Task Encrypt_AnnouncesExpiryOnce_EvenWhenTheWarningWasSkipped_AndIgnoresAThrowingCallback()
    {
        var expired = 0;
        using var key = new DataEncryptionKey(await NewProviderAsync(), new EncryptionDeadline
        {
            WarnAt = DateTimeOffset.UnixEpoch,
            RefuseAt = DateTimeOffset.UnixEpoch.AddMilliseconds(1),
            Reason = "old",
            OnWarning = () => throw new InvalidOperationException("never called"),
            OnExpired = () =>
            {
                expired++;
                throw new InvalidOperationException("bad logger");
            },
        });

        Assert.Throws<EncryptionLimitReachedException>(() => key.Encrypt("x"u8.ToArray()));
        Assert.Throws<EncryptionLimitReachedException>(() => key.Encrypt("x"u8.ToArray()));
        Assert.Equal(1, expired);
    }

    [Fact]
    public async Task CheckDeadline_UnderConcurrentEncrypts_CallsEachCallbackOnce()
    {
        var warned = 0;
        var expired = 0;
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var deadline = new EncryptionDeadline
        {
            WarnAt = clock.Now.AddSeconds(1),
            RefuseAt = clock.Now.AddSeconds(2),
            Reason = "rotate me",
            OnWarning = () => Interlocked.Increment(ref warned),
            OnExpired = () => Interlocked.Increment(ref expired),
        };
        using var key = new DataEncryptionKey(await NewProviderAsync(), deadline, clock);

        clock.Now = deadline.WarnAt;
        Parallel.For(0, 64, _ => key.CheckDeadline());
        clock.Now = deadline.RefuseAt;
        Parallel.For(0, 64, _ => key.CheckDeadline());

        Assert.Equal(1, warned);
        Assert.Equal(1, expired);
    }

    [Fact]
    public async Task Encrypt_WithoutADeadline_IsNeverLimited()
    {
        using var key = new DataEncryptionKey(await NewProviderAsync());

        Assert.Null(key.Deadline);
        Assert.False(key.CheckDeadline(DateTimeOffset.MaxValue));
        Assert.Equal(5 + 28, key.Encrypt("hello"u8.ToArray()).Length);
    }

    // --- KeyRingBuilder ---------------------------------------------------------------------

    [Fact]
    public void WithKeyFileMaxAgeDays_DefaultsTo365_AndAcceptsOneTo3650()
    {
        Assert.Equal(365, KeyRingBuilder.DefaultKeyFileMaxAgeDays);
        Assert.Equal(KeyRingBuilder.DefaultKeyFileMaxAgeDays, new KeyRingBuilder().KeyFileMaxAgeDays);
        Assert.Equal(1, new KeyRingBuilder().WithKeyFileMaxAgeDays(1).KeyFileMaxAgeDays);
        Assert.Equal(3650, new KeyRingBuilder().WithKeyFileMaxAgeDays(3650).KeyFileMaxAgeDays);

        foreach (var days in new[] { 0, -1, 3651 })
        {
            var refused = Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithKeyFileMaxAgeDays(days));
            Assert.StartsWith("KeyFileMaxAgeDays must be between 1 and 3650.", refused.Message);
        }
    }

    [Theory]
    [InlineData(null, 365)]
    [InlineData(30, 30)]
    public async Task Build_LimitsEachKeyFileToItsAgeFromWhenItWasLastWritten(int? maxAgeDays, int days)
    {
        var path = KeyFile();
        var written = new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);
        var builder = Builder().WithKeyFile(1, path);
        if (maxAgeDays is { } configured)
            builder.WithKeyFileMaxAgeDays(configured);

        await using var ring = await builder.BuildAsync();

        var deadline = ((DataEncryptionKey)ring.Get(1)).Deadline!;
        Assert.Equal(written + TimeSpan.FromDays(days), deadline.RefuseAt);
        Assert.Equal(written + TimeSpan.FromDays(days) * 0.9, deadline.WarnAt);
        Assert.Contains($"more than {days} days ago (KeyFileMaxAgeDays)", deadline.Reason);
        Assert.StartsWith($"Key file '{path}' (version 1) was last written {written.UtcDateTime:yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'}, ", deadline.Reason);
    }

    [Fact]
    public async Task Build_ReportsACurrentKeyFileNearingItsAgeAtStartup_Once_AndKeepsEncrypting()
    {
        var logger = new RecordingLogger<KeyRing>();
        await using var ring = await Builder().WithKeyFile(1, KeyFile(ageDays: 340)).WithLogger(logger).BuildAsync();

        var warning = Assert.Single(logger.Entries);
        Assert.Equal(11, warning.EventId);
        Assert.Equal(LogLevel.Warning, warning.Level);
        var protector = ring.CreateProtector("aging");
        Assert.Equal("still fine", Unprotect(protector, protector.Encrypt("still fine")));
        Assert.Equal([11], EventIds(logger));
    }

    [Fact]
    public async Task Encrypt_RefusesACurrentKeyFilePastItsAge_ReportedAtStartup_ButStillDecrypts()
    {
        var path = KeyFile(ageDays: 20);
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        await using var before = await Builder().WithKeyFile(1, path).WithKeyFileMaxAgeDays(30).WithTimeProviderForTesting(clock).BuildAsync();
        var protector = before.CreateProtector("expiring");
        var formatted = protector.Encrypt("written in time");

        clock.Now += TimeSpan.FromDays(15); // now 35 days old
        Assert.Throws<EncryptionLimitReachedException>(() => protector.Encrypt("too late"));
        Assert.Equal("written in time", Unprotect(protector, formatted));

        var logger = new RecordingLogger<KeyRing>();
        await using var after = await Builder().WithKeyFile(1, path).WithKeyFileMaxAgeDays(30)
            .WithTimeProviderForTesting(clock).WithLogger(logger).BuildAsync();
        var expired = Assert.Single(logger.Entries);
        Assert.Equal(12, expired.EventId);
        Assert.Equal(LogLevel.Critical, expired.Level);
        var refused = Assert.Throws<EncryptionLimitReachedException>(() => after.CreateProtector("expiring").Encrypt("too late"));
        Assert.Contains(path, refused.Message);
        Assert.Equal([12], EventIds(logger));
    }

    [Fact]
    public async Task Build_NeverReportsASupersededKeyFile_WhichNeverEncrypts()
    {
        var logger = new RecordingLogger<KeyRing>();
        await using var ring = await Builder().WithKeyFile(1, KeyFile(ageDays: 400)).WithKeyFile(2, KeyFile()).WithLogger(logger).BuildAsync();

        Assert.Equal(2, ring.CurrentVersion);
        Assert.Empty(logger.Entries);
        var protector = ring.CreateProtector("rotated");
        Assert.Equal("fine", Unprotect(protector, protector.Encrypt("fine")));
    }

    [Fact]
    public async Task Build_PutsNoAgeLimitOnEphemeralKeys()
    {
        await using var ring = await Builder().WithEphemeralKey(1).WithoutEphemeralKeyRotation().WithKeyFileMaxAgeDays(1).BuildAsync();

        Assert.Null(((DataEncryptionKey)ring.Get(1)).Deadline);
    }

    [Fact]
    public async Task Build_WithoutALogger_StillRefusesAnExpiredKeyFile()
    {
        await using var ring = await Builder().WithKeyFile(1, KeyFile(ageDays: 40)).WithKeyFileMaxAgeDays(30).BuildAsync();

        Assert.Throws<EncryptionLimitReachedException>(() => ring.CreateProtector("expired").Encrypt("too late"));
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
