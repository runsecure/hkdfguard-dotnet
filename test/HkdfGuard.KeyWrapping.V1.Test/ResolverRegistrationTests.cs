using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// Resolver registration happens once, and no caller can return before it has actually happened -
/// otherwise its first native call could be resolved by the default library search.
/// </summary>
public class ResolverRegistrationTests
{
    [Fact]
    public async Task ACallerArrivingDuringInstallation_WaitsUntilTheInstallHasFinished()
    {
        var gate = new NativeLibraryResolver.RegistrationGate();
        using var installing = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var installed = false;

        var first = Task.Run(() => gate.Run(() =>
        {
            installing.Set();
            release.Wait();
            installed = true;
        }));
        installing.Wait();

        // A second caller arrives while the first is mid-install.
        var second = Task.Run(() =>
        {
            gate.Run(() => throw new InvalidOperationException("must not install twice"));
            return installed; // what this caller can rely on once Run returns
        });

        Assert.False(second.Wait(TimeSpan.FromMilliseconds(200)), "the second caller returned before the install finished");

        release.Set();
        await first;
        Assert.True(await second);
        Assert.True(gate.IsDone);
    }

    [Fact]
    public async Task ManyConcurrentCallers_InstallExactlyOnce()
    {
        var gate = new NativeLibraryResolver.RegistrationGate();
        var installs = 0;
        using var start = new ManualResetEventSlim();

        var callers = Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        {
            start.Wait();
            gate.Run(() => Interlocked.Increment(ref installs));
        })).ToArray();
        start.Set();
        await Task.WhenAll(callers);

        Assert.Equal(1, installs);
    }

    [Fact]
    public void AFailedInstall_IsNotRecorded_SoTheNextCallTriesAgain()
    {
        var gate = new NativeLibraryResolver.RegistrationGate();

        Assert.Throws<InvalidOperationException>(() => gate.Run(() => throw new InvalidOperationException("failed")));
        Assert.False(gate.IsDone);

        var ran = false;
        gate.Run(() => ran = true);

        Assert.True(ran);
        Assert.True(gate.IsDone);
    }

    [Fact]
    public void EnsureRegistered_IsSafeToCallRepeatedly()
    {
        // Setting a resolver twice throws InvalidOperationException; repeated calls must not.
        NativeLibraryResolver.EnsureRegistered();
        NativeLibraryResolver.EnsureRegistered();
    }
}
