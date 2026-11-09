using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace HkdfGuard.SystemdCredentials;

/// <summary>What one systemd-creds run gave back: its exit code, stdout - in pinned memory - and stderr.</summary>
internal sealed record SystemdCredsResult(int ExitCode, SystemdCredential Output, string Error);

/// <summary>Runs systemd-creds with arguments, writing stdin to it; the tests run a fake.</summary>
internal interface ISystemdCredsRunner
{
    Task<SystemdCredsResult> RunAsync(string executablePath, IReadOnlyList<string> arguments, ReadOnlyMemory<byte> stdin,
        TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>
/// Runs the real systemd-creds: arguments as an argument list, never through a shell; stdin written
/// straight to the pipe, not through a TextWriter whose buffer couldn't be cleared; stdout read
/// straight off the pipe into pinned memory. Killed, with anything it started, if it outlasts the
/// timeout or the caller cancels.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Starts the operating system's systemd-creds; the Linux integration tests run it, the unit tests a fake.")]
internal sealed class ProcessSystemdCredsRunner : ISystemdCredsRunner
{
    public static readonly ProcessSystemdCredsRunner Instance = new();

    public async Task<SystemdCredsResult> RunAsync(string executablePath, IReadOnlyList<string> arguments, ReadOnlyMemory<byte> stdin,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(executablePath)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"{executablePath} didn't start.");
        try
        {
            var error = process.StandardError.ReadToEndAsync(timeoutSource.Token);
            var output = SystemdCredential.ReadAsync(process.StandardOutput.BaseStream, timeoutSource.Token);

            await using (var input = process.StandardInput.BaseStream)
            {
                if (!stdin.IsEmpty)
                    await input.WriteAsync(stdin, timeoutSource.Token).ConfigureAwait(false);
            }

            var value = await output.ConfigureAwait(false);
            try
            {
                var message = await error.ConfigureAwait(false);
                await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
                return new SystemdCredsResult(process.ExitCode, value, message);
            }
            catch
            {
                value.Dispose();
                throw;
            }
        }
        catch (OperationCanceledException) when (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            if (cancellationToken.IsCancellationRequested)
                throw;
            throw new TimeoutException($"systemd-creds didn't finish within {timeout}.");
        }
    }
}
