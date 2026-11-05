using System.Text;
using HkdfGuard.Abstractions;

namespace HkdfGuard.SystemdCredentials;

/// <summary>
/// Encrypts and decrypts Linux credentials with systemd-creds, which binds each to this machine's
/// host key, its TPM, or both (<see cref="SystemdCredentialsOptions.Key"/>), and to its name: a
/// credential renamed fails to decrypt. The plaintext never touches a file or a command line:
/// encrypting writes it to systemd-creds' stdin, and decrypting reads it from systemd-creds' stdout
/// into pinned memory.
/// <code>
/// // At deploy, on the machine itself (as root, for system credentials):
/// await credentials.EncryptAsync("tls-password", password, "/etc/credstore.encrypted/tls-password.cred");
///
/// // In the service: LoadCredentialEncrypted=tls-password:/etc/credstore.encrypted/tls-password.cred
/// // in its unit has systemd decrypt it into memory under /run, which ReadLoadedCredential reads -
/// // or, with the privilege to, decrypt it directly:
/// using var value = await credentials.DecryptAsync("tls-password", "/etc/credstore.encrypted/tls-password.cred");
/// </code>
/// <para>
/// Decrypting a system credential directly needs what encrypting it used: root, for the host key,
/// and access to the TPM (the tss group, say) for a TPM-bound one. An unprivileged service reads it
/// through LoadCredentialEncrypted= instead, which systemd decrypts for it into the service's own
/// unswappable in-memory credentials directory (<see cref="ReadLoadedCredential"/>), or uses
/// <see cref="SystemdCredentialsOptions.UserScope"/> credentials.
/// </para>
/// </summary>
public sealed class SystemdCredentials
{
    /// <summary>The environment variable systemd names a service's credentials directory in.</summary>
    public const string CredentialsDirectoryVariable = "CREDENTIALS_DIRECTORY";

    /// <summary>The longest credential name.</summary>
    public const int MaxNameLength = 255;

    private readonly SystemdCredentialsOptions _options;
    private readonly ISystemdCredsRunner _runner;

    /// <param name="options">Where systemd-creds is and how to run it; null for the defaults.</param>
    /// <exception cref="PlatformNotSupportedException">Not Linux</exception>
    /// <exception cref="ArgumentException">The executable path isn't absolute, or the key isn't one</exception>
    /// <exception cref="ArgumentOutOfRangeException">The timeout isn't positive</exception>
    public SystemdCredentials(SystemdCredentialsOptions? options = null)
        : this(options, ProcessSystemdCredsRunner.Instance)
        => RequireLinux(OperatingSystem.IsLinux());

    /// <exception cref="PlatformNotSupportedException">isLinux is false</exception>
    internal static void RequireLinux(bool isLinux)
    {
        if (!isLinux)
            throw new PlatformNotSupportedException("systemd-creds runs only on Linux.");
    }

    /// <summary>Runs systemd-creds through runner, on any OS, for tests.</summary>
    internal SystemdCredentials(SystemdCredentialsOptions? options, ISystemdCredsRunner runner)
    {
        options ??= new SystemdCredentialsOptions();
        if (string.IsNullOrEmpty(options.ExecutablePath) || options.ExecutablePath[0] != '/')
            throw new ArgumentException($"The systemd-creds path must be absolute, not '{options.ExecutablePath}'.", nameof(options));
        if (!Enum.IsDefined(options.Key))
            throw new ArgumentException($"The key must be Auto, Host, Tpm2 or HostAndTpm2, not {options.Key}.", nameof(options));
        if (options.Timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options), options.Timeout, "The timeout must be positive.");

        _options = options;
        _runner = runner;
    }

    /// <summary>
    /// Whether name can be a credential's name: 1-<see cref="MaxNameLength"/> ASCII letters, digits,
    /// '.', '_' and '-', not "." or "..", so it is always a file name and never an option.
    /// </summary>
    public static bool IsValidName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxNameLength
           && name is not "." and not ".."
           && name[0] != '-'
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

    /// <summary>
    /// Encrypts plaintext as the credential name, written to outputPath - systemd-creds encrypt
    /// --name=name - with the plaintext on its stdin. plaintext is the caller's, and isn't zeroed.
    /// </summary>
    /// <exception cref="ArgumentException">name isn't one (see <see cref="IsValidName"/>), or outputPath isn't absolute</exception>
    /// <exception cref="InvalidOperationException">systemd-creds failed; its message says why</exception>
    /// <exception cref="TimeoutException">systemd-creds didn't finish in time, and was killed</exception>
    public async Task EncryptAsync(string name, ReadOnlyMemory<byte> plaintext, string outputPath, CancellationToken cancellationToken = default)
    {
        CheckName(name);
        CheckPath(outputPath, nameof(outputPath));

        var arguments = new List<string> { $"--name={name}", $"--with-key={KeyArgument(_options.Key)}" };
        if (_options.UserScope)
            arguments.Add("--user");
        arguments.AddRange(["encrypt", "-", outputPath]);

        // Encrypting writes to outputPath, not stdout: there is nothing to keep.
        (await RunAsync("encrypt", arguments, plaintext, cancellationToken).ConfigureAwait(false)).Output.Dispose();
    }

    /// <summary>
    /// <see cref="EncryptAsync(string, ReadOnlyMemory{byte}, string, CancellationToken)"/> for text,
    /// encoded as UTF-8 into pinned memory zeroed once it has been written. plaintext is the
    /// caller's, and isn't zeroed.
    /// </summary>
    /// <exception cref="ArgumentException">name isn't one, or outputPath isn't absolute</exception>
    /// <exception cref="InvalidOperationException">systemd-creds failed; its message says why</exception>
    /// <exception cref="TimeoutException">systemd-creds didn't finish in time, and was killed</exception>
    public async Task EncryptAsync(string name, ReadOnlyMemory<char> plaintext, string outputPath, CancellationToken cancellationToken = default)
    {
        var bytes = ArrayUtility.AllocatePinned<byte>(Encoding.UTF8.GetByteCount(plaintext.Span));
        try
        {
            Encoding.UTF8.GetBytes(plaintext.Span, bytes);
            await EncryptAsync(name, bytes.AsMemory(), outputPath, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayUtility.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Decrypts the credential name from inputPath - systemd-creds decrypt --name=name - reading the
    /// value straight from its stdout into pinned memory. A credential encrypted under another name
    /// fails, as does one encrypted on another machine.
    /// </summary>
    /// <returns>The value; dispose it once used, which zeroes it</returns>
    /// <exception cref="ArgumentException">name isn't one, or inputPath isn't absolute</exception>
    /// <exception cref="InvalidOperationException">systemd-creds failed - the wrong name, another
    /// machine's credential, no access to the host key or TPM; its message says why</exception>
    /// <exception cref="TimeoutException">systemd-creds didn't finish in time, and was killed</exception>
    public async Task<SystemdCredential> DecryptAsync(string name, string inputPath, CancellationToken cancellationToken = default)
    {
        CheckName(name);
        CheckPath(inputPath, nameof(inputPath));

        var arguments = new List<string> { $"--name={name}", "--newline=no" };
        if (_options.UserScope)
            arguments.Add("--user");
        arguments.AddRange(["decrypt", inputPath, "-"]);

        var result = await RunAsync("decrypt", arguments, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
        return result.Output;
    }

    /// <summary>
    /// The credential name that systemd decrypted for this service - LoadCredentialEncrypted= or
    /// SetCredentialEncrypted= in its unit - from its in-memory credentials directory under /run,
    /// which only the service can read; null if it has no such credential, or isn't running with any.
    /// </summary>
    /// <param name="name">The credential's name, as the unit names it</param>
    /// <param name="credentialsDirectory">The directory to look in; null for <see cref="CredentialsDirectoryVariable"/>'s.</param>
    /// <returns>The value; dispose it once used, which zeroes it</returns>
    /// <exception cref="ArgumentException">name isn't one</exception>
    /// <exception cref="InvalidDataException">The credential is longer than <see cref="SystemdCredential.MaxLength"/></exception>
    public static SystemdCredential? ReadLoadedCredential(string name, string? credentialsDirectory = null)
        => LoadedCredentialPath(name, credentialsDirectory) is { } path && File.Exists(path) ? SystemdCredential.ReadFile(path) : null;

    /// <summary>Where the loaded credential name would be; null when there is no credentials directory.</summary>
    /// <exception cref="ArgumentException">name isn't one</exception>
    internal static string? LoadedCredentialPath(string name, string? credentialsDirectory)
    {
        CheckName(name);
        var directory = credentialsDirectory ?? Environment.GetEnvironmentVariable(CredentialsDirectoryVariable);
        return string.IsNullOrEmpty(directory) ? null : Path.Join(directory, name);
    }

    private async Task<SystemdCredsResult> RunAsync(string verb, IReadOnlyList<string> arguments, ReadOnlyMemory<byte> stdin,
        CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync(_options.ExecutablePath, arguments, stdin, _options.Timeout, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode == 0)
            return result;

        result.Output.Dispose();
        var detail = string.IsNullOrWhiteSpace(result.Error) ? "" : $": {result.Error.Trim()}";
        throw new InvalidOperationException($"systemd-creds {verb} failed with exit code {result.ExitCode}{detail}");
    }

    private static string KeyArgument(SystemdCredentialKey key) => key switch
    {
        SystemdCredentialKey.Host => "host",
        SystemdCredentialKey.Tpm2 => "tpm2",
        SystemdCredentialKey.HostAndTpm2 => "host+tpm2",
        _ => "auto",
    };

    private static void CheckName(string name)
    {
        if (!IsValidName(name))
            throw new ArgumentException($"'{name}' isn't a credential name: 1-{MaxNameLength} ASCII letters, digits, '.', '_' and '-', not starting with '-'.", nameof(name));
    }

    private static void CheckPath(string path, string paramName)
    {
        if (string.IsNullOrEmpty(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException($"The credential file's path must be absolute, not '{path}'.", paramName);
    }
}
