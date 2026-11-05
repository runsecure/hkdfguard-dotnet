using System.Text;
using HkdfGuard.Abstractions;

namespace HkdfGuard.SystemdCredentials;

/// <summary>
/// An IProtectedReadOnlyCache over systemd credentials - for CertificateOptionsLoader's password,
/// say. A name is looked for first among the credentials systemd decrypted for this service
/// (LoadCredentialEncrypted=, in its in-memory credentials directory), then among the encrypted
/// credential files it was given, which systemd-creds decrypts by that name. Nothing is cached:
/// every lookup reads the credential again, into pinned memory zeroed as soon as it has been copied
/// out. A name it doesn't have is reported missing - Decrypt returns 0.
/// </summary>
public sealed class SystemdCredentialSource : IProtectedReadOnlyCache
{
    private readonly SystemdCredentials? _credentials;
    private readonly IReadOnlyDictionary<string, string> _encryptedFiles;
    private readonly string? _credentialsDirectory;

    /// <param name="credentials">Decrypts the encrypted files; null when there are none.</param>
    /// <param name="encryptedFiles">Encrypted credential files by credential name, absolute paths; null for none.</param>
    /// <param name="credentialsDirectory">The service's credentials directory; null for $CREDENTIALS_DIRECTORY.</param>
    /// <exception cref="ArgumentException">encryptedFiles holds a name that isn't one, or a path that
    /// isn't absolute; or names files but credentials is null</exception>
    public SystemdCredentialSource(SystemdCredentials? credentials = null, IReadOnlyDictionary<string, string>? encryptedFiles = null,
        string? credentialsDirectory = null)
    {
        encryptedFiles ??= new Dictionary<string, string>();
        foreach (var (name, path) in encryptedFiles)
        {
            if (!SystemdCredentials.IsValidName(name))
                throw new ArgumentException($"'{name}' isn't a credential name.", nameof(encryptedFiles));
            if (string.IsNullOrEmpty(path) || !Path.IsPathFullyQualified(path))
                throw new ArgumentException($"The credential file for '{name}' must be an absolute path, not '{path}'.", nameof(encryptedFiles));
        }

        if (encryptedFiles.Count > 0 && credentials is null)
            throw new ArgumentException("Encrypted credential files need a SystemdCredentials to decrypt them.", nameof(credentials));

        _credentials = credentials;
        _encryptedFiles = new Dictionary<string, string>(encryptedFiles, StringComparer.Ordinal);
        _credentialsDirectory = credentialsDirectory;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">result is too small for the value</exception>
    public int Decrypt(string name, Span<byte> result)
    {
        using var credential = Read(name);
        return credential is null ? 0 : CopyBytes(credential, result);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">result is too small for the value</exception>
    public int Decrypt(string name, Span<char> result)
    {
        using var credential = Read(name);
        return credential is null ? 0 : CopyChars(credential, result);
    }

    /// <inheritdoc/>
    /// <remarks>The credential file's length: never less than its value's, in bytes or in chars.</remarks>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        maxLength = Locate(name) is { } path ? (int)Math.Min(new FileInfo(path).Length, int.MaxValue) : 0;
        return maxLength > 0;
    }

    /// <inheritdoc/>
    public async ValueTask<int> DecryptAsync(string name, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        using var credential = await ReadAsync(name, cancellationToken).ConfigureAwait(false);
        return credential is null ? 0 : CopyBytes(credential, result.Span);
    }

    /// <inheritdoc/>
    public async ValueTask<int> DecryptAsync(string name, Memory<char> result, CancellationToken cancellationToken = default)
    {
        using var credential = await ReadAsync(name, cancellationToken).ConfigureAwait(false);
        return credential is null ? 0 : CopyChars(credential, result.Span);
    }

    /// <inheritdoc/>
    public ValueTask<int> GetMaxDecryptedLengthAsync(string name, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(TryGetMaxDecryptedLength(name, out var maxLength) ? maxLength : 0);

    // The file name's value comes from: the loaded credential if there is one, else its encrypted file.
    private string? Locate(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!SystemdCredentials.IsValidName(name))
            return null;

        if (SystemdCredentials.LoadedCredentialPath(name, _credentialsDirectory) is { } loaded && File.Exists(loaded))
            return loaded;
        return _encryptedFiles.TryGetValue(name, out var encrypted) && File.Exists(encrypted) ? encrypted : null;
    }

    // Blocks while systemd-creds runs, off the caller's SynchronizationContext.
    private SystemdCredential? Read(string name)
        => Task.Run(() => ReadAsync(name, CancellationToken.None)).GetAwaiter().GetResult();

    private async Task<SystemdCredential?> ReadAsync(string name, CancellationToken cancellationToken)
    {
        if (Locate(name) is not { } path)
            return null;
        if (!_encryptedFiles.TryGetValue(name, out var encrypted) || encrypted != path)
            return SystemdCredentials.ReadLoadedCredential(name, _credentialsDirectory);

        return await _credentials!.DecryptAsync(name, path, cancellationToken).ConfigureAwait(false);
    }

    private static int CopyBytes(SystemdCredential credential, Span<byte> result)
    {
        if (credential.Length > result.Length)
            throw new ArgumentException($"The credential is {credential.Length} bytes; result holds {result.Length}.", nameof(result));
        credential.Value.CopyTo(result);
        return credential.Length;
    }

    private static int CopyChars(SystemdCredential credential, Span<char> result)
    {
        var count = Encoding.UTF8.GetCharCount(credential.Value);
        if (count > result.Length)
            throw new ArgumentException($"The credential is {count} characters; result holds {result.Length}.", nameof(result));
        return Encoding.UTF8.GetChars(credential.Value, result);
    }
}
