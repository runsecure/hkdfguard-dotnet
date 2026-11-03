namespace HkdfGuard.Abstractions;

/// <summary>
/// The end of a provisioning pipeline that delivers secrets from a secret store as one encrypted file
/// per secret - the folder layout FilePerSecretCache reads at runtime - before a durable KEK exists.
/// An implementation is given the secrets to pull and an <see cref="IPipelineDataProtector"/> when
/// it is created; <see cref="PullSecretsAsync"/> reads each secret and encrypts it at once, bound to
/// its file name, keeping only the encrypted value; <see cref="WriteProtectedSecretFiles"/> then
/// writes one file per secret. No key ring is involved: the protector's key is the only one, and it
/// is handed to the native platform's wrap process once the files are written.
/// <para>
/// The protector belongs to the caller and is never disposed by the writer. Disposing the writer
/// releases its connection to the secret store.
/// </para>
/// </summary>
public interface ISecretPipelineWriter : IDisposable
{
    /// <summary>
    /// Every secret pulled, by file name: its value encrypted by the protector and formatted, as its
    /// file will hold it. Empty until <see cref="PullSecretsAsync"/> completes.
    /// </summary>
    public IReadOnlyDictionary<string, string> ProtectedSecrets { get; }

    /// <summary>
    /// Reads every secret the writer was created with and encrypts each value, keeping it in
    /// <see cref="ProtectedSecrets"/> - replacing whatever an earlier pull kept.
    /// </summary>
    /// <param name="cancellationToken">Cancels the reads</param>
    /// <exception cref="KeyNotFoundException">A secret has no value; every other secret is kept</exception>
    public Task PullSecretsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes every secret in <see cref="ProtectedSecrets"/> as a file in
    /// <paramref name="folderPath"/>, creating the folder if it doesn't exist: the file named for it,
    /// holding its encrypted, formatted value as UTF-8.
    /// </summary>
    /// <param name="folderPath">The folder to write to, absolute or relative to the working directory</param>
    /// <exception cref="ArgumentNullException">folderPath is null</exception>
    /// <exception cref="ArgumentException">folderPath is empty</exception>
    /// <exception cref="InvalidOperationException">No pull has completed</exception>
    public void WriteProtectedSecretFiles(string folderPath);
}
