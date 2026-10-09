using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1;

/// <summary>
/// Protects (Encrypt) a fresh DEK, or reveals (Decrypt) a previously-wrapped one, via the current
/// OS's native HkdfGuard KMS library (see NativeHost) - a TPM2, Secure Enclave, or Platform
/// Crypto Provider key held entirely outside this process, identified only by a service name. No
/// salt/blob machinery is involved: the native library owns the KEK, the wrapped payload's
/// format, and its own key derivation. Since Decrypt takes its wrapped payload as an explicit
/// argument rather than one bound at construction, a single instance freely handles both
/// directions, and any number of different wrapped payloads sharing the same service name. The
/// native ABI has no concept of AAD, so IKeyWrapper itself no longer exposes an AAD-taking
/// overload. The native calls are local and synchronous, so every *Async method completes
/// synchronously and surfaces failures through the returned ValueTask.
/// </summary>
public class NativeHkdfKeyWrapperV1 : IKeyWrapper
{
    private readonly string _serviceName;
    private readonly AbstractHkdfGuardKmsLibrary _library;

    /// <param name="serviceName">Identifies the KEK: 1-128 ASCII letters, digits or '.', not starting
    /// with '.' and without ".." (see ServiceNames).</param>
    /// <exception cref="ArgumentNullException">serviceName is null</exception>
    /// <exception cref="ArgumentException">serviceName breaks a ServiceNames rule</exception>
    public NativeHkdfKeyWrapperV1(string serviceName)
        : this(serviceName, NativeHost.Library)
    {
    }

    internal NativeHkdfKeyWrapperV1(string serviceName, AbstractHkdfGuardKmsLibrary library)
    {
        // Checked here, before the name can ever reach native code.
        ServiceNames.ThrowIfInvalid(serviceName, nameof(serviceName));
        _serviceName = serviceName;
        _library = library;
    }

    /// <inheritdoc/>
    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
            return ValueTask.FromCanceled<int>(cancellationToken);

        var status = _library.WrapDek(_serviceName, plaintext.Span, result.Span, out var bytesWritten);
        return Complete(status, bytesWritten, "wrap");
    }

    /// <inheritdoc/>
    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
            return ValueTask.FromCanceled<int>(cancellationToken);

        var status = _library.UnwrapDek(_serviceName, wrapped.Span, result.Span, out var bytesWritten);
        if (status != AbstractHkdfGuardKmsLibrary.Ok)
            CryptographicOperations.ZeroMemory(result.Span);

        return Complete(status, bytesWritten, "unwrap");
    }

    /// <inheritdoc/>
    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
            return ValueTask.FromCanceled<int>(cancellationToken);

        var status = _library.GenerateAndWrapDek(_serviceName, result.Span, out var bytesWritten);
        return Complete(status, bytesWritten, "generate-and-wrap");
    }

    private ValueTask<int> Complete(int status, int bytesWritten, string operation)
    {
        if (status == AbstractHkdfGuardKmsLibrary.Ok)
            return ValueTask.FromResult(bytesWritten);

        // Name the platform's meaning when it is known - "-13" alone tells an operator nothing.
        var meaning = _library.DescribeStatus(status) is { } description ? $" ({description})" : string.Empty;
        return ValueTask.FromException<int>(new CryptographicException(
            $"Native KMS {operation} failed for service '{_serviceName}' with status {status}{meaning}."));
    }
}
