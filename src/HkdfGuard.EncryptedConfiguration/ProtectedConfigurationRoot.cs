using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace HkdfGuard.EncryptedConfiguration;

/// <summary>
/// Default IProtectedConfigurationRoot. Delegates every IConfigurationRoot member to the
/// wrapped root unchanged, and reveals configuration values formatted as protected secrets via
/// an IDataProtector bound to the given KeyRing. Configuration itself only ever holds formatted
/// ciphertext strings - Decrypt reveals fresh from the underlying root on every call rather
/// than caching anything, so a Reload takes effect immediately. Each value is bound to its own
/// configuration key (see ProtectedConfigurationPurpose): a value moved to a different key fails
/// authentication rather than being decrypted.
/// </summary>
public sealed class ProtectedConfigurationRoot(IConfigurationRoot configurationRoot, KeyRing keyRing)
    : IProtectedConfigurationRoot
{
    /// <inheritdoc cref="IConfiguration"/>
    public string? this[string key]
    {
        get => configurationRoot[key];
        set => configurationRoot[key] = value;
    }

    /// <inheritdoc/>
    public IEnumerable<IConfigurationProvider> Providers => configurationRoot.Providers;

    /// <inheritdoc/>
    public void Reload() => configurationRoot.Reload();

    /// <inheritdoc/>
    public IConfigurationSection GetSection(string key) => configurationRoot.GetSection(key);

    /// <inheritdoc/>
    public IEnumerable<IConfigurationSection> GetChildren() => configurationRoot.GetChildren();

    /// <inheritdoc/>
    public IChangeToken GetReloadToken() => configurationRoot.GetReloadToken();

    /// <inheritdoc/>
    public int Decrypt(string name, Span<char> result)
    {
        using var activity = HkdfGuardTelemetry.EncryptedConfiguration.ActivitySource.StartActivity(ActivityNames.EncryptedConfiguration.Decrypt);
        if (HkdfGuardTelemetry.EncryptedConfiguration.EnableSensitiveLogging)
            HkdfGuardTelemetry.EncryptedConfiguration.LogSensitiveOperation(activity, ActivityNames.EncryptedConfiguration.Decrypt, (AttributeNames.Name, name));

        try
        {
            var value = configurationRoot[name];
            return value is null
                ? 0
                : ProtectorFor(name).Decrypt(value, result);
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(string name, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.EncryptedConfiguration.ActivitySource.StartActivity(ActivityNames.EncryptedConfiguration.Decrypt);
        if (HkdfGuardTelemetry.EncryptedConfiguration.EnableSensitiveLogging)
            HkdfGuardTelemetry.EncryptedConfiguration.LogSensitiveOperation(activity, ActivityNames.EncryptedConfiguration.Decrypt, (AttributeNames.Name, name));

        try
        {
            var value = configurationRoot[name];
            if (value is null)
                return 0;

            // The format provider's max-length bound is computed from the ciphertext's own byte
            // length, so it's a safe upper bound for the decrypted plaintext's UTF8 byte count
            // too, not just its char count.
            // On the stack, or pinned when too large: never somewhere the GC can copy it.
            var protector = ProtectorFor(name);
            var maxChars = protector.GetMaxDecryptedLength(value);
            Span<char> charBuffer = maxChars <= ArrayUtility.MaxStackChars
                ? stackalloc char[maxChars]
                : ArrayUtility.AllocatePinned<char>(maxChars);
            try
            {
                var charsWritten = protector.Decrypt(value, charBuffer);
                return Encoding.UTF8.GetBytes(charBuffer[..charsWritten], result);
            }
            finally
            {
                ArrayUtility.ZeroMemory(charBuffer);
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        var value = configurationRoot[name];
        if (value is null)
        {
            maxLength = 0;
            return false;
        }

        maxLength = ProtectorFor(name).GetMaxDecryptedLength(value);
        return true;
    }

    // Bound to this one key, so a value copied in from another key fails its tag check.
    private IDataProtector ProtectorFor(string name)
        => keyRing.CreateProtector(ProtectedConfigurationPurpose.For(name));
}
