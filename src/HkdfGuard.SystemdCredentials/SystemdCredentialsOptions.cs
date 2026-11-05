namespace HkdfGuard.SystemdCredentials;

/// <summary>Which key systemd-creds encrypts a credential under - its --with-key.</summary>
public enum SystemdCredentialKey
{
    /// <summary>The host key and the TPM when the machine has a TPM, the host key alone when it doesn't ("auto").</summary>
    Auto,

    /// <summary>The host key, /var/lib/systemd/credential.secret, readable only by root ("host").</summary>
    Host,

    /// <summary>The TPM alone, so the credential decrypts only on this machine's TPM ("tpm2").</summary>
    Tpm2,

    /// <summary>Both: decrypting needs the host key and this machine's TPM ("host+tpm2").</summary>
    HostAndTpm2,
}

/// <summary>How <see cref="SystemdCredentials"/> runs systemd-creds.</summary>
public sealed class SystemdCredentialsOptions
{
    /// <summary>
    /// The systemd-creds executable, by absolute path, so no directory on PATH can stand in for it.
    /// Default /usr/bin/systemd-creds.
    /// </summary>
    public string ExecutablePath { get; init; } = "/usr/bin/systemd-creds";

    /// <summary>The key new credentials are encrypted under. Default <see cref="SystemdCredentialKey.Auto"/>.</summary>
    public SystemdCredentialKey Key { get; init; } = SystemdCredentialKey.Auto;

    /// <summary>
    /// Encrypts and decrypts credentials scoped to the calling user (--user; systemd 256 or later),
    /// which an unprivileged account can do through systemd's credential service. Default false:
    /// system credentials, which need root - or, for <see cref="SystemdCredentialKey.Tpm2"/>, access
    /// to the TPM - to encrypt or decrypt directly.
    /// </summary>
    public bool UserScope { get; init; }

    /// <summary>How long one systemd-creds run may take before it is killed. Default 30 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
}
