using Microsoft.Extensions.Logging;

namespace HkdfGuard.Integration.HashiCorpVault;

// Paths only: a query can hold credentials (secret_id, token), so it is never logged.
internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Warning,
        Message = "Vault request {Method} {Path} failed ({Failure}); retry {Retry} of {RetryMax} in {Delay}.")]
    public static partial void Retrying(ILogger logger, HttpMethod method, string path, string failure, int retry, int retryMax, TimeSpan delay);

    [LoggerMessage(EventId = 2, Level = LogLevel.Information,
        Message = "Vault redirected {Method} {Path} to {Location}; following it.")]
    public static partial void FollowingRedirect(ILogger logger, HttpMethod method, string path, string location);

    [LoggerMessage(EventId = 3, Level = LogLevel.Warning,
        Message = "Vault's TLS certificate is not being verified (InsecureSkipVerify, VAULT_SKIP_VERIFY): anyone between this process and Vault can read every token and secret. Use this for a throwaway dev server only.")]
    public static partial void CertificateVerificationSkipped(ILogger logger);
}
