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
}
