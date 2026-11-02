using System.Net;
using System.Security.Authentication;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// When and how often a failed request is retried: vault-client-go's RetryConfiguration (its
/// go-retryablehttp client). Retries happen within the request's timeout, and the request is sent
/// whole each time - its body is held in memory for that.
/// </summary>
public sealed class VaultRetryOptions
{
    /// <summary>The least time to wait before a retry - VAULT_RETRY_WAIT_MIN. Default 1 second.</summary>
    public TimeSpan RetryWaitMin { get; set; } = TimeSpan.FromMilliseconds(1000);

    /// <summary>The most time to wait before a retry - VAULT_RETRY_WAIT_MAX. Default 1.5 seconds.</summary>
    public TimeSpan RetryWaitMax { get; set; } = TimeSpan.FromMilliseconds(1500);

    /// <summary>How many times to retry - VAULT_MAX_RETRIES. Zero or less for none. Default 2: three tries in all.</summary>
    public int RetryMax { get; set; } = 2;

    /// <summary>
    /// Whether to retry, given the response (null if none came) or the exception the attempt failed
    /// with (null if a response came). Null for <see cref="DefaultRetryPolicy"/>.
    /// </summary>
    public Func<HttpResponseMessage?, Exception?, bool>? CheckRetry { get; set; }

    /// <summary>
    /// How long to wait before a retry, given <see cref="RetryWaitMin"/>, <see cref="RetryWaitMax"/>,
    /// the attempt that failed (0 for the first) and its response, if any. Null for
    /// <see cref="LinearJitterBackoff"/>.
    /// </summary>
    public Func<TimeSpan, TimeSpan, int, HttpResponseMessage?, TimeSpan>? Backoff { get; set; }

    /// <summary>
    /// go-retryablehttp's default policy, plus 412 (which Vault answers when an X-Vault-Index state
    /// isn't there yet): retry when no response came - unless the server's certificate was refused -
    /// and on 412, 429, and any 5xx but 501.
    /// </summary>
    public static bool DefaultRetryPolicy(HttpResponseMessage? response, Exception? exception)
    {
        if (exception is not null)
            return !IsCertificateFailure(exception);
        if (response is null)
            return true;

        var status = (int)response.StatusCode;
        return response.StatusCode is HttpStatusCode.PreconditionFailed or HttpStatusCode.TooManyRequests
               || status == 0 || (status >= 500 && response.StatusCode != HttpStatusCode.NotImplemented);
    }

    /// <summary>
    /// go-retryablehttp's LinearJitterBackoff: a random wait between min and max, times the number of
    /// attempts made so far - spread out so clients retrying together don't all arrive together.
    /// </summary>
    public static TimeSpan LinearJitterBackoff(TimeSpan min, TimeSpan max, int attempt, HttpResponseMessage? response)
    {
        var attempts = attempt + 1;
        if (max <= min)
            return min * attempts;

        var jitter = TimeSpan.FromTicks(Random.Shared.NextInt64((max - min).Ticks));
        return (min + jitter) * attempts;
    }

    internal VaultRetryOptions Clone() => (VaultRetryOptions)MemberwiseClone();

    // Another attempt would be refused the same way.
    private static bool IsCertificateFailure(Exception exception)
    {
        for (var e = exception; e is not null; e = e.InnerException)
        {
            if (e is AuthenticationException || e is HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError })
                return true;
        }

        return false;
    }
}
