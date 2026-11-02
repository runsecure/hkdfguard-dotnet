using System.Buffers;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// The rules every HkdfGuard request to Vault follows, for code that makes its own requests rather
/// than going through <see cref="VaultClient"/> - HashiCorpVaultSecretCache and
/// HashiCorpVaultTransitKeyWrapper, which read secrets and keys into pinned memory themselves:
/// where requests may go, which tokens and paths can be sent, how a token is put on a request and
/// wiped once it has gone, which failures are worth retrying and how long to wait, and what Vault's
/// error responses say.
/// </summary>
public static class VaultHttp
{
    /// <summary>The longest token a fixed-size token buffer holds, in characters: what an <see cref="IVaultTokenSource"/> may supply.</summary>
    public const int MaxTokenLength = 2048;

    /// <summary>The longest wait <see cref="RetryDelay"/> returns, jitter aside.</summary>
    public static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(10);

    /// <summary>The fewest retries the secret cache and the transit key wrapper allow.</summary>
    public const int MinRetryCount = 3;

    /// <summary>The most retries the secret cache and the transit key wrapper allow.</summary>
    public const int MaxRetryCount = 10;

    private const string TokenHeader = "X-Vault-Token";

    private static readonly SearchValues<char> SegmentCharacters =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.");

    /// <summary>Whether token can go in a header: non-empty printable ASCII, with no spaces.</summary>
    public static bool IsValidToken(ReadOnlySpan<char> token)
        => !token.IsEmpty && !token.ContainsAnyExceptInRange('!', '~');

    /// <summary>Whether path is '/'-separated segments, each one <see cref="IsValidPathSegment"/>: a path that stays where it's put.</summary>
    public static bool IsValidPath(ReadOnlySpan<char> path)
    {
        foreach (var range in path.Split('/'))
        {
            if (!IsValidPathSegment(path[range]))
                return false;
        }

        return true;
    }

    /// <summary>Whether segment is ASCII letters, digits, '-', '_' and '.', and not empty, "." or "..".</summary>
    public static bool IsValidPathSegment(ReadOnlySpan<char> segment)
        => !segment.IsEmpty && segment is not "." and not ".." && !segment.ContainsAnyExcept(SegmentCharacters);

    /// <summary>
    /// /v1/ under Vault's address - the base every API path goes after - refusing an address that
    /// would send tokens in the clear or that carries credentials, a query or a fragment. A path in
    /// the address is kept as a prefix (Vault behind a reverse proxy).
    /// </summary>
    /// <param name="address">Vault's address, e.g. https://vault.example.com:8200 - the same value
    /// as VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev server).</param>
    /// <exception cref="ArgumentNullException">address is null</exception>
    /// <exception cref="ArgumentException">address isn't absolute, isn't https (or http on loopback),
    /// or holds credentials, a query or a fragment</exception>
    public static Uri ApiBase(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.IsAbsoluteUri)
            throw new ArgumentException($"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.", nameof(address));
        if (address.Scheme != Uri.UriSchemeHttps && !(address.Scheme == Uri.UriSchemeHttp && address.IsLoopback))
            throw new ArgumentException(
                $"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries a token.",
                nameof(address));
        if (address.UserInfo.Length > 0 || address.Query.Length > 0 || address.Fragment.Length > 0)
            throw new ArgumentException($"Vault's address '{address}' must not hold credentials, a query or a fragment.", nameof(address));

        return new Uri(address.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/v1/");
    }

    /// <summary>
    /// The handler to send requests to Vault through when the caller supplies none: TLS 1.2 or
    /// later, no automatic redirects, no cookies, connections recycled every 5 minutes.
    /// </summary>
    public static SocketsHttpHandler CreateHandler() => new()
    {
        // A redirect would carry X-Vault-Token to wherever it points: HttpClient drops only the
        // Authorization header when following one. Vault's standbys forward requests to the active
        // node themselves, so a redirect is answered as an error unless the caller decides otherwise.
        AllowAutoRedirect = false,
        UseCookies = false,
        // Picks up a changed DNS record (a failover) without restarting.
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        ConnectTimeout = TimeSpan.FromSeconds(30),
        SslOptions = { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 },
    };

    /// <summary>
    /// The HttpClient to send requests to Vault through: over supplied, which it doesn't dispose, or
    /// over a handler of <see cref="CreateHandler"/>'s, which it does. TLS options that set anything
    /// configure the SocketsHttpHandler at the bottom of the handler's DelegatingHandler chain. Its
    /// Timeout is infinite: each caller bounds its own attempts.
    /// </summary>
    /// <param name="baseAddress">What relative request URIs resolve against: <see cref="ApiBase"/>'s, say; null for none.</param>
    /// <param name="tls">Null, or empty, for the operating system's trust store and no client certificate.</param>
    /// <exception cref="ArgumentException">tls sets something but supplied's innermost handler isn't a
    /// SocketsHttpHandler, or a certificate, key or key store can't be read</exception>
    public static HttpClient CreateHttpClient(Uri? baseAddress, HttpMessageHandler? supplied, VaultTlsOptions? tls)
    {
        var handler = supplied ?? CreateHandler();
        try
        {
            if (tls is { IsEmpty: false })
                tls.ApplyTo(SocketsHandler(handler, "TLS options"));
        }
        catch when (supplied is null)
        {
            handler.Dispose();
            throw;
        }

        return new HttpClient(handler, disposeHandler: supplied is null)
        {
            BaseAddress = baseAddress,
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        };
    }

    /// <summary>The SocketsHttpHandler at the bottom of handler's DelegatingHandler chain, which what needs.</summary>
    /// <exception cref="ArgumentException">It is a handler of another type</exception>
    internal static SocketsHttpHandler SocketsHandler(HttpMessageHandler handler, string what)
    {
        var innermost = handler;
        while (innermost is DelegatingHandler { InnerHandler: { } inner })
            innermost = inner;

        return innermost as SocketsHttpHandler
               ?? throw new ArgumentException($"The HttpMessageHandler ({innermost.GetType()}) isn't a SocketsHttpHandler, so can't be given {what}.", "options");
    }

    /// <summary>
    /// Checks the settings the secret cache and the transit key wrapper share: where the engine is
    /// mounted, the namespace, each attempt's timeout, and how often and how soon to retry.
    /// </summary>
    /// <param name="paramName">The options' parameter name, which the exceptions carry.</param>
    /// <exception cref="ArgumentException">The mount path, or the namespace (which may be null), isn't a Vault path</exception>
    /// <exception cref="ArgumentOutOfRangeException">The timeout isn't positive, the retry count isn't
    /// <see cref="MinRetryCount"/>-<see cref="MaxRetryCount"/>, or the retry delay isn't zero to <see cref="MaxRetryDelay"/></exception>
    public static void CheckSettings(string mountPath, string? @namespace, TimeSpan timeout, int retryCount, TimeSpan retryDelay, string paramName)
    {
        if (!IsValidPath(mountPath))
            throw new ArgumentException($"The mount path '{mountPath}' isn't a Vault path.", paramName);
        if (@namespace is not null && !IsValidPath(@namespace))
            throw new ArgumentException($"The namespace '{@namespace}' isn't a Vault path.", paramName);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero, paramName);
        if (retryCount is < MinRetryCount or > MaxRetryCount)
            throw new ArgumentOutOfRangeException(paramName, retryCount, $"RetryCount must be {MinRetryCount}-{MaxRetryCount}.");
        if (retryDelay < TimeSpan.Zero || retryDelay > MaxRetryDelay)
            throw new ArgumentOutOfRangeException(paramName, retryDelay, $"RetryDelay must be zero to {MaxRetryDelay}.");
    }

    /// <summary>
    /// Refuses a supplied handler that follows redirects (<see cref="FollowsRedirects"/>) unless
    /// allowRedirects says every redirect target may see the token.
    /// </summary>
    /// <param name="supplied">The caller's handler; null for one of <see cref="CreateHandler"/>'s, which never does.</param>
    /// <param name="paramName">The options' parameter name, which the exception carries.</param>
    /// <exception cref="ArgumentException">supplied follows redirects without allowRedirects</exception>
    public static void CheckRedirects(HttpMessageHandler? supplied, bool allowRedirects, string paramName)
    {
        if (supplied is not null && !allowRedirects && FollowsRedirects(supplied))
            throw new ArgumentException(
                "The HttpMessageHandler follows redirects, which would send the Vault token wherever they point. Set its AllowAutoRedirect to false, or set AllowRedirects if every redirect target may see the token.",
                paramName);
    }

    /// <summary>
    /// A request carrying the headers every HkdfGuard request to Vault does: X-Vault-Request, which a
    /// Vault Agent or proxy configured with require_request_header requires, and X-Vault-Namespace
    /// unless @namespace is null. The body and the token are the caller's; each attempt's timeout is
    /// its cancellation.
    /// </summary>
    public static HttpRequestMessage CreateRequest(HttpMethod method, Uri uri, string? @namespace)
    {
        var request = new HttpRequestMessage(method, uri);
        request.Headers.TryAddWithoutValidation("X-Vault-Request", "true");
        if (@namespace is not null)
            request.Headers.TryAddWithoutValidation("X-Vault-Namespace", @namespace);
        return request;
    }

    /// <summary>
    /// Makes attempt, and makes it again after a wait each time it fails transiently
    /// (<see cref="IsTransient"/>), at most retryCount more times: <see cref="RetryDelay"/> from
    /// retryDelay, plus a random 0-100 ms. The last failure, or one that isn't transient, propagates
    /// as it is.
    /// </summary>
    /// <param name="cancellationToken">The caller's own cancellation, passed to every attempt and wait, and never retried.</param>
    public static async Task<T> WithRetriesAsync<T>(int retryCount, TimeSpan retryDelay, Func<CancellationToken, Task<T>> attempt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        for (var retry = 0; ; retry++)
        {
            try
            {
                return await attempt(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e) when (retry < retryCount && IsTransient(e, cancellationToken))
            {
                await Task.Delay(RetryDelay(retryDelay, retry, Random.Shared.Next(0, 101)), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <inheritdoc cref="WithRetriesAsync{T}"/>
    public static Task WithRetriesAsync(int retryCount, TimeSpan retryDelay, Func<CancellationToken, Task> attempt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        return WithRetriesAsync(retryCount, retryDelay, async token =>
        {
            await attempt(token).ConfigureAwait(false);
            return true;
        }, cancellationToken);
    }

    /// <summary>
    /// Whether the handler at the bottom of handler's DelegatingHandler chain follows redirects
    /// itself, which would send the token wherever they point. One of a type other than
    /// SocketsHttpHandler or HttpClientHandler can't be told, so counts as not.
    /// </summary>
    public static bool FollowsRedirects(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        while (handler is DelegatingHandler { InnerHandler: { } inner })
            handler = inner;

        return handler switch
        {
            SocketsHttpHandler sockets => sockets.AllowAutoRedirect,
            HttpClientHandler client => client.AllowAutoRedirect,
            _ => false,
        };
    }

    /// <summary>
    /// Sends request with token in its X-Vault-Token header, unbuffered (HttpClient would otherwise
    /// copy the response body into a pooled buffer it returns uncleared), then takes the header off
    /// and zeroes it - the only copy of the token this makes - once the request has been sent or has
    /// failed.
    /// </summary>
    /// <param name="token">The token, already checked with <see cref="IsValidToken"/>: added without
    /// the copies header validation could make.</param>
    /// <exception cref="ArgumentException">token isn't one</exception>
    public static async Task<HttpResponseMessage> SendWithTokenAsync(HttpClient http, HttpRequestMessage request, ReadOnlyMemory<char> token,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(request);
        if (!IsValidToken(token.Span))
            throw new ArgumentException("A Vault token is printable ASCII, with no spaces.", nameof(token));

        // Made by new string from the token's chars, so it is no literal or interned string anything
        // else could share, and can be zeroed.
        var header = new string(token.Span);
        try
        {
            request.Headers.TryAddWithoutValidation(TokenHeader, header);
            return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Removed first, so nothing that sees the request afterwards sees the zeroed header.
            request.Headers.Remove(TokenHeader);
            ArrayUtility.ZeroMemory(MemoryMarshal.AsMemory(header.AsMemory()).Span);
        }
    }

    /// <summary>
    /// Sends request with the token protectedToken holds: decrypted into a pinned array
    /// (<see cref="DecryptToken"/>), sent as <see cref="SendWithTokenAsync(HttpClient, HttpRequestMessage, ReadOnlyMemory{char}, CancellationToken)"/>
    /// sends it, and the array zeroed once the request has been sent or has failed.
    /// </summary>
    /// <exception cref="InvalidOperationException">As <see cref="DecryptToken"/></exception>
    public static async Task<HttpResponseMessage> SendWithTokenAsync(HttpClient http, HttpRequestMessage request, IDataProtector tokenProtector,
        string? protectedToken, CancellationToken cancellationToken)
    {
        var token = DecryptToken(tokenProtector, protectedToken, out var length);
        try
        {
            return await SendWithTokenAsync(http, request, token.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayUtility.ZeroMemory(token.AsSpan());
        }
    }

    /// <summary>
    /// The token protectedToken holds, decrypted with tokenProtector into a pinned array the caller
    /// zeroes once used; its first length characters are the token. Refused unless it is protected by
    /// tokenProtector - it parses, its key version is on the ring, and it authenticates under the
    /// protector's purpose - and is a token. The protector's exceptions aren't chained: a parser handed
    /// an unprotected token could quote it.
    /// </summary>
    /// <exception cref="InvalidOperationException">protectedToken is empty, isn't protected by
    /// tokenProtector, or doesn't hold a token</exception>
    public static char[] DecryptToken(IDataProtector tokenProtector, string? protectedToken, out int length)
    {
        ArgumentNullException.ThrowIfNull(tokenProtector);
        if (string.IsNullOrEmpty(protectedToken))
            throw new InvalidOperationException("The Vault token provider returned no token.");

        int maxLength;
        try
        {
            maxLength = tokenProtector.GetMaxDecryptedLength(protectedToken);
        }
        catch (FormatException)
        {
            throw NotProtected();
        }

        var chars = ArrayUtility.AllocatePinned<char>(maxLength);
        try
        {
            try
            {
                length = tokenProtector.Decrypt(protectedToken, chars);
            }
            catch (Exception e) when (e is FormatException or CryptographicException or KeyNotFoundException)
            {
                throw NotProtected();
            }

            if (!IsValidToken(chars.AsSpan(0, length)))
                throw new InvalidOperationException("The protected Vault token isn't a token: printable ASCII, with no spaces.");

            return chars;
        }
        catch
        {
            ArrayUtility.ZeroMemory(chars.AsSpan());
            throw;
        }
    }

    /// <summary>
    /// The wait before retry number retry (0 for the first): baseDelay, doubled for each retry before
    /// it, at most <see cref="MaxRetryDelay"/> - plus jitterMilliseconds, so clients retrying together
    /// spread out.
    /// </summary>
    public static TimeSpan RetryDelay(TimeSpan baseDelay, int retry, int jitterMilliseconds)
    {
        var backoff = baseDelay * Math.Pow(2, retry);
        return (backoff < MaxRetryDelay ? backoff : MaxRetryDelay) + TimeSpan.FromMilliseconds(jitterMilliseconds);
    }

    /// <summary>
    /// Whether another attempt may not meet the failure exception: no answer at all (connection
    /// refused or reset, DNS), a connection lost mid-response, the attempt's own timeout (a
    /// cancellation that isn't cancellationToken's), or Vault busy or briefly unable to answer - an
    /// HttpRequestException carrying 429, or a 5xx other than 501.
    /// </summary>
    /// <param name="cancellationToken">The caller's own cancellation, which is never retried.</param>
    public static bool IsTransient(Exception exception, CancellationToken cancellationToken) => exception switch
    {
        HttpRequestException http => http.StatusCode is not { } status
                                     || status == HttpStatusCode.TooManyRequests
                                     || ((int)status >= 500 && status != HttpStatusCode.NotImplemented),
        IOException => true,
        OperationCanceledException => !cancellationToken.IsCancellationRequested,
        _ => false,
    };

    /// <summary>
    /// The errors Vault listed in an error response body: its "errors" array, each as text; empty if
    /// it has none; null if the body isn't Vault's JSON - a proxy's page, say.
    /// </summary>
    public static string[]? ReadErrors(ReadOnlySpan<byte> body)
    {
        try
        {
            var reader = new Utf8JsonReader(body);
            using var json = JsonDocument.ParseValue(ref reader);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            if (!root.TryGetProperty("errors", out var errors))
                return [];

            return errors.ValueKind == JsonValueKind.Array ? errors.EnumerateArray().Select(e => e.ToString()).ToArray() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static InvalidOperationException NotProtected()
        => new("The Vault token provider returned a token that isn't protected by the token protector it was given: hand over tokenProtector.Encrypt(token), never the token itself.");
}
