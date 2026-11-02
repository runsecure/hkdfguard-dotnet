using System.Net;
using System.Text.Json;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault;

public sealed partial class VaultClient
{
    private const string HealthPath = "/v1/sys/health";

    /// <summary>Reads the value at path (GET /v1/path); null if Vault answers with no body.</summary>
    /// <param name="path">The path under /v1/, with or without that prefix.</param>
    /// <param name="options">Settings for this request.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <exception cref="VaultResponseException">Vault refused the request</exception>
    public Task<VaultResponse<Dictionary<string, JsonElement>>?> ReadAsync(string path, VaultRequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        return SendAsync<Dictionary<string, JsonElement>>(HttpMethod.Get, V1Path(path), null, QueryParameters(options), options, cancellationToken);
    }

    /// <summary>
    /// Reads path (GET /v1/path) and returns Vault's response as it is: not parsed, not checked for an
    /// error status, and not bound by <see cref="VaultClientOptions.RequestTimeout"/> - for a large or
    /// streamed body. Dispose the response.
    /// </summary>
    public async Task<HttpResponseMessage> ReadRawAsync(string path, VaultRequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        var (response, _) = await SendCoreAsync(HttpMethod.Get, V1Path(path), null, QueryParameters(options), options, cancellationToken)
            .ConfigureAwait(false);
        return response;
    }

    /// <summary>Writes body, as a JSON object, to path (POST /v1/path).</summary>
    /// <exception cref="VaultResponseException">Vault refused the request</exception>
    public Task<VaultResponse<Dictionary<string, JsonElement>>?> WriteAsync(string path, IReadOnlyDictionary<string, object?> body,
        VaultRequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(body);
        return SendAsync<Dictionary<string, JsonElement>>(HttpMethod.Post, V1Path(path), body, QueryParameters(options), options, cancellationToken);
    }

    /// <summary>Writes body as it is to path (POST /v1/path).</summary>
    /// <exception cref="VaultResponseException">Vault refused the request</exception>
    public Task<VaultResponse<Dictionary<string, JsonElement>>?> WriteFromBytesAsync(string path, ReadOnlyMemory<byte> body,
        VaultRequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        return SendBytesAsync<Dictionary<string, JsonElement>>(HttpMethod.Post, V1Path(path), body, QueryParameters(options), options, cancellationToken);
    }

    /// <summary>
    /// Writes what body holds to path (POST /v1/path). It's read whole first - into pinned memory,
    /// zeroed afterwards - so a retry can send it again.
    /// </summary>
    /// <exception cref="VaultResponseException">Vault refused the request</exception>
    public async Task<VaultResponse<Dictionary<string, JsonElement>>?> WriteFromStreamAsync(string path, Stream body,
        VaultRequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(body);
        using var buffer = new SecureBufferWriter(body.CanSeek ? body.Length - body.Position : null);
        await buffer.ReadFromAsync(body, cancellationToken).ConfigureAwait(false);
        return await WriteFromBytesAsync(path, buffer.WrittenMemory, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Lists the keys at path (GET /v1/path?list=true).</summary>
    /// <exception cref="VaultResponseException">Vault refused the request</exception>
    public Task<VaultResponse<Dictionary<string, JsonElement>>?> ListAsync(string path, VaultRequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        var query = QueryParameters(options);
        query.Add(new("list", "true"));
        return SendAsync<Dictionary<string, JsonElement>>(HttpMethod.Get, V1Path(path), null, query, options, cancellationToken);
    }

    /// <summary>Deletes the value at path (DELETE /v1/path).</summary>
    /// <exception cref="VaultResponseException">Vault refused the request</exception>
    public Task<VaultResponse<Dictionary<string, JsonElement>>?> DeleteAsync(string path, VaultRequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        return SendAsync<Dictionary<string, JsonElement>>(HttpMethod.Delete, V1Path(path), null, QueryParameters(options), options, cancellationToken);
    }

    /// <summary>
    /// The response wrappingToken wraps (PUT /v1/sys/wrapping/unwrap, made with that token); see
    /// https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
    /// </summary>
    /// <typeparam name="T">What the wrapped response's data holds, as the method that was wrapped returns it.</typeparam>
    /// <param name="wrappingToken">The wrapping token - <see cref="VaultResponseWrapInfo.Token"/>, or one protected with <see cref="ProtectToken"/>.</param>
    /// <exception cref="VaultResponseException">Vault refused the token: unknown, expired or already used</exception>
    public Task<VaultResponse<T>?> UnwrapAsync<T>(IVaultTokenProvider wrappingToken, VaultRequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappingToken);
        return SendAsync<T>(HttpMethod.Put, "/v1/sys/wrapping/unwrap", null, null, (options ?? new VaultRequestOptions()) with { Token = wrappingToken },
            cancellationToken);
    }

    /// <summary>
    /// Sends a request - body, if any, as JSON - and reads Vault's response into a
    /// <see cref="VaultResponse{T}"/>; null if it has no body. The generated methods all come here.
    /// </summary>
    internal async Task<VaultResponse<T>?> SendAsync<T>(HttpMethod method, string path, object? body,
        List<KeyValuePair<string, string>>? query, VaultRequestOptions? options, CancellationToken cancellationToken)
    {
        if (body is null)
            return await SendBytesAsync<T>(method, path, null, query, options, cancellationToken).ConfigureAwait(false);

        using var json = new SecureBufferWriter();
        VaultJson.Serialize(json, body);
        return await SendBytesAsync<T>(method, path, json.WrittenMemory, query, options, cancellationToken).ConfigureAwait(false);
    }

    private async Task<VaultResponse<T>?> SendBytesAsync<T>(HttpMethod method, string path, ReadOnlyMemory<byte>? body,
        List<KeyValuePair<string, string>>? query, VaultRequestOptions? options, CancellationToken cancellationToken)
    {
        using var timeout = _options.RequestTimeout > TimeSpan.Zero ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken) : null;
        timeout?.CancelAfter(_options.RequestTimeout);
        var token = timeout?.Token ?? cancellationToken;
        try
        {
            var (response, request) = await SendCoreAsync(method, path, body, query, options, token).ConfigureAwait(false);
            using (request)
            using (response)
            {
                // Unbuffered by HttpClient, whose pooled buffer would be returned uncleared: read into
                // pinned memory, zeroed once parsed.
                using var content = new SecureBufferWriter(response.Content.Headers.ContentLength);
                var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
                await using (stream.ConfigureAwait(false))
                    await content.ReadFromAsync(stream, token).ConfigureAwait(false);

                // sys/health answers 429, 472, 473, 501 and 503 with the health status itself.
                if (!IsSuccess(response.StatusCode) && path != HealthPath)
                    throw VaultResponseException.Create(response, content.WrittenSpan, request.Method, request.RequestUri!);

                return Parse<T>(content.WrittenSpan);
            }
        }
        catch (OperationCanceledException e) when (timeout?.IsCancellationRequested == true && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"Vault didn't answer {method} {path} within {_options.RequestTimeout}.", e);
        }
    }

    // body as a VaultResponse<T>: the standard envelope when it has a "data" member (as
    // vault-client-go decides) - or "auth" or "wrap_info", so a token is never mistaken for data -
    // otherwise body whole as its Data (sys/health, sys/leader, sys/seal-status...).
    private VaultResponse<T>? Parse<T>(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
            return null;

        return IsEnvelope(body)
            ? VaultJson.Deserialize<VaultResponse<T>>(body, _tokenProtector)
            : new VaultResponse<T> { Data = VaultJson.Deserialize<T>(body, _tokenProtector) };
    }

    private static bool IsEnvelope(ReadOnlySpan<byte> body)
    {
        try
        {
            // Malformed JSON throws rather than ending early: the reader is given the whole body.
            var reader = new Utf8JsonReader(body);
            reader.Read();
            if (reader.TokenType != JsonTokenType.StartObject)
                return false;

            for (reader.Read(); reader.TokenType == JsonTokenType.PropertyName; reader.Read())
            {
                if (reader.ValueTextEquals("data"u8) || reader.ValueTextEquals("auth"u8) || reader.ValueTextEquals("wrap_info"u8))
                    return true;
                reader.Read();
                reader.Skip();
            }

            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    // Sends the request, retrying and following a redirect as configured, and calls the response
    // callbacks. The caller disposes the response and request; neither carries the token any more.
    private async Task<(HttpResponseMessage Response, HttpRequestMessage Request)> SendCoreAsync(HttpMethod method, string path,
        ReadOnlyMemory<byte>? body, List<KeyValuePair<string, string>>? query, VaultRequestOptions? options, CancellationToken cancellationToken)
    {
        var modifiers = Volatile.Read(ref _modifiers).Merge(options);
        var uri = new Uri(_baseAddress + path + QueryString(query), UriKind.Absolute);

        if (_options.RateLimiter is { } limiter)
            await limiter.WaitAsync(cancellationToken).ConfigureAwait(false);

        var states = _replicationStates?.Snapshot() ?? [];

        // Asked for once per request; a provider's failure is its own to retry, so isn't retried here.
        var protectedToken = modifiers.Token is { } provider ? await provider.GetTokenAsync(cancellationToken).ConfigureAwait(false) : null;

        var redirects = 1;
        while (true)
        {
            var (response, request) = await SendWithRetriesAsync(method, uri, path, body, modifiers, states, protectedToken, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                if (RedirectTarget(response, request, ref redirects) is not { } target)
                {
                    foreach (var callback in modifiers.ResponseCallbacks)
                        callback(request, response);
                    _replicationStates?.Record(response);
                    return (response, request);
                }

                if (_logger is not null)
                    Log.FollowingRedirect(_logger, method, path, target.GetLeftPart(UriPartial.Path));
                uri = target;
            }
            catch
            {
                response.Dispose();
                request.Dispose();
                throw;
            }

            response.Dispose();
            request.Dispose();
        }
    }

    // Where a redirect response says to go, if following it is allowed; null if response isn't one.
    private Uri? RedirectTarget(HttpResponseMessage response, HttpRequestMessage request, ref int redirects)
    {
        var status = response.StatusCode;
        if (status is not (HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.TemporaryRedirect))
            return null;

        var from = request.RequestUri!;
        if (response.Headers.Location is not { } location)
            throw new VaultRedirectException(status, "could not read the redirect location", null, request.Method, from);
        if (!location.IsAbsoluteUri)
            location = new Uri(from, location);

        if (!_options.FollowRedirects)
            throw new VaultRedirectException(status, "redirects are disabled", location, request.Method, from);
        if (redirects <= 0)
            throw new VaultRedirectException(status, "at most one redirect is allowed", location, request.Method, from);
        redirects--;

        if (from.Scheme == Uri.UriSchemeHttps && location.Scheme != Uri.UriSchemeHttps)
            throw new VaultRedirectException(status, "the redirect would cause a protocol downgrade", location, request.Method, from);
        if (location.Scheme != Uri.UriSchemeHttps
            && !(location.Scheme == Uri.UriSchemeHttp && (location.IsLoopback || _options.AllowUnencryptedHttp)))
            throw new VaultRedirectException(status, "the redirect would send the token over unencrypted http", location, request.Method, from);

        return location;
    }

    // One request, sent until it succeeds, fails in a way not worth retrying, or runs out of retries.
    // Each attempt is a new HttpRequestMessage: one can't be sent twice.
    private async Task<(HttpResponseMessage Response, HttpRequestMessage Request)> SendWithRetriesAsync(HttpMethod method, Uri uri, string path,
        ReadOnlyMemory<byte>? body, RequestModifiers modifiers, string[] states, string? protectedToken, CancellationToken cancellationToken)
    {
        var retry = _options.Retry;
        for (var attempt = 0; ; attempt++)
        {
            var request = CreateRequest(method, uri, body, modifiers, states);
            HttpResponseMessage? response = null;
            Exception? failure = null;
            try
            {
                foreach (var callback in modifiers.RequestCallbacks)
                    callback(request);
                response = await SendOnceAsync(request, protectedToken, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e) when (e is HttpRequestException or IOException && !cancellationToken.IsCancellationRequested
                                      && attempt < retry.RetryMax && _checkRetry(null, e))
            {
                failure = e;
            }
            catch
            {
                // Not worth retrying, or out of retries: the exception is the request's.
                request.Dispose();
                throw;
            }

            if (failure is not null || (attempt < retry.RetryMax && _checkRetry(response, null)))
            {
                var delay = _backoff(retry.RetryWaitMin, retry.RetryWaitMax, attempt, response);
                if (delay < TimeSpan.Zero)
                    delay = TimeSpan.Zero;
                if (_logger is not null)
                    Log.Retrying(_logger, method, path, failure?.Message ?? $"{(int)response!.StatusCode} {response.StatusCode}", attempt + 1, retry.RetryMax, delay);

                response?.Dispose();
                request.Dispose();
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                continue;
            }

            return (response!, request);
        }
    }

    // Sends request with the token in its header, and takes it out again - zeroed - once sent. The
    // decrypted token is zeroed as well.
    private async Task<HttpResponseMessage> SendOnceAsync(HttpRequestMessage request, string? protectedToken, CancellationToken cancellationToken)
    {
        if (protectedToken is null)
            return await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

        var token = VaultHttp.DecryptToken(_tokenProtector, protectedToken, out var length);
        try
        {
            return await VaultHttp.SendWithTokenAsync(_http, request, token.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayUtility.ZeroMemory(token.AsSpan());
        }
    }

    // A request carrying the client's headers, as vault-client-go's newRequest builds it; the token is
    // added only as it's sent.
    private static HttpRequestMessage CreateRequest(HttpMethod method, Uri uri, ReadOnlyMemory<byte>? body, RequestModifiers modifiers, string[] states)
    {
        var request = new HttpRequestMessage(method, uri);
        if (body is { } content)
            request.Content = new ReadOnlyMemoryContent(content);

        foreach (var (name, values) in modifiers.CustomHeaders)
        {
            if (!request.Headers.TryAddWithoutValidation(name, values))
                request.Content?.Headers.TryAddWithoutValidation(name, values);
        }

        if (modifiers.UserAgent is { } userAgent)
            request.Headers.TryAddWithoutValidation("User-Agent", userAgent);

        // Required by a Vault Agent or proxy configured with require_request_header.
        request.Headers.TryAddWithoutValidation("X-Vault-Request", "true");

        if (modifiers.Namespace is { } ns)
            request.Headers.TryAddWithoutValidation("X-Vault-Namespace", ns);

        foreach (var credential in modifiers.MfaCredentials)
            request.Headers.TryAddWithoutValidation("X-Vault-MFA", credential);

        if (modifiers.ResponseWrappingTtl > TimeSpan.Zero)
            request.Headers.TryAddWithoutValidation("X-Vault-Wrap-TTL", GoDuration.Format(modifiers.ResponseWrappingTtl));

        switch (modifiers.ReplicationForwardingMode)
        {
            case ReplicationForwardingMode.Always:
                request.Headers.TryAddWithoutValidation("X-Vault-Forward", "active-node");
                break;
            case ReplicationForwardingMode.Inconsistent:
                request.Headers.TryAddWithoutValidation("X-Vault-Inconsistent", "forward-active-node");
                break;
        }

        foreach (var state in states)
            request.Headers.TryAddWithoutValidation(VaultReplication.IndexHeader, state);

        return request;
    }

    private static bool IsSuccess(HttpStatusCode status) => (int)status is >= 200 and <= 399;

    // query, sorted by name (values of one name keep their order) as Go's url.Values.Encode sorts it.
    private static string QueryString(List<KeyValuePair<string, string>>? query)
    {
        if (query is not { Count: > 0 })
            return "";

        return "?" + string.Join('&', query
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
    }

    // path under /v1/, whether or not it starts with "/", "v1/" or "/v1/" already.
    internal static string V1Path(string path)
    {
        if (path.StartsWith("/v1/", StringComparison.Ordinal))
            return path;
        if (path.StartsWith("v1/", StringComparison.Ordinal))
            return "/" + path;
        if (path.StartsWith('/'))
            return "/v1" + path;
        return "/v1/" + path;
    }
}
