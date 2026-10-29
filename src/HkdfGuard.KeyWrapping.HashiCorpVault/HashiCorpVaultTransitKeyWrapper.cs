using System.Buffers;
using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.SecureFile;

namespace HkdfGuard.KeyWrapping.HashiCorpVault;

/// <summary>
/// Protects (encrypt) and reveals (decrypt) a DEK under one key in a HashiCorp Vault transit
/// secrets engine, and generates fresh DEKs with datakey/wrapped - so on that path the plaintext
/// DEK never leaves Vault. The KEK never enters this process; every call is a request to Vault's
/// HTTP API, authorized by the token's policy and recorded in Vault's audit log. A wrapped DEK is
/// Vault's ciphertext as it returns it, "vault:v{version}:{base64}", in ASCII.
/// <para>
/// The key is pinned by its path: every request names it, and a ciphertext carries only its key
/// version, never its key, so a key file wrapped under another transit key fails to authenticate
/// rather than being revealed. Vault's key rotation (transit/keys/{name}/rotate) keeps the name and
/// is transparent here: new DEKs are wrapped under the latest version, and older ones still reveal
/// while their version is at or above the key's min_decryption_version. The key must be an AEAD
/// key that isn't derived - aes256-gcm96 (Vault's default), aes128-gcm96 or chacha20-poly1305.
/// </para>
/// <para>
/// The context, if any, is bound into every wrapped DEK as Vault's associated_data (AAD): decrypt
/// fails unless it is presented again exactly. datakey/wrapped ignores associated_data, so with a
/// context <see cref="GenerateAndWrapAsync"/> generates the DEK here and wraps it with encrypt
/// instead - the plaintext DEK then does cross the network to Vault, as on <see cref="WrapAsync"/>.
/// A response whose warnings say Vault ignored a parameter (a Vault too old for associated_data)
/// is refused, so a context is never silently dropped. Vault's audit log HMACs request fields by
/// default, but the context isn't a secret and must not hold one.
/// </para>
/// <para>
/// Key files are read only from where an untrusted account can't have written or replaced them
/// (see <see cref="ReadKeyFileAsync"/> and <see cref="KeyFileTrust"/>). Pinning the key stops a key
/// file wrapped under another key; this stops one wrapped under this key by anyone whose policy
/// allows encrypt, which would otherwise choose the DEK new data is encrypted under.
/// </para>
/// <para>
/// Plaintext key bytes this class owns are zeroed once used: the request body encrypt is sent
/// (the DEK, base64-encoded), the response body decrypt answers with, read off the network unbuffered
/// into pinned memory, and the DEK decoded out of it. The token is copied into pinned memory by its
/// <see cref="IVaultTokenSource"/>, and from there into the one string the header needs, zeroed as
/// soon as the request has been sent. What can't be zeroed is below HttpClient: the HTTP stack's own
/// buffers (TLS encryption and decryption, socket reads and writes).
/// </para>
/// <para>
/// Requests go to /v1/ under Vault's address, which must be https except on loopback; the
/// wrapper's own HTTP handler follows no redirects, which would carry the token elsewhere. A
/// request that fails transiently - no answer, a connection lost mid-response, a timed-out attempt,
/// 429 or a 5xx other than 501 - is retried (see <see cref="HashiCorpVaultTransitKeyWrapperOptions.RetryCount"/>).
/// Dispose the wrapper to release its connections.
/// </para>
/// </summary>
public sealed class HashiCorpVaultTransitKeyWrapper : IKeyWrapper, IDisposable
{
    /// <summary>The length of the DEK <see cref="GenerateAndWrapAsync"/> generates: 32 bytes (AES-256).</summary>
    public const int GeneratedKeyLength = 32;

    /// <summary>The largest plaintext <see cref="WrapAsync"/> accepts, in bytes: its ciphertext still
    /// fits <see cref="WrappedKeyLimits.MaxBytes"/>.</summary>
    public const int MaxPlaintextLength = 256;

    /// <summary>The longest context, in UTF-8 bytes.</summary>
    public const int MaxContextLength = 1024;

    /// <summary>The longest key name.</summary>
    public const int MaxKeyNameLength = 128;

    /// <summary>The longest token an <see cref="IVaultTokenSource"/> may supply, in characters.</summary>
    public const int MaxTokenLength = 2048;

    /// <summary>The largest response read from Vault, in bytes; a transit answer is well under 1 KB.</summary>
    internal const int MaxResponseLength = 16 * 1024;

    private const string TokenHeader = "X-Vault-Token";

    private static readonly SearchValues<char> SegmentCharacters =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.");

    private static readonly SearchValues<byte> Base64Bytes =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="u8);

    private static readonly MediaTypeHeaderValue Json = new("application/json");

    // Asks for a 256-bit key: GeneratedKeyLength bytes.
    private static readonly byte[] DataKeyBody = "{\"bits\":256}"u8.ToArray();

    private static ReadOnlySpan<byte> PlaintextPrefix => "{\"plaintext\":\""u8;

    private static ReadOnlySpan<byte> CiphertextPrefix => "{\"ciphertext\":\""u8;

    private readonly HttpClient _http;
    private readonly IVaultTokenSource _tokenSource;
    private readonly string _keyName;
    private readonly Uri _encryptPath;
    private readonly Uri _decryptPath;
    private readonly Uri _dataKeyPath;
    private readonly bool _hasContext;
    // Closes every encrypt and decrypt body: the closing quote of its value, the context if any,
    // and the closing brace.
    private readonly byte[] _bodySuffix;
    private readonly string? _namespace;
    private readonly TimeSpan _timeout;
    private readonly int _retryCount;
    private readonly TimeSpan _retryDelay;
    private readonly KeyFileTrust _keyFileTrust;

    /// <param name="address">Vault's address, e.g. https://vault.example.com:8200 - the same value
    /// as VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev server).
    /// A path, if any, is kept as a prefix (Vault behind a reverse proxy).</param>
    /// <param name="keyName">The transit key that wraps every DEK, e.g. "myapp-kek".</param>
    /// <param name="tokenSource">Supplies the token every request is made with.</param>
    /// <param name="context">Bound into every wrapped DEK as associated_data and required again to
    /// reveal it; null or empty binds none.</param>
    /// <param name="keyFileTrust">Who besides the operating system's administrators may have
    /// written a key file <see cref="ReadKeyFileAsync"/> reads; null trusts administrators only
    /// (<see cref="KeyFileTrust.AdministratorsOnly"/>).</param>
    /// <param name="options">The transit engine called and how to reach it; null for the engine at
    /// "transit".</param>
    /// <exception cref="ArgumentNullException">address, keyName or tokenSource is null</exception>
    /// <exception cref="ArgumentException">address isn't https (or http on loopback), or holds
    /// credentials, a query or a fragment; keyName isn't a key name; the context is over
    /// <see cref="MaxContextLength"/> bytes; the mount path or namespace isn't one; or the
    /// HttpMessageHandler follows redirects without AllowRedirects</exception>
    /// <exception cref="ArgumentOutOfRangeException">The timeout isn't positive, or the retry count
    /// or delay is out of range</exception>
    public HashiCorpVaultTransitKeyWrapper(Uri address, string keyName, IVaultTokenSource tokenSource,
        string? context = null, KeyFileTrust? keyFileTrust = null, HashiCorpVaultTransitKeyWrapperOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(keyName);
        ArgumentNullException.ThrowIfNull(tokenSource);
        options ??= new HashiCorpVaultTransitKeyWrapperOptions();
        var apiBase = ApiBase(address);

        if (keyName.Length > MaxKeyNameLength || !IsValidSegment(keyName))
            throw new ArgumentException(
                $"The key name '{keyName}' isn't one: 1-{MaxKeyNameLength} ASCII letters, digits, '-', '_' and '.', and not \".\" or \"..\".", nameof(keyName));
        if (!IsValidPath(options.MountPath))
            throw new ArgumentException($"The mount path '{options.MountPath}' isn't a Vault path.", nameof(options));
        if (options.Namespace is not null && !IsValidPath(options.Namespace))
            throw new ArgumentException($"The namespace '{options.Namespace}' isn't a Vault path.", nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.Timeout, TimeSpan.Zero, nameof(options));
        if (options.RetryCount is < HashiCorpVaultTransitKeyWrapperOptions.MinRetryCount or > HashiCorpVaultTransitKeyWrapperOptions.MaxRetryCount)
            throw new ArgumentOutOfRangeException(nameof(options), options.RetryCount,
                $"RetryCount must be {HashiCorpVaultTransitKeyWrapperOptions.MinRetryCount}-{HashiCorpVaultTransitKeyWrapperOptions.MaxRetryCount}.");
        if (options.RetryDelay < TimeSpan.Zero || options.RetryDelay > HashiCorpVaultTransitKeyWrapperOptions.MaxRetryDelay)
            throw new ArgumentOutOfRangeException(nameof(options), options.RetryDelay,
                $"RetryDelay must be zero to {HashiCorpVaultTransitKeyWrapperOptions.MaxRetryDelay}.");
        if (options.HttpMessageHandler is { } supplied && !options.AllowRedirects && FollowsRedirects(supplied))
            throw new ArgumentException(
                "The HttpMessageHandler follows redirects, which would send the Vault token wherever they point. Set its AllowAutoRedirect to false, or set AllowRedirects if every redirect target may see the token.",
                nameof(options));

        var contextBytes = Encoding.UTF8.GetBytes(context ?? "");
        if (contextBytes.Length > MaxContextLength)
            throw new ArgumentException($"The context is {contextBytes.Length} bytes in UTF-8; at most {MaxContextLength} are allowed.", nameof(context));

        _tokenSource = tokenSource;
        _keyName = keyName;
        _encryptPath = new Uri($"{options.MountPath}/encrypt/{keyName}", UriKind.Relative);
        _decryptPath = new Uri($"{options.MountPath}/decrypt/{keyName}", UriKind.Relative);
        _dataKeyPath = new Uri($"{options.MountPath}/datakey/wrapped/{keyName}", UriKind.Relative);
        // Vault treats an empty associated_data as none, so an empty context is none too.
        _hasContext = contextBytes.Length > 0;
        _bodySuffix = _hasContext
            ? Encoding.ASCII.GetBytes($"\",\"associated_data\":\"{Convert.ToBase64String(contextBytes)}\"}}")
            : "\"}"u8.ToArray();
        _namespace = options.Namespace;
        _timeout = options.Timeout;
        _retryCount = options.RetryCount;
        _retryDelay = options.RetryDelay;
        _keyFileTrust = keyFileTrust ?? KeyFileTrust.AdministratorsOnly;

        var handler = options.HttpMessageHandler ?? new SocketsHttpHandler
        {
            // A redirect would carry X-Vault-Token to wherever it points: HttpClient drops only the
            // Authorization header when following one. Vault's standbys forward requests to the
            // active node themselves, so a redirect is answered as an error instead.
            AllowAutoRedirect = false,
            UseCookies = false,
            // Picks up a changed DNS record (a failover) without restarting.
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
        _http = new HttpClient(handler, disposeHandler: options.HttpMessageHandler is null)
        {
            BaseAddress = apiBase,
            // Each attempt's own timeout covers the token as well as the request.
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        };
    }

    /// <summary>Releases the wrapper's connections, and its HTTP handler unless the caller supplied it.</summary>
    public void Dispose() => _http.Dispose();

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">plaintext is empty or over <see cref="MaxPlaintextLength"/>
    /// bytes, or result is too small for the wrapped DEK</exception>
    /// <exception cref="CryptographicException">Vault refused the request, or could not be reached
    /// (the HttpRequestException or IOException is the inner exception), or returned no ciphertext</exception>
    /// <exception cref="InvalidOperationException">The token source supplied no token, or one that isn't a token</exception>
    public async ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (plaintext.IsEmpty || plaintext.Length > MaxPlaintextLength)
            throw new ArgumentException($"Vault transit wraps 1-{MaxPlaintextLength} bytes here; got {plaintext.Length}.", nameof(plaintext));

        // Pinned, so no copy of the base64-encoded DEK is left behind by compaction before it is zeroed.
        var body = ArrayUtility.AllocatePinned<byte>(
            PlaintextPrefix.Length + Base64.GetMaxEncodedToUtf8Length(plaintext.Length) + _bodySuffix.Length);
        try
        {
            var length = WriteBody(body, PlaintextPrefix, plaintext.Span, encode: true);
            var response = await PostAsync("wrap", _encryptPath, body.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            return ReadAnswer(response, "wrap", result, plaintext: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">result is too small for the revealed key</exception>
    /// <exception cref="CryptographicException">wrapped is empty, over
    /// <see cref="WrappedKeyLimits.MaxBytes"/> or isn't a Vault ciphertext; or Vault refused it -
    /// tampered with, wrapped under another key or under a different context, or its key version
    /// is below min_decryption_version - or could not be reached (the HttpRequestException or
    /// IOException is the inner exception)</exception>
    /// <exception cref="InvalidOperationException">The token source supplied no token, or one that isn't a token</exception>
    public async ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        // Refused locally: no ciphertext Vault produces is outside these bounds, and one that is
        // Vault's ciphertext needs no escaping to go in the request body.
        if (wrapped.IsEmpty || wrapped.Length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException($"A wrapped DEK is 1-{WrappedKeyLimits.MaxBytes} bytes; got {wrapped.Length}.");
        if (!IsVaultCiphertext(wrapped.Span))
            throw new CryptographicException("A wrapped DEK is a Vault transit ciphertext, vault:v{version}:{base64}; this isn't one.");

        try
        {
            var body = new byte[CiphertextPrefix.Length + wrapped.Length + _bodySuffix.Length];
            var length = WriteBody(body, CiphertextPrefix, wrapped.Span, encode: false);
            var response = await PostAsync("unwrap", _decryptPath, body.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            return ReadAnswer(response, "unwrap", result, plaintext: true);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(result.Span);
            throw;
        }
    }

    /// <summary>
    /// Generates a fresh <see cref="GeneratedKeyLength"/>-byte DEK wrapped under the key. Without a
    /// context Vault generates it and returns it wrapped only (datakey/wrapped), so the plaintext
    /// DEK never leaves Vault on this call. With a context - which datakey/wrapped would ignore - it
    /// is generated here and wrapped with encrypt, then zeroed.
    /// </summary>
    /// <param name="result">The wrapped key</param>
    /// <param name="cancellationToken">Cancels the operation</param>
    /// <returns>Number of bytes written to the result</returns>
    /// <exception cref="ArgumentException">result is too small for the wrapped DEK</exception>
    /// <exception cref="CryptographicException">Vault refused the request, or could not be reached
    /// (the HttpRequestException or IOException is the inner exception), or returned no ciphertext</exception>
    /// <exception cref="InvalidOperationException">The token source supplied no token, or one that isn't a token</exception>
    public async ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (_hasContext)
        {
            var dek = ArrayUtility.AllocatePinned<byte>(GeneratedKeyLength);
            try
            {
                RandomNumberGenerator.Fill(dek);
                return await WrapAsync(dek, result, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dek);
            }
        }

        var response = await PostAsync("generate-and-wrap", _dataKeyPath, DataKeyBody, cancellationToken).ConfigureAwait(false);
        return ReadAnswer(response, "generate-and-wrap", result, plaintext: false);
    }

    /// <summary>
    /// Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than
    /// the operating system's administrators and the <see cref="KeyFileTrust"/> given at
    /// construction could have written or replaced - the managed equivalent of the native library's
    /// checks. On Windows the file must be on a local fixed drive, reached through real folders (no
    /// symbolic link, junction or substituted drive), and it and every folder above
    /// it must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and
    /// every directory above it must be owned by root or a trusted user and writable by nobody else
    /// (by its group only if that group is trusted), and only symbolic links a trusted user owns are
    /// followed. It is also refused if it is empty, over <see cref="WrappedKeyLimits.MaxBytes"/>, or
    /// looks like an unwrapped key.
    /// </summary>
    /// <param name="path">The key file's path</param>
    /// <param name="cancellationToken">Cancels the read</param>
    /// <returns>The file's contents, still wrapped</returns>
    /// <exception cref="FileNotFoundException">The file doesn't exist</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read the file, or it isn't
    /// somewhere only trusted principals can modify</exception>
    /// <exception cref="InvalidDataException">The file is empty, too long, or holds what looks like an
    /// unwrapped key</exception>
    /// <exception cref="IOException">The file can't be read, or another process has it open for writing</exception>
    /// <exception cref="ArgumentException">The <see cref="KeyFileTrust"/> names a principal that can't be trusted</exception>
    public ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
        => TrustedKeyFile.ReadAsync(path, _keyFileTrust, cancellationToken);

    /// <summary>Whether token can go in a header: non-empty printable ASCII, with no spaces.</summary>
    internal static bool IsValidToken(ReadOnlySpan<char> token)
        => !token.IsEmpty && !token.ContainsAnyExceptInRange('!', '~');

    /// <summary>Whether value is a transit ciphertext as Vault writes it: vault:v{version}:{base64}.</summary>
    internal static bool IsVaultCiphertext(ReadOnlySpan<byte> value)
    {
        if (!value.StartsWith("vault:v"u8))
            return false;

        var rest = value["vault:v"u8.Length..];
        var digits = rest.IndexOfAnyExceptInRange((byte)'0', (byte)'9');
        return digits is > 0 and <= 10
               && rest[digits] == (byte)':'
               && rest.Length > digits + 1
               && !rest[(digits + 1)..].ContainsAnyExcept(Base64Bytes);
    }

    /// <summary>
    /// The wait before retry number <paramref name="retry"/> (0 for the first): baseDelay, doubled
    /// for each retry before it, at most MaxRetryDelay - plus jitterMilliseconds.
    /// </summary>
    internal static TimeSpan RetryDelay(TimeSpan baseDelay, int retry, int jitterMilliseconds)
    {
        var backoff = baseDelay * Math.Pow(2, retry);
        return (backoff < HashiCorpVaultTransitKeyWrapperOptions.MaxRetryDelay ? backoff : HashiCorpVaultTransitKeyWrapperOptions.MaxRetryDelay)
               + TimeSpan.FromMilliseconds(jitterMilliseconds);
    }

    // prefix, then value (base64-encoded if encode), then the suffix: a whole encrypt or decrypt
    // body. Returns its length.
    private int WriteBody(Span<byte> body, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> value, bool encode)
    {
        prefix.CopyTo(body);
        var length = prefix.Length;
        if (encode)
        {
            Base64.EncodeToUtf8(value, body[length..], out _, out var written);
            length += written;
        }
        else
        {
            value.CopyTo(body[length..]);
            length += value.Length;
        }

        _bodySuffix.CopyTo(body[length..]);
        return length + _bodySuffix.Length;
    }

    // Posts body to path and returns Vault's successful response, in a pinned buffer the caller
    // zeroes. The token is asked for once; a request that fails transiently is retried. Vault's
    // refusals, and failures to reach it once the retries are spent, become CryptographicException.
    private async Task<byte[]> PostAsync(string operation, Uri path, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var token = ArrayUtility.AllocatePinned<char>(MaxTokenLength);
        try
        {
            // A source's failure is its own to retry, so isn't retried here, and propagates as it is.
            int tokenLength;
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(_timeout);
                tokenLength = await _tokenSource.CopyTokenAsync(token, timeout.Token).ConfigureAwait(false);
            }

            if (tokenLength is <= 0 or > MaxTokenLength || !IsValidToken(token.AsSpan(0, tokenLength)))
                throw new InvalidOperationException("The Vault token source supplied no token, or one that isn't a token: printable ASCII, with no spaces.");

            for (var retry = 0; ; retry++)
            {
                try
                {
                    return await SendAsync(path, body, token.AsMemory(0, tokenLength), cancellationToken).ConfigureAwait(false);
                }
                catch (Exception e) when (retry < _retryCount && IsTransient(e, cancellationToken))
                {
                    await Task.Delay(RetryDelay(_retryDelay, retry, Random.Shared.Next(0, 101)), cancellationToken).ConfigureAwait(false);
                }
                catch (Exception e) when (e is HttpRequestException or IOException
                                          || (e is OperationCanceledException && !cancellationToken.IsCancellationRequested))
                {
                    var reason = e is OperationCanceledException ? $"no answer within {_timeout}" : e.Message;
                    throw new CryptographicException($"Vault transit {operation} failed for key '{_keyName}': {reason}", e);
                }
            }
        }
        finally
        {
            ArrayUtility.ZeroMemory(token.AsSpan());
        }
    }

    // A failure another attempt may not meet: no answer at all (connection refused or reset, DNS),
    // a connection lost mid-response, the attempt's own timeout, or Vault busy or briefly unable to
    // answer - 429, or a 5xx other than 501.
    private static bool IsTransient(Exception e, CancellationToken cancellationToken) => e switch
    {
        HttpRequestException http => http.StatusCode is not { } status
                                     || status == HttpStatusCode.TooManyRequests
                                     || ((int)status >= 500 && status != HttpStatusCode.NotImplemented),
        IOException => true,
        OperationCanceledException => !cancellationToken.IsCancellationRequested,
        _ => false,
    };

    // One attempt: one request, and Vault's whole response, within the attempt's timeout. A
    // successful response is returned in a pinned buffer; any other is thrown as an
    // HttpRequestException carrying Vault's status and errors.
    private async Task<byte[]> SendAsync(Uri path, ReadOnlyMemory<byte> body, ReadOnlyMemory<char> token, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);

        // Sent from body itself, not a copy: ReadOnlyMemoryContent writes from the memory it's given.
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new ReadOnlyMemoryContent(body) };
        request.Content.Headers.ContentType = Json;
        request.Headers.Add("X-Vault-Request", "true");
        if (_namespace is not null)
            request.Headers.Add("X-Vault-Namespace", _namespace);

        HttpResponseMessage sent;
        var header = new string(token.Span);
        try
        {
            // Checked by PostAsync - printable ASCII, nothing to parse - so added as it is, without
            // the copies validation could make.
            request.Headers.TryAddWithoutValidation(TokenHeader, header);

            // Unbuffered: HttpClient would otherwise copy the body into a pooled buffer it returns uncleared.
            sent = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        }
        finally
        {
            // The request is sent, or has failed: zero the header's only copy of the token. It was
            // made by new string from the token's chars, so it is no literal or interned string
            // anything else could share.
            ArrayUtility.ZeroMemory(MemoryMarshal.AsMemory(header.AsMemory()).Span);
        }

        using var response = sent;
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        // One byte over the limit, so a body that doesn't fit is noticed rather than truncated.
        var buffer = ArrayUtility.AllocatePinned<byte>(MaxResponseLength + 1);
        try
        {
            var length = 0;
            for (int read; length < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token).ConfigureAwait(false)) > 0;)
                length += read;
            if (length > MaxResponseLength)
                throw new CryptographicException($"Vault's answer for key '{_keyName}' is over {MaxResponseLength} bytes; a transit answer is far smaller.");

            if (response.IsSuccessStatusCode)
            {
                // A pinned copy just its size, for the caller to zero; this buffer is zeroed below.
                var answer = ArrayUtility.AllocatePinned<byte>(length);
                buffer.AsSpan(0, length).CopyTo(answer);
                return answer;
            }

            var errors = ReadErrors(buffer.AsSpan(0, length));
            var detail = errors is { Length: > 0 } ? ": " + string.Join("; ", errors) : "";
            throw new HttpRequestException($"Vault answered {(int)response.StatusCode} {response.StatusCode}{detail}", null, response.StatusCode);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    // Takes data.plaintext (decoded) or data.ciphertext out of a successful answer into result,
    // then zeroes the answer and the copy of the value read out of it.
    private int ReadAnswer(byte[] response, string operation, Memory<byte> result, bool plaintext)
    {
        // Never longer than the answer it is read out of.
        var value = ArrayUtility.AllocatePinned<byte>(response.Length);
        try
        {
            var length = ReadData(response, plaintext ? "plaintext"u8 : "ciphertext"u8, operation, value);
            return plaintext
                ? DecodePlaintext(value.AsSpan(0, length), result.Span)
                : CopyCiphertext(value.AsSpan(0, length), result, operation);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
            CryptographicOperations.ZeroMemory(response);
        }
    }

    // Copies the string at data.{name} in a successful response into value, unescaped, and returns
    // its length. Refused if it is missing or repeated, isn't a string, or the response's warnings
    // say Vault ignored a parameter - as a Vault too old for associated_data does, leaving a DEK
    // bound to no context.
    private int ReadData(ReadOnlySpan<byte> json, ReadOnlySpan<byte> name, string operation, Span<byte> value)
    {
        var length = 0;
        var found = false;
        var ignoredParameter = false;
        try
        {
            // Read never returns false before the root object ends: the input is the whole answer,
            // so a truncated one throws instead.
            var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = 16 });
            reader.Read();
            if (reader.TokenType != JsonTokenType.StartObject)
                throw Malformed(operation);

            for (reader.Read(); reader.TokenType == JsonTokenType.PropertyName; reader.Read())
            {
                if (reader.ValueTextEquals("data"u8))
                {
                    reader.Read();
                    if (reader.TokenType != JsonTokenType.StartObject)
                    {
                        reader.Skip();
                        continue;
                    }

                    for (reader.Read(); reader.TokenType == JsonTokenType.PropertyName; reader.Read())
                    {
                        var isValue = reader.ValueTextEquals(name);
                        reader.Read();
                        if (!isValue)
                        {
                            reader.Skip();
                            continue;
                        }

                        if (found || reader.TokenType != JsonTokenType.String)
                            throw Malformed(operation);
                        // Vault doesn't escape base64 or its ciphertext, but a proxy re-encoding
                        // the answer might.
                        length = reader.CopyString(value);
                        found = true;
                    }
                }
                else if (reader.ValueTextEquals("warnings"u8))
                {
                    reader.Read();
                    if (reader.TokenType != JsonTokenType.StartArray)
                    {
                        reader.Skip();
                        continue;
                    }

                    for (reader.Read(); reader.TokenType != JsonTokenType.EndArray; reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.String && reader.GetString()!.Contains("unrecognized parameters", StringComparison.OrdinalIgnoreCase))
                            ignoredParameter = true;
                        reader.Skip();
                    }
                }
                else
                {
                    reader.Read();
                    reader.Skip();
                }
            }
        }
        catch (JsonException)
        {
            throw Malformed(operation);
        }

        if (ignoredParameter)
            throw new CryptographicException(
                $"Vault transit {operation} for key '{_keyName}' ignored a parameter it was sent, so its answer can't be used: a context needs a Vault that supports associated_data.");
        if (!found || length == 0)
            throw new CryptographicException($"Vault transit {operation} for key '{_keyName}' returned no {Encoding.ASCII.GetString(name)}.");

        return length;
    }

    private CryptographicException Malformed(string operation)
        => new($"Vault transit {operation} for key '{_keyName}' returned a response that isn't Vault's.");

    private int CopyCiphertext(ReadOnlySpan<byte> ciphertext, Memory<byte> result, string operation)
    {
        if (!IsVaultCiphertext(ciphertext))
            throw new CryptographicException($"Vault transit {operation} for key '{_keyName}' returned something that isn't a ciphertext.");

        // A key file over the limit would be refused when read back, so refuse to produce one.
        if (ciphertext.Length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException(
                $"Vault transit {operation} for key '{_keyName}' returned {ciphertext.Length} bytes; a wrapped DEK is at most {WrappedKeyLimits.MaxBytes}.");

        if (ciphertext.Length > result.Length)
            throw new ArgumentException($"The wrapped DEK is {ciphertext.Length} bytes; result holds {result.Length}.", nameof(result));

        ciphertext.CopyTo(result.Span);
        return ciphertext.Length;
    }

    // Decodes the revealed key into result, through a pinned buffer that is zeroed: decoded
    // straight into result, a key too long for it would be partly written before that was known.
    private int DecodePlaintext(ReadOnlySpan<byte> base64, Span<byte> result)
    {
        var decoded = ArrayUtility.AllocatePinned<byte>(Base64.GetMaxDecodedFromUtf8Length(base64.Length));
        try
        {
            if (Base64.DecodeFromUtf8(base64, decoded, out _, out var length) != OperationStatus.Done || length == 0)
                throw new CryptographicException($"Vault transit unwrap for key '{_keyName}' returned a plaintext that isn't base64.");
            if (length > result.Length)
                throw new ArgumentException($"The revealed key is {length} bytes; result holds {result.Length}.", nameof(result));

            decoded.AsSpan(0, length).CopyTo(result);
            return length;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    // The errors Vault listed in an error response; null if it isn't Vault's JSON. An error
    // response holds no key material.
    private static string[]? ReadErrors(ReadOnlySpan<byte> body)
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

    // /v1/ under Vault's address, refusing an address that would send tokens in the clear (http
    // anywhere but loopback) or that carries credentials, a query or a fragment.
    private static Uri ApiBase(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.IsAbsoluteUri)
            throw new ArgumentException($"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.", nameof(address));
        if (address.Scheme != Uri.UriSchemeHttps && !(address.Scheme == Uri.UriSchemeHttp && address.IsLoopback))
            throw new ArgumentException(
                $"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries a token and DEKs.", nameof(address));
        if (address.UserInfo.Length > 0 || address.Query.Length > 0 || address.Fragment.Length > 0)
            throw new ArgumentException($"Vault's address '{address}' must not hold credentials, a query or a fragment.", nameof(address));

        return new Uri(address.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/v1/");
    }

    // Whether the handler at the bottom of handler's DelegatingHandler chain follows redirects. One
    // of a type other than SocketsHttpHandler or HttpClientHandler can't be told, so counts as not.
    private static bool FollowsRedirects(HttpMessageHandler handler)
    {
        while (handler is DelegatingHandler { InnerHandler: { } inner })
            handler = inner;

        return handler switch
        {
            SocketsHttpHandler sockets => sockets.AllowAutoRedirect,
            HttpClientHandler client => client.AllowAutoRedirect,
            _ => false,
        };
    }

    // '/'-separated segments, none empty, "." or "..": a path that stays where it's put.
    private static bool IsValidPath(ReadOnlySpan<char> path)
    {
        foreach (var range in path.Split('/'))
        {
            if (!IsValidSegment(path[range]))
                return false;
        }

        return true;
    }

    private static bool IsValidSegment(ReadOnlySpan<char> segment)
        => !segment.IsEmpty && segment is not "." and not ".." && !segment.ContainsAnyExcept(SegmentCharacters);
}
