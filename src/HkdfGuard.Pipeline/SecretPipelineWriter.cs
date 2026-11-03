using System.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;

namespace HkdfGuard.Pipeline;

/// <summary>
/// The shared plumbing of an <see cref="ISecretPipelineWriter"/> over one secret store: the store's
/// writer supplies only <see cref="ReadSecretAsync"/>, which reads one secret and hands its values to
/// <see cref="Protect"/> or <see cref="ProtectKeys(ReadOnlySpan{byte}, IReadOnlyList{SecretRequest}, IDictionary{string, string})"/>.
/// Everything else - naming, grouping, encrypting, keeping and writing - is here. No key ring is
/// involved: the protector's key is the only one.
/// <para>
/// A secret name is the store's name for a secret, optionally followed by
/// <see cref="KeySeparator"/> and a key it holds: "prod/app#password" is the password key of the
/// secret prod/app. A name without one reads the store's default key, if it has one, or else the
/// secret's whole value. The secrets named are grouped by the store's name, so each is read once
/// however many of its keys are listed.
/// </para>
/// <para>
/// A secret's file name is its name with every '/' and '#' replaced by <see cref="FileNameSeparator"/>
/// (see <see cref="GetFileName"/>): "prod/app#password" is written as prod__app__password. A name
/// whose file name FilePerSecretCache couldn't read is refused. Each value is encrypted bound to its
/// file name - Encrypt(value, fileName) - which is the name FilePerSecretCache decrypts it under, so
/// a renamed file fails authentication.
/// </para>
/// <para>
/// A secret's plaintext never becomes a string: <see cref="Protect"/> takes it as UTF-8 bytes,
/// which the store's writer keeps in pinned memory, and decodes it onto the stack (or into pinned
/// memory) for the protector, zeroing it. The protector is the caller's and is never disposed, so its
/// key can be handed to the wrap process once the files are written. An instance isn't thread-safe.
/// </para>
/// </summary>
public abstract class SecretPipelineWriter : ISecretPipelineWriter
{
    /// <summary>Separates a secret's name from the key it reads: "prod/app#password".</summary>
    public const char KeySeparator = '#';

    /// <summary>Replaces each '/' and '#' of a secret name in its file name.</summary>
    public const string FileNameSeparator = "__";

    private readonly IPipelineDataProtector _protector;

    // The secrets to pull, by the store's name: each is read once, for its whole value and its keys.
    private readonly Dictionary<string, List<SecretRequest>> _requests = new(StringComparer.Ordinal);

    // Each secret's encrypted, formatted value, by file name. File names are found ignoring case on
    // Windows and macOS, so two differing only in case are refused as one.
    private readonly Dictionary<string, string> _protectedSecrets = new(StringComparer.OrdinalIgnoreCase);
    private bool _pulled;

    /// <param name="protector">Encrypts every value read. Owned by the caller: the writer never
    /// disposes it.</param>
    /// <param name="secretNames">The secrets to pull, each a name with the key to read after '#' if
    /// any. Copied: a later change to the list isn't seen.</param>
    /// <param name="isValidSecretName">Whether the store can hold a secret by a name, before any '#'.</param>
    /// <param name="defaultKey">The key a name without one reads, for a store whose secrets are all
    /// sets of keys (HashiCorp Vault's KV); null when such a name reads the secret's whole value.</param>
    /// <exception cref="ArgumentNullException">protector, secretNames or isValidSecretName is null</exception>
    /// <exception cref="ArgumentException">secretNames is empty, or holds a null, a name the store
    /// can't hold (with a key), one whose file name isn't one FilePerSecretCache can read, or two with
    /// the same file name, in any case; or defaultKey is empty or holds '#'</exception>
    protected SecretPipelineWriter(IPipelineDataProtector protector, IList<string> secretNames, Func<string, bool> isValidSecretName,
        string? defaultKey = null)
    {
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(secretNames);
        ArgumentNullException.ThrowIfNull(isValidSecretName);
        if (defaultKey is not null && (defaultKey.Length == 0 || defaultKey.Contains(KeySeparator)))
            throw new ArgumentException($"The default key '{defaultKey}' isn't a key.", nameof(defaultKey));

        _protector = protector;
        AddRequests(secretNames, isValidSecretName, defaultKey);
    }

    /// <inheritdoc/>
    public IReadOnlyDictionary<string, string> ProtectedSecrets => _protectedSecrets;

    /// <summary>
    /// The file a secret name is written as: the name with every '/' and '#' replaced by
    /// <see cref="FileNameSeparator"/> - "prod/app#password" is prod__app__password - and the name
    /// its value is bound to, so the one to look it up by in FilePerSecretCache.
    /// </summary>
    /// <exception cref="ArgumentNullException">secretName is null</exception>
    public static string GetFileName(string secretName)
    {
        ArgumentNullException.ThrowIfNull(secretName);
        return secretName.Replace("/", FileNameSeparator, StringComparison.Ordinal)
            .Replace(KeySeparator.ToString(), FileNameSeparator, StringComparison.Ordinal);
    }

    /// <summary>
    /// Reads every secret named in the constructor from the store and encrypts each value, keeping
    /// it in <see cref="ProtectedSecrets"/> - replacing whatever an earlier pull kept. All of them are
    /// read before any missing one is reported.
    /// </summary>
    /// <param name="cancellationToken">Cancels the reads</param>
    /// <exception cref="KeyNotFoundException">A secret doesn't exist, or has no such key, or its value
    /// there is empty or isn't a value; every other secret is kept</exception>
    /// <remarks>Any other failure <see cref="ReadSecretAsync"/> throws propagates, and nothing is kept.</remarks>
    public async Task PullSecretsAsync(CancellationToken cancellationToken = default)
    {
        _protectedSecrets.Clear();
        _pulled = false;

        var pulled = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, requests) in _requests)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            await ReadSecretAsync(name, requests, values, cancellationToken).ConfigureAwait(false);
            foreach (var request in requests)
            {
                if (values.TryGetValue(request.FileName, out var value))
                    pulled.Add(request.FileName, value);
            }
        }

        foreach (var (fileName, value) in pulled)
            _protectedSecrets.Add(fileName, value);
        _pulled = true;

        var missing = _requests.Values.SelectMany(r => r).Where(r => !pulled.ContainsKey(r.FileName)).Select(r => r.SecretName).ToList();
        if (missing.Count > 0)
            throw new KeyNotFoundException($"The secret store holds no value for: {string.Join(", ", missing)}.");
    }

    /// <summary>
    /// Writes every secret in <see cref="ProtectedSecrets"/> as a file in
    /// <paramref name="folderPath"/>, creating the folder if it doesn't exist: the file named for it,
    /// holding its encrypted, formatted value as UTF-8. A file already there by that name is
    /// replaced; any other file is left as it is.
    /// <para>
    /// Only encrypted values are written, but FilePerSecretCache refuses a folder or file anyone but
    /// administrators and the principals it trusts can modify: write them where the deployment can
    /// set that, or set it once they're written.
    /// </para>
    /// </summary>
    /// <param name="folderPath">The folder to write to, absolute or relative to the working directory</param>
    /// <exception cref="ArgumentNullException">folderPath is null</exception>
    /// <exception cref="ArgumentException">folderPath is empty</exception>
    /// <exception cref="InvalidOperationException">No pull has completed</exception>
    public void WriteProtectedSecretFiles(string folderPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(folderPath);
        if (!_pulled)
            throw new InvalidOperationException($"No secrets have been pulled: call {nameof(PullSecretsAsync)} first.");

        var folder = Path.GetFullPath(folderPath);
        Directory.CreateDirectory(folder);
        foreach (var (fileName, value) in _protectedSecrets)
            File.WriteAllText(Path.Join(folder, fileName), value);
    }

    /// <summary>Releases the writer's connection to the store.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases the store's connection when disposing is true.</summary>
    protected virtual void Dispose(bool disposing)
    {
    }

    /// <summary>
    /// Reads the one secret named name and encrypts the value each of <paramref name="requests"/>
    /// asks for into <paramref name="values"/>, by its file name - with <see cref="Protect"/> or
    /// <see cref="ProtectKeys(ReadOnlySpan{byte}, IReadOnlyList{SecretRequest}, IDictionary{string, string})"/> -
    /// or returns without doing so if it doesn't exist. Any other failure should throw. A request
    /// left out of values is reported missing.
    /// </summary>
    /// <param name="name">The store's name for the secret, before any '#'</param>
    /// <param name="requests">What to read from it: its whole value, a key, or both</param>
    /// <param name="values">Receives each value encrypted, by file name</param>
    /// <param name="cancellationToken">Cancels the read</param>
    protected abstract Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken);

    /// <summary>
    /// Encrypts a secret's whole value into values for each of <paramref name="requests"/> without a
    /// key, and, when it is a JSON object, the value of each requested key it holds (see
    /// <see cref="ProtectKeys(ReadOnlySpan{byte}, IReadOnlyList{SecretRequest}, IDictionary{string, string})"/>),
    /// by file name. An empty secret holds nothing. secret is the caller's to zero.
    /// </summary>
    /// <exception cref="InvalidDataException">The secret isn't UTF-8 text, or is a JSON object holding a key more than once</exception>
    protected void ProtectSecret(ReadOnlySpan<byte> secret, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values)
    {
        if (secret.IsEmpty)
            return;

        foreach (var request in requests)
        {
            if (request.Key is null)
                values.Add(request.FileName, Protect(secret, request.FileName));
        }

        if (requests.Any(r => r.Key is not null))
            ProtectKeys(secret, requests, values);
    }

    /// <summary>
    /// Decodes plaintext's UTF-8 into chars on the stack, or pinned when too large - never somewhere
    /// the GC can copy it - and encrypts them bound to fileName; the chars are zeroed. plaintext is
    /// the caller's to zero.
    /// </summary>
    /// <returns>The encrypted, formatted value</returns>
    /// <exception cref="InvalidDataException">plaintext isn't UTF-8 text, which the protector can't encrypt as it is</exception>
    protected string Protect(ReadOnlySpan<byte> plaintext, string fileName)
    {
        // Decoding would replace every invalid sequence, so a binary value would be written altered.
        if (!System.Text.Unicode.Utf8.IsValid(plaintext))
            throw new InvalidDataException("The secret isn't UTF-8 text: the pipeline protector encrypts text.");

        var charCount = Encoding.UTF8.GetCharCount(plaintext);
        Span<char> chars = charCount <= ArrayUtility.MaxStackChars
            ? stackalloc char[charCount]
            : ArrayUtility.AllocatePinned<char>(charCount);
        try
        {
            Encoding.UTF8.GetChars(plaintext, chars);
            return _protector.Encrypt(chars, fileName);
        }
        finally
        {
            ArrayUtility.ZeroMemory(chars);
        }
    }

    /// <summary>
    /// When json is exactly one JSON object, encrypts the value of each key of
    /// <paramref name="requests"/> it holds into values, as
    /// <see cref="ProtectKeys(ref Utf8JsonReader, IReadOnlyList{SecretRequest}, IDictionary{string, string})"/>
    /// does; anything else - plain text that merely starts like JSON included - holds no keys.
    /// </summary>
    /// <exception cref="InvalidDataException">The object holds a key more than once</exception>
    protected void ProtectKeys(ReadOnlySpan<byte> json, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values)
    {
        if (!IsObject(json))
            return;

        var reader = new Utf8JsonReader(json);
        reader.Read();
        ProtectKeys(ref reader, requests, values);
    }

    /// <summary>
    /// Encrypts the value of each key of <paramref name="requests"/> that the object reader is at the
    /// start of holds into values, by file name, leaving reader at its end: a string as its text, a
    /// number, true or false as its JSON text. A null, object, array or empty value is left out.
    /// Every value is unescaped into pinned memory, and zeroed once encrypted.
    /// </summary>
    /// <exception cref="InvalidDataException">The object holds a key more than once</exception>
    protected void ProtectKeys(ref Utf8JsonReader reader, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (NextProperty(ref reader))
        {
            // Not named: a key is part of a secret name, which is never logged.
            if (!seen.Add(reader.GetString()!))
                throw new InvalidDataException("The secret holds a key more than once.");

            var request = Find(ref reader, requests);
            reader.Read();
            if (request is not null && reader.TokenType is JsonTokenType.String or JsonTokenType.Number or JsonTokenType.True or JsonTokenType.False)
            {
                if (ProtectValue(ref reader, request.FileName) is { } value)
                    values.Add(request.FileName, value);
            }
            else
            {
                reader.Skip();
            }
        }
    }

    /// <summary>
    /// Reads the first token of a whole JSON document and says whether it starts an object. An empty
    /// or all-whitespace document has no first token, and the reader throws JsonException for it, so
    /// there is nothing else to check.
    /// </summary>
    protected static bool StartsObject(ref Utf8JsonReader reader)
    {
        reader.Read();
        return reader.TokenType == JsonTokenType.StartObject;
    }

    /// <summary>
    /// Moves reader to the next token and says whether it is a property name - false at the end of
    /// the object reader is in. Inside an object the reader can't run out of data without throwing
    /// JsonException, so there is nothing else to check.
    /// </summary>
    protected static bool NextProperty(ref Utf8JsonReader reader)
    {
        reader.Read();
        return reader.TokenType == JsonTokenType.PropertyName;
    }

    /// <summary>
    /// Unescapes the string reader is at into pinned memory (a number, true or false is copied as its
    /// JSON text) and encrypts it bound to fileName, zeroing it.
    /// </summary>
    /// <returns>The encrypted, formatted value; null if it is empty</returns>
    protected string? ProtectValue(ref Utf8JsonReader reader, string fileName)
    {
        // Unescaped, a string is never longer than it is escaped.
        var bytes = ArrayUtility.AllocatePinned<byte>(reader.ValueSpan.Length);
        try
        {
            int length;
            if (reader.TokenType == JsonTokenType.String)
            {
                length = reader.CopyString(bytes);
            }
            else
            {
                reader.ValueSpan.CopyTo(bytes);
                length = reader.ValueSpan.Length;
            }

            return length == 0 ? null : Protect(bytes.AsSpan(0, length), fileName);
        }
        finally
        {
            ArrayUtility.ZeroMemory(bytes);
        }
    }

    private void AddRequests(IList<string> secretNames, Func<string, bool> isValidSecretName, string? defaultKey)
    {
        if (secretNames.Count == 0)
            throw new ArgumentException("No secrets are named.", nameof(secretNames));

        var fileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var secretName in secretNames)
        {
            if (secretName is null)
                throw new ArgumentException("A secret name is null.", nameof(secretNames));

            var separator = secretName.IndexOf(KeySeparator);
            var name = separator < 0 ? secretName : secretName[..separator];
            var key = separator < 0 ? defaultKey : secretName[(separator + 1)..];
            var fileName = GetFileName(secretName);
            if (name.Length == 0 || !isValidSecretName(name) || key is { Length: 0 })
                throw new ArgumentException($"'{secretName}' isn't a secret name this store can hold, with a key after '{KeySeparator}' if any.", nameof(secretNames));
            if (!FilePerSecretCache.IsValidName(fileName))
                throw new ArgumentException($"'{secretName}' can't be written as a file: its file name '{fileName}' must be 1-{FilePerSecretCache.MaxNameLength} ASCII letters, digits, '-', '_' and '.', not starting with '.'.", nameof(secretNames));
            if (!fileNames.Add(fileName))
                throw new ArgumentException($"'{secretName}' would be written as '{fileName}', as another secret named is.", nameof(secretNames));

            if (!_requests.TryGetValue(name, out var requests))
                _requests.Add(name, requests = []);
            requests.Add(new SecretRequest(secretName, key, fileName));
        }
    }

    // One JSON object and nothing after it but whitespace.
    private static bool IsObject(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(json);
        try
        {
            if (!StartsObject(ref reader))
                return false;

            reader.Skip();
            return !reader.Read();
        }
        catch (JsonException)
        {
            return false;
        }
    }

    // The request for the key reader is at the name of, if any.
    private static SecretRequest? Find(ref Utf8JsonReader reader, IReadOnlyList<SecretRequest> requests)
    {
        foreach (var request in requests)
        {
            if (request.Key is not null && reader.ValueTextEquals(request.Key))
                return request;
        }

        return null;
    }
}

/// <summary>One secret name a <see cref="SecretPipelineWriter"/> pulls: what to read, and the file it is written as.</summary>
/// <param name="SecretName">The name as it was given, key and all</param>
/// <param name="Key">The key to read; null for the secret's whole value</param>
/// <param name="FileName">The file it is written as, and the name its value is bound to</param>
public sealed record SecretRequest(string SecretName, string? Key, string FileName);
