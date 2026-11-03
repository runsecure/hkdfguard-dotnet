using System.Net;
using System.Text;
using System.Text.Json;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// Vault answered with a status outside 200-399 (vault-client-go's ResponseError). A request that
/// gets no answer - Vault unreachable, say - fails with the HttpRequestException HttpClient threw.
/// </summary>
public sealed class VaultResponseException : HttpRequestException
{
    internal VaultResponseException(string message, HttpStatusCode statusCode, IReadOnlyList<string> errors, byte[]? rawResponseBytes,
        HttpMethod requestMethod, Uri requestUri)
        : base(message, null, statusCode)
    {
        Errors = errors;
        RawResponseBytes = rawResponseBytes;
        RequestMethod = requestMethod;
        RequestUri = requestUri;
    }

    /// <summary>The errors Vault listed in its response; empty if it listed none.</summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>The response body, when it held no errors to list.</summary>
    public byte[]? RawResponseBytes { get; }

    /// <summary>The method of the request Vault refused.</summary>
    public HttpMethod RequestMethod { get; }

    /// <summary>The URI of the request Vault refused.</summary>
    public Uri RequestUri { get; }

    // The errors body lists, as {"errors":[...]} or {"error":"..."}; failing those, the body itself.
    internal static VaultResponseException Create(HttpResponseMessage response, ReadOnlySpan<byte> body, HttpMethod method, Uri uri)
    {
        var status = response.StatusCode;
        var reason = string.IsNullOrEmpty(response.ReasonPhrase) ? status.ToString() : response.ReasonPhrase;
        var errors = ReadErrors(body);
        if (errors is { Count: > 0 })
            return new VaultResponseException($"{(int)status} {reason}: {string.Join(", ", errors)}", status, errors, null, method, uri);

        var raw = body.IsEmpty ? null : body.ToArray();
        var message = raw is null ? $"{(int)status} {reason}" : $"{(int)status} {reason}: {Encoding.UTF8.GetString(raw)}";
        return new VaultResponseException(message, status, [], raw, method, uri);
    }

    private static List<string>? ReadErrors(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
            return null;

        try
        {
            // Malformed JSON throws rather than ending early: the reader is given the whole body.
            var reader = new Utf8JsonReader(body);
            reader.Read();
            if (reader.TokenType != JsonTokenType.StartObject)
                return null;

            List<string>? errors = null;
            string? error = null;
            for (reader.Read(); reader.TokenType == JsonTokenType.PropertyName; reader.Read())
            {
                if (reader.ValueTextEquals("errors"u8))
                {
                    reader.Read();
                    errors = ReadStrings(ref reader);
                }
                else if (reader.ValueTextEquals("error"u8))
                {
                    reader.Read();
                    if (reader.TokenType == JsonTokenType.String)
                        error = reader.GetString();
                    else
                        reader.Skip();
                }
                else
                {
                    reader.Read();
                    reader.Skip();
                }
            }

            return errors is { Count: > 0 } ? errors : string.IsNullOrEmpty(error) ? null : [error];
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // A JSON array of strings; null if it is anything else.
    private static List<string>? ReadStrings(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            reader.Skip();
            return null;
        }

        var strings = new List<string>();
        var allStrings = true;
        for (reader.Read(); reader.TokenType != JsonTokenType.EndArray; reader.Read())
        {
            if (reader.TokenType == JsonTokenType.String)
                strings.Add(reader.GetString()!);
            else
            {
                allStrings = false;
                reader.Skip();
            }
        }

        return allStrings ? strings : null;
    }
}

/// <summary>
/// Vault answered with a redirect (301, 302 or 307) the client wouldn't follow: redirects are off
/// (<see cref="VaultClientOptions.FollowRedirects"/>), it was the request's second, it would go from
/// https to http, or its location couldn't be read. vault-client-go's RedirectError.
/// </summary>
public sealed class VaultRedirectException : HttpRequestException
{
    internal VaultRedirectException(HttpStatusCode statusCode, string reason, Uri? redirectLocation, HttpMethod requestMethod, Uri requestUri)
        : base($"{(int)statusCode}: redirect error: {reason}", null, statusCode)
    {
        Reason = reason;
        RedirectLocation = redirectLocation;
        RequestMethod = requestMethod;
        RequestUri = requestUri;
    }

    /// <summary>Why the redirect wasn't followed.</summary>
    public string Reason { get; }

    /// <summary>Where the redirect pointed, if that could be read.</summary>
    public Uri? RedirectLocation { get; }

    /// <summary>The method of the redirected request.</summary>
    public HttpMethod RequestMethod { get; }

    /// <summary>The URI of the redirected request.</summary>
    public Uri RequestUri { get; }
}
