using System.Text.Json;

namespace HkdfGuard.Integration.HashiCorpVault.Generator;

/// <summary>What the generator needs from Vault's OpenAPI document, in document order.</summary>
internal sealed record OpenApiSpec(string ApiVersion, IReadOnlyList<OpenApiOperation> Operations, IReadOnlyDictionary<string, JsonElement> Schemas)
{
    private static readonly string[] Methods = ["get", "put", "post", "delete", "patch"];

    /// <summary>Reads the document root; its elements must outlive the spec.</summary>
    /// <exception cref="InvalidDataException">An operation lacks an id or tag, or uses something the generator doesn't handle</exception>
    public static OpenApiSpec Read(JsonElement root)
    {
        var version = root.GetProperty("info").GetProperty("version").GetString() ?? "";
        var operations = new List<OpenApiOperation>();
        foreach (var path in root.GetProperty("paths").EnumerateObject())
        {
            var item = path.Value;
            var shared = Parameters(item);
            foreach (var member in item.EnumerateObject())
            {
                if (!Methods.Contains(member.Name))
                    continue;

                var operation = member.Value;
                var id = String(operation, "operationId") ?? throw new InvalidDataException($"{member.Name} {path.Name} has no operationId.");
                var tags = operation.TryGetProperty("tags", out var t) ? t.EnumerateArray().Select(e => e.GetString()!).ToArray() : [];
                if (tags.Length != 1)
                    throw new InvalidDataException($"Operation {id} has {tags.Length} tags; the generator expects exactly one.");

                // Operation parameters first, then the path's that it doesn't override - as openapi-generator orders them.
                var own = Parameters(operation);
                var parameters = own.Concat(shared.Where(s => !own.Any(o => o.Name == s.Name && o.In == s.In))).ToList();

                operations.Add(new OpenApiOperation(
                    id, tags[0], member.Name.ToUpperInvariant(), path.Name,
                    String(operation, "summary"), String(operation, "description"), String(item, "description"),
                    Bool(operation, "deprecated"),
                    Bool(operation, "x-vault-unauthenticated") || Bool(item, "x-vault-unauthenticated"),
                    Bool(operation, "x-vault-sudo") || Bool(item, "x-vault-sudo"),
                    parameters, RequestSchema(id, operation), ResponseSchema(operation)));
            }
        }

        var schemas = root.GetProperty("components").GetProperty("schemas").EnumerateObject().ToDictionary(s => s.Name, s => s.Value, StringComparer.Ordinal);
        return new OpenApiSpec(version, operations, schemas);
    }

    public static string? String(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    public static bool Bool(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;

    /// <summary>The schema a $ref names, without its "#/components/schemas/" prefix; null if element isn't a $ref.</summary>
    public static string? RefName(JsonElement schema)
    {
        if (String(schema, "$ref") is not { } reference)
            return null;

        const string prefix = "#/components/schemas/";
        return reference.StartsWith(prefix, StringComparison.Ordinal)
            ? reference[prefix.Length..]
            : throw new InvalidDataException($"Unsupported $ref '{reference}': only {prefix}... is handled.");
    }

    private static List<OpenApiParameter> Parameters(JsonElement element)
    {
        if (!element.TryGetProperty("parameters", out var parameters))
            return [];

        return parameters.EnumerateArray().Select(p => new OpenApiParameter(
            String(p, "name")!, String(p, "in")!, String(p, "description"),
            p.TryGetProperty("schema", out var schema) ? schema : default,
            Bool(p, "required"))).ToList();
    }

    private static JsonElement? RequestSchema(string id, JsonElement operation)
    {
        if (!operation.TryGetProperty("requestBody", out var body))
            return null;

        var content = body.GetProperty("content");
        if (!content.TryGetProperty("application/json", out var json) || content.EnumerateObject().Count() != 1)
            throw new InvalidDataException($"Operation {id} has a request body that isn't only application/json.");
        return json.GetProperty("schema");
    }

    // The first 2xx response's JSON schema, if it has one.
    private static JsonElement? ResponseSchema(JsonElement operation)
    {
        if (!operation.TryGetProperty("responses", out var responses))
            return null;

        foreach (var response in responses.EnumerateObject())
        {
            if (!response.Name.StartsWith('2'))
                continue;
            if (response.Value.TryGetProperty("content", out var content) && content.TryGetProperty("application/json", out var json)
                && json.TryGetProperty("schema", out var schema))
                return schema;
            return null;
        }

        return null;
    }
}

/// <summary>One endpoint and method.</summary>
internal sealed record OpenApiOperation(
    string Id, string Tag, string Method, string Path, string? Summary, string? Description, string? PathDescription,
    bool Deprecated, bool Unauthenticated, bool Sudo, IReadOnlyList<OpenApiParameter> Parameters,
    JsonElement? RequestSchema, JsonElement? ResponseSchema);

/// <summary>A path or query parameter.</summary>
internal sealed record OpenApiParameter(string Name, string In, string? Description, JsonElement Schema, bool Required)
{
    /// <summary>Whether this is the path parameter where the auth method or secrets engine is mounted.</summary>
    public bool IsMountPath => In == "path" && Name.EndsWith("_mount_path", StringComparison.Ordinal);
}
