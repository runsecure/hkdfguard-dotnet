using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HkdfGuard.Integration.HashiCorpVault.Generator;

/// <summary>
/// Generates HkdfGuard.Integration.HashiCorpVault's typed API from Vault's OpenAPI document: what
/// vault-client-go's generate/templates produce through openapi-generator, in C#. One class per tag
/// (AuthApi, IdentityApi, SecretsApi, SystemApi) with one method per operation, the VaultClient
/// properties that reach them, and one model per schema in the Schema namespace.
/// <para>
/// As vault-client-go, operations whose id ends in 2, 3 or 4 (duplicates Vault's spec lists for
/// alternative paths) or starts EnterpriseStub are left out, and so are their schemas.
/// </para>
/// <para>
/// Settings can narrow that further: an "include" list of regular expressions, matched against each
/// operation's method name without its Async suffix (KvV2Read, AppRoleLogin). Only operations one of
/// them matches are generated, only the schemas those operations use (directly, or through another
/// schema), and only the classes that still have an operation. Each expression must match at least
/// one operation, so a typo or an operation the spec has dropped is noticed rather than silently
/// generating less.
/// </para>
/// </summary>
public static partial class VaultClientGenerator
{
    private const string Namespace = "HkdfGuard.Integration.HashiCorpVault";

    // The tags in the order vault-client-go lists them, and what each class holds.
    private static readonly (string Tag, string Summary)[] KnownTags =
    [
        ("auth", "Vault's auth methods and tokens."),
        ("identity", "Vault's identity store: entities, groups, aliases, OIDC and MFA."),
        ("secrets", "Vault's secrets engines."),
        ("system", "Vault's system backend (sys/)."),
    ];

    // Names generated code uses itself, so a parameter can't take them.
    private static readonly HashSet<string> ReservedParameterNames = ["options", "cancellationToken", "request", "requestPath", "query"];

    /// <summary>
    /// The generated files for the OpenAPI document openApiJson, by path relative to the output
    /// directory ('/'-separated), each with '\n' line endings.
    /// </summary>
    /// <param name="openApiJson">Vault's OpenAPI document.</param>
    /// <param name="settingsJson">The generator's settings - {"include": ["^KvV2", ...]} - or null to
    /// generate every operation vault-client-go does.</param>
    /// <exception cref="InvalidDataException">The document uses something the generator doesn't
    /// handle, the settings aren't valid, or an include pattern matches no operation</exception>
    public static IReadOnlyDictionary<string, string> Generate(string openApiJson, string? settingsJson = null)
    {
        var include = ReadInclude(settingsJson);
        using var document = JsonDocument.Parse(openApiJson);
        var spec = OpenApiSpec.Read(document.RootElement);

        var operations = spec.Operations.Where(o => !IsExcluded(CSharp.Pascal(o.Id))).ToList();
        if (include is not null)
        {
            foreach (var pattern in include.Where(p => !operations.Any(o => p.IsMatch(CSharp.Pascal(o.Id)))))
                throw new InvalidDataException($"The include pattern '{pattern}' matches no operation.");
            operations = [.. operations.Where(o => include.Any(p => p.IsMatch(CSharp.Pascal(o.Id))))];
        }

        var schemaNames = spec.Schemas.Keys.Where(name => !IsExcludedSchema(name)).Order(StringComparer.Ordinal).ToList();

        // Which operations send or return each schema, for its summary and how it's typed.
        var requestUses = new Dictionary<string, List<OpenApiOperation>>(StringComparer.Ordinal);
        var responseUses = new Dictionary<string, List<OpenApiOperation>>(StringComparer.Ordinal);
        foreach (var operation in operations)
        {
            if (operation.RequestSchema is { } request && OpenApiSpec.RefName(request) is { } requestName)
                Use(requestUses, requestName, operation);
            if (operation.ResponseSchema is { } response && OpenApiSpec.RefName(response) is { } responseName)
                Use(responseUses, responseName, operation);
        }

        foreach (var used in requestUses.Keys.Concat(responseUses.Keys))
        {
            if (!schemaNames.Contains(used))
                throw new InvalidDataException($"Schema {used} is used by a generated operation but is missing or excluded.");
        }

        // Narrowed, only the schemas the operations use are generated: those they send or return, and
        // those those refer to.
        if (include is not null)
            schemaNames = [.. Referenced(spec, requestUses.Keys.Concat(responseUses.Keys)).Order(StringComparer.Ordinal)];

        foreach (var clash in schemaNames.GroupBy(CSharp.Pascal).Where(g => g.Count() > 1))
            throw new InvalidDataException($"Schemas {string.Join(", ", clash)} would all be named {clash.Key}.");

        var files = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var tags = OrderTags(operations.Select(o => o.Tag).Distinct());
        files["VaultClient.Apis.g.cs"] = ClientFile(spec, tags);
        foreach (var tag in tags)
            files[$"{ApiClass(tag)}.g.cs"] = ApiFile(spec, tag, operations.Where(o => o.Tag == tag).ToList());
        foreach (var name in schemaNames)
        {
            files[$"Schema/{CSharp.Pascal(name)}.g.cs"] = ModelFile(spec, name, spec.Schemas[name],
                requestUses.GetValueOrDefault(name) ?? [], responseUses.GetValueOrDefault(name) ?? []);
        }

        // The templates' raw string literals take this file's line endings, which a checkout can change.
        foreach (var path in files.Keys.ToList())
            files[path] = files[path].ReplaceLineEndings("\n");

        return files;
    }

    // The settings' include patterns; null without settings or an include list.
    private static List<Regex>? ReadInclude(string? settingsJson)
    {
        if (settingsJson is null)
            return null;

        try
        {
            using var settings = JsonDocument.Parse(settingsJson);
            if (settings.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("The generator's settings must be a JSON object.");

            List<Regex>? include = null;
            foreach (var setting in settings.RootElement.EnumerateObject())
            {
                switch (setting.Name)
                {
                    case "description":
                        break;
                    case "include" when setting.Value.ValueKind == JsonValueKind.Array && setting.Value.GetArrayLength() > 0
                                        && setting.Value.EnumerateArray().All(p => p.ValueKind == JsonValueKind.String):
                        include = [.. setting.Value.EnumerateArray().Select(p => new Regex(p.GetString()!, RegexOptions.CultureInvariant))];
                        break;
                    case "include":
                        throw new InvalidDataException("The generator's \"include\" setting must be a non-empty array of regular expressions.");
                    default:
                        throw new InvalidDataException($"Unknown generator setting '{setting.Name}': only \"include\" and \"description\" are.");
                }
            }

            return include;
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"The generator's settings aren't JSON: {e.Message}", e);
        }
        catch (ArgumentException e)
        {
            throw new InvalidDataException($"An include pattern isn't a regular expression: {e.Message}", e);
        }
    }

    // roots, and every schema they refer to, however indirectly.
    private static HashSet<string> Referenced(OpenApiSpec spec, IEnumerable<string> roots)
    {
        var found = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>(roots);
        while (pending.TryPop(out var name))
        {
            if (!found.Add(name))
                continue;
            if (!spec.Schemas.TryGetValue(name, out var schema))
                throw new InvalidDataException($"Schema {name} is referred to but missing.");
            foreach (var reference in References(schema))
                pending.Push(reference);
        }

        return found;
    }

    private static IEnumerable<string> References(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object when OpenApiSpec.RefName(element) is { } reference => [reference],
        JsonValueKind.Object => element.EnumerateObject().SelectMany(p => References(p.Value)),
        JsonValueKind.Array => element.EnumerateArray().SelectMany(References),
        _ => [],
    };

    // vault-client-go's partial_filter_operation.
    private static bool IsExcluded(string operationName)
        => operationName.EndsWith('2') || operationName.EndsWith('3') || operationName.EndsWith('4')
           || operationName.StartsWith("EnterpriseStub", StringComparison.Ordinal);

    // vault-client-go's .openapi-generator-ignore: model_*2_request.go, ..., model_enterprise_stub*.
    private static bool IsExcludedSchema(string name) => ExcludedSchema().IsMatch(name);

    [GeneratedRegex("^EnterpriseStub|[234](Request|Response)$")]
    private static partial Regex ExcludedSchema();

    private static void Use(Dictionary<string, List<OpenApiOperation>> uses, string schema, OpenApiOperation operation)
    {
        if (!uses.TryGetValue(schema, out var list))
            uses[schema] = list = [];
        list.Add(operation);
    }

    private static List<string> OrderTags(IEnumerable<string> tags)
    {
        var all = tags.ToHashSet(StringComparer.Ordinal);
        return KnownTags.Select(k => k.Tag).Where(all.Contains)
            .Concat(all.Where(t => !KnownTags.Any(k => k.Tag == t)).Order(StringComparer.Ordinal))
            .ToList();
    }

    private static string ApiClass(string tag) => CSharp.Pascal(tag) + "Api";

    private static string MethodName(OpenApiOperation operation) => CSharp.Pascal(operation.Id) + "Async";

    private static string TagSummary(string tag) => KnownTags.FirstOrDefault(k => k.Tag == tag).Summary ?? $"Vault's \"{tag}\" endpoints.";

    private static string Header(OpenApiSpec spec) =>
        $"""
        // <auto-generated>
        //     Generated by HkdfGuard.Integration.HashiCorpVault.Generator from openapi.json (HashiCorp Vault API {spec.ApiVersion}).
        //     Don't edit: change the generator or the spec, and regenerate (docs/how-to/use-hashicorp-vault-client.md).
        // </auto-generated>

        #nullable enable

        """;

    private static string ClientFile(OpenApiSpec spec, IReadOnlyList<string> tags)
    {
        var code = new StringBuilder(Header(spec));
        code.Append($$"""

            namespace {{Namespace}};

            public sealed partial class VaultClient
            {
            """).Append('\n');

        for (var i = 0; i < tags.Count; i++)
        {
            var tag = tags[i];
            var type = ApiClass(tag);
            var field = "_" + char.ToLowerInvariant(CSharp.Pascal(tag)[0]) + CSharp.Pascal(tag)[1..];
            if (i > 0)
                code.Append('\n');
            code.Append($$"""
                    private {{type}}? {{field}};

                    /// <summary>{{CSharp.Xml(TagSummary(tag))}}</summary>
                    public {{type}} {{CSharp.Pascal(tag)}} => {{field}} ??= new {{type}}(this);

                """);
        }

        return code.Append("}\n").ToString();
    }

    private static string ApiFile(OpenApiSpec spec, string tag, IReadOnlyList<OpenApiOperation> operations)
    {
        var type = ApiClass(tag);
        var code = new StringBuilder(Header(spec));
        code.Append($$"""

            using System.Text.Json;

            namespace {{Namespace}};

            /// <summary>{{CSharp.Xml(TagSummary(tag))}} Reached through <see cref="VaultClient.{{CSharp.Pascal(tag)}}"/>.</summary>
            public sealed partial class {{type}}
            {
                private readonly VaultClient _client;

                internal {{type}}(VaultClient client) => _client = client;

            """);

        foreach (var operation in operations)
            code.Append('\n').Append(Method(spec, operation));

        return code.Append("}\n").ToString();
    }

    private static string Method(OpenApiSpec spec, OpenApiOperation operation)
    {
        var mount = operation.Parameters.FirstOrDefault(p => p.IsMountPath);
        var pathParameters = operation.Parameters.Where(p => p.In == "path" && !p.IsMountPath).ToList();
        var queryParameters = operation.Parameters.Where(p => p.In == "query" && p.Name != "list").ToList();
        var lists = operation.Parameters.Any(p => p.In == "query" && p.Name == "list");
        foreach (var other in operation.Parameters.Where(p => p.In is not ("path" or "query")))
            throw new InvalidDataException($"Operation {operation.Id} has a {other.In} parameter, {other.Name}; only path and query parameters are handled.");

        // C# names for the parameters, kept clear of each other and of the generated code's own.
        var names = new Dictionary<OpenApiParameter, string>();
        foreach (var parameter in pathParameters.Concat(queryParameters))
        {
            var name = CSharp.Camel(parameter.Name);
            while (ReservedParameterNames.Contains(name.TrimStart('@')) || names.ContainsValue(name))
                name += "Parameter";
            names[parameter] = name;
        }

        var responseType = operation.ResponseSchema is { } response && OpenApiSpec.RefName(response) is { } responseName
            ? "Schema." + CSharp.Pascal(responseName)
            : "Dictionary<string, JsonElement>";
        string? requestType = operation.RequestSchema is not { } request ? null
            : OpenApiSpec.RefName(request) is { } requestName ? "Schema." + CSharp.Pascal(requestName)
            : IsFreeForm(request) ? "IReadOnlyDictionary<string, object?>"
            : throw new InvalidDataException($"Operation {operation.Id}'s request body is neither a $ref nor a free-form object.");

        var signature = new List<string>();
        signature.AddRange(pathParameters.Select(p => $"{ParameterType(operation, p)} {names[p]}"));
        if (requestType is not null)
            signature.Add($"{requestType} request");
        signature.AddRange(queryParameters.Select(p => $"{ParameterType(operation, p)} {names[p]}"));
        signature.Add("VaultRequestOptions? options = null");
        signature.Add("CancellationToken cancellationToken = default");

        var code = new StringBuilder();
        var description = operation.Description;
        var summary = operation.Summary ?? description ?? operation.PathDescription;
        if (operation.Summary is null)
            description = null;
        code.Append($"    /// <summary>{CSharp.Xml(summary ?? $"{operation.Method} /v1{operation.Path}.")}</summary>\n");

        var remarks = new StringBuilder($"<c>{CSharp.Xml($"{operation.Method} /v1{operation.Path}")}</c>");
        if (lists)
            remarks.Append(" with <c>list=true</c>");
        remarks.Append('.');
        if (description is not null)
            remarks.Append(' ').Append(CSharp.Xml(description));
        if (operation.Unauthenticated)
            remarks.Append(" Needs no token.");
        if (operation.Sudo)
            remarks.Append(" Needs a token with sudo capability.");
        code.Append($"    /// <remarks>{remarks}</remarks>\n");

        foreach (var parameter in pathParameters.Concat(queryParameters))
            code.Append($"    /// <param name=\"{names[parameter].TrimStart('@')}\">{ParameterDoc(parameter)}</param>\n");
        if (requestType is not null)
            code.Append("    /// <param name=\"request\">The request body.</param>\n");
        if (mount is not null)
        {
            var defaultMount = MountDefault(operation, mount);
            code.Append($"    /// <param name=\"options\">Settings for this request; <see cref=\"VaultRequestOptions.MountPath\"/> is where the {(operation.Tag == "auth" ? "auth method" : "secrets engine")} is mounted, \"{CSharp.Xml(defaultMount)}\" by default.</param>\n");
        }
        else
            code.Append("    /// <param name=\"options\">Settings for this request.</param>\n");
        code.Append("    /// <param name=\"cancellationToken\">Cancels the request.</param>\n");
        code.Append("    /// <returns>Vault's response; null if it has no body.</returns>\n");
        code.Append("    /// <exception cref=\"VaultResponseException\">Vault refused the request</exception>\n");
        if (operation.Deprecated)
            code.Append("    [Obsolete(\"Deprecated by Vault.\")]\n");

        code.Append($"    public Task<VaultResponse<{responseType}>?> {MethodName(operation)}({string.Join(", ", signature)})\n");
        code.Append("    {\n");

        foreach (var parameter in pathParameters.Concat(queryParameters).Where(p => ParameterType(operation, p) == "string"))
            code.Append($"        ArgumentNullException.ThrowIfNull({names[parameter]});\n");
        if (requestType is not null)
            code.Append("        ArgumentNullException.ThrowIfNull(request);\n");

        code.Append($"        var requestPath = {PathExpression(operation, mount, names)};\n");
        code.Append("        var query = VaultClient.QueryParameters(options);\n");
        if (lists)
            code.Append("        query.Add(new(\"list\", \"true\"));\n");
        foreach (var parameter in queryParameters)
            code.Append($"        query.Add(new({CSharp.Literal(parameter.Name)}, VaultClient.FormatQueryValue({names[parameter]})));\n");

        code.Append($"        return _client.SendAsync<{responseType}>(HttpMethod.{CSharp.Pascal(operation.Method.ToLowerInvariant())}, requestPath, {(requestType is null ? "null" : "request")}, query, options, cancellationToken);\n");
        code.Append("    }\n");
        return code.ToString();
    }

    // "/v1" + the path, its placeholders filled in - each escaped as one segment, the mount path with
    // options' or the default - as vault-client-go's strings.Replace(..., url.PathEscape(...)).
    private static string PathExpression(OpenApiOperation operation, OpenApiParameter? mount, IReadOnlyDictionary<OpenApiParameter, string> names)
    {
        var parts = new List<string>();
        var literal = new StringBuilder("/v1");
        foreach (Match match in Placeholder().Matches(operation.Path + "{}"))
        {
            literal.Append(match.Groups[1].Value);
            var name = match.Groups[2].Value;
            if (name.Length == 0)
                break;

            if (literal.Length > 0)
                parts.Add(CSharp.Literal(literal.ToString()));
            literal.Clear();

            if (mount is not null && name == mount.Name)
                parts.Add($"VaultClient.EscapePathSegment(VaultClient.MountPathOr(options, {CSharp.Literal(MountDefault(operation, mount))}))");
            else if (names.FirstOrDefault(n => n.Key.In == "path" && n.Key.Name == name).Value is { } parameter)
                parts.Add($"VaultClient.EscapePathSegment({parameter})");
            else
                throw new InvalidDataException($"Operation {operation.Id}'s path {operation.Path} has a placeholder {{{name}}} with no parameter.");
        }

        if (literal.Length > 0)
            parts.Add(CSharp.Literal(literal.ToString()));
        return string.Join(" + ", parts);
    }

    [GeneratedRegex(@"([^{]*)\{([^}]*)\}")]
    private static partial Regex Placeholder();

    private static string MountDefault(OpenApiOperation operation, OpenApiParameter mount)
        => mount.Schema.ValueKind == JsonValueKind.Object && OpenApiSpec.String(mount.Schema, "default") is { Length: > 0 } value
            ? value
            : throw new InvalidDataException($"Operation {operation.Id}'s mount path parameter {mount.Name} has no default.");

    private static string ParameterType(OpenApiOperation operation, OpenApiParameter parameter)
    {
        var type = parameter.Schema.ValueKind == JsonValueKind.Object ? OpenApiSpec.String(parameter.Schema, "type") : null;
        return type switch
        {
            "string" => "string",
            "integer" => OpenApiSpec.String(parameter.Schema, "format") == "int64" ? "long" : "int",
            "boolean" => "bool",
            _ => throw new InvalidDataException($"Operation {operation.Id}'s parameter {parameter.Name} is a {type ?? "typeless"}; only string, integer and boolean are handled."),
        };
    }

    private static string ParameterDoc(OpenApiParameter parameter)
    {
        var doc = new StringBuilder(CSharp.Xml(parameter.Description ?? $"The {parameter.Name} {parameter.In} parameter."));
        // ParameterType has already refused a parameter without a schema.
        if (parameter.Schema.TryGetProperty("default", out var defaultValue))
            doc.Append(" Vault's default: ").Append(CSharp.Xml(defaultValue.GetRawText())).Append('.');
        return doc.ToString();
    }

    private static bool IsFreeForm(JsonElement schema)
        => OpenApiSpec.String(schema, "type") == "object" && !schema.TryGetProperty("properties", out _);

    private static string ModelFile(OpenApiSpec spec, string name, JsonElement schema, IReadOnlyList<OpenApiOperation> sentBy, IReadOnlyList<OpenApiOperation> returnedBy)
    {
        if (OpenApiSpec.String(schema, "type") is not "object")
            throw new InvalidDataException($"Schema {name} isn't an object; only object schemas are handled.");

        // Sent, it's written: free-form values are any object, and required members are required.
        // Returned, it's read: free-form values are JSON, and nothing is relied on being there.
        var isRequest = sentBy.Count > 0 || (returnedBy.Count == 0 && name.EndsWith("Request", StringComparison.Ordinal));
        // As openapi-generator names models: Vault's spec has a few with underscores.
        var type = CSharp.Pascal(name);
        var required = schema.TryGetProperty("required", out var r) ? r.EnumerateArray().Select(e => e.GetString()!).ToHashSet() : [];

        var code = new StringBuilder(Header(spec));
        code.Append($$"""

            using System.Text.Json;
            using System.Text.Json.Serialization;

            namespace {{Namespace}}.Schema;

            /// <summary>{{ModelSummary(name, schema, sentBy, returnedBy)}}</summary>
            public sealed class {{type}}
            {

            """);

        var used = new HashSet<string>(StringComparer.Ordinal) { type };
        var first = true;
        var properties = schema.TryGetProperty("properties", out var p) ? p.EnumerateObject().ToList() : [];
        foreach (var property in properties)
        {
            var propertyName = CSharp.Pascal(property.Name);
            if (propertyName == type)
                propertyName += "Value";
            var unique = propertyName;
            for (var i = 2; !used.Add(unique); i++)
                unique = propertyName + i;

            var isRequired = isRequest && required.Contains(property.Name);
            var propertyType = TypeOf(name + "." + property.Name, property.Value, isRequest);
            if (!isRequired)
                propertyType += "?";

            if (!first)
                code.Append('\n');
            first = false;
            AppendPropertyDoc(code, property.Value);
            code.Append($"    [JsonPropertyName({CSharp.Literal(property.Name)})]\n");
            if (OpenApiSpec.Bool(property.Value, "deprecated"))
                code.Append("    [Obsolete(\"Deprecated by Vault.\")]\n");
            code.Append($"    public {(isRequired ? "required " : "")}{propertyType} {unique} {{ get; set; }}\n");
        }

        return code.Append("}\n").ToString();
    }

    private static string ModelSummary(string name, JsonElement schema, IReadOnlyList<OpenApiOperation> sentBy, IReadOnlyList<OpenApiOperation> returnedBy)
    {
        if (OpenApiSpec.String(schema, "description") is { Length: > 0 } description)
            return CSharp.Xml(description);

        static string Methods(IEnumerable<OpenApiOperation> operations)
            => string.Join(", ", operations.Select(o => $"<see cref=\"{Namespace}.{ApiClass(o.Tag)}.{MethodName(o)}\"/>"));

        if (sentBy.Count > 0)
            return $"The request body of {Methods(sentBy)}.";
        if (returnedBy.Count > 0)
            return $"The data {Methods(returnedBy)} return{(returnedBy.Count == 1 ? "s" : "")}.";
        return $"The {CSharp.Xml(name)} schema.";
    }

    private static void AppendPropertyDoc(StringBuilder code, JsonElement property)
    {
        code.Append($"    /// <summary>{CSharp.Xml(OpenApiSpec.String(property, "description") ?? "Not described by Vault's spec.")}</summary>\n");

        var remarks = new List<string>();
        if (OpenApiSpec.String(property, "format") == "duration")
            remarks.Add("A duration: seconds, or a Go duration such as \"24h\".");
        if (property.TryGetProperty("enum", out var values) && values.ValueKind == JsonValueKind.Array)
            remarks.Add("One of: " + string.Join(", ", values.EnumerateArray().Select(v => v.GetRawText())) + ".");
        if (property.TryGetProperty("default", out var defaultValue))
            remarks.Add("Vault's default: " + defaultValue.GetRawText() + ".");
        if (remarks.Count > 0)
            code.Append($"    /// <remarks>{CSharp.Xml(string.Join(" ", remarks))}</remarks>\n");
    }

    // The C# type a property's schema maps to, without nullability: vault-client-go's type mapping,
    // but with free-form values as object (sent) or JsonElement (returned) where Go has interface{}.
    private static string TypeOf(string where, JsonElement schema, bool isRequest)
    {
        if (OpenApiSpec.RefName(schema) is { } reference)
            return CSharp.Pascal(reference);

        return OpenApiSpec.String(schema, "type") switch
        {
            "string" => OpenApiSpec.String(schema, "format") == "date-time" ? "DateTimeOffset" : "string",
            "integer" => OpenApiSpec.String(schema, "format") == "int64" ? "long" : "int",
            "number" => "double",
            "boolean" => "bool",
            "array" => schema.TryGetProperty("items", out var items)
                ? $"List<{TypeOf(where, items, isRequest)}>"
                : isRequest ? "List<object?>" : "List<JsonElement>",
            "object" when schema.TryGetProperty("properties", out _)
                => throw new InvalidDataException($"{where} is an object with properties of its own; only free-form objects are handled inline."),
            "object" when schema.TryGetProperty("additionalProperties", out var values) && values.ValueKind == JsonValueKind.Object
                => $"Dictionary<string, {TypeOf(where, values, isRequest)}>",
            "object" => isRequest ? "Dictionary<string, object?>" : "Dictionary<string, JsonElement>",
            null => isRequest ? "object" : "JsonElement",
            var other => throw new InvalidDataException($"{where} has type '{other}', which the generator doesn't handle."),
        };
    }
}
