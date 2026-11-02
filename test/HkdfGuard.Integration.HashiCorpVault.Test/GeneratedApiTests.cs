using System.Net;
using HkdfGuard.Integration.HashiCorpVault.Generator;
using HkdfGuard.Integration.HashiCorpVault.Schema;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>
/// The generated API: that the checked-in code is what the generator makes of the checked-in spec,
/// that its methods send what vault-client-go's would, and how the generator handles a spec.
/// </summary>
public class GeneratedApiTests
{
    private static readonly string Library = Path.Combine(RepositoryRoot(), "src", "HkdfGuard.Integration.HashiCorpVault");

    [Fact]
    public void TheGeneratedCode_IsWhatTheSpecGenerates()
    {
        var expected = VaultClientGenerator.Generate(File.ReadAllText(Path.Combine(Library, "openapi.json")),
            File.ReadAllText(Path.Combine(Library, GeneratorCommand.SettingsFileName)));
        var generated = Path.Combine(Library, "Generated");
        var onDisk = Directory.EnumerateFiles(generated, "*.g.cs", SearchOption.AllDirectories)
            .ToDictionary(f => Path.GetRelativePath(generated, f).Replace('\\', '/'), f => File.ReadAllText(f).ReplaceLineEndings("\n"));

        // Regenerate with: dotnet run --project tools/HkdfGuard.Integration.HashiCorpVault.Generator
        Assert.Equal(expected.Keys.Order(StringComparer.Ordinal), onDisk.Keys.Order(StringComparer.Ordinal));
        foreach (var (path, content) in expected)
            Assert.True(content == onDisk[path], $"Generated/{path} differs from what openapi.json generates: regenerate it.");
    }

    [Fact]
    public void TheGeneratedApi_IsTheSubsetGeneratorJsonNames()
    {
        var files = VaultClientGenerator.Generate(File.ReadAllText(Path.Combine(Library, "openapi.json")),
            File.ReadAllText(Path.Combine(Library, GeneratorCommand.SettingsFileName)));
        var methods = files.Where(f => f.Key.EndsWith("Api.g.cs", StringComparison.Ordinal))
            .ToDictionary(f => f.Key, f => System.Text.RegularExpressions.Regex.Matches(f.Value, @" ([A-Za-z0-9]+)Async\(").Select(m => m.Groups[1].Value).ToList());

        Assert.Equal(["AuthApi.g.cs", "SecretsApi.g.cs", "SystemApi.g.cs"], methods.Keys.Order(StringComparer.Ordinal));
        Assert.Contains("AppRoleLogin", methods["AuthApi.g.cs"]);
        Assert.Contains("TokenRenewSelf", methods["AuthApi.g.cs"]);
        Assert.DoesNotContain("AppRoleWriteRole", methods["AuthApi.g.cs"]);
        Assert.DoesNotContain("TokenWriteRole", methods["AuthApi.g.cs"]);
        Assert.All(methods["SecretsApi.g.cs"], m => Assert.Matches("^(KvV1|KvV2|Cubbyhole|Transit)", m));
        Assert.Equal(["LeaderStatus", "MountsListSecretsEngines", "ReadHealthStatus", "ReadWrappingProperties", "Rewrap", "SealStatus", "Unwrap", "Wrap"],
            methods["SystemApi.g.cs"].Order(StringComparer.Ordinal));
        Assert.Equal((35, 60), (methods["AuthApi.g.cs"].Count, methods["SecretsApi.g.cs"].Count));
    }

    [Fact]
    public async Task AGeneratedRead_EscapesThePath_AndUsesTheDefaultOrGivenMount()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Respond = _ => FakeVault.Json(HttpStatusCode.OK, """{"data":{"data":{"password":"s3cret"},"metadata":{"version":3}}}""");

        var response = await t.Client.Secrets.KvV2ReadAsync("my app/db");
        await t.Client.Secrets.KvV2ReadAsync("x", new VaultRequestOptions { MountPath = "/my/mount/" });
        await t.Client.Secrets.KvV2ReadAsync("x", new VaultRequestOptions { MountPath = "/" });

        Assert.Equal("s3cret", response!.Data!.Data!["password"].GetString());
        Assert.Equal(3, response.Data.Metadata!["version"].GetInt32());
        Assert.Equal(["/v1/kv-v2/data/my%20app%2Fdb", "/v1/my%2Fmount/data/x", "/v1/kv-v2/data/x"], t.Vault.Requests.Select(r => r.Uri.AbsolutePath));
        Assert.All(t.Vault.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
    }

    [Fact]
    public async Task AGeneratedWrite_PostsItsModel_LeavingOutWhatIsntSet()
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.Secrets.KvV2WriteAsync("foo", new KvV2WriteRequest
        {
            Data = new Dictionary<string, object?> { ["password1"] = "abc123", ["password2"] = "correct horse battery staple" },
            Options = new Dictionary<string, object?> { ["cas"] = 0 },
        }, new VaultRequestOptions { MountPath = "secret" });

        var request = t.Vault.Single();
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/v1/secret/data/foo", request.PathAndQuery);
        Assert.Equal("""{"data":{"password1":"abc123","password2":"correct horse battery staple"},"options":{"cas":0}}""", request.BodyText);
    }

    [Fact]
    public async Task RequiredMembers_AreAlwaysSent()
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.Secrets.TransitSetCertificateForKeyAsync("myapp-kek", new TransitSetCertificateForKeyRequest { CertificateChain = "pem" });

        Assert.Equal(("/v1/transit/keys/myapp-kek/set-certificate", """{"certificate_chain":"pem"}"""),
            (t.Vault.Single().PathAndQuery, t.Vault.Single().BodyText));
    }

    [Fact]
    public async Task AGeneratedList_AddsListTrue_ToTheCallersQuery()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, """{"data":{"keys":["a","b/"]}}""");

        var response = await t.Client.Secrets.KvV2ListAsync("dir", new VaultRequestOptions { QueryParameters = [new("after", "a")] });

        Assert.Equal(["a", "b/"], response!.Data!.Keys!);
        Assert.Equal("/v1/kv-v2/metadata/dir/?after=a&list=true", t.Vault.Single().PathAndQuery);
    }

    [Fact]
    public async Task AFreeFormBody_IsSentAsItIs()
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.Secrets.CubbyholeWriteAsync("note", new Dictionary<string, object?> { ["text"] = "hi", ["n"] = 1 });

        Assert.Equal(("/v1/cubbyhole/note", """{"text":"hi","n":1}"""), (t.Vault.Single().PathAndQuery, t.Vault.Single().BodyText));
    }

    [Fact]
    public async Task AGeneratedMethod_RefusesNullArguments()
    {
        using var t = await TestClient.CreateAsync();

        await Assert.ThrowsAsync<ArgumentNullException>(() => t.Client.Secrets.KvV2ReadAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => t.Client.Secrets.KvV2WriteAsync("p", null!));
        Assert.Empty(t.Vault.Requests);
    }

    [Theory]
    [InlineData(false, "false")]
    [InlineData(true, "true")]
    public void QueryValues_AreFormattedAsGoFormatsThem(bool value, string expected)
    {
        Assert.Equal(expected, VaultClient.FormatQueryValue(value));
        Assert.Equal("12345", VaultClient.FormatQueryValue(12345));
        Assert.Equal("-9", VaultClient.FormatQueryValue(-9L));
        Assert.Equal("str", VaultClient.FormatQueryValue("str"));
    }

    [Fact]
    public void TheGenerator_LeavesOutDuplicatesAndEnterpriseStubs_AndTheirSchemas()
    {
        var files = VaultClientGenerator.Generate(Spec(
            paths: """
                "/a/{a_mount_path}/item/{name}": {
                  "parameters": [
                    {"name": "name", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The item's <name>."},
                    {"name": "a_mount_path", "in": "path", "required": true, "schema": {"type": "string", "default": "a"}}
                  ],
                  "x-vault-sudo": true,
                  "get": {"operationId": "a-read", "tags": ["secrets"], "summary": "Reads & returns.",
                          "parameters": [{"name": "list", "in": "query", "required": true, "schema": {"type": "string", "enum": ["true"]}},
                                         {"name": "version", "in": "query", "schema": {"type": "integer"}},
                                         {"name": "options", "in": "query", "schema": {"type": "boolean", "default": false}},
                                         {"name": "class", "in": "query", "schema": {"type": "integer", "format": "int64"}}],
                          "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AReadResponse"}}}}}},
                  "post": {"operationId": "a-write", "tags": ["secrets"], "deprecated": true,
                           "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A_writeRequest"}}}},
                           "responses": {"204": {"description": "No Content"}}},
                  "delete": {"operationId": "a-delete2", "tags": ["secrets"], "responses": {"204": {"description": "No Content"}}}
                },
                "/sys/stub": {"get": {"operationId": "enterprise-stub-read", "tags": ["system"], "responses": {}}},
                "/sys/thing": {"post": {"operationId": "thing", "tags": ["custom"], "x-vault-unauthenticated": true, "description": "Does a thing.",
                               "requestBody": {"content": {"application/json": {"schema": {"type": "object", "additionalProperties": true}}}},
                               "responses": {"200": {"description": "OK"}}}}
                """,
            schemas: """
                "AReadResponse": {"type": "object", "properties": {
                  "a_read_response": {"type": "string"},
                  "ttl": {"type": "string", "format": "duration", "default": "1h", "enum": ["1h", "2h"]},
                  "when": {"type": "string", "format": "date-time"},
                  "count": {"type": "integer", "format": "int64"}, "rate": {"type": "number"}, "ok": {"type": "boolean"},
                  "list": {"type": "array"}, "ints": {"type": "array", "items": {"type": "integer"}},
                  "map": {"type": "object"}, "typed_map": {"type": "object", "additionalProperties": {"type": "string"}},
                  "any": {}, "old": {"type": "string", "deprecated": true}, "Ok": {"type": "boolean"}}},
                "A_writeRequest": {"type": "object", "required": ["name"], "properties": {
                  "name": {"type": "string"}, "map": {"type": "object"}, "list": {"type": "array"}, "any": {},
                  "ref": {"$ref": "#/components/schemas/AReadResponse"}}},
                "ADelete2Response": {"type": "object"},
                "EnterpriseStubReadResponse": {"type": "object"},
                "Unused": {"type": "object", "description": "Not used."},
                "UnusedRequest": {"type": "object"}
                """));

        Assert.Equal(["CustomApi.g.cs", "Schema/AReadResponse.g.cs", "Schema/AWriteRequest.g.cs", "Schema/Unused.g.cs", "Schema/UnusedRequest.g.cs",
            "SecretsApi.g.cs", "VaultClient.Apis.g.cs"], files.Keys);

        var secrets = files["SecretsApi.g.cs"];
        Assert.Contains("public Task<VaultResponse<Schema.AReadResponse>?> AReadAsync(string name, int version, bool optionsParameter, long @class, VaultRequestOptions? options = null, CancellationToken cancellationToken = default)", secrets);
        Assert.Contains("var requestPath = \"/v1/a/\" + VaultClient.EscapePathSegment(VaultClient.MountPathOr(options, \"a\")) + \"/item/\" + VaultClient.EscapePathSegment(name);", secrets);
        Assert.Contains("query.Add(new(\"list\", \"true\"));", secrets);
        Assert.Contains("query.Add(new(\"options\", VaultClient.FormatQueryValue(optionsParameter)));", secrets);
        Assert.Contains("<summary>Reads &amp; returns.</summary>", secrets);
        Assert.Contains("<param name=\"name\">The item's &lt;name&gt;.</param>", secrets);
        Assert.Contains("<param name=\"optionsParameter\">The options query parameter. Vault's default: false.</param>", secrets);
        Assert.Contains("Needs a token with sudo capability.", secrets);
        Assert.Contains("[Obsolete(\"Deprecated by Vault.\")]\n    public Task<VaultResponse<Dictionary<string, JsonElement>>?> AWriteAsync(string name, Schema.AWriteRequest request,", secrets);
        Assert.DoesNotContain("ADelete2", secrets);

        var custom = files["CustomApi.g.cs"];
        Assert.Contains("ThingAsync(IReadOnlyDictionary<string, object?> request, VaultRequestOptions? options = null", custom);
        Assert.Contains("<summary>Does a thing.</summary>", custom);
        Assert.Contains("Needs no token.", custom);
        Assert.Contains("public CustomApi Custom => _custom ??= new CustomApi(this);", files["VaultClient.Apis.g.cs"]);
        Assert.Contains("Vault's \"custom\" endpoints.", custom);

        var response = files["Schema/AReadResponse.g.cs"];
        Assert.Contains("public string? AReadResponseValue { get; set; }", response);
        Assert.Contains("<remarks>A duration: seconds, or a Go duration such as \"24h\". One of: \"1h\", \"2h\". Vault's default: \"1h\".</remarks>", response);
        Assert.Contains("public DateTimeOffset? When { get; set; }", response);
        Assert.Contains("public long? Count { get; set; }", response);
        Assert.Contains("public double? Rate { get; set; }", response);
        Assert.Contains("public List<JsonElement>? List { get; set; }", response);
        Assert.Contains("public List<int>? Ints { get; set; }", response);
        Assert.Contains("public Dictionary<string, JsonElement>? Map { get; set; }", response);
        Assert.Contains("public Dictionary<string, string>? TypedMap { get; set; }", response);
        Assert.Contains("public JsonElement? Any { get; set; }", response);
        Assert.Contains("[Obsolete(\"Deprecated by Vault.\")]\n    public string? Old { get; set; }", response);
        Assert.Contains("public bool? Ok2 { get; set; }", response);
        Assert.Contains("<summary>The data <see cref=\"HkdfGuard.Integration.HashiCorpVault.SecretsApi.AReadAsync\"/> returns.</summary>", response);

        var request = files["Schema/AWriteRequest.g.cs"];
        Assert.Contains("public sealed class AWriteRequest", request);
        Assert.Contains("public required string Name { get; set; }", request);
        Assert.Contains("public Dictionary<string, object?>? Map { get; set; }", request);
        Assert.Contains("public List<object?>? List { get; set; }", request);
        Assert.Contains("public object? Any { get; set; }", request);
        Assert.Contains("public AReadResponse? Ref { get; set; }", request);
        Assert.Contains("<summary>The request body of <see cref=\"HkdfGuard.Integration.HashiCorpVault.SecretsApi.AWriteAsync\"/>.</summary>", request);

        Assert.Contains("<summary>Not used.</summary>", files["Schema/Unused.g.cs"]);
        Assert.Contains("<summary>The UnusedRequest schema.</summary>", files["Schema/UnusedRequest.g.cs"]);
        Assert.All(files.Values, f => Assert.DoesNotContain('\r', f));
    }

    [Theory]
    [InlineData("""{"/x": {"get": {"tags": ["system"], "responses": {}}}}""", "{}", "no operationId")]
    [InlineData("""{"/x": {"get": {"operationId": "x", "responses": {}}}}""", "{}", "has 0 tags")]
    [InlineData("""{"/x": {"get": {"operationId": "x", "tags": ["a", "b"], "responses": {}}}}""", "{}", "has 2 tags")]
    [InlineData("""{"/x": {"get": {"operationId": "x", "tags": ["system"], "parameters": [{"name": "h", "in": "header", "schema": {"type": "string"}}], "responses": {}}}}""", "{}", "header parameter")]
    [InlineData("""{"/x": {"get": {"operationId": "x", "tags": ["system"], "parameters": [{"name": "q", "in": "query", "schema": {"type": "array"}}], "responses": {}}}}""", "{}", "only string, integer and boolean")]
    [InlineData("""{"/x": {"get": {"operationId": "x", "tags": ["system"], "parameters": [{"name": "q", "in": "query"}], "responses": {}}}}""", "{}", "is a typeless")]
    [InlineData("""{"/x/{y}": {"get": {"operationId": "x", "tags": ["system"], "responses": {}}}}""", "{}", "placeholder {y} with no parameter")]
    [InlineData("""{"/x/{q}": {"get": {"operationId": "x", "tags": ["system"], "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}], "responses": {}}}}""", "{}", "placeholder {q} with no parameter")]
    [InlineData("""{"/{m_mount_path}": {"get": {"operationId": "x", "tags": ["secrets"], "parameters": [{"name": "m_mount_path", "in": "path", "schema": {"type": "string"}}], "responses": {}}}}""", "{}", "has no default")]
    [InlineData("""{"/x": {"post": {"operationId": "x", "tags": ["system"], "requestBody": {"content": {"text/plain": {"schema": {"type": "string"}}}}, "responses": {}}}}""", "{}", "isn't only application/json")]
    [InlineData("""{"/x": {"post": {"operationId": "x", "tags": ["system"], "requestBody": {"content": {"application/json": {"schema": {"type": "string"}}}}, "responses": {}}}}""", "{}", "neither a $ref nor a free-form object")]
    [InlineData("""{"/x": {"post": {"operationId": "x", "tags": ["system"], "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/definitions/X"}}}}, "responses": {}}}}""", "{}", "Unsupported $ref")]
    [InlineData("""{"/x": {"post": {"operationId": "x", "tags": ["system"], "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Missing"}}}}, "responses": {}}}}""", "{}", "missing or excluded")]
    [InlineData("{}", """{"S": {"type": "string"}}""", "isn't an object")]
    [InlineData("{}", """{"S": {"type": "object", "properties": {"p": {"type": "object", "properties": {}}}}}""", "properties of its own")]
    [InlineData("{}", """{"S": {"type": "object", "properties": {"p": {"type": "tuple"}}}}""", "type 'tuple'")]
    [InlineData("{}", """{"A_b": {"type": "object"}, "AB": {"type": "object"}}""", "would all be named AB")]
    public void TheGenerator_RefusesWhatItDoesntHandle(string paths, string schemas, string message)
    {
        var e = Assert.Throws<InvalidDataException>(() => VaultClientGenerator.Generate(Spec(paths[1..^1], schemas[1..^1])));

        Assert.Contains(message, e.Message);
    }

    [Fact]
    public void TheGenerator_LetsAnOperationOverrideAPathParameter_AndTypesItsFirst2xxResponse()
    {
        var files = VaultClientGenerator.Generate("""
            {"openapi": "3.0.2", "info": {"title": "test", "version": null},
             "paths": {
               "/x/{name}": {
                 "x-vault-unauthenticated": true,
                 "parameters": [{"name": "name", "in": "path", "description": "Shared.", "schema": {"type": "string"}}],
                 "get": {"operationId": "x-read", "tags": ["system"],
                         "parameters": [{"name": "name", "in": "path", "description": "Overridden.", "schema": {"type": "string"}}],
                         "responses": {"400": {"description": "Bad"},
                                       "200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/XResponse"}}}}}},
                 "delete": {"operationId": "x-delete", "tags": ["system"], "x-vault-sudo": true}
               }},
             "components": {"schemas": {"XResponse": {"type": "object"}}}}
            """);

        var api = files["SystemApi.g.cs"];
        Assert.Contains("HashiCorp Vault API ).", api);
        Assert.Contains("<param name=\"name\">Overridden.</param>", api);
        // The read takes its own; only the delete, which doesn't override it, takes the path's.
        Assert.Equal(1, api.Split("<param name=\"name\">Shared.</param>").Length - 1);
        Assert.Contains("Task<VaultResponse<Schema.XResponse>?> XReadAsync(string name,", api);
        Assert.Contains("Task<VaultResponse<Dictionary<string, JsonElement>>?> XDeleteAsync(string name,", api);
        Assert.Equal(2, api.Split("Needs no token.").Length - 1);
        Assert.Equal(1, api.Split("Needs a token with sudo capability.").Length - 1);
    }

    private const string NarrowingPaths = """
        "/a": {
          "get": {"operationId": "a-read", "tags": ["secrets"],
                  "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AReadResponse"}}}}}},
          "post": {"operationId": "a-write", "tags": ["secrets"],
                   "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/AWriteRequest"}}}},
                   "responses": {"204": {"description": "No Content"}}}
        },
        "/b": {"get": {"operationId": "b-read", "tags": ["identity"],
                       "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BReadResponse"}}}}}}}
        """;

    private const string NarrowingSchemas = """
        "AReadResponse": {"type": "object", "properties": {"item": {"$ref": "#/components/schemas/Item"},
                                                            "items": {"type": "array", "items": {"$ref": "#/components/schemas/Other"}}}},
        "Item": {"type": "object", "properties": {"inner": {"$ref": "#/components/schemas/Inner"}}},
        "Inner": {"type": "object", "properties": {"back": {"$ref": "#/components/schemas/Item"}}},
        "Other": {"type": "object"},
        "AWriteRequest": {"type": "object"},
        "BReadResponse": {"type": "object"},
        "Unused": {"type": "object"}
        """;

    [Fact]
    public void AnIncludeList_KeepsOnlyItsOperations_TheSchemasTheyUse_AndTheirClasses()
    {
        var files = VaultClientGenerator.Generate(Spec(NarrowingPaths, NarrowingSchemas), """{"description": "test", "include": ["^ARead$"]}""");

        Assert.Equal(["Schema/AReadResponse.g.cs", "Schema/Inner.g.cs", "Schema/Item.g.cs", "Schema/Other.g.cs", "SecretsApi.g.cs", "VaultClient.Apis.g.cs"],
            files.Keys.Order(StringComparer.Ordinal));
        Assert.Contains("AReadAsync", files["SecretsApi.g.cs"]);
        Assert.DoesNotContain("AWriteAsync", files["SecretsApi.g.cs"]);
        Assert.DoesNotContain("Identity", files["VaultClient.Apis.g.cs"]);
    }

    [Fact]
    public void WithoutSettings_OrAnIncludeList_EverythingIsGenerated()
    {
        var all = VaultClientGenerator.Generate(Spec(NarrowingPaths, NarrowingSchemas));

        Assert.Equal(all.Keys, VaultClientGenerator.Generate(Spec(NarrowingPaths, NarrowingSchemas), """{"description": "nothing narrowed"}""").Keys);
        Assert.Contains("Schema/Unused.g.cs", all.Keys);
        Assert.Contains("IdentityApi.g.cs", all.Keys);
    }

    [Theory]
    [InlineData("""{"include": ["^ARead$", "^Missing$"]}""", "'^Missing$' matches no operation")]
    [InlineData("""{"include": []}""", "non-empty array")]
    [InlineData("""{"include": "^ARead$"}""", "non-empty array")]
    [InlineData("""{"include": [1]}""", "non-empty array")]
    [InlineData("""{"include": ["("]}""", "isn't a regular expression")]
    [InlineData("""{"exclude": ["x"]}""", "Unknown generator setting 'exclude'")]
    [InlineData("""["^ARead$"]""", "must be a JSON object")]
    [InlineData("not json", "aren't JSON")]
    public void BadSettings_AreRefused(string settings, string message)
    {
        var e = Assert.Throws<InvalidDataException>(() => VaultClientGenerator.Generate(Spec(NarrowingPaths, NarrowingSchemas), settings));

        Assert.Contains(message, e.Message);
    }

    [Fact]
    public void AnIncludedOperationsMissingSchema_IsRefused()
    {
        var e = Assert.Throws<InvalidDataException>(() => VaultClientGenerator.Generate(
            Spec(NarrowingPaths, NarrowingSchemas.Replace("\"Inner\": {\"type\": \"object\", \"properties\": {\"back\": {\"$ref\": \"#/components/schemas/Item\"}}},", "")),
            """{"include": ["^ARead$"]}"""));

        Assert.Contains("Schema Inner is referred to but missing", e.Message);
    }

    [Fact]
    public void TheGeneratorCommand_TakesSettings_GivenOrBesideTheSpec()
    {
        var directory = Directory.CreateTempSubdirectory("hkdfguard-generator");
        try
        {
            var spec = Path.Combine(directory.FullName, "spec.json");
            var given = Path.Combine(directory.FullName, "narrow.json");
            File.WriteAllText(spec, Spec(NarrowingPaths, NarrowingSchemas));
            File.WriteAllText(given, """{"include": ["^BRead$"]}""");
            File.WriteAllText(Path.Combine(directory.FullName, GeneratorCommand.SettingsFileName), """{"include": ["^ARead$"]}""");

            var (_, besideMessage) = Run(directory.FullName, "--spec", spec, "--output", Path.Combine(directory.FullName, "beside"));
            var (_, givenMessage) = Run(directory.FullName, "--spec", spec, "--settings", given, "--output", Path.Combine(directory.FullName, "given"));

            Assert.Contains("with " + Path.Combine(directory.FullName, GeneratorCommand.SettingsFileName), besideMessage);
            Assert.True(File.Exists(Path.Combine(directory.FullName, "beside", "SecretsApi.g.cs")));
            Assert.Contains("with " + given, givenMessage);
            Assert.True(File.Exists(Path.Combine(directory.FullName, "given", "IdentityApi.g.cs")));
            Assert.False(File.Exists(Path.Combine(directory.FullName, "given", "SecretsApi.g.cs")));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Theory]
    [InlineData("kv-v2-read", "KvV2Read")]
    [InlineData("hcp_link_resource_ID", "HcpLinkResourceID")]
    [InlineData("2fa", "_2fa")]
    [InlineData("--", "Value")]
    public void Pascal_NamesAsOpenApiGeneratorDoes(string name, string expected) => Assert.Equal(expected, CSharp.Pascal(name));

    [Theory]
    [InlineData("role_name", "roleName")]
    [InlineData("namespace", "@namespace")]
    [InlineData("2fa", "_2fa")]
    public void Camel_EscapesKeywords(string name, string expected) => Assert.Equal(expected, CSharp.Camel(name));

    [Fact]
    public void Literal_EscapesWhatACStringCantHoldAsItIs()
        => Assert.Equal("\"a\\\\b\\\"c\\n\\r\\t\\u0001\"", CSharp.Literal("a\\b\"c\n\r\t\u0001"));

    [Fact]
    public void TheGeneratorCommand_WritesOnlyChangedFiles_AndDeletesStaleOnes()
    {
        var directory = Directory.CreateTempSubdirectory("hkdfguard-generator");
        try
        {
            var spec = Path.Combine(directory.FullName, "spec.json");
            var output = Path.Combine(directory.FullName, "out");
            File.WriteAllText(spec, Spec("""
                "/sys/x": {"get": {"operationId": "x", "tags": ["system"], "responses": {}}}
                """, ""));
            Directory.CreateDirectory(Path.Combine(output, "Schema"));
            File.WriteAllText(Path.Combine(output, "Schema", "Stale.g.cs"), "stale");
            File.WriteAllText(Path.Combine(output, "keep.txt"), "not generated");

            Assert.Equal((0, "2 files from " + spec + ": 2 written, 0 unchanged, 1 stale deleted, in " + output + "."),
                Run(directory.FullName, "--spec", spec, "--output", output));
            var written = File.GetLastWriteTimeUtc(Path.Combine(output, "SystemApi.g.cs"));
            Assert.Equal(0, Run(directory.FullName, "--spec", spec, "--output", output).Code);

            Assert.Equal(written, File.GetLastWriteTimeUtc(Path.Combine(output, "SystemApi.g.cs")));
            Assert.False(File.Exists(Path.Combine(output, "Schema", "Stale.g.cs")));
            Assert.True(File.Exists(Path.Combine(output, "keep.txt")));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void TheGeneratorCommand_DefaultsToTheLibrarysSpec_FoundFromTheRepositoryRoot()
    {
        var directory = Directory.CreateTempSubdirectory("hkdfguard-generator");
        try
        {
            var (code, message) = Run(Path.Combine(Library, "Generated", "Schema"), "--output", directory.FullName);

            Assert.Equal(0, code);
            Assert.Contains(Path.Combine(Library, "openapi.json"), message);
            Assert.True(File.Exists(Path.Combine(directory.FullName, "Schema", "KvV2ReadResponse.g.cs")));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void TheGeneratorCommand_DefaultsTheOutput_UnderTheRepositoryRoot()
    {
        // A stand-in repository, so nothing under the real one is written.
        var directory = Directory.CreateTempSubdirectory("hkdfguard-generator");
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "HkdfGuard.sln"), "");
            var spec = Path.Combine(directory.FullName, "spec.json");
            File.WriteAllText(spec, Spec("""
                "/sys/x": {"get": {"operationId": "x", "tags": ["system"], "responses": {}}}
                """, ""));

            Assert.Equal(0, Run(directory.FullName, "--spec", spec).Code);

            Assert.True(File.Exists(Path.Combine(directory.FullName, "src", "HkdfGuard.Integration.HashiCorpVault", "Generated", "SystemApi.g.cs")));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Theory]
    [InlineData("--bogus")]
    [InlineData("--spec")]
    [InlineData(null)]
    public void TheGeneratorCommand_RefusesBadArguments_OrNoRepository(string? argument)
    {
        var directory = Directory.CreateTempSubdirectory("hkdfguard-generator");
        try
        {
            var (code, message) = Run(directory.FullName, argument is null ? [] : [argument]);

            Assert.Equal(2, code);
            Assert.Contains(argument is null ? "repository root" : "Usage", message);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void TheGeneratorProgram_RunsTheCommand()
    {
        var output = Console.Out;
        var error = Console.Error;
        try
        {
            Console.SetOut(TextWriter.Null);
            Console.SetError(TextWriter.Null);
            Assert.Equal(2, typeof(VaultClientGenerator).Assembly.EntryPoint!.Invoke(null, [new[] { "--bogus" }]));
        }
        finally
        {
            Console.SetOut(output);
            Console.SetError(error);
        }
    }

    private static (int Code, string Message) Run(string currentDirectory, params string[] args)
    {
        using var output = new StringWriter();
        var code = GeneratorCommand.Run(args, currentDirectory, output, output);
        return (code, output.ToString().Trim());
    }

    private static string Spec(string paths, string schemas)
        => """{"openapi": "3.0.2", "info": {"title": "test", "version": "9.9.9"}, "paths": {""" + paths
           + """}, "components": {"schemas": {""" + schemas + "}}}";

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HkdfGuard.sln")))
                return directory.FullName;
        }

        throw new InvalidOperationException("No HkdfGuard.sln above the test's directory.");
    }
}
