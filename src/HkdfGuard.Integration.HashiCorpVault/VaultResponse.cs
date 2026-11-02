using System.Text.Json.Serialization;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// What Vault answers most requests with. A response without a "data", "auth" or "wrap_info"
/// member - sys/health, sys/leader and sys/seal-status, for instance - is read whole into <see cref="Data"/>.
/// </summary>
/// <typeparam name="T">What <see cref="Data"/> holds: a generated Schema model, or a dictionary of JSON values.</typeparam>
public sealed class VaultResponse<T>
{
    /// <summary>The id of the request this answers.</summary>
    [JsonPropertyName("request_id")]
    public string? RequestId { get; set; }

    /// <summary>The lease on a dynamic secret, for renewing or revoking it.</summary>
    [JsonPropertyName("lease_id")]
    public string? LeaseId { get; set; }

    /// <summary>How long the lease lasts, in seconds.</summary>
    [JsonPropertyName("lease_duration")]
    public long LeaseDuration { get; set; }

    /// <summary>Whether the lease can be renewed.</summary>
    [JsonPropertyName("renewable")]
    public bool Renewable { get; set; }

    /// <summary>The response's contents, whose shape depends on the endpoint.</summary>
    [JsonPropertyName("data")]
    public T? Data { get; set; }

    /// <summary>Things Vault wants noticed that didn't fail the request.</summary>
    [JsonPropertyName("warnings")]
    public List<string>? Warnings { get; set; }

    /// <summary>The token a login issued, and about it; null for anything but a login.</summary>
    [JsonPropertyName("auth")]
    public VaultResponseAuth? Auth { get; set; }

    /// <summary>The wrapping token, when the response was wrapped (<see cref="VaultRequestOptions.ResponseWrappingTtl"/>).</summary>
    [JsonPropertyName("wrap_info")]
    public VaultResponseWrapInfo? WrapInfo { get; set; }
}

/// <summary>The token a login issued, and about it.</summary>
public sealed class VaultResponseAuth
{
    /// <summary>
    /// The token, protected by the client's token protector as the response was read - it never
    /// becomes a string. Hand it to <see cref="VaultClient.SetToken(IVaultTokenProvider)"/> or
    /// <see cref="VaultRequestOptions.Token"/>.
    /// </summary>
    [JsonPropertyName("client_token")]
    public StaticVaultToken? ClientToken { get; set; }

    /// <summary>The token's accessor: for looking it up or revoking it, not for making requests.</summary>
    [JsonPropertyName("accessor")]
    public string? Accessor { get; set; }

    /// <summary>Every policy the token carries.</summary>
    [JsonPropertyName("policies")]
    public List<string>? Policies { get; set; }

    /// <summary>The policies attached to the token itself.</summary>
    [JsonPropertyName("token_policies")]
    public List<string>? TokenPolicies { get; set; }

    /// <summary>The policies the token gets from its identity.</summary>
    [JsonPropertyName("identity_policies")]
    public List<string>? IdentityPolicies { get; set; }

    /// <summary>The auth method's metadata about the login.</summary>
    [JsonPropertyName("metadata")]
    public Dictionary<string, string>? Metadata { get; set; }

    /// <summary>Whether the token has no parent.</summary>
    [JsonPropertyName("orphan")]
    public bool Orphan { get; set; }

    /// <summary>The identity entity the token belongs to.</summary>
    [JsonPropertyName("entity_id")]
    public string? EntityId { get; set; }

    /// <summary>How long the token lasts, in seconds.</summary>
    [JsonPropertyName("lease_duration")]
    public long LeaseDuration { get; set; }

    /// <summary>Whether the token can be renewed.</summary>
    [JsonPropertyName("renewable")]
    public bool Renewable { get; set; }

    /// <summary>Set when the login needs multi-factor validation before it issues a token.</summary>
    [JsonPropertyName("mfa_requirement")]
    public VaultMfaRequirement? MfaRequirement { get; set; }
}

/// <summary>A wrapped response: the token that unwraps it, and about it.</summary>
public sealed class VaultResponseWrapInfo
{
    /// <summary>
    /// The wrapping token, protected by the client's token protector as the response was read. Hand
    /// it to <see cref="VaultClient.UnwrapAsync{T}"/>.
    /// </summary>
    [JsonPropertyName("token")]
    public StaticVaultToken? Token { get; set; }

    /// <summary>The wrapping token's accessor.</summary>
    [JsonPropertyName("accessor")]
    public string? Accessor { get; set; }

    /// <summary>How long the wrapping token lasts, in seconds.</summary>
    [JsonPropertyName("ttl")]
    public long Ttl { get; set; }

    /// <summary>When the response was wrapped.</summary>
    [JsonPropertyName("creation_time")]
    public DateTimeOffset? CreationTime { get; set; }

    /// <summary>The path whose response was wrapped.</summary>
    [JsonPropertyName("creation_path")]
    public string? CreationPath { get; set; }

    /// <summary>When a token is wrapped, that token's accessor.</summary>
    [JsonPropertyName("wrapped_accessor")]
    public string? WrappedAccessor { get; set; }
}

/// <summary>The multi-factor validation a login needs.</summary>
public sealed class VaultMfaRequirement
{
    /// <summary>The id to validate against (sys/mfa/validate).</summary>
    [JsonPropertyName("mfa_request_id")]
    public string? MfaRequestId { get; set; }

    /// <summary>The constraints, by name: each satisfied by any one of its methods.</summary>
    [JsonPropertyName("mfa_constraints")]
    public Dictionary<string, VaultMfaConstraintAny>? MfaConstraints { get; set; }
}

/// <summary>A constraint any one of whose methods satisfies it.</summary>
public sealed class VaultMfaConstraintAny
{
    /// <summary>The methods that satisfy it.</summary>
    [JsonPropertyName("any")]
    public List<VaultMfaMethodId>? Any { get; set; }
}

/// <summary>An MFA method.</summary>
public sealed class VaultMfaMethodId
{
    /// <summary>The method's type: totp, duo, okta or pingid.</summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    /// <summary>The method's id.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>Whether it takes a passcode.</summary>
    [JsonPropertyName("uses_passcode")]
    public bool UsesPasscode { get; set; }
}
