using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>Whether a performance standby forwards requests to the active node (Vault Enterprise).</summary>
public enum ReplicationForwardingMode
{
    /// <summary>No forwarding header.</summary>
    None,

    /// <summary>
    /// X-Vault-Forward: a performance standby forwards every request to the active node; see
    /// https://developer.hashicorp.com/vault/docs/enterprise/consistency#unconditional-forwarding-performance-standbys-only.
    /// </summary>
    Always,

    /// <summary>
    /// X-Vault-Inconsistent: a performance standby forwards a request to the active node only when it
    /// hasn't caught up with the replication state it requires - see
    /// <see cref="VaultReplication.RequireReplicationStates"/> and
    /// https://developer.hashicorp.com/vault/docs/enterprise/consistency#conditional-forwarding-performance-standbys-only.
    /// </summary>
    Inconsistent,
}

/// <summary>
/// A cluster's replication state from an X-Vault-Index header: the sdk's WALState.
/// </summary>
/// <param name="Cluster">The cluster's id.</param>
/// <param name="LocalIndex">The local write-ahead log index.</param>
/// <param name="ReplicatedIndex">The replicated write-ahead log index.</param>
public readonly record struct VaultReplicationState(string Cluster, ulong LocalIndex, ulong ReplicatedIndex)
{
    /// <summary>
    /// The state raw holds: base64 of v1:cluster-id:local-index:replicated-index:hmac. With an hmacKey
    /// the hmac (hex HMAC-SHA256 of everything before it) is verified as well.
    /// </summary>
    /// <exception cref="FormatException">raw isn't a replication state, or its HMAC doesn't match</exception>
    public static VaultReplicationState Parse(string raw, ReadOnlySpan<byte> hmacKey = default)
    {
        ArgumentNullException.ThrowIfNull(raw);
        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(raw));
        }
        catch (FormatException e)
        {
            throw new FormatException($"Could not decode the replication state: {e.Message}", e);
        }

        var lastColon = decoded.LastIndexOf(':');
        if (lastColon < 0)
            throw new FormatException("Invalid replication state header format.");

        var state = decoded[..lastColon];
        byte[] stateHmac;
        try
        {
            stateHmac = Convert.FromHexString(decoded.AsSpan(lastColon + 1));
        }
        catch (FormatException e)
        {
            throw new FormatException($"Invalid replication state header HMAC '{decoded[(lastColon + 1)..]}'.", e);
        }

        if (!hmacKey.IsEmpty && !CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(hmacKey, Encoding.UTF8.GetBytes(state)), stateHmac))
            throw new FormatException("Invalid replication state header HMAC (mismatch).");

        var pieces = state.Split(':');
        if (pieces.Length != 4 || pieces[0] != "v1" || pieces[1].Length == 0)
            throw new FormatException("Invalid replication state header format.");
        if (!ulong.TryParse(pieces[2], NumberStyles.None, CultureInfo.InvariantCulture, out var localIndex))
            throw new FormatException("Invalid local index in replication state header.");
        if (!ulong.TryParse(pieces[3], NumberStyles.None, CultureInfo.InvariantCulture, out var replicatedIndex))
            throw new FormatException("Invalid replicated index in replication state header.");

        return new VaultReplicationState(pieces[1], localIndex, replicatedIndex);
    }
}

/// <summary>
/// Read-your-writes across a Vault Enterprise cluster by hand - what
/// <see cref="VaultClientOptions.EnforceReadYourWritesConsistency"/> does for every request: record
/// the state a write's response carries, then require it of a later read; see
/// https://developer.hashicorp.com/vault/docs/enterprise/consistency#conditional-forwarding-performance-standbys-only.
/// </summary>
public static class VaultReplication
{
    internal const string IndexHeader = "X-Vault-Index";

    /// <summary>A response callback handing record the response's replication state (X-Vault-Index), or null if it has none.</summary>
    public static Action<HttpRequestMessage, HttpResponseMessage> RecordReplicationState(Action<string?> record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return (_, response) => record(response.Headers.TryGetValues(IndexHeader, out var values) ? values.FirstOrDefault() : null);
    }

    /// <summary>A request callback requiring states (X-Vault-Index) of the node that answers - states recorded with <see cref="RecordReplicationState"/>.</summary>
    public static Action<HttpRequestMessage> RequireReplicationStates(params string[] states)
    {
        ArgumentNullException.ThrowIfNull(states);
        string[] copy = [.. states];
        return request =>
        {
            foreach (var state in copy)
                request.Headers.TryAddWithoutValidation(IndexHeader, state);
        };
    }

    /// <summary>
    /// The states to require after seeing newState, given those required so far: each old state newer
    /// than newState kept, newState kept if newer than any - both when neither is newer - sorted, with
    /// no duplicates. Just newState when there are no old states or more than two, or when any can't
    /// be compared with it (unparsable, or another cluster's).
    /// </summary>
    public static string[] MergeReplicationStates(IReadOnlyList<string> oldStates, string newState)
    {
        ArgumentNullException.ThrowIfNull(oldStates);
        ArgumentNullException.ThrowIfNull(newState);
        if (oldStates.Count is 0 or > 2)
            return [newState];

        var merged = new List<string>();
        foreach (var old in oldStates)
        {
            int comparison;
            try
            {
                comparison = Compare(old, newState);
            }
            catch (FormatException)
            {
                return [newState];
            }

            switch (comparison)
            {
                case 1:
                    merged.Add(old);
                    break;
                case -1:
                    merged.Add(newState);
                    break;
                default:
                    merged.Add(old);
                    merged.Add(newState);
                    break;
            }
        }

        // strutil.RemoveDuplicates: trimmed, empties dropped, distinct, sorted.
        return [.. merged.Select(s => s.Trim()).Where(s => s.Length > 0).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    /// <summary>1 if s1 is newer than s2 or the same, -1 if older, 0 if neither is.</summary>
    /// <exception cref="FormatException">Either isn't a replication state, or they're different clusters'</exception>
    internal static int Compare(string s1, string s2)
    {
        var r1 = VaultReplicationState.Parse(s1);
        var r2 = VaultReplicationState.Parse(s2);
        if (r1.Cluster != r2.Cluster)
            throw new FormatException("Can't compare replication states from different clusters.");

        if (r1.LocalIndex >= r2.LocalIndex && r1.ReplicatedIndex >= r2.ReplicatedIndex)
            return 1;
        if (r1.LocalIndex <= r2.LocalIndex && r1.ReplicatedIndex <= r2.ReplicatedIndex)
            return -1;
        return 0;
    }
}

/// <summary>
/// The replication states a client has seen, for <see cref="VaultClientOptions.EnforceReadYourWritesConsistency"/>:
/// at most two, as <see cref="VaultReplication.MergeReplicationStates"/> keeps them.
/// </summary>
internal sealed class ReplicationStateCache
{
    private readonly Lock _lock = new();
    private string[] _states;

    public ReplicationStateCache(string[]? states = null) => _states = states ?? [];

    /// <summary>Merges the state response carries, if any, into those seen.</summary>
    public void Record(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(VaultReplication.IndexHeader, out var values))
            return;
        var state = values.First();
        if (state.Length == 0)
            return;

        lock (_lock)
            _states = VaultReplication.MergeReplicationStates(_states, state);
    }

    /// <summary>The states seen so far, to require of the next request.</summary>
    public string[] Snapshot()
    {
        lock (_lock)
            return _states;
    }

    public ReplicationStateCache Clone() => new(Snapshot());
}
