using System.Reflection;
using System.Runtime.InteropServices;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>The User-Agent every request carries: library/version (OS; architecture; runtime), as vault-client-go's.</summary>
internal static class VaultUserAgent
{
    public static readonly string Value = Create(typeof(VaultClient).Assembly);

    internal static string Create(Assembly library)
        => Create(library.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            RuntimeInformation.OSDescription, RuntimeInformation.OSArchitecture.ToString(), Environment.Version.ToString());

    internal static string Create(string? version, string os, string architecture, string runtime)
    {
        // Without the source revision SourceLink appends.
        version = version?.Split('+')[0] is { Length: > 0 } v ? v : "0.0.0";
        var agent = $"HkdfGuard.Integration.HashiCorpVault/{version} ({os}; {architecture}; .NET {runtime})";

        // Only what a header can carry: an OS description could hold anything.
        return string.Create(agent.Length, agent, static (chars, s) =>
        {
            for (var i = 0; i < s.Length; i++)
                chars[i] = s[i] is >= ' ' and <= '~' ? s[i] : ' ';
        });
    }
}
