namespace HkdfGuard.Abstractions;

/// <summary>
/// The rule for a service name - the identity of a KEK in the native KMS library: 1 to
/// <see cref="MaxLength"/> characters, each an ASCII letter, digit or '.', not starting with '.'
/// and never containing "..". Typically reverse-DNS, e.g. "com.example.orders". Enforced in
/// .NET before any native call, so a bad name fails with a clear message instead of a native
/// status code, and is never passed across the boundary at all.
/// </summary>
public static class ServiceNames
{
    /// <summary>Longest service name, in characters (each is ASCII, so also in bytes).</summary>
    public const int MaxLength = 128;

    /// <summary>True if <paramref name="name"/> satisfies every rule.</summary>
    public static bool IsValid(string? name) => GetProblem(name) is null;

    /// <summary>
    /// Why <paramref name="name"/> is not a valid service name, or null if it is.
    /// </summary>
    public static string? GetProblem(string? name)
    {
        if (string.IsNullOrEmpty(name))
            return "A service name is required.";

        if (name.Length > MaxLength)
            return $"A service name is at most {MaxLength} characters; this one is {name.Length}.";

        if (name[0] == '.')
            return "A service name can't start with '.'.";

        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (c == '.')
            {
                if (i > 0 && name[i - 1] == '.')
                    return "A service name can't contain '..'.";
            }
            else if (!char.IsAsciiLetterOrDigit(c))
            {
                return $"A service name may contain only ASCII letters, digits and '.'; it has U+{(int)c:X4} at position {i}.";
            }
        }

        return null;
    }

    /// <summary>Throws if <paramref name="name"/> is not a valid service name.</summary>
    /// <param name="name">The candidate service name.</param>
    /// <param name="paramName">The parameter name reported in the exception.</param>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="ArgumentException">name breaks a rule; the message says which</exception>
    public static void ThrowIfInvalid(string? name, string paramName)
    {
        ArgumentNullException.ThrowIfNull(name, paramName);

        if (GetProblem(name) is { } problem)
            throw new ArgumentException(problem, paramName);
    }
}
