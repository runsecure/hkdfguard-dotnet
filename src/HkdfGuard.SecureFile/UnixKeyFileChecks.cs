namespace HkdfGuard.SecureFile;

/// <summary>
/// Decides whether a key file's path on Linux or macOS can be trusted: resolves it the way the
/// kernel would, from <c>/</c>, checking everything it passes through. Every directory and the file
/// itself must be owned by root or a <see cref="KeyFileTrust.UnixUserIds"/> user, must not be
/// writable by others, and may be writable by its group only if that is a
/// <see cref="KeyFileTrust.UnixGroupIds"/> group. A symbolic link is followed only if a trusted user
/// owns it, and its target is then checked in turn - so macOS's root-owned /etc to private/etc
/// works, and a link anyone else made doesn't. Nothing under /tmp, /var/tmp or another
/// world-writable directory passes, sticky or not.
/// <para>
/// The path is checked before it is opened, not through the opened descriptor. That is enough:
/// nobody untrusted can write to any directory on the resolved path, or to the file, so nobody
/// untrusted can change what it resolves to between the check and the open.
/// </para>
/// </summary>
internal static class UnixKeyFileChecks
{
    // The kernel's own limit on symbolic links followed in one lookup.
    internal const int MaxSymbolicLinks = 40;

    /// <summary>
    /// Resolves <paramref name="path"/>, checking each component, and returns the resolved path,
    /// which contains no symbolic links.
    /// </summary>
    /// <param name="path">An absolute path.</param>
    /// <param name="getStatus">lstat-style status of a path, or null if nothing is there.</param>
    /// <param name="readLink">A symbolic link's stored target.</param>
    /// <exception cref="FileNotFoundException">Nothing is at the path, or a directory on it is missing.</exception>
    /// <exception cref="UnauthorizedAccessException">A component is not trusted, or the path isn't a regular file.</exception>
    internal static string ResolveTrusted(string path, KeyFileTrust trust, Func<string, UnixFileStatus?> getStatus, Func<string, string?> readLink)
    {
        if (!path.StartsWith('/'))
            throw new ArgumentException($"'{path}' is not an absolute path.", nameof(path));

        var root = getStatus("/") ?? throw new UnauthorizedAccessException("'/' could not be examined.");
        RequireTrusted("/", root, trust, path);

        var pending = new Stack<string>();
        PushComponents(pending, path);
        var resolved = "/";
        var resolvedType = UnixFileType.Directory;
        var linksFollowed = 0;

        while (pending.TryPop(out var name))
        {
            if (name is "" or ".")
                continue;

            if (resolvedType != UnixFileType.Directory)
                throw new FileNotFoundException($"Key file '{path}' runs through '{resolved}', which is not a directory.", path);

            if (name == "..")
            {
                // resolved never contains a symbolic link, so its parent is its lexical parent.
                resolved = ParentOf(resolved);
                continue;
            }

            var candidate = resolved == "/" ? $"/{name}" : $"{resolved}/{name}";
            if (getStatus(candidate) is not { } status)
                throw new FileNotFoundException($"Key file '{path}' was not found ('{candidate}' does not exist).", path);

            if (status.Type == UnixFileType.SymbolicLink)
            {
                if (!IsTrustedUser(status.OwnerId, trust))
                    throw Untrusted(path, $"'{candidate}' is a symbolic link owned by uid {status.OwnerId}, and only links owned by root or a trusted user are followed");
                if (++linksFollowed > MaxSymbolicLinks)
                    throw Untrusted(path, $"it follows more than {MaxSymbolicLinks} symbolic links");

                var target = readLink(candidate) ?? throw Untrusted(path, $"'{candidate}' could not be read as a symbolic link");
                if (target.StartsWith('/'))
                    resolved = "/";
                PushComponents(pending, target);
                continue;
            }

            RequireTrusted(candidate, status, trust, path);
            resolved = candidate;
            resolvedType = status.Type;
        }

        if (resolvedType != UnixFileType.RegularFile)
            throw Untrusted(path, $"it resolves to '{resolved}', which is not a regular file");

        return resolved;
    }

    private static void RequireTrusted(string candidate, UnixFileStatus status, KeyFileTrust trust, string path)
    {
        if (!IsTrustedUser(status.OwnerId, trust))
            throw Untrusted(path, $"'{candidate}' is owned by uid {status.OwnerId}, not root or a trusted user");

        if ((status.Permissions & UnixFileMode.OtherWrite) != 0)
            throw Untrusted(path, $"'{candidate}' is writable by every user");

        if ((status.Permissions & UnixFileMode.GroupWrite) != 0 && !trust.UnixGroupIds.Contains(status.GroupId))
            throw Untrusted(path, $"'{candidate}' is writable by group {status.GroupId}, which is not a trusted group");
    }

    private static bool IsTrustedUser(uint uid, KeyFileTrust trust) => uid == 0 || trust.UnixUserIds.Contains(uid);

    private static UnauthorizedAccessException Untrusted(string path, string why)
        => new($"Key file '{path}' is not trusted: {why}. Keep key files where only root (or a trusted deployer, see KeyFileTrust) can write, all the way up from /.");

    private static void PushComponents(Stack<string> pending, string path)
    {
        var components = path.Split('/');
        for (var i = components.Length - 1; i >= 0; i--)
            pending.Push(components[i]);
    }

    internal static string ParentOf(string path)
    {
        var slash = path.LastIndexOf('/');
        return slash <= 0 ? "/" : path[..slash];
    }
}
