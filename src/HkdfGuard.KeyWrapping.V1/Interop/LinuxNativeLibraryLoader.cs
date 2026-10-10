using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Loads the Linux native KMS library from its package's install location and nowhere else. The
/// library receives every plaintext DEK on unwrap and chooses every "random" DEK on
/// generate-and-wrap, and the tpm2-tss library it loads receives every ECDH shared secret, so
/// loading an impostor of either would hand over every key. The runtime's default probe would look
/// in the application directory and LD_LIBRARY_PATH; this loader replaces it.
/// <list type="number">
/// <item><b>Location.</b> The file the libhkdfguard1 package installs: the Debian multiarch
/// directory (/usr/lib/x86_64-linux-gnu or /usr/lib/aarch64-linux-gnu) if it is there, otherwise
/// /usr/lib64 (the RPM packages). Only "nothing is there" moves on to the next location; a path
/// that can't be examined is refused.</item>
/// <item><b>Path integrity.</b> Every directory walked through, every symbolic link followed, and
/// the file itself must be owned by root, and no directory or file may be writable by its group
/// or by others. Symbolic links are followed component by component, each one checked where it
/// lies, so a link can only lead somewhere root chose (/lib to usr/lib, say).</item>
/// <item><b>Content.</b> The file's SHA-256 must be one of <see cref="KnownReleases"/>. Linux has
/// no platform code signature to check, so this pin is what tells a genuine release from any
/// other ELF file root may have put at that path.</item>
/// <item><b>Environment.</b> An absolute path is never searched for, but the library's
/// dependencies are found by name: through LD_LIBRARY_PATH, and after LD_PRELOAD and LD_AUDIT
/// objects that can interpose on any symbol. So every directory on LD_LIBRARY_PATH and every
/// path-named LD_PRELOAD or LD_AUDIT object must pass the same path checks, and none may be
/// relative, empty (the working directory) or use $ORIGIN-style substitutions. Both the
/// environment the process started with (/proc/self/environ, what the dynamic linker read) and
/// the current one are checked.</item>
/// <item><b>What was loaded.</b> After dlopen, dladdr must place the library's export in the
/// verified file, and every object in its dependency closure (read from each file's DT_NEEDED
/// entries) must be bound to a file that passes the path checks. This catches a dependency the
/// process had already loaded from somewhere else under the same name. On failure the library is
/// unloaded - though, as on macOS, any initializer an impostor had has already run; the
/// environment check exists so that it never gets that far in practice.</item>
/// </list>
/// Any failed check throws; there is deliberately no fallback and no override.
/// <para>
/// Two things are out of reach here. The tpm2-tss TCTI module is loaded later, at the first TPM
/// call, by name; the environment check is what covers it. And the .NET runtime's own injection
/// points (startup hooks, CLR profilers) are not dynamic-linker settings; protect the service's
/// environment for those, as on every platform.
/// </para>
/// </summary>
internal static class LinuxNativeLibraryLoader
{
    /// <summary>The library's SONAME, which the package installs as a regular file.</summary>
    internal const string FileName = "libhkdfguard.so.1";

    /// <summary>The RPM packages' library directory, used when there is no Debian multiarch one.</summary>
    internal const string Lib64Directory = "/usr/lib64";

    /// <summary>An export every genuine build has; its address tells dladdr which file was loaded.</summary>
    internal const string ProbeExport = "hkdfguard_wrap_dek";

    /// <summary>
    /// The SHA-256 of every native release this assembly accepts, with what it is. Each distribution
    /// and architecture gets its own build, so each needs its own entry; a release whose hash is
    /// not here is refused until this assembly is updated to list it.
    /// </summary>
    internal static readonly FrozenDictionary<string, string> KnownReleases = new Dictionary<string, string>
    {
        ["a3a9312fd2d603a62e6a5b1ed46ba5e4a51adcba321aa5a1014a762ff07ca064"] = "libhkdfguard1 0.1.0-1~ubuntu24.04.1 (amd64)",
    }.ToFrozenDictionary(StringComparer.Ordinal);

    // The dynamic-linker variables that decide where, or what, it loads.
    internal const string LibraryPathVariable = "LD_LIBRARY_PATH";
    internal const string PreloadVariable = "LD_PRELOAD";
    internal const string AuditVariable = "LD_AUDIT";

    // The kernel's own limit on symbolic links followed in one lookup.
    internal const int MaxSymbolicLinks = 40;

    private const int ENOENT = 2;
    private const int ENOTDIR = 20;

    private static readonly Lock Gate = new();
    private static IntPtr _handle;

    /// <summary>
    /// Verifies and loads the installed library, once per process; later calls return the same
    /// handle. A failure isn't cached, so a fixed installation is picked up on the next call.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">The process is neither x64 nor arm64.</exception>
    /// <exception cref="DllNotFoundException">The library is not installed.</exception>
    /// <exception cref="SecurityException">The installed file, its location, its dependencies or the environment failed verification.</exception>
    [SupportedOSPlatform("linux")]
    [ExcludeFromCodeCoverage(Justification = "Wires the covered policy methods to Linux system calls; exercised by the installed-library tests where the package is present.")]
    public static IntPtr Load()
    {
        lock (Gate)
        {
            if (_handle != IntPtr.Zero)
                return _handle;

            var candidates = CandidatePaths(RuntimeInformation.ProcessArchitecture);
            var path = ResolveTrusted(ChoosePath(candidates, LinuxNative.Probe), UnixFileType.RegularFile, LinuxNative.GetStatusOrNull, LinuxNative.ReadLink)!;
            VerifyContent(path, HashFile, KnownReleases);

            var environment = ReadEnvironment(Environment.GetEnvironmentVariable, LinuxNative.ReadInitialEnvironment());
            VerifyEnvironment(environment, (p, type) => ResolveTrusted(p, type, LinuxNative.GetStatusOrNull, LinuxNative.ReadLink, allowMissing: true));

            var handle = NativeLibrary.Load(path);
            try
            {
                string Trusted(string p) => ResolveTrusted(p, UnixFileType.RegularFile, LinuxNative.GetStatusOrNull, LinuxNative.ReadLink)!;

                var loaded = NativeLibrary.TryGetExport(handle, ProbeExport, out var export) ? LinuxNative.GetImagePath(export) : null;
                VerifyLoadedImage(path, loaded is null ? null : Trusted(loaded));
                VerifyDependencies(path, ElfDependencies.ReadNeeded, LinuxNative.GetLoadedPath, Trusted);
            }
            catch
            {
                NativeLibrary.Free(handle);
                throw;
            }

            _handle = handle;
            return _handle;
        }
    }

    /// <summary>
    /// Where the package may have installed the library for a process of
    /// <paramref name="processArchitecture"/>, in the order they are tried.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">No package is built for that architecture.</exception>
    internal static string[] CandidatePaths(Architecture processArchitecture)
    {
        var triplet = processArchitecture switch
        {
            Architecture.X64 => "x86_64-linux-gnu",
            Architecture.Arm64 => "aarch64-linux-gnu",
            _ => throw new PlatformNotSupportedException(
                $"The HkdfGuard native KMS library is built for x64 and arm64 Linux only; this process is {processArchitecture}."),
        };

        return [$"/usr/lib/{triplet}/{FileName}", $"{Lib64Directory}/{FileName}"];
    }

    /// <summary>
    /// The first candidate that exists. "Exists" is decided by statx, so "can't look" is never
    /// mistaken for "not there".
    /// </summary>
    /// <param name="probe">statx's result for a path: 0 if it exists, else the errno.</param>
    /// <exception cref="DllNotFoundException">None exists.</exception>
    /// <exception cref="SecurityException">A candidate could not be examined.</exception>
    internal static string ChoosePath(IReadOnlyList<string> candidates, Func<string, int> probe)
    {
        foreach (var candidate in candidates)
        {
            var errno = probe(candidate);
            if (errno == 0)
                return candidate;
            if (errno is not (ENOENT or ENOTDIR))
                throw new SecurityException(
                    $"Could not tell whether the HkdfGuard native library '{candidate}' exists (statx failed with errno {errno}); refusing to guess or to fall back to another location.");
        }

        throw new DllNotFoundException(
            $"The HkdfGuard native KMS library is not installed. Install the libhkdfguard1 package (hkdfguard-libs on RPM distributions); it is loaded only from {string.Join(" or ", candidates.Select(c => $"'{c}'"))}.");
    }

    /// <summary>
    /// Resolves <paramref name="path"/> the way the kernel would, checking everything it passes
    /// through: every directory and the final object must be owned by root and writable by
    /// neither group nor others, and every symbolic link must be owned by root (its target is then
    /// resolved and checked in turn). Returns the resolved path, which contains no symbolic links.
    /// </summary>
    /// <param name="getStatus">lstat-style status of a path, or null if nothing is there.</param>
    /// <param name="readLink">A symbolic link's stored target.</param>
    /// <param name="allowMissing">
    /// When true, a path that runs into a missing component returns null instead of throwing:
    /// everything up to it was checked, so only root could create what is missing.
    /// </param>
    /// <exception cref="SecurityException">A check failed, or the final object is not of <paramref name="expectedType"/>.</exception>
    internal static string? ResolveTrusted(string path, UnixFileType expectedType, Func<string, UnixFileStatus?> getStatus, Func<string, string?> readLink, bool allowMissing = false)
    {
        if (!path.StartsWith('/'))
            throw new SecurityException($"'{path}' is not an absolute path; the HkdfGuard native library and its dependencies are only trusted at absolute paths.");

        var root = getStatus("/") ?? throw new SecurityException("'/' could not be examined.");
        RequireRootControlled("/", root);

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
                throw new SecurityException($"'{path}' runs through '{resolved}', which is not a directory.");

            if (name == "..")
            {
                // resolved never contains a symbolic link, so its parent is its lexical parent.
                resolved = ParentOf(resolved);
                continue;
            }

            var candidate = resolved == "/" ? $"/{name}" : $"{resolved}/{name}";
            if (getStatus(candidate) is not { } status)
                return allowMissing ? null : throw new SecurityException($"'{candidate}' does not exist (resolving '{path}').");

            if (status.Type == UnixFileType.SymbolicLink)
            {
                if (status.OwnerId != 0)
                    throw new SecurityException($"'{candidate}' is a symbolic link owned by uid {status.OwnerId}; only links owned by root are followed (resolving '{path}').");
                if (++linksFollowed > MaxSymbolicLinks)
                    throw new SecurityException($"'{path}' follows more than {MaxSymbolicLinks} symbolic links.");

                var target = readLink(candidate) ?? throw new SecurityException($"'{candidate}' could not be read as a symbolic link.");
                if (target.StartsWith('/'))
                    resolved = "/";
                PushComponents(pending, target);
                continue;
            }

            RequireRootControlled(candidate, status);
            resolved = candidate;
            resolvedType = status.Type;
        }

        if (resolvedType != expectedType)
            throw new SecurityException($"'{path}' resolves to '{resolved}', which is a {Describe(resolvedType)}, not a {Describe(expectedType)}.");

        return resolved;
    }

    private static void RequireRootControlled(string path, UnixFileStatus status)
    {
        if (status.OwnerId != 0)
            throw new SecurityException(
                $"'{path}' is owned by uid {status.OwnerId}; the HkdfGuard native library and its dependencies are only trusted in locations owned by root.");

        if ((status.Permissions & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new SecurityException(
                $"'{path}' is writable by its group or by every user; the HkdfGuard native library and its dependencies are only trusted in locations only root can modify.");
    }

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

    /// <summary>Requires the file's SHA-256 to be a known release.</summary>
    /// <exception cref="SecurityException">It isn't.</exception>
    internal static void VerifyContent(string path, Func<string, string> sha256Hex, IReadOnlyDictionary<string, string> knownReleases)
    {
        var hash = sha256Hex(path);
        if (!knownReleases.ContainsKey(hash))
            throw new SecurityException(
                $"'{path}' has SHA-256 {hash}, which is not a HkdfGuard native release this version of HkdfGuard.KeyWrapping.V1 recognizes; refusing to load it. If it is a newer genuine release, update HkdfGuard.KeyWrapping.V1.");
    }

    [ExcludeFromCodeCoverage(Justification = "One-line adapter over SHA256.HashData; the decision is VerifyContent's.")]
    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    /// <summary>
    /// Every value each dynamic-linker variable has had: in the environment the process started
    /// with (<paramref name="initialEnvironment"/>, /proc/self/environ's NUL-separated block, if it
    /// could be read) and in the current one.
    /// </summary>
    internal static IReadOnlyDictionary<string, IReadOnlyList<string>> ReadEnvironment(Func<string, string?> current, byte[]? initialEnvironment)
    {
        string[] names = [LibraryPathVariable, PreloadVariable, AuditVariable];
        var values = names.ToDictionary(n => n, _ => new List<string>(), StringComparer.Ordinal);

        if (initialEnvironment is not null)
        {
            foreach (var entry in Encoding.UTF8.GetString(initialEnvironment).Split('\0'))
            {
                var equals = entry.IndexOf('=');
                if (equals > 0 && values.TryGetValue(entry[..equals], out var list))
                    list.Add(entry[(equals + 1)..]);
            }
        }

        foreach (var name in names)
        {
            if (current(name) is { } value && !values[name].Contains(value))
                values[name].Add(value);
        }

        return values.ToDictionary(p => p.Key, p => (IReadOnlyList<string>)p.Value, StringComparer.Ordinal);
    }

    /// <summary>
    /// Requires every location the dynamic-linker variables could make it load from to pass the
    /// path checks.
    /// </summary>
    /// <param name="environment">Every value of each variable (see <see cref="ReadEnvironment"/>).</param>
    /// <param name="resolveTrusted">
    /// <see cref="ResolveTrusted"/> with missing paths allowed: throws if the path is untrusted,
    /// returns null if nothing is there.
    /// </param>
    /// <exception cref="SecurityException">A value names a location that isn't trusted.</exception>
    internal static void VerifyEnvironment(IReadOnlyDictionary<string, IReadOnlyList<string>> environment, Func<string, UnixFileType, string?> resolveTrusted)
    {
        // An empty LD_LIBRARY_PATH is ignored by the dynamic linker; an empty entry within one is
        // the working directory.
        foreach (var value in environment.GetValueOrDefault(LibraryPathVariable) ?? [])
        {
            if (value.Length == 0)
                continue;

            foreach (var entry in value.Split(':', ';'))
            {
                if (entry.Length == 0)
                    throw Untrusted(LibraryPathVariable, value, "an empty entry, which means the working directory");
                VerifyLocation(LibraryPathVariable, value, entry, UnixFileType.Directory, resolveTrusted);
            }
        }

        // Objects to preload or audit: separated by spaces or colons (LD_PRELOAD), or colons
        // (LD_AUDIT). A bare name is found by the same search as any dependency, which the
        // LD_LIBRARY_PATH check above already covers.
        foreach (var (variable, separators) in new[] { (PreloadVariable, new[] { ' ', ':' }), (AuditVariable, new[] { ':' }) })
        {
            foreach (var value in environment.GetValueOrDefault(variable) ?? [])
            {
                foreach (var entry in value.Split(separators, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (entry.Contains('/') || entry.Contains('$'))
                        VerifyLocation(variable, value, entry, UnixFileType.RegularFile, resolveTrusted);
                }
            }
        }
    }

    private static void VerifyLocation(string variable, string value, string entry, UnixFileType type, Func<string, UnixFileType, string?> resolveTrusted)
    {
        if (entry.Contains('$'))
            throw Untrusted(variable, value, $"'{entry}', which uses a dynamic string token ($ORIGIN, $LIB or $PLATFORM) that can't be checked in advance");
        if (!entry.StartsWith('/'))
            throw Untrusted(variable, value, $"'{entry}', which is relative to the working directory");

        try
        {
            resolveTrusted(entry, type);
        }
        catch (Exception e) when (e is SecurityException or IOException)
        {
            throw new SecurityException(
                $"{variable} ('{value}') names '{entry}', which the dynamic linker could load the HkdfGuard native library's dependencies from: {e.Message} Remove it from {variable}, or make it a location only root can modify.", e);
        }
    }

    private static SecurityException Untrusted(string variable, string value, string what)
        => new($"{variable} ('{value}') contains {what}; the dynamic linker could load the HkdfGuard native library's dependencies from there. Refusing to load it.");

    /// <summary>Requires that the file the dynamic linker reports having loaded is the one that was verified.</summary>
    /// <param name="expectedPath">The verified path that was passed to dlopen.</param>
    /// <param name="loadedPath">The resolved path dladdr reports for the library's export, or null if it has no such export or the linker can't say.</param>
    /// <exception cref="SecurityException">They differ.</exception>
    internal static void VerifyLoadedImage(string expectedPath, string? loadedPath)
    {
        if (loadedPath is null)
            throw new SecurityException(
                $"The library loaded for '{expectedPath}' has no '{ProbeExport}' export, or the dynamic linker cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.");

        if (loadedPath != expectedPath)
            throw new SecurityException(
                $"The dynamic linker bound '{expectedPath}' to '{loadedPath}', a different file; it has been unloaded and the HkdfGuard native library was not loaded.");
    }

    /// <summary>
    /// Walks the library's dependency closure - each file's DT_NEEDED names, then theirs - and
    /// requires every one to be bound to a trusted file.
    /// </summary>
    /// <param name="libraryPath">The verified library.</param>
    /// <param name="readNeeded">A file's DT_NEEDED names.</param>
    /// <param name="loadedPathOf">The path of the already-loaded object a name is bound to, or null if none is.</param>
    /// <param name="resolveTrusted">Resolves a path, throwing unless it passes the path checks.</param>
    /// <exception cref="SecurityException">A dependency is not loaded from a trusted file.</exception>
    internal static void VerifyDependencies(string libraryPath, Func<string, IReadOnlyList<string>> readNeeded, Func<string, string?> loadedPathOf, Func<string, string> resolveTrusted)
    {
        var visited = new HashSet<string>(StringComparer.Ordinal) { libraryPath };
        var pending = new Queue<string>([libraryPath]);

        while (pending.TryDequeue(out var file))
        {
            foreach (var name in readNeeded(file))
            {
                var loaded = loadedPathOf(name)
                    ?? throw new SecurityException($"'{file}' depends on '{name}', but no loaded object answers to that name; cannot tell where it came from.");

                string resolved;
                try
                {
                    resolved = resolveTrusted(loaded);
                }
                catch (Exception e) when (e is SecurityException or IOException)
                {
                    throw new SecurityException(
                        $"The HkdfGuard native library's dependency '{name}' (needed by '{file}') was loaded from '{loaded}', which is not trusted: {e.Message}", e);
                }

                if (visited.Add(resolved))
                    pending.Enqueue(resolved);
            }
        }
    }

    // Never a symbolic link: ResolveTrusted always follows them.
    private static string Describe(UnixFileType type) => type switch
    {
        UnixFileType.Directory => "directory",
        UnixFileType.RegularFile => "regular file",
        _ => "special file",
    };
}
