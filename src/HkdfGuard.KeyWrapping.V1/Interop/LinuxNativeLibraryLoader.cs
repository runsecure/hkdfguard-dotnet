using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
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
/// lies, so a link can only lead somewhere root chose (/lib to usr/lib, say). Linux has no
/// platform code signature and the file is not content-pinned: a release's authenticity is
/// verified with Sigstore/cosign when the package is installed, so path integrity is what this
/// loader enforces.</item>
/// <item><b>Environment.</b> An absolute path is never searched for, but the library's
/// dependencies are found by name: through LD_LIBRARY_PATH, and after LD_PRELOAD and LD_AUDIT
/// objects that can interpose on any symbol. So every directory on LD_LIBRARY_PATH and every
/// path-named LD_PRELOAD or LD_AUDIT object must pass the same path checks, and none may be
/// relative, empty (the working directory) or use $ORIGIN-style substitutions. Both the
/// environment the process started with (/proc/self/environ, what the dynamic linker read) and
/// the current one are checked.</item>
/// <item><b>What would be loaded.</b> Before dlopen, the process's own dynamic linker (its
/// PT_INTERP, which must itself pass the path checks) is asked, in list mode (ld.so --list, the
/// mechanism ldd uses), where it would find every object the library pulls in, under the
/// LD_LIBRARY_PATH and LD_PRELOAD the process started with. List mode resolves exactly as dlopen
/// would - RUNPATH, ld.so.cache and all - but runs none of the libraries' code, so every path it
/// reports must pass the path checks before any of it can run here. A name it can't find refuses
/// the load.</item>
/// <item><b>What was loaded.</b> After dlopen, dladdr must place the library's export in the
/// verified file, and every object in its dependency closure (read from each file's DT_NEEDED
/// entries) must be bound to a file that passes the path checks. This catches what list mode
/// can't see: a dependency name the process had already bound to some other object before the
/// library was loaded. On failure the library is unloaded - though, as on macOS, any initializer
/// an impostor had has already run; the checks before loading exist so that it never gets that
/// far in practice.</item>
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

    // The dynamic-linker variables that decide where, or what, it loads.
    internal const string LibraryPathVariable = "LD_LIBRARY_PATH";
    internal const string PreloadVariable = "LD_PRELOAD";
    internal const string AuditVariable = "LD_AUDIT";

    // The kernel's own limit on symbolic links followed in one lookup.
    internal const int MaxSymbolicLinks = 40;

    /// <summary>How long the dynamic linker's list run may take: it only maps files and reads headers.</summary>
    internal static readonly TimeSpan ListingTimeout = TimeSpan.FromSeconds(30);

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

            var initialEnvironment = LinuxNative.ReadInitialEnvironment();
            var environment = ReadEnvironment(Environment.GetEnvironmentVariable, initialEnvironment);
            VerifyEnvironment(environment, (p, type) => ResolveTrusted(p, type, LinuxNative.GetStatusOrNull, LinuxNative.ReadLink, allowMissing: true));

            string Trusted(string p) => ResolveTrusted(p, UnixFileType.RegularFile, LinuxNative.GetStatusOrNull, LinuxNative.ReadLink)!;
            VerifyBeforeLoading(path, initialEnvironment, Trusted);

            var handle = NativeLibrary.Load(path);
            try
            {
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

    /// <summary>
    /// Asks this process's own dynamic linker, in list mode, where it would find everything
    /// <paramref name="library"/> pulls in, and requires each of those files to pass the path
    /// checks - before dlopen, so nothing that would fail them ever runs here.
    /// </summary>
    /// <param name="library">The verified library.</param>
    /// <param name="initialEnvironment">/proc/self/environ's block, or null if it could not be read.</param>
    /// <param name="resolveTrusted">Resolves a path, throwing unless it passes the path checks.</param>
    /// <exception cref="SecurityException">The dynamic linker is untrusted, can't say, or would load an untrusted file.</exception>
    [SupportedOSPlatform("linux")]
    [ExcludeFromCodeCoverage(Justification = "Wires the covered policy methods to /proc/self/exe and the dynamic linker; its parts run against the real dynamic linker in the Linux-only tests.")]
    internal static void VerifyBeforeLoading(string library, byte[]? initialEnvironment, Func<string, string> resolveTrusted)
    {
        string? interpreter;
        try
        {
            interpreter = ElfDependencies.ReadInterpreter("/proc/self/exe");
        }
        catch (Exception e) when (e is SecurityException or IOException or UnauthorizedAccessException)
        {
            throw new SecurityException($"Could not read which dynamic linker this process runs under: {e.Message}", e);
        }

        if (interpreter is null)
            throw new SecurityException(
                $"This process has no dynamic linker (a statically linked executable), so it can't be asked what '{library}' would load; refusing to load it.");

        string trustedInterpreter;
        try
        {
            trustedInterpreter = resolveTrusted(interpreter);
        }
        catch (Exception e) when (e is SecurityException or IOException)
        {
            throw new SecurityException(
                $"This process's dynamic linker '{interpreter}' is not trusted, so it can't be asked what '{library}' would load: {e.Message}", e);
        }

        var output = ListDependencies(trustedInterpreter, library, ListingEnvironment(initialEnvironment));
        VerifyListing(library, ParseListing(library, output), resolveTrusted);
    }

    /// <summary>
    /// Runs <c><paramref name="interpreter"/> --list <paramref name="library"/></c> - directly, no
    /// shell - with exactly <paramref name="environment"/>, and returns what it printed.
    /// </summary>
    /// <exception cref="SecurityException">The run could not start, failed or timed out.</exception>
    [SupportedOSPlatform("linux")]
    [ExcludeFromCodeCoverage(Justification = "Starts the real dynamic linker; exercised by the Linux-only tests.")]
    internal static string ListDependencies(string interpreter, string library, IReadOnlyDictionary<string, string> environment)
    {
        var startInfo = new ProcessStartInfo(interpreter)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        startInfo.ArgumentList.Add("--list");
        startInfo.ArgumentList.Add(library);
        // Starts as a copy of this process's environment; the run gets only what is listed.
        startInfo.Environment.Clear();
        foreach (var (name, value) in environment)
            startInfo.Environment[name] = value;

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException)
        {
            throw new SecurityException($"The dynamic linker '{interpreter}' could not be started to say what '{library}' would load: {e.Message}", e);
        }

        process.StandardInput.Close();
        // Both pipes are drained concurrently, so neither can fill and stall the run.
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(ListingTimeout))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception e) when (e is InvalidOperationException or Win32Exception)
            {
                // It exited on its own in the meantime.
            }

            process.WaitForExit();
            throw new SecurityException($"The dynamic linker did not say within {ListingTimeout.TotalSeconds:0} seconds what '{library}' would load; refusing to load it.");
        }

        process.WaitForExit(); // lets the redirected streams reach their end
        var output = stdout.GetAwaiter().GetResult();
        var errors = stderr.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
            throw new SecurityException(
                $"The dynamic linker could not say what '{library}' would load (exit status {process.ExitCode}: {errors.Trim()}); refusing to load it.");

        return output;
    }

    /// <summary>
    /// The whole environment the dynamic linker's list mode runs with: the LD_LIBRARY_PATH and
    /// LD_PRELOAD the process started with - what dlopen itself uses, since the linker reads them
    /// once at startup - and nothing else. LD_AUDIT is left out: an audit module is code the list
    /// run would execute, and its locations were already checked before this runs. Where a
    /// variable appears more than once, the last value is kept, as the dynamic linker does.
    /// </summary>
    /// <param name="initialEnvironment">/proc/self/environ's NUL-separated block, or null if it could not be read.</param>
    /// <exception cref="SecurityException">One of the two variables is not valid UTF-8, so it can't be passed on unchanged.</exception>
    internal static IReadOnlyDictionary<string, string> ListingEnvironment(byte[]? initialEnvironment)
    {
        var environment = new Dictionary<string, string>(StringComparer.Ordinal);
        if (initialEnvironment is null)
            return environment;

        var strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        var prefixes = new[] { LibraryPathVariable, PreloadVariable }.Select(n => (Name: n, Prefix: Encoding.ASCII.GetBytes(n + "="))).ToArray();
        ReadOnlySpan<byte> block = initialEnvironment;
        while (!block.IsEmpty)
        {
            var end = block.IndexOf((byte)0);
            var entry = end < 0 ? block : block[..end];
            block = end < 0 ? ReadOnlySpan<byte>.Empty : block[(end + 1)..];

            foreach (var (name, prefix) in prefixes)
            {
                if (!entry.StartsWith(prefix))
                    continue;

                try
                {
                    environment[name] = strict.GetString(entry[prefix.Length..]);
                }
                catch (DecoderFallbackException e)
                {
                    throw new SecurityException($"{name} in this process's startup environment is not valid UTF-8, so the dynamic linker can't be asked what it would load under it; refusing to load the HkdfGuard native library.", e);
                }
            }
        }

        return environment;
    }

    /// <summary>
    /// Every file path in the output of the dynamic linker's list mode, in order. Its lines are
    /// "\tname => /path (0xaddress)", "\t/path (0xaddress)" (the linker itself and preloaded
    /// objects) and "\tname (0xaddress)" (the vDSO, which has no file). A name it couldn't find
    /// ("=> not found"), or any line in another form, refuses: what can't be read can't be checked.
    /// </summary>
    /// <param name="library">The library that was listed, for messages.</param>
    /// <exception cref="SecurityException">A dependency was not found, or a line can't be read.</exception>
    internal static IReadOnlyList<string> ParseListing(string library, string output)
    {
        const string NotFound = " => not found";
        var paths = new List<string>();
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
                continue;

            if (line.EndsWith(NotFound, StringComparison.Ordinal))
                throw new SecurityException($"The dynamic linker can't find '{line[..^NotFound.Length]}', which '{library}' needs; refusing to load it.");

            var open = line.LastIndexOf(" (0x", StringComparison.Ordinal);
            if (open < 0 || !line.EndsWith(')'))
                throw new SecurityException($"The dynamic linker's list of what '{library}' would load has a line this loader doesn't understand ('{line}'); refusing to load it.");

            var entry = line[..open];
            var arrow = entry.IndexOf(" => ", StringComparison.Ordinal);
            if (arrow >= 0)
                entry = entry[(arrow + " => ".Length)..];

            if (!entry.StartsWith('/'))
            {
                if (entry.Contains('/') || entry.Contains(' '))
                    throw new SecurityException($"The dynamic linker would load '{entry}' for '{library}', which is not an absolute path; refusing to load it.");
                continue; // the vDSO: in the kernel, not a file
            }

            paths.Add(entry);
        }

        return paths;
    }

    /// <summary>Requires every path the dynamic linker's list mode reported to pass the path checks.</summary>
    /// <param name="library">The library that was listed, for messages.</param>
    /// <param name="paths">What <see cref="ParseListing"/> returned.</param>
    /// <param name="resolveTrusted">Resolves a path, throwing unless it passes the path checks.</param>
    /// <exception cref="SecurityException">A path is not trusted; the first one is named.</exception>
    internal static void VerifyListing(string library, IReadOnlyList<string> paths, Func<string, string> resolveTrusted)
    {
        foreach (var path in paths)
        {
            try
            {
                resolveTrusted(path);
            }
            catch (Exception e) when (e is SecurityException or IOException)
            {
                throw new SecurityException($"Loading '{library}' would also load '{path}', which is not trusted; nothing was loaded: {e.Message}", e);
            }
        }
    }

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
