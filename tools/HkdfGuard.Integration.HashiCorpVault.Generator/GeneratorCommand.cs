using System.Text;

namespace HkdfGuard.Integration.HashiCorpVault.Generator;

/// <summary>
/// The generator's command line: [--spec &lt;openapi.json&gt;] [--settings &lt;generator.json&gt;]
/// [--output &lt;directory&gt;]. The spec and output default to the library's own, found from the
/// repository root - the directory holding HkdfGuard.sln, at or above the current one - and the
/// settings to generator.json beside the spec, if there is one (see VaultClientGenerator). Files are
/// only rewritten when they change, and *.g.cs files the spec no longer produces are deleted.
/// </summary>
internal static class GeneratorCommand
{
    /// <summary>The settings file looked for beside the spec.</summary>
    public const string SettingsFileName = "generator.json";

    /// <returns>0 on success, 2 for bad arguments or no repository root.</returns>
    public static int Run(IReadOnlyList<string> args, string currentDirectory, TextWriter output, TextWriter error)
    {
        string? spec = null, settings = null, outputDirectory = null;
        for (var i = 0; i < args.Count; i++)
        {
            switch (args[i])
            {
                case "--spec" when i + 1 < args.Count:
                    spec = args[++i];
                    break;
                case "--settings" when i + 1 < args.Count:
                    settings = args[++i];
                    break;
                case "--output" when i + 1 < args.Count:
                    outputDirectory = args[++i];
                    break;
                default:
                    error.WriteLine($"Unknown argument '{args[i]}'. Usage: [--spec <openapi.json>] [--settings <generator.json>] [--output <directory>]");
                    return 2;
            }
        }

        if (spec is null || outputDirectory is null)
        {
            if (RepositoryRoot(currentDirectory) is not { } root)
            {
                error.WriteLine("Couldn't find the repository root (HkdfGuard.sln) at or above the current directory; run from inside it, or pass --spec and --output.");
                return 2;
            }

            var library = Path.Combine(root, "src", "HkdfGuard.Integration.HashiCorpVault");
            spec ??= Path.Combine(library, "openapi.json");
            outputDirectory ??= Path.Combine(library, "Generated");
        }

        settings ??= Path.Combine(Path.GetDirectoryName(Path.GetFullPath(spec))!, SettingsFileName);
        var hasSettings = File.Exists(settings);
        var files = VaultClientGenerator.Generate(File.ReadAllText(spec), hasSettings ? File.ReadAllText(settings) : null);
        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var written = 0;
        foreach (var (relative, content) in files)
        {
            var path = Path.Combine(outputDirectory, relative.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(path) && File.ReadAllText(path, utf8).ReplaceLineEndings("\n") == content)
                continue;

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content, utf8);
            written++;
        }

        var expected = files.Keys
            .Select(relative => Path.GetFullPath(Path.Combine(outputDirectory, relative.Replace('/', Path.DirectorySeparatorChar))))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var deleted = 0;
        foreach (var stale in Directory.EnumerateFiles(outputDirectory, "*.g.cs", SearchOption.AllDirectories))
        {
            if (!expected.Contains(Path.GetFullPath(stale)))
            {
                File.Delete(stale);
                deleted++;
            }
        }

        output.WriteLine($"{files.Count} files from {spec}{(hasSettings ? " with " + settings : "")}: {written} written, {files.Count - written} unchanged, {deleted} stale deleted, in {outputDirectory}.");
        return 0;
    }

    private static string? RepositoryRoot(string start)
    {
        for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HkdfGuard.sln")))
                return directory.FullName;
        }

        return null;
    }
}
