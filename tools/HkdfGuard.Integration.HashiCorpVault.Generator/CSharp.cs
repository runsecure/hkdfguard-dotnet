using System.Text;
using System.Text.RegularExpressions;

namespace HkdfGuard.Integration.HashiCorpVault.Generator;

/// <summary>Turning the spec's names and prose into C# identifiers, literals and XML doc comments.</summary>
internal static partial class CSharp
{
    private static readonly HashSet<string> Keywords =
    [
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked", "class", "const", "continue",
        "decimal", "default", "delegate", "do", "double", "else", "enum", "event", "explicit", "extern", "false", "finally",
        "fixed", "float", "for", "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock",
        "long", "namespace", "new", "null", "object", "operator", "out", "override", "params", "private", "protected",
        "public", "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof", "stackalloc", "static", "string",
        "struct", "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort",
        "using", "virtual", "void", "volatile", "while",
    ];

    /// <summary>name in PascalCase: split at anything but letters and digits, each part's first letter capitalized - "kv-v2-read" is KvV2Read, as openapi-generator names it.</summary>
    public static string Pascal(string name)
    {
        var result = new StringBuilder();
        foreach (var part in NonAlphanumeric().Split(name))
        {
            if (part.Length > 0)
                result.Append(char.ToUpperInvariant(part[0])).Append(part, 1, part.Length - 1);
        }

        if (result.Length == 0)
            return "Value";
        // Letters and digits only: one can't start with a digit.
        return (char.IsLetter(result[0]) ? "" : "_") + result.ToString();
    }

    /// <summary>name in camelCase, escaped with @ if it's a keyword.</summary>
    public static string Camel(string name)
    {
        var pascal = Pascal(name);
        var camel = pascal[0] == '_' ? pascal : char.ToLowerInvariant(pascal[0]) + pascal[1..];
        return Keywords.Contains(camel) ? "@" + camel : camel;
    }

    /// <summary>value as a C# string literal.</summary>
    public static string Literal(string value)
    {
        var result = new StringBuilder("\"");
        foreach (var c in value)
        {
            result.Append(c switch
            {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ when char.IsControl(c) => $"\\u{(int)c:x4}",
                _ => c.ToString(),
            });
        }

        return result.Append('"').ToString();
    }

    /// <summary>text for an XML doc comment: whitespace collapsed to single spaces, &amp;, &lt; and &gt; escaped.</summary>
    public static string Xml(string text)
        => Whitespace().Replace(text, " ").Trim().Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    [GeneratedRegex("[^A-Za-z0-9]+")]
    private static partial Regex NonAlphanumeric();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
