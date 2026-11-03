using System.Globalization;
using System.Text;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>Go's duration syntax - "1h30m", "300ms", "2.5s" - which Vault and its environment variables use.</summary>
internal static class GoDuration
{
    private const long NanosecondsPerTick = 100;

    /// <summary>time.ParseDuration: an optional sign, then one or more decimal numbers each with a unit (ns, us, µs, ms, s, m, h); "0" alone needs none.</summary>
    /// <exception cref="FormatException">value isn't a duration</exception>
    /// <exception cref="OverflowException">value is longer than a TimeSpan holds</exception>
    public static TimeSpan Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var s = value.AsSpan();
        var negative = false;
        if (s.Length > 0 && s[0] is '-' or '+')
        {
            negative = s[0] == '-';
            s = s[1..];
        }

        if (s is "0")
            return TimeSpan.Zero;
        if (s.IsEmpty)
            throw new FormatException($"Invalid duration '{value}'.");

        decimal nanoseconds = 0;
        while (!s.IsEmpty)
        {
            var digits = 0;
            while (digits < s.Length && (char.IsAsciiDigit(s[digits]) || s[digits] == '.'))
                digits++;
            var number = s[..digits];
            if (number.IsEmpty || number is "." || number.IndexOf('.') != number.LastIndexOf('.'))
                throw new FormatException($"Invalid duration '{value}'.");
            s = s[digits..];

            var unitLength = 0;
            while (unitLength < s.Length && !char.IsAsciiDigit(s[unitLength]) && s[unitLength] != '.')
                unitLength++;
            decimal perUnit = s[..unitLength] switch
            {
                "ns" => 1,
                "us" or "µs" or "μs" => 1_000,
                "ms" => 1_000_000,
                "s" => 1_000_000_000,
                "m" => 60_000_000_000,
                "h" => 3_600_000_000_000,
                [] => throw new FormatException($"Missing unit in duration '{value}'."),
                _ => throw new FormatException($"Unknown unit '{s[..unitLength].ToString()}' in duration '{value}'."),
            };
            s = s[unitLength..];

            nanoseconds += decimal.Parse(number.StartsWith('.') ? "0" + number.ToString() : number.ToString(), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture) * perUnit;
        }

        var ticks = decimal.Truncate(nanoseconds / NanosecondsPerTick);
        if (ticks > TimeSpan.MaxValue.Ticks)
            throw new OverflowException($"The duration '{value}' is too long.");

        return TimeSpan.FromTicks((long)(negative ? -ticks : ticks));
    }

    /// <summary>Duration.String: "1h2m3.5s", "5m0s", "1.5ms", "0s".</summary>
    public static string Format(TimeSpan duration)
    {
        if (duration == TimeSpan.Zero)
            return "0s";

        var result = new StringBuilder();
        if (duration < TimeSpan.Zero)
            result.Append('-');
        var nanoseconds = (ulong)Math.Abs((decimal)duration.Ticks) * NanosecondsPerTick;

        if (nanoseconds < 1_000_000_000)
        {
            var small = nanoseconds switch
            {
                < 1_000 => $"{nanoseconds}ns",
                < 1_000_000 => Fraction(nanoseconds, 1_000) + "µs",
                _ => Fraction(nanoseconds, 1_000_000) + "ms",
            };
            return result.Append(small).ToString();
        }

        var minutes = nanoseconds / 60_000_000_000;
        var hours = minutes / 60;
        if (hours > 0)
            result.Append(hours).Append('h');
        if (minutes > 0)
            result.Append(minutes % 60).Append('m');
        return result.Append(Fraction(nanoseconds % 60_000_000_000, 1_000_000_000)).Append('s').ToString();
    }

    // value / unit, with as many fractional digits as it needs.
    private static string Fraction(ulong value, ulong unit)
    {
        var whole = (value / unit).ToString(CultureInfo.InvariantCulture);
        var fraction = value % unit;
        if (fraction == 0)
            return whole;

        var width = (int)Math.Log10(unit);
        return whole + "." + fraction.ToString(CultureInfo.InvariantCulture).PadLeft(width, '0').TrimEnd('0');
    }
}
