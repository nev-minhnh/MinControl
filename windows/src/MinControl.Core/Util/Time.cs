using System.Diagnostics;
using System.Globalization;
using MinControl.Core.Abstractions;

namespace MinControl.Core.Util;

/// <summary>RFC 3339 UTC helpers. Wire format is always <c>yyyy-MM-ddTHH:mm:ssZ</c> (whole seconds, Z suffix).</summary>
public static class Time
{
    public static string Utc(DateTimeOffset t) =>
        t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>Parses an RFC 3339 timestamp that must end in Z. Returns false on anything else.</summary>
    public static bool TryParseUtc(string? s, out DateTimeOffset value)
    {
        value = default;
        if (string.IsNullOrEmpty(s) || !s.EndsWith('Z')) return false;
        return DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value);
    }

    public static DateTimeOffset ParseUtc(string s) =>
        TryParseUtc(s, out var v) ? v : throw new FormatException($"not an RFC 3339 UTC timestamp: '{s}'");

    /// <summary>Local calendar day key (yyyy-MM-dd) of <paramref name="utc"/> in <paramref name="tz"/>.</summary>
    public static string DayKey(DateTimeOffset utc, TimeZoneInfo tz) =>
        TimeZoneInfo.ConvertTime(utc, tz).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}

/// <summary>Production clock: wall clock from the OS, monotonic ms from <see cref="Stopwatch"/> (process start based).</summary>
public sealed class SystemClock : IClock
{
    private readonly long _start = Stopwatch.GetTimestamp();
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    public long MonotonicMs => (long)Stopwatch.GetElapsedTime(_start).TotalMilliseconds;
}

/// <summary>Resolves IANA ids (policy timezone) to <see cref="TimeZoneInfo"/>; cached.</summary>
public static class TimeZones
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, TimeZoneInfo?> Cache = new();

    public static TimeZoneInfo? TryFind(string ianaId) => Cache.GetOrAdd(ianaId, id =>
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById(id); }
        catch (TimeZoneNotFoundException) { }
        catch (InvalidTimeZoneException) { }
        try
        {
            return TimeZoneInfo.TryConvertIanaIdToWindowsId(id, out var win) ? TimeZoneInfo.FindSystemTimeZoneById(win) : null;
        }
        catch (Exception) { return null; }
    });

    public static TimeZoneInfo Find(string ianaId) =>
        TryFind(ianaId) ?? throw new TimeZoneNotFoundException($"unknown IANA timezone '{ianaId}'");
}
