using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MinControl.Core.Storage;

/// <summary>
/// "Expected stop" marker (<c>%ProgramData%\MinControl\expected-stop.json</c>): Setup and the MSI write it right before
/// they stop the service (upgrade, repair, re-enrolment, uninstall), so the service does not report
/// <c>tamper.service_stopped</c> for its own maintenance. Content: <c>{"at":"&lt;RFC 3339 UTC&gt;","by":"msi|setup"}</c>.
/// A marker is fresh for <see cref="Freshness"/>; the service deletes it when it consumes it and on start.
/// </summary>
public static class ExpectedStopMarker
{
    public const string FileName = "expected-stop.json";
    public static readonly TimeSpan Freshness = TimeSpan.FromMinutes(10);

    /// <summary>Writes the marker (creates the folder). Best effort: returns false on failure.</summary>
    public static bool Write(string path, string by, DateTimeOffset utcNow)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var json = new JsonObject
            {
                ["at"] = utcNow.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
                ["by"] = by,
            }.ToJsonString();
            File.WriteAllText(path, json);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Time stamp of the marker, null when missing or unreadable.</summary>
    public static DateTimeOffset? ReadAt(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var node = JsonNode.Parse(File.ReadAllText(path));
            var at = node?["at"]?.GetValue<string>();
            return DateTimeOffset.TryParse(at, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)
                ? t : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    /// <summary>True when a marker exists and is younger than <see cref="Freshness"/> (and not from the future by more
    /// than a minute — a clock change must not turn an old marker into a permanent one).</summary>
    public static bool IsFresh(string path, DateTimeOffset utcNow)
    {
        if (ReadAt(path) is not { } at) return false;
        var age = utcNow - at;
        return age >= TimeSpan.FromMinutes(-1) && age <= Freshness;
    }

    public static void Delete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}
