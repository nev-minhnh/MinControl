using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Util;

namespace MinControl.Core.Cloud;

/// <summary>One sealed screenshot on disk.</summary>
public readonly record struct ScreenFile(DateOnly Day, string EventId, long Size, string Path);

/// <summary>
/// On-device screenshot store (API.md §9): sealed blobs live in <c>&lt;root&gt;\&lt;yyyy-mm-dd&gt;\&lt;eventId&gt;.bin</c> under the
/// restricted DataPaths root. Also owns blob-key validation (only our own keys, no traversal) and retention.
/// </summary>
public sealed class ScreenshotStorage
{
    public const long DefaultCapBytes = 2L * 1024 * 1024 * 1024;
    public const string DateFormat = "yyyy-MM-dd";

    public ScreenshotStorage(string root) { Root = root; }

    public string Root { get; }

    public static string DayString(DateTimeOffset utc) => utc.UtcDateTime.ToString(DateFormat, CultureInfo.InvariantCulture);

    public static string KeyFor(string deviceId, DateOnly day, string eventId) =>
        $"screens/{deviceId}/{day.ToString(DateFormat, CultureInfo.InvariantCulture)}/{eventId}.bin";

    /// <summary>Accepts exactly <c>screens/&lt;ownDeviceId&gt;/&lt;date&gt;/&lt;ULID&gt;.bin</c>; everything else (traversal, other device, odd chars) is rejected.</summary>
    public static bool TryParseKey(string? key, string ownDeviceId, out DateOnly day, out string eventId)
    {
        day = default; eventId = "";
        if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(ownDeviceId) || key.Length > 128) return false;
        var parts = key.Split('/');
        if (parts.Length != 4 || parts[0] != "screens" || !string.Equals(parts[1], ownDeviceId, StringComparison.Ordinal)) return false;
        var date = parts[2];
        if (date.Length != 10 || !DateOnly.TryParseExact(date, DateFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out day)) return false;
        const string ext = ".bin";
        var file = parts[3];
        if (!file.EndsWith(ext, StringComparison.Ordinal)) return false;
        var id = file[..^ext.Length];
        if (!UlidGenerator.IsValid(id)) return false;
        eventId = id;
        return true;
    }

    public string PathFor(DateOnly day, string eventId) =>
        System.IO.Path.Combine(Root, day.ToString(DateFormat, CultureInfo.InvariantCulture), eventId + ".bin");

    /// <summary>Atomically writes the sealed bytes (temp file + rename).</summary>
    public void Write(DateOnly day, string eventId, byte[] sealedBytes)
    {
        var path = PathFor(day, eventId);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, sealedBytes);
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>Reads the file for a validated key, or null when it does not exist.</summary>
    public byte[]? TryRead(string? key, string ownDeviceId)
    {
        if (!TryParseKey(key, ownDeviceId, out var day, out var id)) return null;
        var path = PathFor(day, id);
        try { return File.Exists(path) ? File.ReadAllBytes(path) : null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    public List<ScreenFile> List()
    {
        var all = new List<ScreenFile>();
        if (!Directory.Exists(Root)) return all;
        foreach (var dir in Directory.EnumerateDirectories(Root))
        {
            if (!DateOnly.TryParseExact(System.IO.Path.GetFileName(dir), DateFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var day)) continue;
            foreach (var f in Directory.EnumerateFiles(dir, "*.bin"))
            {
                try { all.Add(new ScreenFile(day, System.IO.Path.GetFileNameWithoutExtension(f), new FileInfo(f).Length, f)); }
                catch (IOException) { }
            }
        }
        return all;
    }

    /// <summary>
    /// Pure selection: files older than <paramref name="retentionDays"/> (day &lt; today − retentionDays), then, oldest first
    /// (day, then ULID), as many more as needed to bring the survivors under <paramref name="capBytes"/>.
    /// </summary>
    public static List<ScreenFile> SelectForDeletion(IReadOnlyCollection<ScreenFile> files, DateOnly today, int retentionDays, long capBytes)
    {
        var cutoff = today.AddDays(-Math.Max(retentionDays, 0));
        var doomed = files.Where(f => f.Day < cutoff).ToList();
        var survivors = files.Where(f => f.Day >= cutoff)
            .OrderBy(f => f.Day).ThenBy(f => f.EventId, StringComparer.Ordinal).ToList();
        long total = survivors.Sum(f => f.Size);
        foreach (var f in survivors)
        {
            if (total <= capBytes) break;
            doomed.Add(f);
            total -= f.Size;
        }
        return doomed;
    }

    /// <summary>Deletes the selected files and empty day folders. Returns the number of files removed.</summary>
    public int Cleanup(DateTimeOffset now, int? retentionDays, long capBytes = DefaultCapBytes, ILogger? log = null)
    {
        log ??= NullLogger.Instance;
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        var files = List();
        // no policy yet → no age limit, the size cap still applies
        var doomed = SelectForDeletion(files, today, retentionDays ?? int.MaxValue / 2, capBytes);
        int removed = 0;
        foreach (var f in doomed)
        {
            try { File.Delete(f.Path); removed++; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { log.LogWarning("could not delete {Path}: {Msg}", f.Path, e.Message); }
        }
        if (Directory.Exists(Root))
            foreach (var dir in Directory.EnumerateDirectories(Root))
            {
                try { if (!Directory.EnumerateFileSystemEntries(dir).Any()) Directory.Delete(dir); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }
        if (removed > 0) log.LogInformation("screenshot cleanup removed {Count} files", removed);
        return removed;
    }
}
