using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MinControl.Browser.History;

/// <summary>Per (sid, browser, profile) read position. <see cref="LastVisitTime"/> is WebKit µs of the newest
/// emitted visit; <see cref="Size"/> is the History file size at the last read (shrink detection).</summary>
public sealed record HistoryCursor(long LastVisitId, long LastVisitTime, long Size);

/// <summary>JSON file under the restricted %ProgramData%\MinControl root; written atomically (tmp + move).</summary>
public sealed class HistoryCursorStore
{
    private readonly string _path;
    private readonly ILogger _log;
    private readonly object _gate = new();
    private Dictionary<string, HistoryCursor>? _cache;

    public HistoryCursorStore(string path, ILogger? log = null)
    {
        _path = path;
        _log = log ?? NullLogger.Instance;
    }

    public static string Key(string sid, string browser, string profile) => sid + "|" + browser + "|" + profile;

    public HistoryCursor? Get(string key)
    {
        lock (_gate) return Load().TryGetValue(key, out var c) ? c : null;
    }

    public void Set(string key, HistoryCursor cursor)
    {
        lock (_gate)
        {
            var map = Load();
            if (map.TryGetValue(key, out var old) && old == cursor) return;
            map[key] = cursor;
            Save(map);
        }
    }

    private Dictionary<string, HistoryCursor> Load()
    {
        if (_cache is not null) return _cache;
        try
        {
            if (File.Exists(_path))
                _cache = JsonSerializer.Deserialize<Dictionary<string, HistoryCursor>>(File.ReadAllText(_path), JsonOptions);
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            _log.LogWarning("history cursor file unreadable ({Msg}); starting fresh", e.Message);
        }
        return _cache ??= new Dictionary<string, HistoryCursor>(StringComparer.Ordinal);
    }

    private void Save(Dictionary<string, HistoryCursor> map)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            string tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(map, JsonOptions));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _log.LogWarning("history cursor save failed: {Msg}", e.Message);
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
}
