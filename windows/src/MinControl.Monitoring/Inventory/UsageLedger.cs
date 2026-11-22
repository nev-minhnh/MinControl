using System.Globalization;
using System.Text.Json;

namespace MinControl.Monitoring.Inventory;

/// <summary>Small rolling per-user exe → (last used, active seconds per UTC day) table for the last 7 days.
/// In memory, persisted as JSON in the monitoring state dir. Thread-safe.</summary>
internal sealed class UsageLedger
{
    private const int Days = 7, MaxExesPerUser = 400;

    private sealed class Row
    {
        public string Path { get; set; } = "";
        public DateTimeOffset LastUsed { get; set; }
        public Dictionary<string, double> Seconds { get; set; } = new();
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, Dictionary<string, Row>> _users = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _file;
    private bool _dirty;

    public UsageLedger(MonitoringOptions options) : this(System.IO.Path.Combine(options.StateDirectory, "inventory-usage.json")) { }
    public UsageLedger(string? file) { _file = file; Load(); }

    private static string Day(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private Row GetRow(string sid, string path, DateTimeOffset now)
    {
        if (!_users.TryGetValue(sid, out var rows)) _users[sid] = rows = new(StringComparer.OrdinalIgnoreCase);
        if (!rows.TryGetValue(path, out var r))
        {
            if (rows.Count >= MaxExesPerUser) Prune(rows, now, force: true);
            rows[path] = r = new Row { Path = path, LastUsed = now };
        }
        return r;
    }

    /// <summary>A process of this exe started (or was found running).</summary>
    public void Touch(string sid, string path, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(path)) return;
        lock (_gate) { var r = GetRow(sid, path, now); if (now > r.LastUsed) r.LastUsed = now; _dirty = true; }
    }

    /// <summary>The exe was in the foreground (non-idle) for <paramref name="seconds"/>.</summary>
    public void AddActive(string sid, string path, double seconds, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(path) || seconds <= 0) return;
        lock (_gate)
        {
            var r = GetRow(sid, path, now);
            r.LastUsed = now;
            var d = Day(now);
            r.Seconds[d] = r.Seconds.GetValueOrDefault(d) + seconds;
            _dirty = true;
        }
    }

    public IReadOnlyList<SeenExe> Snapshot(string sid, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_users.TryGetValue(sid, out var rows)) return [];
            Prune(rows, now, force: false);
            var from = Day(now.AddDays(-(Days - 1)));
            return rows.Values.Select(r => new SeenExe(r.Path,
                    (int)Math.Round(r.Seconds.Where(kv => string.CompareOrdinal(kv.Key, from) >= 0).Sum(kv => kv.Value) / 60.0),
                    r.LastUsed)).ToList();
        }
    }

    private static void Prune(Dictionary<string, Row> rows, DateTimeOffset now, bool force)
    {
        var cutoff = now.AddDays(-Days);
        var from = Day(now.AddDays(-(Days - 1)));
        foreach (var k in rows.Where(kv => kv.Value.LastUsed < cutoff).Select(kv => kv.Key).ToList()) rows.Remove(k);
        foreach (var r in rows.Values)
            foreach (var d in r.Seconds.Keys.Where(d => string.CompareOrdinal(d, from) < 0).ToList()) r.Seconds.Remove(d);
        if (force && rows.Count >= MaxExesPerUser)
            foreach (var k in rows.OrderBy(kv => kv.Value.LastUsed).Take(rows.Count / 4 + 1).Select(kv => kv.Key).ToList()) rows.Remove(k);
    }

    public void Save()
    {
        if (_file is null) return;
        try
        {
            string json;
            lock (_gate)
            {
                if (!_dirty) return;
                json = JsonSerializer.Serialize(_users);
                _dirty = false;
            }
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_file)!);
            var tmp = _file + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, _file, overwrite: true);
        }
        catch { /* best effort */ }
    }

    private void Load()
    {
        if (_file is null || !File.Exists(_file)) return;
        try
        {
            var data = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, Row>>>(File.ReadAllText(_file));
            if (data is null) return;
            foreach (var (sid, rows) in data)
                _users[sid] = new Dictionary<string, Row>(rows, StringComparer.OrdinalIgnoreCase);
        }
        catch { /* corrupt: start empty */ }
    }
}
