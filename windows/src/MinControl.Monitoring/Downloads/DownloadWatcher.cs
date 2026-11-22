using System.Collections.Concurrent;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Monitoring.Rules;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace MinControl.Monitoring.Downloads;

/// <summary>
/// FileSystemWatcher on each managed user's Downloads folder (only users with <c>monitoring.downloads</c>).
/// A file is reported as <c>download.completed</c> once it is no longer a browser temp file, its size and
/// mtime have been stable for <see cref="MonitoringOptions.DownloadStableAfter"/>, and it can be opened for
/// reading; sha256 is computed then. URLs come from the browser extension separately.
/// </summary>
internal sealed class DownloadWatcher : IMonitorComponent
{
    private const string DownloadsKnownFolder = "{374DE290-123F-4565-9164-39C4925E467B}";

    private static readonly HashSet<string> PartialExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut", ".!qb", ".aria2",
    };

    private sealed class Pending
    {
        public required string Sid;
        public long Size = -1;
        public long MTime;
        public long StableSince;
    }

    private readonly IUserDirectory _users;
    private readonly IPolicyProvider _policy;
    private readonly IEventSink _sink;
    private readonly MonitoringOptions _options;
    private readonly ILogger _log;
    private readonly Dictionary<string, (string Dir, FileSystemWatcher Watcher)> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Pending> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _reported = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private Timer? _tick;
    private Timer? _refresh;
    private int _busy;

    public DownloadWatcher(IUserDirectory users, IPolicyProvider policy, IEventSink sink, MonitoringOptions options, ILogger log)
    {
        _users = users;
        _policy = policy;
        _sink = sink;
        _options = options;
        _log = log;
    }

    public void Start()
    {
        _policy.PolicyChanged += OnPolicyChanged;
        _refresh = new Timer(_ => RefreshWatchers(), null, TimeSpan.Zero, TimeSpan.FromSeconds(60));
        _tick = new Timer(_ => CheckPending(), null, 1000, 1000);
    }

    public void Stop()
    {
        _policy.PolicyChanged -= OnPolicyChanged;
        _refresh?.Dispose();
        _tick?.Dispose();
        lock (_gate)
        {
            foreach (var (_, w) in _watchers.Values) w.Dispose();
            _watchers.Clear();
        }
    }

    private void OnPolicyChanged(object? sender, Core.Policy.DevicePolicy e) => ThreadPool.QueueUserWorkItem(_ => RefreshWatchers());

    private void RefreshWatchers()
    {
        try
        {
            var wanted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var policy = _policy.Current;
            if (policy is not null)
            {
                foreach (var sid in _users.ManagedSids)
                {
                    if (!policy.Users.TryGetValue(sid, out var up) || !up.Monitoring.Downloads) continue;
                    var dir = DownloadsDir(sid);
                    if (dir is not null && Directory.Exists(dir)) wanted[sid] = dir;
                }
            }

            lock (_gate)
            {
                foreach (var sid in _watchers.Keys.ToList())
                {
                    if (!wanted.TryGetValue(sid, out var dir) || !string.Equals(dir, _watchers[sid].Dir, StringComparison.OrdinalIgnoreCase))
                    {
                        _watchers[sid].Watcher.Dispose();
                        _watchers.Remove(sid);
                    }
                }
                foreach (var (sid, dir) in wanted)
                {
                    if (_watchers.ContainsKey(sid)) continue;
                    var w = new FileSystemWatcher(dir)
                    {
                        IncludeSubdirectories = false,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                        InternalBufferSize = 64 * 1024,
                    };
                    string s = sid;
                    w.Created += (_, e) => Touch(s, e.FullPath);
                    w.Changed += (_, e) => Touch(s, e.FullPath);
                    w.Renamed += (_, e) => Touch(s, e.FullPath);
                    w.Error += (_, e) => _log.LogDebug(e.GetException(), "Downloads watcher overflow for {Sid}", s);
                    w.EnableRaisingEvents = true;
                    _watchers[sid] = (dir, w);
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Refreshing download watchers failed");
        }
    }

    /// <summary>Downloads known folder from the user's (loaded) hive, else &lt;profile&gt;\Downloads.</summary>
    private string? DownloadsDir(string sid)
    {
        var profile = _users.ProfilePath(sid);
        if (profile is null) return null;
        try
        {
            using var key = Registry.Users.OpenSubKey(
                sid + @"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
            if (key?.GetValue(DownloadsKnownFolder, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string raw
                && raw.Length > 0)
            {
                var expanded = PathExpander.Expand(raw, profile);
                if (!expanded.Contains('%')) return expanded;
            }
        }
        catch { /* hive not loaded or denied */ }
        return Path.Combine(profile, "Downloads");
    }

    private void Touch(string sid, string path)
    {
        if (PartialExtensions.Contains(Path.GetExtension(path))) return;
        var name = Path.GetFileName(path);
        if (name.StartsWith('~') || name.StartsWith(".", StringComparison.Ordinal)
            || name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) return;
        _pending.AddOrUpdate(path, _ => new Pending { Sid = sid }, (_, p) => { p.StableSince = 0; return p; });
    }

    private void CheckPending()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            long now = Environment.TickCount64;
            foreach (var (path, p) in _pending)
            {
                FileInfo fi;
                try
                {
                    fi = new FileInfo(path);
                    if (!fi.Exists) { _pending.TryRemove(path, out _); continue; }
                }
                catch { _pending.TryRemove(path, out _); continue; }

                long mtime = fi.LastWriteTimeUtc.Ticks;
                if (fi.Length != p.Size || mtime != p.MTime || p.StableSince == 0)
                {
                    p.Size = fi.Length;
                    p.MTime = mtime;
                    p.StableSince = now;
                    continue;
                }
                if (now - p.StableSince < (long)_options.DownloadStableAfter.TotalMilliseconds) continue;
                if (!CanOpen(path)) continue;   // still held exclusively by the writer

                _pending.TryRemove(path, out _);
                var id = $"{path}|{p.Size}|{p.MTime}";
                if (!_reported.TryAdd(id, 0)) continue;
                if (_reported.Count > 10_000) _reported.Clear();

                var sha = FileFactsCache.ComputeSha256(path);
                try
                {
                    _sink.Emit(EventTypes.DownloadCompleted, p.Sid, EventData.Download(Path.GetFileName(path), p.Size, sha));
                }
                catch (Exception ex) { _log.LogWarning(ex, "Emit download.completed"); }
            }
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private static bool CanOpen(string path)
    {
        try
        {
            using var _ = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return true;
        }
        catch { return false; }
    }
}
