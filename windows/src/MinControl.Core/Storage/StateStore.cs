using Microsoft.Data.Sqlite;

namespace MinControl.Core.Storage;

public sealed record PinnedKey(string KeyId, string Alg, byte[] PublicKey);

public sealed record StoredPolicy(int Version, long Seq, string EnvelopeJson, string BodyJson, string StoredAt);

/// <summary>Kinds of temporary per-user overrides created by commands.</summary>
public static class OverrideKinds
{
    public const string Lock = "lock", Pause = "pause", AddTime = "add_time";
}

public sealed record OverrideRow(long Id, string Sid, string Kind, string? Until, string? Day, string? Scope, int? Minutes, string? CommandId);

public sealed record OutboxItem(long Id, string Type, string Json);

/// <summary>
/// The agent's durable state in SQLite (<c>state.db</c>): enrolment meta, pinned master keys, per-kind seq,
/// policy + its envelope, overrides, usage ledger, approvals, outbox (screenshots live on disk, API.md §9).
/// One connection guarded by a lock: the agent's write rate is tiny (ledger flush every 30 s, events).
/// </summary>
public sealed class StateStore : IDisposable
{
    public const long DefaultOutboxCapBytes = 500L * 1024 * 1024;

    private readonly SqliteConnection _db;
    private readonly object _gate = new();
    private long _outboxBytes;

    public long OutboxCapBytes { get; set; } = DefaultOutboxCapBytes;

    /// <param name="dbPath">file path, or <c>:memory:</c> for tests.</param>
    public StateStore(string dbPath)
    {
        if (dbPath != ":memory:") Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dbPath))!);
        _db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath, Pooling = false }.ToString());
        _db.Open();
        Exec(dbPath == ":memory:" ? "PRAGMA foreign_keys=ON;" : "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;");
        Exec("""
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS master_keys (key_id TEXT PRIMARY KEY, alg TEXT NOT NULL, public_key BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS seq (kind TEXT PRIMARY KEY, last INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL, seq INTEGER NOT NULL,
                envelope TEXT NOT NULL, body TEXT NOT NULL, stored_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS overrides (id INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT NOT NULL, kind TEXT NOT NULL,
                until TEXT NULL, day TEXT NULL, scope TEXT NULL, minutes INTEGER NULL, command_id TEXT NULL);
            CREATE INDEX IF NOT EXISTS ix_overrides_sid ON overrides(sid);
            CREATE TABLE IF NOT EXISTS ledger (sid TEXT NOT NULL, day TEXT NOT NULL, bucket TEXT NOT NULL, ms INTEGER NOT NULL,
                PRIMARY KEY (sid, day, bucket));
            CREATE TABLE IF NOT EXISTS approvals (sid TEXT NOT NULL, sha256 TEXT NOT NULL, decision TEXT NOT NULL, at TEXT NOT NULL,
                PRIMARY KEY (sid, sha256));
            CREATE TABLE IF NOT EXISTS approval_requests (sid TEXT NOT NULL, sha256 TEXT NOT NULL, at TEXT NOT NULL,
                PRIMARY KEY (sid, sha256));
            CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, json TEXT NOT NULL, size INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_outbox_type ON outbox(type, id);
            CREATE TABLE IF NOT EXISTS applied_commands (command_id TEXT PRIMARY KEY, at TEXT NOT NULL);
            DROP TABLE IF EXISTS pending_blobs;
            """);
        _outboxBytes = Scalar<long>("SELECT COALESCE(SUM(size),0) FROM outbox");
    }

    public void Dispose() { lock (_gate) _db.Dispose(); }

    // ---------------------------------------------------------------- meta
    public static class MetaKeys
    {
        public const string DeviceId = "device_id", ServerUrl = "server_url", MasterSealPubKey = "master_seal_pub",
            LastOnlineUtc = "last_online_utc", EnrolledAt = "enrolled_at";
    }

    public string? GetMeta(string key)
    {
        lock (_gate) return Scalar<string?>("SELECT v FROM meta WHERE k=$k", ("$k", key));
    }

    public void SetMeta(string key, string? value)
    {
        lock (_gate)
        {
            if (value is null) Exec("DELETE FROM meta WHERE k=$k", ("$k", key));
            else Exec("INSERT INTO meta(k,v) VALUES($k,$v) ON CONFLICT(k) DO UPDATE SET v=excluded.v", ("$k", key), ("$v", value));
        }
    }

    // ---------------------------------------------------------------- master keys
    public IReadOnlyList<PinnedKey> GetMasterKeys()
    {
        lock (_gate)
        {
            using var cmd = Cmd("SELECT key_id, alg, public_key FROM master_keys ORDER BY key_id");
            using var r = cmd.ExecuteReader();
            var list = new List<PinnedKey>();
            while (r.Read()) list.Add(new PinnedKey(r.GetString(0), r.GetString(1), (byte[])r[2]));
            return list;
        }
    }

    /// <summary>Replaces all pinned keys (enrolment only).</summary>
    public void ReplaceMasterKeys(IEnumerable<PinnedKey> keys)
    {
        lock (_gate)
        {
            using var tx = Begin();
            Exec("DELETE FROM master_keys");
            foreach (var k in keys)
                Exec("INSERT INTO master_keys(key_id,alg,public_key) VALUES($i,$a,$p)", ("$i", k.KeyId), ("$a", k.Alg), ("$p", k.PublicKey));
            tx.Commit(); _tx = null;
        }
    }

    // ---------------------------------------------------------------- seq
    public long GetSeq(string kind)
    {
        lock (_gate) return Scalar<long?>("SELECT last FROM seq WHERE kind=$k", ("$k", kind)) ?? 0;
    }

    /// <summary>Atomically sets seq[kind]=seq if seq &gt; current. Returns false on replay.</summary>
    public bool TryAdvanceSeq(string kind, long seq)
    {
        lock (_gate)
        {
            var cur = Scalar<long?>("SELECT last FROM seq WHERE kind=$k", ("$k", kind)) ?? 0;
            if (seq <= cur) return false;
            Exec("INSERT INTO seq(kind,last) VALUES($k,$s) ON CONFLICT(kind) DO UPDATE SET last=excluded.last", ("$k", kind), ("$s", seq));
            return true;
        }
    }

    // ---------------------------------------------------------------- policy
    public StoredPolicy? GetPolicy()
    {
        lock (_gate)
        {
            using var cmd = Cmd("SELECT version, seq, envelope, body, stored_at FROM policy WHERE id=1");
            using var r = cmd.ExecuteReader();
            return r.Read() ? new StoredPolicy(r.GetInt32(0), r.GetInt64(1), r.GetString(2), r.GetString(3), r.GetString(4)) : null;
        }
    }

    public void SavePolicy(StoredPolicy p)
    {
        lock (_gate)
            Exec("""
                INSERT INTO policy(id,version,seq,envelope,body,stored_at) VALUES(1,$v,$s,$e,$b,$t)
                ON CONFLICT(id) DO UPDATE SET version=excluded.version, seq=excluded.seq, envelope=excluded.envelope,
                    body=excluded.body, stored_at=excluded.stored_at
                """, ("$v", p.Version), ("$s", p.Seq), ("$e", p.EnvelopeJson), ("$b", p.BodyJson), ("$t", p.StoredAt));
    }

    // ---------------------------------------------------------------- overrides
    public IReadOnlyList<OverrideRow> GetOverrides(string sid)
    {
        lock (_gate)
        {
            using var cmd = Cmd("SELECT id,sid,kind,until,day,scope,minutes,command_id FROM overrides WHERE sid=$s ORDER BY id", ("$s", sid));
            using var r = cmd.ExecuteReader();
            var list = new List<OverrideRow>();
            while (r.Read())
                list.Add(new OverrideRow(r.GetInt64(0), r.GetString(1), r.GetString(2), r.IsDBNull(3) ? null : r.GetString(3),
                    r.IsDBNull(4) ? null : r.GetString(4), r.IsDBNull(5) ? null : r.GetString(5),
                    r.IsDBNull(6) ? null : r.GetInt32(6), r.IsDBNull(7) ? null : r.GetString(7)));
            return list;
        }
    }

    /// <summary>Removes lock/pause overrides of a user (both, since the newest of lock_now/pause_limits wins).</summary>
    public void ClearLockAndPause(string sid)
    {
        lock (_gate) Exec("DELETE FROM overrides WHERE sid=$s AND kind IN ('lock','pause')", ("$s", sid));
    }

    public void ClearOverride(string sid, string kind)
    {
        lock (_gate) Exec("DELETE FROM overrides WHERE sid=$s AND kind=$k", ("$s", sid), ("$k", kind));
    }

    public void AddOverride(OverrideRow o)
    {
        lock (_gate)
            Exec("INSERT INTO overrides(sid,kind,until,day,scope,minutes,command_id) VALUES($s,$k,$u,$d,$sc,$m,$c)",
                ("$s", o.Sid), ("$k", o.Kind), ("$u", o.Until), ("$d", o.Day), ("$sc", o.Scope), ("$m", o.Minutes), ("$c", o.CommandId));
    }

    /// <summary>Drops lock/pause overrides whose <c>until</c> passed and add_time grants for days before <paramref name="oldestDayToKeep"/>.</summary>
    public void PruneOverrides(string nowUtc, string oldestDayToKeep)
    {
        lock (_gate)
        {
            // RFC 3339 Z strings with whole seconds compare lexicographically
            Exec("DELETE FROM overrides WHERE kind IN ('lock','pause') AND until IS NOT NULL AND until <= $n", ("$n", nowUtc));
            Exec("DELETE FROM overrides WHERE kind='add_time' AND day < $d", ("$d", oldestDayToKeep));
        }
    }

    // ---------------------------------------------------------------- ledger
    /// <summary>bucket "" = total screen time, otherwise the group name.</summary>
    public IReadOnlyDictionary<string, long> GetLedger(string sid, string day)
    {
        lock (_gate)
        {
            using var cmd = Cmd("SELECT bucket, ms FROM ledger WHERE sid=$s AND day=$d", ("$s", sid), ("$d", day));
            using var r = cmd.ExecuteReader();
            var map = new Dictionary<string, long>(StringComparer.Ordinal);
            while (r.Read()) map[r.GetString(0)] = r.GetInt64(1);
            return map;
        }
    }

    public void AddLedger(IEnumerable<(string Sid, string Day, string Bucket, long Ms)> deltas)
    {
        lock (_gate)
        {
            using var tx = Begin();
            foreach (var (sid, day, bucket, ms) in deltas)
                Exec("INSERT INTO ledger(sid,day,bucket,ms) VALUES($s,$d,$b,$m) ON CONFLICT(sid,day,bucket) DO UPDATE SET ms=ms+excluded.ms",
                    ("$s", sid), ("$d", day), ("$b", bucket), ("$m", ms));
            tx.Commit(); _tx = null;
        }
    }

    public void PruneLedger(string oldestDayToKeep)
    {
        lock (_gate) Exec("DELETE FROM ledger WHERE day < $d", ("$d", oldestDayToKeep));
    }

    // ---------------------------------------------------------------- approvals
    public string? GetApproval(string sid, string sha256)
    {
        lock (_gate) return Scalar<string?>("SELECT decision FROM approvals WHERE sid=$s AND sha256=$h", ("$s", sid), ("$h", sha256));
    }

    public void SetApproval(string sid, string sha256, string decision, string atUtc)
    {
        lock (_gate)
            Exec("INSERT INTO approvals(sid,sha256,decision,at) VALUES($s,$h,$d,$a) ON CONFLICT(sid,sha256) DO UPDATE SET decision=excluded.decision, at=excluded.at",
                ("$s", sid), ("$h", sha256), ("$d", decision), ("$a", atUtc));
    }

    /// <summary>Records that request.exe_approval was sent for (sid, sha256). True only the first time (persisted).</summary>
    public bool MarkApprovalRequested(string sid, string sha256, string atUtc)
    {
        lock (_gate)
        {
            using var cmd = Cmd("INSERT OR IGNORE INTO approval_requests(sid,sha256,at) VALUES($s,$h,$a)",
                ("$s", sid), ("$h", sha256), ("$a", atUtc));
            return cmd.ExecuteNonQuery() == 1;
        }
    }

    // ---------------------------------------------------------------- applied commands (re-ack after reconnect)
    public const int AppliedCommandsKept = 2000;

    public bool IsCommandApplied(string commandId)
    {
        lock (_gate) return Scalar<long>("SELECT COUNT(*) FROM applied_commands WHERE command_id=$c", ("$c", commandId)) > 0;
    }

    public void MarkCommandApplied(string commandId, string atUtc)
    {
        lock (_gate)
        {
            Exec("INSERT OR IGNORE INTO applied_commands(command_id,at) VALUES($c,$a)", ("$c", commandId), ("$a", atUtc));
            Exec($"DELETE FROM applied_commands WHERE rowid NOT IN (SELECT rowid FROM applied_commands ORDER BY rowid DESC LIMIT {AppliedCommandsKept})");
        }
    }

    // ---------------------------------------------------------------- outbox
    public long OutboxBytes { get { lock (_gate) return _outboxBytes; } }
    public long OutboxCount { get { lock (_gate) return Scalar<long>("SELECT COUNT(*) FROM outbox"); } }

    /// <summary>Appends an event. Over the cap, drops oldest usage.tick first, then oldest non-tamper events; never tamper.*.</summary>
    public void EnqueueOutbox(string type, string json)
    {
        lock (_gate)
        {
            var size = (long)System.Text.Encoding.UTF8.GetByteCount(json);
            Exec("INSERT INTO outbox(type,json,size) VALUES($t,$j,$z)", ("$t", type), ("$j", json), ("$z", size));
            _outboxBytes += size;
            if (_outboxBytes > OutboxCapBytes) EnforceOutboxCap();
        }
    }

    private void EnforceOutboxCap()
    {
        foreach (var where in new[] { "type='usage.tick'", "type NOT LIKE 'tamper.%'" })
        {
            while (_outboxBytes > OutboxCapBytes)
            {
                // delete in chunks of 200 oldest rows matching the class
                var freed = Scalar<long?>($"SELECT SUM(size) FROM (SELECT size FROM outbox WHERE {where} ORDER BY id LIMIT 200)") ?? 0;
                if (freed == 0) break;
                Exec($"DELETE FROM outbox WHERE id IN (SELECT id FROM outbox WHERE {where} ORDER BY id LIMIT 200)");
                _outboxBytes -= freed;
            }
        }
    }

    public IReadOnlyList<OutboxItem> PeekOutbox(int max)
    {
        lock (_gate)
        {
            using var cmd = Cmd("SELECT id, type, json FROM outbox ORDER BY id LIMIT $n", ("$n", max));
            using var r = cmd.ExecuteReader();
            var list = new List<OutboxItem>();
            while (r.Read()) list.Add(new OutboxItem(r.GetInt64(0), r.GetString(1), r.GetString(2)));
            return list;
        }
    }

    public void DeleteOutbox(IEnumerable<long> ids)
    {
        lock (_gate)
        {
            using var tx = Begin();
            foreach (var id in ids)
            {
                var size = Scalar<long?>("SELECT size FROM outbox WHERE id=$i", ("$i", id));
                if (size is null) continue;
                Exec("DELETE FROM outbox WHERE id=$i", ("$i", id));
                _outboxBytes -= size.Value;
            }
            tx.Commit(); _tx = null;
        }
    }

    // ---------------------------------------------------------------- wipe (unenroll)
    public void WipeAll()
    {
        lock (_gate)
        {
            Exec("DELETE FROM meta; DELETE FROM master_keys; DELETE FROM seq; DELETE FROM policy; DELETE FROM overrides; " +
                 "DELETE FROM ledger; DELETE FROM approvals; DELETE FROM approval_requests; DELETE FROM applied_commands; DELETE FROM outbox;");
            _outboxBytes = 0;
        }
    }

    // ---------------------------------------------------------------- helpers (caller holds _gate)
    private SqliteTransaction? _tx;

    private SqliteTransaction Begin() => _tx = _db.BeginTransaction();

    private SqliteCommand Cmd(string sql, params (string Name, object? Value)[] args)
    {
        var cmd = _db.CreateCommand();
        cmd.CommandText = sql;
        if (_tx?.Connection is not null) cmd.Transaction = _tx;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return cmd;
    }

    private void Exec(string sql, params (string Name, object? Value)[] args)
    {
        using var cmd = Cmd(sql, args);
        cmd.ExecuteNonQuery();
    }

    private T Scalar<T>(string sql, params (string Name, object? Value)[] args)
    {
        using var cmd = Cmd(sql, args);
        var v = cmd.ExecuteScalar();
        if (v is null || v is DBNull) return default!;
        var t = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
        return (T)Convert.ChangeType(v, t, System.Globalization.CultureInfo.InvariantCulture);
    }
}
