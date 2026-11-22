-- MinControl D1 schema. ids = ULID TEXT, times = RFC 3339 UTC TEXT normalised to
-- `YYYY-MM-DDTHH:MM:SS.sssZ` (Date.toISOString) so lexical order = time order. JSON = TEXT.
-- D1 enforces foreign keys by default.

-- Registered master (parent phone) public keys. role sign = policy/command envelopes, read = API requests.
CREATE TABLE master_keys (
  key_id TEXT PRIMARY KEY,          -- first 16 hex of sha256(raw public key)
  alg TEXT NOT NULL,                -- ed25519 | es256
  public_key TEXT NOT NULL,         -- b64url raw key (Ed25519 32 B, P-256 uncompressed SEC1 65 B)
  role TEXT NOT NULL,               -- sign | read
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

-- Single-row settings (k = 'master_seal_pub_key', ...).
CREATE TABLE config (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- One row per enrolled Windows PC.
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  os_version TEXT,
  agent_version TEXT,
  device_pub_key TEXT NOT NULL,     -- b64url raw Ed25519
  enrolled_at TEXT NOT NULL,
  online INTEGER NOT NULL DEFAULT 0,
  last_seen_at TEXT,
  state_json TEXT,                  -- last DeviceState
  policy_version INTEGER,           -- latest accepted policy version (server side)
  applied_policy_version INTEGER,   -- last version the device reported as applied
  timezone TEXT,                    -- from the latest policy, used to bucket usage per local day
  retention_json TEXT,              -- policy.retentionDays of the latest policy
  offline_alerted_at TEXT,          -- last "offline > 2 h" alert (one per offline period)
  revoked_at TEXT
);

-- Local Windows users on a device; managed = listed in the latest policy.
CREATE TABLE managed_users (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT NOT NULL,
  name TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  managed INTEGER NOT NULL DEFAULT 0,
  label TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (device_id, user_sid)
);

-- Signed policy envelopes per device (mirror of the DeviceHub queue; one row per accepted seq).
CREATE TABLE policies (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  version INTEGER NOT NULL,
  signed_blob TEXT NOT NULL,        -- SignedEnvelope JSON
  key_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',  -- queued|delivered|applied|rejected
  error TEXT,
  PRIMARY KEY (device_id, seq)
);

-- Signed commands queued for devices, with their ack state (written by DeviceHub).
CREATE TABLE commands (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  type TEXT NOT NULL,
  signed_blob TEXT NOT NULL,
  seq INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',  -- queued|delivered|applied|rejected|failed|expired
  ack_at TEXT,
  ack_error TEXT,
  ack_detail TEXT
);
CREATE INDEX idx_commands_device_status ON commands (device_id, status, created_at);
CREATE INDEX idx_commands_status_expires ON commands (status, expires_at);

-- Generic telemetry events (event.schema.json).
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  mono_ms INTEGER NOT NULL,
  type TEXT NOT NULL,
  data_json TEXT NOT NULL,
  received_at TEXT NOT NULL
);
CREATE INDEX idx_events_device_user_ts ON events (device_id, user_sid, ts);
CREATE INDEX idx_events_device_type_ts ON events (device_id, type, ts);
CREATE INDEX idx_events_device_ts ON events (device_id, ts, id);

-- Denormalised web.visit / web.search / web.blocked events for the web history screen.
CREATE TABLE web_visits (
  id TEXT PRIMARY KEY,              -- event id
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,               -- visit|search|blocked
  url TEXT,
  host TEXT,
  title TEXT,                       -- page title (visit) or query (search)
  duration_sec INTEGER,
  category TEXT,                    -- blocked: category or reason; search: engine
  transition TEXT
);
CREATE INDEX idx_web_visits_device_user_ts ON web_visits (device_id, user_sid, ts);
CREATE INDEX idx_web_visits_device_kind_ts ON web_visits (device_id, kind, ts);
CREATE INDEX idx_web_visits_host ON web_visits (device_id, host);

-- Per-day, per-app usage aggregated from usage.tick.
CREATE TABLE usage_daily (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT NOT NULL,
  day TEXT NOT NULL,                -- YYYY-MM-DD in the policy timezone
  exe TEXT NOT NULL,
  grp TEXT NOT NULL DEFAULT '',
  active_sec INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, user_sid, day, exe)
);
CREATE INDEX idx_usage_daily_device_day ON usage_daily (device_id, day);

-- Per-day network domains aggregated from net.domain.
CREATE TABLE domains_daily (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT NOT NULL,
  day TEXT NOT NULL,
  host TEXT NOT NULL,
  exe TEXT NOT NULL DEFAULT '',
  allowed INTEGER NOT NULL,
  connections INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, user_sid, day, host, exe, allowed)
);
CREATE INDEX idx_domains_daily_device_day ON domains_daily (device_id, day);

-- Metadata of sealed screenshots; the blob itself lives in R2.
CREATE TABLE screenshots (
  id TEXT PRIMARY KEY,              -- event id
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  blob_key TEXT NOT NULL,
  width INTEGER NOT NULL,
  height INTEGER NOT NULL,
  reason TEXT NOT NULL,             -- interval|command
  command_id TEXT,
  foreground_exe TEXT
);
CREATE INDEX idx_screenshots_device_user_ts ON screenshots (device_id, user_sid, ts);
CREATE INDEX idx_screenshots_device_ts ON screenshots (device_id, ts, id);

-- Alerts (API.md section 6); each one is pushed to every push subscription.
CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  type TEXT NOT NULL,               -- event type, 'blocked.burst' or 'device.offline'
  severity TEXT NOT NULL,           -- info|warn|critical
  event_id TEXT UNIQUE,
  data_json TEXT NOT NULL,          -- {title, body, ...}
  pushed_at TEXT,
  acked_at TEXT
);
CREATE INDEX idx_alerts_ts ON alerts (ts, id);
CREATE INDEX idx_alerts_device_user_type_ts ON alerts (device_id, user_sid, type, ts);

-- FCM tokens of the master app (push targets).
CREATE TABLE push_subscriptions (
  id TEXT PRIMARY KEY,
  fcm_token TEXT NOT NULL UNIQUE,
  master_key_id TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT
);

-- One-time enrolment codes (8 chars Crockford base32, 15 min TTL, single use, 5 failed attempts max).
CREATE TABLE pairing_codes (
  code TEXT PRIMARY KEY,            -- normalised: upper case, no dash
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  device_id TEXT REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX idx_pairing_codes_expires ON pairing_codes (expires_at);
