-- MinControl D1 schema (M0). ids = ULID TEXT, times = RFC 3339 UTC TEXT, JSON = TEXT.
-- D1 enforces foreign keys by default.

-- One row per enrolled Windows PC.
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  os_version TEXT,
  device_pub_key TEXT NOT NULL,
  enrolled_at TEXT NOT NULL,
  last_seen_at TEXT,
  state_json TEXT,
  revoked_at TEXT
);

-- Local Windows users on a device; managed = under parental control.
CREATE TABLE managed_users (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT NOT NULL,
  name TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  managed INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (device_id, user_sid)
);

-- Signed policy envelopes, versioned per device.
CREATE TABLE policies (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  signed_blob TEXT NOT NULL,
  key_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT,
  PRIMARY KEY (device_id, version)
);

-- Signed commands queued for devices, with their ack state.
CREATE TABLE commands (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  type TEXT NOT NULL,
  signed_blob TEXT NOT NULL,
  seq INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',  -- queued|sent|applied|rejected|failed|expired
  ack_at TEXT,
  ack_error TEXT,
  ack_detail TEXT
);
CREATE INDEX idx_commands_device_status ON commands (device_id, status, created_at);

-- Generic telemetry events (event.schema.json).
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  mono_ms INTEGER NOT NULL,
  type TEXT NOT NULL,
  data_json TEXT NOT NULL
);
CREATE INDEX idx_events_device_user_ts ON events (device_id, user_sid, ts);
CREATE INDEX idx_events_device_type_ts ON events (device_id, type, ts);

-- Denormalised web.visit events for search.
CREATE TABLE web_visits (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  url TEXT NOT NULL,
  host TEXT,
  title TEXT,
  duration_sec INTEGER,
  transition TEXT
);
CREATE INDEX idx_web_visits_device_user_ts ON web_visits (device_id, user_sid, ts);
CREATE INDEX idx_web_visits_host ON web_visits (device_id, host);

-- Per-day, per-app usage aggregated from usage.tick.
CREATE TABLE usage_daily (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT NOT NULL,
  day TEXT NOT NULL,            -- YYYY-MM-DD in the policy timezone
  exe TEXT NOT NULL,
  grp TEXT NOT NULL DEFAULT '',
  active_sec INTEGER NOT NULL DEFAULT 0,
  idle_sec INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, user_sid, day, exe)
);
CREATE INDEX idx_usage_daily_device_user_day ON usage_daily (device_id, user_sid, day);

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
CREATE INDEX idx_domains_daily_device_user_day ON domains_daily (device_id, user_sid, day);

-- Metadata of sealed screenshots; the blob itself lives in R2.
CREATE TABLE screenshots (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  blob_key TEXT NOT NULL,
  width INTEGER NOT NULL,
  height INTEGER NOT NULL,
  reason TEXT NOT NULL,         -- interval|command
  command_id TEXT,
  foreground_exe TEXT
);
CREATE INDEX idx_screenshots_device_user_ts ON screenshots (device_id, user_sid, ts);

-- Alert-worthy events that triggered (or will trigger) a push.
CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT,
  ts TEXT NOT NULL,
  type TEXT NOT NULL,
  event_id TEXT,
  summary TEXT,
  pushed_at TEXT,
  acked_at TEXT
);
CREATE INDEX idx_alerts_device_user_ts ON alerts (device_id, user_sid, ts);

-- FCM tokens of the master app (push targets).
CREATE TABLE push_subscriptions (
  id TEXT PRIMARY KEY,
  fcm_token TEXT NOT NULL UNIQUE,
  master_key_id TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT
);

-- One-time enrolment codes (8 chars, 15 min TTL).
CREATE TABLE pairing_codes (
  code TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  device_id TEXT REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX idx_pairing_codes_expires ON pairing_codes (expires_at);
