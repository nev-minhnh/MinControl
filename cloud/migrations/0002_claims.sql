-- QR pairing initiated by the device (API.md section 10).
CREATE TABLE claims (
  claim_id TEXT PRIMARY KEY,        -- b64url of 16 random bytes
  code TEXT NOT NULL,               -- 8 Crockford chars, manual fallback
  device_pub_key TEXT NOT NULL,     -- b64url raw Ed25519
  hostname TEXT NOT NULL,
  os_version TEXT,
  agent_version TEXT,
  local_users_json TEXT NOT NULL,   -- [{sid,name,isAdmin}]
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|rejected|expired
  device_id TEXT,                   -- set on approval
  approved_by TEXT,                 -- keyId of the sign key that approved
  created_ip TEXT
);
CREATE INDEX idx_claims_code ON claims (code);
CREATE INDEX idx_claims_created ON claims (created_at);

-- Fixed-window rate limit for POST /v1/enroll/start: 10 per IP per hour (bucket = UTC hour).
CREATE TABLE claim_rate (
  ip TEXT NOT NULL,
  bucket TEXT NOT NULL,             -- e.g. 2026-11-22T14
  n INTEGER NOT NULL,
  PRIMARY KEY (ip, bucket)
);
