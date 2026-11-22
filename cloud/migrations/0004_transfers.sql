-- Phone transfer (API.md section 13A).
-- Pending keys design: the NEW phone's keys are kept ONLY in the transfer row (new_keys_json,
-- new_seal_pub_key) until /complete. master_keys is untouched until then, so a claimed-but-unconfirmed
-- transfer can never authenticate anything. /complete activates them atomically.
CREATE TABLE transfers (
  id TEXT PRIMARY KEY,               -- ULID (transferId)
  token_hash TEXT NOT NULL UNIQUE,   -- sha256 hex of the b64url token (token itself is never stored)
  created_by_key TEXT NOT NULL,      -- keyId of the old phone's sign key
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|claimed|done|expired
  expires_at TEXT NOT NULL,          -- 10 min after create, pushed to 10 min after claim
  new_keys_json TEXT,                -- [{keyId,alg,publicKey,role}] from the claim
  new_seal_pub_key TEXT,
  transport_pub_key TEXT,            -- ephemeral X25519 of the new phone
  sealed_seal_key TEXT,              -- old seal private key sealed to transport_pub_key (set on complete)
  complete_nonce TEXT,               -- guards the statements of the atomic complete batch
  created_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX idx_transfers_status ON transfers (status, expires_at);

-- Per-device delivery state of the master_keys envelope of a transfer (written by DeviceHub).
CREATE TABLE transfer_devices (
  transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',   -- queued|delivered|applied|rejected
  error TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (transfer_id, device_id)
);
