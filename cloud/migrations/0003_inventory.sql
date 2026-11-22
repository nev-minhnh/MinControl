-- Latest app inventory per (device, managed user) (API.md section 11); replaced on every upload.
CREATE TABLE app_inventory (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_sid TEXT NOT NULL,
  generated_at TEXT NOT NULL,       -- normalised RFC 3339 UTC
  apps_json TEXT NOT NULL,          -- [App]
  PRIMARY KEY (device_id, user_sid)
);
