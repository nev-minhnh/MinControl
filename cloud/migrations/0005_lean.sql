-- API.md section 16: lean storage. net.domain / usage.tick only feed the daily aggregates now.
ALTER TABLE domains_daily ADD COLUMN first_seen TEXT;
ALTER TABLE domains_daily ADD COLUMN last_seen TEXT;

DELETE FROM events WHERE type IN ('net.domain', 'usage.tick');

-- Indexes no query needs (each costs one extra written row per insert / indexed-column update).
DROP INDEX IF EXISTS idx_events_device_type_ts;     -- type filters run on idx_events_device_ts / device_user_ts
DROP INDEX IF EXISTS idx_web_visits_host;           -- only LIKE '%q%' on host, an index cannot serve it
DROP INDEX IF EXISTS idx_commands_device_status;    -- commands are fetched by PK; cron scans a tiny table
DROP INDEX IF EXISTS idx_commands_status_expires;   -- (status rewrites hit this index on every ack)
DROP INDEX IF EXISTS idx_pairing_codes_expires;     -- tiny, purged daily
DROP INDEX IF EXISTS idx_claims_created;            -- cron purge of a tiny table
DROP INDEX IF EXISTS idx_transfers_status;          -- tiny table
