// Data removal for API.md section 18: device deletion, "last device gone" cleanup, era wipe and full reset.
import type { Env } from "./env";
import { nowIso } from "./lib/time";
import { closeMasterLiveSockets } from "./routes/live";

type Wait = (p: Promise<unknown>) => void;

/** Tables keyed by device_id, children first (D1 enforces foreign keys; cascades are not relied on). */
const DEVICE_TABLES = [
  "events", "web_visits", "usage_daily", "domains_daily", "screenshots", "alerts", "commands",
  "policies", "managed_users", "app_inventory", "transfer_devices", "claims",
] as const;

async function purgeHub(env: Env, deviceId: string): Promise<void> {
  try {
    await env.DEVICE_HUB.get(env.DEVICE_HUB.idFromName(deviceId)).purge();
  } catch (e) {
    console.error("wipe: hub purge failed", deviceId, e instanceof Error ? e.message : e);
  }
}

/** Deletes the device and ALL its data (D1 + DeviceHub storage, sockets closed). Returns false if it did not exist. */
export async function deleteDeviceAndData(env: Env, deviceId: string): Promise<boolean> {
  const existed = (await env.DB.prepare("SELECT 1 AS x FROM devices WHERE id = ?").bind(deviceId).first()) !== null;
  await env.DB.batch([
    ...DEVICE_TABLES.map((t) => env.DB.prepare(`DELETE FROM ${t} WHERE device_id = ?`).bind(deviceId)),
    env.DB.prepare("DELETE FROM pairing_codes WHERE device_id = ?").bind(deviceId),
    env.DB.prepare("DELETE FROM devices WHERE id = ?").bind(deviceId),
  ]);
  await purgeHub(env, deviceId);
  return existed;
}

/** Master keys revoked, seal key and push subscriptions cleared: the next scanning phone becomes master (TOFU, section 12). */
export async function resetMasterIdentity(env: Env, waitUntil: Wait): Promise<void> {
  closeMasterLiveSockets(env, waitUntil); // before devices/keys vanish; harmless when none are left
  await env.DB.batch([
    env.DB.prepare("UPDATE master_keys SET revoked_at = ? WHERE revoked_at IS NULL").bind(nowIso()),
    env.DB.prepare("DELETE FROM config WHERE k = 'master_seal_pub_key'"),
    env.DB.prepare("DELETE FROM push_subscriptions"),
  ]);
}

/** Section 18.4: once the last device is gone, forget the master. */
export async function afterDeviceRemoved(env: Env, waitUntil: Wait): Promise<boolean> {
  if ((await env.DB.prepare("SELECT 1 AS x FROM devices LIMIT 1").first()) !== null) return false;
  await resetMasterIdentity(env, waitUntil);
  return true;
}

async function deleteDevices(env: Env, exceptDeviceId: string | null): Promise<void> {
  const rows = (await env.DB.prepare("SELECT id FROM devices WHERE id IS NOT ?").bind(exceptDeviceId).all<{ id: string }>()).results;
  for (const r of rows) await deleteDeviceAndData(env, r.id);
}

/**
 * Section 18.5: a new master registered after an earlier era. Removes every other device with its data, all alerts,
 * push subscriptions and the notify settings; `config` meter rows (usage:*) and the new master stay.
 */
export async function wipePreviousEra(env: Env, keepDeviceId: string): Promise<void> {
  await deleteDevices(env, keepDeviceId);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM alerts WHERE device_id IS NOT ?").bind(keepDeviceId),
    env.DB.prepare("DELETE FROM push_subscriptions"),
    env.DB.prepare("DELETE FROM config WHERE k = 'settings'"),
    env.DB.prepare("DELETE FROM transfers"),
  ]);
}

/** Section 18.6: everything goes (pending PC claims stay so a PC showing its QR can still be paired). */
export async function wipeAll(env: Env, waitUntil: Wait): Promise<void> {
  closeMasterLiveSockets(env, waitUntil);
  await deleteDevices(env, null);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM alerts"),
    env.DB.prepare("DELETE FROM master_keys"),
    env.DB.prepare("DELETE FROM push_subscriptions"),
    env.DB.prepare("DELETE FROM transfers"),
    env.DB.prepare("DELETE FROM pairing_codes"),
    env.DB.prepare("DELETE FROM config WHERE k NOT LIKE 'usage:%'"),
  ]);
}
