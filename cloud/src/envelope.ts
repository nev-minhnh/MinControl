// Server-side verification of master-signed envelopes before they are queued (defence in depth; the
// device verifies again). Order mirrors protocol/README.md rule 6; the seq check happens in DeviceHub
// because it must be atomic per device.
import type { MasterKeyRow } from "./auth/master";
import { verifySignature } from "./lib/crypto";
import { b64urlDecode, fromUtf8 } from "./lib/encoding";
import { HttpError } from "./lib/http";
import { normTs, parseTs } from "./lib/time";
import { validateSignedBody, validateSignedEnvelope } from "./generated/validators";

export interface SignedEnvelope {
  v: 1;
  alg: "ed25519" | "es256";
  keyId: string;
  payload: string;
  sig: string;
}

export interface SignedBody<B = Record<string, unknown>> {
  deviceId: string;
  kind: "policy" | "command" | "master_keys";
  seq: number;
  issuedAt: string;
  expiresAt: string;
  body: B;
}

export interface VerifiedEnvelope<B = Record<string, unknown>> {
  envelope: SignedEnvelope;
  signed: SignedBody<B>;
  /** normalised issuedAt / expiresAt */
  issuedAt: string;
  expiresAt: string;
}

/** Envelope is valid from issuedAt - 5 min until (exclusive) expiresAt. */
export const ISSUED_AT_SKEW_MS = 300_000;

const reject = (code: string, message: string, status = 400) => new HttpError(status, code, message);

export async function verifyEnvelope<B = Record<string, unknown>>(
  input: unknown,
  expectedKind: "policy" | "command" | "master_keys",
  deviceId: string,
  lookupSignKey: (keyId: string) => Promise<MasterKeyRow | null>,
  now: number = Date.now(),
): Promise<VerifiedEnvelope<B>> {
  if (!validateSignedEnvelope(input)) {
    throw reject("invalid_body", "body is not a SignedEnvelope");
  }
  const envelope = input as SignedEnvelope;

  const key = await lookupSignKey(envelope.keyId);
  if (!key || key.role !== "sign") throw reject("unknown_key", "envelope keyId is not a registered sign key", 403);
  if (key.alg !== envelope.alg) throw reject("bad_signature", "envelope alg does not match the registered key", 403);

  const payload = b64urlDecode(envelope.payload);
  const sig = b64urlDecode(envelope.sig);
  const pub = b64urlDecode(key.public_key);
  if (!payload || !sig || !pub || !(await verifySignature(key.alg, pub, sig, payload))) {
    throw reject("bad_signature", "envelope signature invalid", 403);
  }

  let signed: unknown;
  try {
    signed = JSON.parse(fromUtf8(payload));
  } catch {
    throw reject("invalid_body", "payload is not UTF-8 JSON");
  }
  // Light structural checks first so the error codes match the device's order.
  const s = signed as Partial<SignedBody>;
  if (typeof s !== "object" || s === null) throw reject("invalid_body", "payload is not an object");
  if (s.deviceId !== deviceId) throw reject("wrong_device", "payload deviceId does not match the path");
  if (s.kind !== expectedKind) throw reject("invalid_body", `payload kind must be ${expectedKind}`);

  const issued = typeof s.issuedAt === "string" ? parseTs(s.issuedAt) : NaN;
  const expires = typeof s.expiresAt === "string" ? parseTs(s.expiresAt) : NaN;
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) {
    throw reject("invalid_body", "issuedAt/expiresAt invalid");
  }
  if (!(issued - ISSUED_AT_SKEW_MS <= now && now < expires)) throw reject("expired", "envelope is not yet valid or expired");

  if (!validateSignedBody(signed)) {
    const e = validateSignedBody.errors?.[0];
    throw new HttpError(400, "invalid_body", "signed body does not match the schema", e ? [{ path: e.instancePath, message: e.message }] : undefined);
  }
  return {
    envelope,
    signed: signed as SignedBody<B>,
    issuedAt: normTs(s.issuedAt as string)!,
    expiresAt: normTs(s.expiresAt as string)!,
  };
}
