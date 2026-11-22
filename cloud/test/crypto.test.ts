import { describe, expect, it } from "vitest";
import { requestSigningString, verifyMasterRequest } from "../src/auth/master";
import { issueUploadToken, verifyUploadToken } from "../src/auth/upload-token";
import { verifyEnvelope } from "../src/envelope";
import { keyIdOf, normalizePairingCode, randomCrockford, secretEquals, verifySignature } from "../src/lib/crypto";
import { b64urlDecode, b64urlEncode, utf8 } from "../src/lib/encoding";
import { ulid, ULID_RE } from "../src/lib/ulid";

const DEVICE = "01JDQ3Z8K4M2N6P8R0S2T4V6W8";

async function ed25519() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  const sign = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, data));
  return { raw, sign, keyId: await keyIdOf(raw) };
}

async function es256() {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  const sign = async (data: Uint8Array) =>
    new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, data));
  return { raw, sign, keyId: await keyIdOf(raw) };
}

describe("encoding", () => {
  it("b64url round-trips without padding", () => {
    for (const len of [0, 1, 2, 3, 31, 32, 64]) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      const s = b64urlEncode(bytes);
      expect(s).not.toMatch(/[=+/]/);
      expect(b64urlDecode(s)).toEqual(bytes);
    }
  });
  it("rejects padded or non-url input", () => {
    expect(b64urlDecode("AA==")).toBeNull();
    expect(b64urlDecode("a+b/")).toBeNull();
    expect(b64urlDecode("A")).toBeNull();
  });
});

describe("signatures", () => {
  it("verifies Ed25519 and rejects tampering", async () => {
    const k = await ed25519();
    const data = utf8("hello");
    const sig = await k.sign(data);
    expect(await verifySignature("ed25519", k.raw, sig, data)).toBe(true);
    expect(await verifySignature("ed25519", k.raw, sig, utf8("hellO"))).toBe(false);
    expect(k.keyId).toMatch(/^[0-9a-f]{16}$/);
  });
  it("verifies ES256 P1363 (64-byte r||s)", async () => {
    const k = await es256();
    expect(k.raw.length).toBe(65);
    const data = utf8("payload");
    const sig = await k.sign(data);
    expect(sig.length).toBe(64);
    expect(await verifySignature("es256", k.raw, sig, data)).toBe(true);
    expect(await verifySignature("ed25519", k.raw, sig, data)).toBe(false);
  });
});

describe("pairing codes and ids", () => {
  it("generates Crockford codes and normalises user input", () => {
    const code = randomCrockford(8);
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/);
    expect(normalizePairingCode("k7q2-9xmb")).toBe("K7Q29XMB");
    expect(normalizePairingCode("IO1L-0000")).toBe("1011" + "0000");
    expect(normalizePairingCode("K7Q2-9XM")).toBeNull();
    expect(normalizePairingCode("K7Q2-9XMU")).toBeNull();
  });
  it("ulid has the protocol shape and sorts by time", () => {
    const a = ulid(1_700_000_000_000);
    const b = ulid(1_700_000_000_001);
    expect(a).toMatch(ULID_RE);
    expect(a < b).toBe(true);
  });
  it("secretEquals", async () => {
    expect(await secretEquals("abc", "abc")).toBe(true);
    expect(await secretEquals("abc", "abd")).toBe(false);
  });
});

describe("upload tokens", () => {
  it("issues and verifies, bound to the device", async () => {
    const now = 1_800_000_000_000;
    const t = await issueUploadToken("s3cret", DEVICE, now);
    expect(await verifyUploadToken("s3cret", t.token, now + 1000)).toBe(DEVICE);
    expect(await verifyUploadToken("other", t.token, now)).toBeNull();
    expect(await verifyUploadToken("s3cret", t.token, now + 3601_000)).toBeNull();
    const forged = t.token.replace(DEVICE, "01JDQ3Z8K4M2N6P8R0S2T4V6W9");
    expect(await verifyUploadToken("s3cret", forged, now)).toBeNull();
  });
});

describe("master request auth", () => {
  it("accepts a correctly signed request and rejects a modified body", async () => {
    const k = await ed25519();
    const now = Date.now();
    const ts = String(Math.floor(now / 1000));
    const body = utf8('{"fcmToken":"x"}');
    const path = "/v1/master/push/subscribe?a=1";
    const sig = b64urlEncode(await k.sign(utf8(await requestSigningString("POST", path, ts, body))));
    const req = new Request("https://x.test" + path, { method: "POST", headers: { "x-mc-auth": `v1;${k.keyId};${ts};${sig}` } });
    const lookup = async (id: string) =>
      id === k.keyId ? { key_id: k.keyId, alg: "ed25519" as const, public_key: b64urlEncode(k.raw), role: "read" as const } : null;
    await expect(verifyMasterRequest(req, body, lookup, now)).resolves.toMatchObject({ key_id: k.keyId });
    await expect(verifyMasterRequest(req, utf8("{}"), lookup, now)).rejects.toMatchObject({ code: "bad_signature" });
    await expect(verifyMasterRequest(req, body, lookup, now + 301_000)).rejects.toMatchObject({ code: "stale_request" });
  });
});

describe("envelope verification", () => {
  async function makeEnvelope(k: Awaited<ReturnType<typeof ed25519>>, over: Record<string, unknown> = {}) {
    const now = Date.now();
    const signed = {
      deviceId: DEVICE,
      kind: "command",
      seq: 7,
      issuedAt: new Date(now - 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
      expiresAt: new Date(now + 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
      body: { commandId: "01JDQ40000000000000000V0CK", type: "refresh" },
      ...over,
    };
    const payload = utf8(JSON.stringify(signed));
    return { v: 1, alg: "ed25519", keyId: k.keyId, payload: b64urlEncode(payload), sig: b64urlEncode(await k.sign(payload)) };
  }

  it("accepts a valid command envelope and enforces device, kind, expiry and key role", async () => {
    const k = await ed25519();
    const lookup = async (id: string) =>
      id === k.keyId ? { key_id: k.keyId, alg: "ed25519" as const, public_key: b64urlEncode(k.raw), role: "sign" as const } : null;
    const env = await makeEnvelope(k);
    const ok = await verifyEnvelope(env, "command", DEVICE, lookup);
    expect(ok.signed.seq).toBe(7);
    await expect(verifyEnvelope(env, "command", "01JDQ3Z8K4M2N6P8R0S2T4V6W9", lookup)).rejects.toMatchObject({ code: "wrong_device" });
    await expect(verifyEnvelope(env, "policy", DEVICE, lookup)).rejects.toMatchObject({ code: "invalid_body" });
    const expired = await makeEnvelope(k, { issuedAt: "2020-01-01T00:00:00Z", expiresAt: "2020-01-01T01:00:00Z" });
    await expect(verifyEnvelope(expired, "command", DEVICE, lookup)).rejects.toMatchObject({ code: "expired" });
    const readKey = async (id: string) => ((await lookup(id)) ? { ...(await lookup(id))!, role: "read" as const } : null);
    await expect(verifyEnvelope(env, "command", DEVICE, readKey)).rejects.toMatchObject({ code: "unknown_key" });
    const badBody = await makeEnvelope(k, { body: { commandId: "01JDQ40000000000000000V0CK", type: "add_time", userSid: "S-1-5-21-1-2-3-1001", minutes: 0 } });
    await expect(verifyEnvelope(badBody, "command", DEVICE, lookup)).rejects.toMatchObject({ code: "invalid_body" });
    const tampered = { ...env, sig: b64urlEncode(new Uint8Array(64)) };
    await expect(verifyEnvelope(tampered, "command", DEVICE, lookup)).rejects.toMatchObject({ code: "bad_signature" });
  });
});
