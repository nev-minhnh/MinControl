import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { validateDeviceState, validateWsDeviceMessage } from "../src/generated/validators";

const root = join(import.meta.dirname, "..", "..", "protocol");
const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false, strictRequired: false });
(addFormats as unknown as (a: Ajv2020) => void)(ajv);
for (const f of readdirSync(root).filter((f) => f.endsWith(".schema.json"))) {
  ajv.addSchema(JSON.parse(readFileSync(join(root, f), "utf8")));
}

const groups = [
  ["valid", true],
  ["invalid", false],
  ["semantic-invalid", true],
] as const;

for (const stem of readdirSync(join(root, "fixtures"))) {
  describe(stem, () => {
    for (const [group, expected] of groups) {
      const dir = join(root, "fixtures", stem, group);
      if (!existsSync(dir)) continue;
      for (const file of readdirSync(dir)) {
        it(`${group}/${file} ${expected ? "validates" : "is rejected"}`, () => {
          const validate = ajv.getSchema(`https://mincontrol.local/protocol/${stem}.schema.json`);
          expect(validate, `schema for ${stem}`).toBeTruthy();
          expect(validate!(JSON.parse(readFileSync(join(dir, file), "utf8")))).toBe(expected);
        });
      }
    }
  });
}

// The Worker uses precompiled validators (scripts/gen-validators.mjs); they must agree with the fixtures.
describe("generated validators vs device-state fixtures", () => {
  for (const [group, expected] of [["valid", true], ["invalid", false]] as const) {
    const dir = join(root, "fixtures", "device-state", group);
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir)) {
      const state = JSON.parse(readFileSync(join(dir, file), "utf8"));
      it(`${group}/${file} as DeviceState and as ws state frame`, () => {
        expect(validateDeviceState(state)).toBe(expected);
        expect(validateWsDeviceMessage({ t: "state", state })).toBe(expected);
      });
    }
  }

  it("ws auth ts is an integer; policy_rejected.error uses the command-ack enum", () => {
    const auth = { t: "auth", deviceId: "01JDQ3Z8K4M2N6P8R0S2T4V6W8", sig: "A".repeat(86) };
    expect(validateWsDeviceMessage({ ...auth, ts: 1763801400 })).toBe(true);
    expect(validateWsDeviceMessage({ ...auth, ts: "1763801400" })).toBe(false);
    expect(validateWsDeviceMessage({ t: "policy_rejected", seq: 3, error: "invalid_body" })).toBe(true);
    expect(validateWsDeviceMessage({ t: "policy_rejected", seq: 3, error: "bogus" })).toBe(false);
  });
});
