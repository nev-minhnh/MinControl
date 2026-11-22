import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

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
