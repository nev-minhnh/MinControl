// Reference contract check: every fixtures/<stem>/valid/*.json must validate against <stem>.schema.json,
// every fixtures/<stem>/invalid/*.json must fail.
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false, strictRequired: false });
addFormats(ajv);
const schemaFiles = readdirSync(root).filter((f) => f.endsWith(".schema.json"));
for (const f of schemaFiles) ajv.addSchema(JSON.parse(readFileSync(join(root, f), "utf8")));

let failures = 0, checked = 0;
for (const stem of readdirSync(join(root, "fixtures"))) {
  const validate = ajv.getSchema(`https://mincontrol.local/protocol/${stem}.schema.json`);
  if (!validate) { console.error(`no schema for fixtures/${stem}`); failures++; continue; }
  for (const group of ["valid", "invalid", "semantic-invalid"]) {
    const dir = join(root, "fixtures", stem, group);
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir)) {
      checked++;
      const ok = validate(JSON.parse(readFileSync(join(dir, file), "utf8")));
      if (ok !== (group !== "invalid")) {
        failures++;
        console.error(`FAIL ${stem}/${group}/${file}`, group !== "invalid" ? JSON.stringify(validate.errors?.slice(0, 3)) : "(unexpectedly valid)");
      }
    }
  }
}
console.log(`${checked} fixtures checked, ${failures} failures`);
process.exit(failures ? 1 : 0);
