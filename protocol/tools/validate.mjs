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
// services.json catalog: schema + uniqueness (ids, domains across services) + every entry blocks something
{
  const validate = ajv.getSchema("https://mincontrol.local/protocol/services.schema.json");
  const cat = JSON.parse(readFileSync(join(root, "services.json"), "utf8"));
  checked++;
  if (!validate(cat)) { failures++; console.error("FAIL services.json", JSON.stringify(validate.errors?.slice(0, 3))); }
  const ids = new Set(), doms = new Map();
  for (const s of cat.services ?? []) {
    if (ids.has(s.id)) { failures++; console.error(`FAIL services.json duplicate id ${s.id}`); }
    ids.add(s.id);
    if (!s.domains.length && !s.apps.length) { failures++; console.error(`FAIL services.json ${s.id} has no domains or apps`); }
    for (const d of s.domains) {
      if (doms.has(d)) { failures++; console.error(`FAIL services.json domain ${d} in both ${doms.get(d)} and ${s.id}`); }
      doms.set(d, s.id);
    }
  }
}
// search-engines.json (API.md section 19): schema, unique ids/domains, never a Google/Bing/YouTube/MSN/Microsoft host
{
  const validate = ajv.getSchema("https://mincontrol.local/protocol/search-engines.schema.json");
  const cat = JSON.parse(readFileSync(join(root, "search-engines.json"), "utf8"));
  checked++;
  if (!validate(cat)) { failures++; console.error("FAIL search-engines.json", JSON.stringify(validate.errors?.slice(0, 3))); }
  const forbidden = new Set(["google", "gstatic", "googleapis", "googleusercontent", "googlevideo", "bing", "youtube", "youtu", "ytimg",
    "msn", "microsoft", "msedge", "live", "office", "outlook", "windows", "azure", "bingapis", "msftconnecttest", "gvt1"]);
  const ids = new Set(), doms = new Map();
  for (const e of cat.engines ?? []) {
    if (ids.has(e.id)) { failures++; console.error(`FAIL search-engines.json duplicate id ${e.id}`); }
    ids.add(e.id);
    for (const d of e.domains) {
      const bad = d.split(".").find((l) => forbidden.has(l));
      if (bad) { failures++; console.error(`FAIL search-engines.json ${e.id}: ${d} contains forbidden label "${bad}"`); }
      if (doms.has(d)) { failures++; console.error(`FAIL search-engines.json domain ${d} in both ${doms.get(d)} and ${e.id}`); }
      doms.set(d, e.id);
    }
  }
}
// app-groups.json (API.md section 19): schema, required groups, unique ids, no duplicate matches, javaw.exe only with a path
{
  const validate = ajv.getSchema("https://mincontrol.local/protocol/app-groups.schema.json");
  const cat = JSON.parse(readFileSync(join(root, "app-groups.json"), "utf8"));
  checked++;
  if (!validate(cat)) { failures++; console.error("FAIL app-groups.json", JSON.stringify(validate.errors?.slice(0, 3))); }
  const required = ["games", "social-chat", "video-entertainment", "music", "browsers-other", "study", "creative"];
  const ids = new Set(cat.groups.map((g) => g.id));
  for (const r of required) if (!ids.has(r)) { failures++; console.error(`FAIL app-groups.json missing group ${r}`); }
  if (ids.size !== cat.groups.length) { failures++; console.error("FAIL app-groups.json duplicate group id"); }
  const seen = new Map();
  for (const g of cat.groups) {
    for (const m of g.match) {
      const key = JSON.stringify([m.exe?.toLowerCase(), m.path?.toLowerCase(), m.publisher?.toLowerCase(), m.sha256]);
      if (seen.has(key)) { failures++; console.error(`FAIL app-groups.json ${JSON.stringify(m)} in both ${seen.get(key)} and ${g.id}`); }
      seen.set(key, g.id);
      if (m.exe && /[\\/]/.test(m.exe)) { failures++; console.error(`FAIL app-groups.json exe must be a file name: ${m.exe}`); }
      if (m.exe?.toLowerCase() === "javaw.exe" && !m.path) { failures++; console.error("FAIL app-groups.json javaw.exe needs a path pattern"); }
      if (m.publisher && !/[A-Za-z]{3}/.test(m.publisher.replace(/\*/g, ""))) { failures++; console.error(`FAIL app-groups.json publisher too broad: ${m.publisher}`); }
    }
  }
}
console.log(`${checked} fixtures checked, ${failures} failures`);
process.exit(failures ? 1 : 0);
