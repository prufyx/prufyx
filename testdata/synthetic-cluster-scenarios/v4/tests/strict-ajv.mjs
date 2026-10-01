import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "../../../../architecture/node_modules/ajv/dist/2020.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const schemaDir = path.join(root, "schema");
const ajv = new Ajv2020({ allErrors: true, strict: true, strictSchema: true });
const validators = new Map();
for (const name of fs.readdirSync(schemaDir).filter((x) => x.endsWith(".json")).sort()) {
  const schema = JSON.parse(fs.readFileSync(path.join(schemaDir, name), "utf8"));
  validators.set(name, ajv.compile(schema));
}

function read(name) { return JSON.parse(fs.readFileSync(path.join(root, name), "utf8")); }
function assertValid(name, schemaName) {
  const validate = validators.get(schemaName);
  if (!validate(read(name))) throw new Error(`positive document rejected: ${name}\n${ajv.errorsText(validate.errors)}`);
}
function assertInvalid(label, value, schemaName) {
  const validate = validators.get(schemaName);
  if (validate(value)) throw new Error(`negative mutation accepted: ${label}`);
}
function mutate(value, fn) { const copy = structuredClone(value); fn(copy); return copy; }
function firstEvaluatedOracle() {
  const index = read("corpus-index.json");
  const ref = index.scenarioRefs.find((x) => x.scenarioId !== "syn-v4-conflicting-argo-cd-versions" && x.scenarioId !== "syn-v4-stale-observation-negative");
  return read(ref.oraclePath);
}
function firstEvaluatedScenario() {
  const index = read("corpus-index.json");
  const ref = index.scenarioRefs.find((x) => x.scenarioId === "syn-v4-config-mismatch-attention");
  return read(ref.scenarioPath);
}

// All five schemas must compile in strict Ajv 8.20 mode; all 39 owned
// documents must validate under the same compiled validators.
for (const name of ["corpus-index.schema.json", "expected-oracle.schema.json", "migration-provenance.schema.json", "replay-bridge-gate.schema.json", "scenario.schema.json"]) {
  if (!validators.has(name)) throw new Error(`missing schema validator: ${name}`);
}
assertValid("corpus-index.json", "corpus-index.schema.json");
assertValid("replay-bridge-gate.json", "replay-bridge-gate.schema.json");
assertValid("migration-provenance.json", "migration-provenance.schema.json");
for (const name of fs.readdirSync(path.join(root, "scenarios")).filter((x) => x.endsWith(".json")).sort()) assertValid(`scenarios/${name}`, "scenario.schema.json");
for (const name of fs.readdirSync(path.join(root, "oracles")).filter((x) => x.endsWith(".json")).sort()) assertValid(`oracles/${name}`, "expected-oracle.schema.json");

// The corrected package reasonClass is a closed const field: all four
// malformed/missing/changed/extra variants must fail independently.
const packageOracle = firstEvaluatedOracle();
for (const [kind, fn] of [
  ["missing", (x) => delete x.packageUnknown.reasonClass],
  ["changed", (x) => { x.packageUnknown.reasonClass = "MISSING_OR_UNSUPPORTED_CONTEXT"; }],
  ["wrong-type", (x) => { x.packageUnknown.reasonClass = 7; }],
  ["extra", (x) => { x.packageUnknown.unreviewedField = true; }],
]) assertInvalid(`oracle packageUnknown.reasonClass ${kind}`, fn(mutate(packageOracle, () => {})), "expected-oracle.schema.json");

// Both evaluator row schemas require reasonClass and reject malformed row
// values. A changed value is deliberately malformed for the generic pattern.
for (const [label, doc, schemaName] of [
  ["scenario", firstEvaluatedScenario(), "scenario.schema.json"],
  ["oracle", packageOracle, "expected-oracle.schema.json"],
]) {
  for (const [kind, fn] of [
    ["missing", (row) => delete row.reasonClass],
    ["changed", (row) => { row.reasonClass = ""; }],
    ["wrong-type", (row) => { row.reasonClass = false; }],
    ["extra", (row) => { row.unreviewedField = true; }],
  ]) {
    const mutated = mutate(doc, (x) => fn(x.expectations?.evaluator?.predicateOutcomes?.[0] ?? x.evaluator.predicateOutcomes[0]));
    assertInvalid(`${label} evaluator reasonClass ${kind}`, mutated, schemaName);
  }
}

// Every corrected integrity field is typed as string as well as constrained by
// its digest pattern. Test missing, malformed (changed), wrong-type and extra
// object variants for each field in the migration contract.
const migration = read("migration-provenance.json");
for (const [field, make] of [
  ["v2Digest", (x) => x.fileMappings[0]],
  ["v3Digest", (x) => x.fileMappings[0]],
  ["preDigest", (x) => x.sourceTree],
  ["postDigest", (x) => x.sourceTree],
]) {
  for (const [kind, fn] of [
    ["missing", (obj) => delete obj[field]],
    ["changed", (obj) => { obj[field] = "sha256:not-a-digest"; }],
    ["wrong-type", (obj) => { obj[field] = 7; }],
    ["extra", (obj) => { obj.unreviewedField = true; }],
  ]) {
    const mutated = mutate(migration, (x) => fn(make(x)));
    assertInvalid(`migration ${field} ${kind}`, mutated, "migration-provenance.schema.json");
  }
}

console.log("strict Ajv 8.20: 5 schemas, 39 positive documents, 28 corrected-field negatives PASS");
