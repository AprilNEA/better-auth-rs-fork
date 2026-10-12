import assert from "node:assert/strict";
import { assertObservationReplay, observationPointer, observationValueType } from "./observation-replay.mjs";

export function sqlCleanupHostObservations(record) {
  const fields = [];
  const hostFields = new Set(["stack", "sourceURL", "originalLine", "originalColumn", "column"]);
  if (record.backend === "mysql") hostFields.add("line");
  function collect(node, path) {
    if (node === null || typeof node !== "object") return;
    if (node.type === "error" && Object.hasOwn(node, "identity")) {
      fields.push({ path: observationPointer([...path, "error", "stack"]), type: observationValueType(node.error.stack), value: node.error.stack });
      for (const [index, [name, descriptor]] of node.properties.entries()) {
        if (hostFields.has(name) && ["string", "number"].includes(typeof descriptor.value)) {
          fields.push({
            path: observationPointer([...path, "properties", index, 1, "value"]),
            name, ownKeyPosition: node.ownKeys.indexOf(name),
            type: observationValueType(descriptor.value), value: descriptor.value,
          });
        }
      }
    }
    for (const [name, value] of Object.entries(node)) collect(value, [...path, name]);
  }
  for (const [caseIndex, captured] of record.cases.entries()) {
    for (const phase of ["ownerSetup", "setup", "steps"]) {
      for (const [index, observation] of (captured[phase] ?? []).entries()) {
        if (!observation.returned) collect(observation.error.raw.root, ["cases", caseIndex, phase, index, "error", "raw", "root"]);
      }
    }
  }
  return fields;
}

export function assertApiKeyCleanupSqlReplay(actual, expected) {
  const sourceHost = sqlCleanupHostObservations(expected);
  const replayHost = sqlCleanupHostObservations(actual);
  const hostPaths = new Set(sourceHost.map(field => field.path));
  assertObservationReplay(actual, expected, `${expected.backend} API Key cleanup`, hostPaths);
  const shapes = fields => fields.map(({ value, ...shape }) => shape);
  assert.deepEqual(shapes(replayHost), shapes(sourceHost), "SQL cleanup Error host field shape");
}
