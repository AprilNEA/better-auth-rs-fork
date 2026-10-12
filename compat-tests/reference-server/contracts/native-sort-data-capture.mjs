import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureMemory, captureApiKey, captureJwk } from "./native-sort-consumers-capture.mjs";
import { assertNativeSortObservation, nativeSortScenarios, jwkSortScenarios } from "./native-sort-consumers-shared.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { withSecondarySourceExports } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const scenarios = nativeSortScenarios.filter(scenario => scenario.fail?.phase !== "read" && scenario.mutate?.phase !== "read");
const observed = { version: "1.7.6", boundary: "data-records-with-native-methods", cases: [] };
const output = process.argv[2];
assert.ok(output, "Pass the native sorting data-record capture output path");
try {
  await withClock(async setClock => {
    setClock(2_000_000_000_000);
    await withSecondarySourceExports("@better-auth/api-key", ["applySortingAndPagination"], async (module, provenance) => {
      observed.apiKeySource = provenance;
      for (const scenario of scenarios) {
        for (const direction of ["asc", "desc"]) {
          observed.cases.push(await captureMemory(scenario, direction, "data"));
          observed.cases.push(await captureApiKey(module, scenario, direction, "data"));
        }
        observed.cases.push(await captureJwk(scenario, "custom", undefined, "data"));
      }
      for (const scenario of jwkSortScenarios) {
        for (const lane of ["default", "custom"]) {
          for (const algorithm of [undefined, "EdDSA"]) observed.cases.push(await captureJwk(scenario, lane, algorithm, "data"));
        }
      }
    });
  });
  assert.equal(observed.cases.length, scenarios.length * 5 + jwkSortScenarios.length * 4);
  assertNativeSortObservation(observed);
  writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
} finally {
  const serialized = `${JSON.stringify(observed, null, 2)}\n`;
  writeFileSync(`${output}.raw.json`, serialized);
  await writeObservation(serialized);
}
