import { expect, test } from "bun:test";
import { writeSync } from "node:fs";
import { apiKeyCleanupScenarios, captureApiKeyCleanupFields } from "./api-key-cleanup-fields-capture.mjs";

test("API Key cleanup binds mapped Date, JSON and serial-reference predicates in order", async () => {
  const observation = await captureApiKeyCleanupFields();
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual(apiKeyCleanupScenarios);
  for (const captured of observation.cases) {
    writeSync(1, `${JSON.stringify({ contract: "api-key-cleanup-fields", version: observation.version, backend: observation.backend, current: observation.current, case: captured })}\n`);
  }
});
