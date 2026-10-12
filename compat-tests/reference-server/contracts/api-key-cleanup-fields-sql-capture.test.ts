import { expect, test } from "bun:test";
import { writeSync } from "node:fs";
import { apiKeyCleanupScenarios } from "./api-key-cleanup-fields-capture.mjs";
import { captureApiKeyCleanupSqlFields } from "./api-key-cleanup-fields-sql-capture.mjs";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`capture complete API Key cleanup field behavior for ${backend}`, async () => {
    const observation = await captureApiKeyCleanupSqlFields(backend);
    writeSync(1, `${JSON.stringify({ contract: "api-key-cleanup-fields-sql", ...observation })}\n`);
    expect(observation.cases.map(captured => captured.scenario)).toStrictEqual(apiKeyCleanupScenarios);
    for (const captured of observation.cases) {
      expect(captured.setup).toHaveLength(3);
      expect(captured.steps.map(step => step.attempt)).toStrictEqual([1, 2]);
      expect(captured.steps.map(step => step.events)).toStrictEqual([[], []]);
    }
  });
}
