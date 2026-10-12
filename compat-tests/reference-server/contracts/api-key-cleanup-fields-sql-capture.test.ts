import { expect, test } from "bun:test";
import { apiKeyCleanupScenarios } from "./api-key-cleanup-fields-capture.mjs";
import { captureApiKeyCleanupSqlFields } from "./api-key-cleanup-fields-sql-capture.mjs";
import { assertApiKeyCleanupSqlReplay, sqlCleanupHostObservations } from "./api-key-cleanup-fields-sql-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`capture complete API Key cleanup field behavior for ${backend}`, async () => {
    const observation = await captureApiKeyCleanupSqlFields(backend);
    await writeObservation(`${JSON.stringify({ contract: "api-key-cleanup-fields-sql", ...observation })}\n`);
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/api-key-cleanup-fields-sql-${backend}-1.7.6.json`, import.meta.url)).json();
    await writeObservation(`${JSON.stringify({ contract: "api-key-cleanup-fields-sql-host", backend,
      source: sqlCleanupHostObservations(fixture), replay: sqlCleanupHostObservations(observation),
    })}\n`);
    assertApiKeyCleanupSqlReplay(observation, fixture);
    expect(observation.cases.map(captured => captured.scenario)).toStrictEqual(apiKeyCleanupScenarios);
    for (const captured of observation.cases) {
      expect(captured.setup).toHaveLength(3);
      expect(captured.steps.map(step => step.attempt)).toStrictEqual([1, 2]);
      expect(captured.steps.map(step => step.events)).toStrictEqual([[], []]);
    }
  });
}

test("SQL cleanup replay preserves driver metadata and exact Error graph paths", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-cleanup-fields-sql-postgres-1.7.6.json", import.meta.url)).json();
  const error = record => record.cases[1].setup[0].error.raw.root;
  const property = (record, name) => error(record).properties.find(([key]) => key === name)[1];
  const hostOnly = structuredClone(fixture);
  error(hostOnly).error.stack = "error: the same database error on another host";
  property(hostOnly, "stack").value = error(hostOnly).error.stack;
  property(hostOnly, "sourceURL").value = "/another-checkout/node_modules/pg-protocol/dist/parser.js";
  property(hostOnly, "originalLine").value += 1;
  expect(() => assertApiKeyCleanupSqlReplay(hostOnly, fixture)).not.toThrow();

  for (const change of [
    record => { property(record, "code").value = "wrong-code"; },
    record => { property(record, "line").value += 1; },
    record => { property(record, "where").value = "changed SQL context"; },
    record => { property(record, "originalLine").value = "wrong-type"; },
    record => { property(record, "stack").writable = false; },
    record => { error(record).ownKeys.reverse(); },
    record => { error(record).properties.reverse(); },
    record => { error(record).error.cause = "changed cause"; },
    record => { delete property(record, "detail").value; },
  ]) {
    const actual = structuredClone(fixture);
    change(actual);
    expect(() => assertApiKeyCleanupSqlReplay(actual, fixture)).toThrow();
  }

  const mysql = await Bun.file(new URL("../../../tests/fixtures/api-key-cleanup-fields-sql-mysql-1.7.6.json", import.meta.url)).json();
  const actual = structuredClone(mysql);
  actual.cases[2].setup[0].error.raw.root.properties.find(([key]) => key === "sql")[1].value += " changed";
  expect(() => assertApiKeyCleanupSqlReplay(actual, mysql)).toThrow();
});
