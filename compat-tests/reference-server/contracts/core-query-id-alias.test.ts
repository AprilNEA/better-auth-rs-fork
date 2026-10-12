import { expect, test } from "bun:test";
import { writeSync } from "node:fs";
import { captureCoreQueryIdAliases, coreQueryIdAliasOperations } from "./core-query-id-alias-capture.mjs";

test("Memory core model queries preserve first-ID aliases and ordered list/count bindings", async () => {
  const observation = await captureCoreQueryIdAliases();
  expect(observation.cases.map(captured => [captured.model, captured.operation, captured.serial])).toStrictEqual(
    coreQueryIdAliasOperations.flatMap(([model, operation]) => [false, true].map(serial => [model, operation, serial])),
  );
  for (const captured of observation.cases) {
    writeSync(1, `${JSON.stringify({ contract: "core-query-id-alias", version: observation.version, backend: observation.backend, case: captured })}\n`);
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/core-query-id-alias-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});
