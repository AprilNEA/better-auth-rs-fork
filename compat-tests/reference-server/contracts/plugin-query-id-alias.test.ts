import { expect, test } from "bun:test";
import { capturePluginQueryIdAliases, queryIdAliasOperations } from "./plugin-query-id-alias-capture.mjs";

test("Memory plugin atomic predicates retain the first selected-ID alias", async () => {
  const observation = await capturePluginQueryIdAliases();
  expect(observation.cases.map(captured => [captured.model, captured.operation, captured.serial])).toStrictEqual(
    queryIdAliasOperations.flatMap(([model, operation]) => [false, true].map(serial => [model, operation, serial])),
  );
  for (const captured of observation.cases) {
    process.stdout.write(`${JSON.stringify({ contract: "plugin-query-id-alias", version: observation.version, backend: observation.backend, case: captured })}\n`);
  }
});
