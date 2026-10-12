import { expect, test } from "bun:test";
import { captureAdapterQueryIdAliases } from "./adapter-id-slot-capture.mjs";

test("Memory shared plugin CRUD retains first-query ID aliases across JWK and Wallet", async () => {
  const observation = await captureAdapterQueryIdAliases();
  expect(observation.cases.map(captured => [captured.model, captured.serial, captured.operation])).toStrictEqual(
    ["jwks", "walletAddress"].flatMap(model => [false, true].flatMap(serial => ["findOne", "update", "delete"].map(operation => [model, serial, operation]))),
  );
  for (const captured of observation.cases) {
    process.stdout.write(`${JSON.stringify({ contract: "adapter-query-id-alias", version: observation.version, backend: observation.backend, case: captured })}\n`);
  }
});
