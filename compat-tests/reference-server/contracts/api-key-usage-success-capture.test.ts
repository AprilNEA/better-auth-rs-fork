import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("deferred secondary usage retains the complete fresh merged record", async () => {
  await expectStandaloneObservation(
    new URL("./api-key-usage-success-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/api-key-usage-success-1.7.6.json", import.meta.url),
    "api-key-usage-success",
  );
}, 120_000);
