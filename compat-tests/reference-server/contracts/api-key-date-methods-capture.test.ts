import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("API Key cache dates invoke native methods before complete storage writes", async () => {
  await expectStandaloneObservation(
    new URL("./api-key-date-methods-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/api-key-date-methods-1.7.6.json", import.meta.url),
    "API Key native date methods",
  );
}, 120_000);
