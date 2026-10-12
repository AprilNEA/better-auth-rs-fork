import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("throwing background Logger preserves current-call and retained-task ownership", async () => {
  await expectStandaloneObservation(
    new URL("./logger-background-ownership-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/logger-background-ownership-1.7.6.json", import.meta.url),
    "logger-background-ownership",
  );
}, 120_000);
