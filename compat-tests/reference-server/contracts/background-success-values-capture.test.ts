import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("shared background primitives preserve successful completion values", async () => {
  await expectStandaloneObservation(
    new URL("./background-success-values-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/background-success-values-1.7.6.json", import.meta.url),
    "background-success-values",
  );
}, 120_000);
