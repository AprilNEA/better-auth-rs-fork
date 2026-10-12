import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("API Key cache key evaluation preserves source call order and pending storage ownership", async () => {
  await expectStandaloneObservation(
    new URL("./api-key-cache-key-order-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/api-key-cache-key-order-1.7.6.json", import.meta.url),
    "API Key cache native call order",
  );
}, 120_000);
