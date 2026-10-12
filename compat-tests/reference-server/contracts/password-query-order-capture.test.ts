import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("password consumers preserve truthiness, query order, and selected-account writes", async () => {
  await expectStandaloneCapture(
    new URL("./password-query-order-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/password-query-order-1.7.6.json", import.meta.url),
  );
}, 120_000);
