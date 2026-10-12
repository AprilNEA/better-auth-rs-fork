import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("password endpoints preserve authoritative User identity, native revocation, and committed failures", async () => {
  await expectStandaloneCapture(
    new URL("./password-session-boundary-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/password-session-boundary-1.7.6.json", import.meta.url),
  );
}, 120_000);
