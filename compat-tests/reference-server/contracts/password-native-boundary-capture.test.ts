import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("password consumers preserve projected values and native verification boundaries", async () => {
  await expectStandaloneCapture(
    new URL("./password-native-boundary-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/password-native-boundary-1.7.6.json", import.meta.url),
  );
}, 120_000);
