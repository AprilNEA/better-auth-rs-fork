import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("capture Verification native consume hydration, callback failures, and prior atomic deletion", async () => {
  await expectStandaloneObservation(
    new URL("./verification-consume-native-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/verification-consume-native-1.7.6.json", import.meta.url),
    "verification-consume-native",
  );
});
