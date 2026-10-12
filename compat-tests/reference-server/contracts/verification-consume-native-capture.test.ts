import { test } from "bun:test";
import { captureVerificationConsumeNative } from "./verification-consume-native-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture Verification native consume hydration, callback failures, and prior atomic deletion", async () => {
  const serialized = JSON.stringify({ contract: "verification-consume-native", ...await captureVerificationConsumeNative() });
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/verification-consume-native-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(JSON.parse(serialized), fixture, "verification-consume-native");
});
