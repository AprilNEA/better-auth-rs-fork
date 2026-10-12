import { test } from "bun:test";
import { captureVerificationConsumeNative } from "./verification-consume-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture Verification native consume hydration, callback failures, and prior atomic deletion", async () => {
  await writeObservation(`${JSON.stringify({ contract: "verification-consume-native", ...await captureVerificationConsumeNative() })}\n`);
});
