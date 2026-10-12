import { test } from "bun:test";
import { captureVerificationAuthConsumerNative } from "./verification-auth-consumer-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture real password, TwoFactor, and OAuth Proxy native Verification consumers", async () => {
  await writeObservation(`${JSON.stringify({ contract: "verification-auth-consumer-native", ...await captureVerificationAuthConsumerNative() })}\n`);
}, 120_000);
