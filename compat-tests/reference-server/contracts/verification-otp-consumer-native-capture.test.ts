import { test } from "bun:test";
import { captureVerificationOtpConsumerNative } from "./verification-otp-consumer-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture real Email and Phone OTP native Verification consumption and failure persistence", async () => {
  await writeObservation(`${JSON.stringify({ contract: "verification-otp-consumer-native", ...await captureVerificationOtpConsumerNative() })}\n`);
}, 120_000);
