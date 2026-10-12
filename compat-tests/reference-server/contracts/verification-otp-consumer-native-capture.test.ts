import { test } from "bun:test";
import { captureVerificationOtpConsumerNative } from "./verification-otp-consumer-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";

test("capture real Email and Phone OTP native Verification consumption and failure persistence", async () => {
  const serialized = JSON.stringify({ contract: "verification-otp-consumer-native", ...await captureVerificationOtpConsumerNative() });
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/verification-otp-consumer-native-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(JSON.parse(serialized), fixture, "verification-otp-consumer-native");
}, 120_000);
