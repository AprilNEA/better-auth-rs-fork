import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("capture real Email and Phone OTP native Verification consumption and failure persistence", async () => {
  await expectStandaloneObservation(
    new URL("./verification-otp-consumer-native-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/verification-otp-consumer-native-1.7.6.json", import.meta.url),
    "verification-otp-consumer-native",
  );
}, 120_000);
