import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("Email OTP override retains the inner endpoint success object", async () => {
  await expectStandaloneObservation(
    new URL("./email-otp-override-values-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/email-otp-override-values-1.7.6.json", import.meta.url),
    "email-otp-override-values",
  );
}, 120_000);
