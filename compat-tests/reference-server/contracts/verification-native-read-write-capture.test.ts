import { test } from "bun:test";
import { captureVerificationNativeReadWrite } from "./verification-native-read-write-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture Verification native reads, update identity, and storage callback failures", async () => {
  const observation = { contract: "verification-native-read-write", ...await captureVerificationNativeReadWrite() };
  await writeObservation(`${JSON.stringify(observation)}\n`);
});
