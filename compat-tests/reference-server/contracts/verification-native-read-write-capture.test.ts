import { test } from "bun:test";
import { captureVerificationNativeReadWrite } from "./verification-native-read-write-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture Verification native reads, update identity, and storage callback failures", async () => {
  const serialized = JSON.stringify({ contract: "verification-native-read-write", ...await captureVerificationNativeReadWrite() });
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/verification-native-read-write-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(JSON.parse(serialized), fixture, "verification-native-read-write");
});
