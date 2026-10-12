import { test } from "bun:test";
import { captureSessionSecondaryNative } from "./session-secondary-native-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture complete Session secondary records, native method calls, and failure persistence", async () => {
  const observation = { contract: "session-secondary-native", ...await captureSessionSecondaryNative() };
  const serialized = JSON.stringify(observation);
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/session-secondary-native-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(JSON.parse(serialized), fixture, "session-secondary-native");
});
