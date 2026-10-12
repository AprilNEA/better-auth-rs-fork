import { test } from "bun:test";
import { captureSafeJsonNative } from "./safe-json-native-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture safeJSONParse native map dispatch, sparse slots, getter order, and logger failures", async () => {
  const observation = { contract: "safe-json-native", ...await captureSafeJsonNative() };
  const serialized = JSON.stringify(observation);
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/safe-json-native-1.7.6.json", import.meta.url)).json();
  // The stack retains the capture caller's source coordinates in the immutable fixture.
  const hostPaths = new Set(["/cases/4/logs/0/arguments/properties/0/1/value/properties/0/1/value/properties/6/1/value"]);
  assertObservationReplay(JSON.parse(serialized), fixture, "safe-json-native", hostPaths);
});
