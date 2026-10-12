import { test } from "bun:test";
import { captureApiKeyReferenceNative } from "./api-key-reference-native-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture native API Key reference methods and prior storage writes", async () => {
  const observation = { contract: "api-key-reference-native", ...await captureApiKeyReferenceNative() };
  await writeObservation(`${JSON.stringify(observation)}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-reference-native-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(observation, fixture, "api-key-reference-native");
});
