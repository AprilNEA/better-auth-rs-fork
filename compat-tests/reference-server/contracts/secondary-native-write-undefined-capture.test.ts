import { test } from "bun:test";
import { captureSecondaryNativeWriteUndefined } from "./secondary-native-write-undefined-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture native undefined secondary writes and prior persistence", async () => {
  const serialized = JSON.stringify({ contract: "secondary-native-write-undefined", ...await captureSecondaryNativeWriteUndefined() });
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/secondary-native-write-undefined-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(JSON.parse(serialized), fixture, "secondary-native-write-undefined");
});
