import { test } from "bun:test";
import { captureSecondaryNativeWriteUndefined } from "./secondary-native-write-undefined-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture native undefined secondary writes and prior persistence", async () => {
  await writeObservation(`${JSON.stringify({ contract: "secondary-native-write-undefined", ...await captureSecondaryNativeWriteUndefined() })}\n`);
});
