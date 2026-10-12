import { test } from "bun:test";
import { captureSessionSecondaryNative } from "./session-secondary-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture complete Session secondary records, native method calls, and failure persistence", async () => {
  await writeObservation(`${JSON.stringify({ contract: "session-secondary-native", ...await captureSessionSecondaryNative() })}\n`);
});
