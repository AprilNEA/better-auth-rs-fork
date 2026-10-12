import { test } from "bun:test";
import { captureSafeJsonNative } from "./safe-json-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture safeJSONParse native map dispatch, sparse slots, getter order, and logger failures", async () => {
  await writeObservation(`${JSON.stringify({ contract: "safe-json-native", ...await captureSafeJsonNative() })}\n`);
});
