import { test } from "bun:test";
import { captureJsonParseNative } from "./json-parse-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture pinned JSON parser diagnostics, native conversion failures, and safeJSONParse logging", async () => {
  await writeObservation(`${JSON.stringify({ contract: "json-parse-native", ...await captureJsonParseNative() })}\n`);
});
