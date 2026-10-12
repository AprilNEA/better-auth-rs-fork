import { test } from "bun:test";
import { captureApiKeyReferenceNative } from "./api-key-reference-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture native API Key reference methods and prior storage writes", async () => {
  await writeObservation(`${JSON.stringify({ contract: "api-key-reference-native", ...await captureApiKeyReferenceNative() })}\n`);
});
