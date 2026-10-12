import { test } from "bun:test";
import { captureOAuthLogoutNative } from "./oauth-logout-native-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture provider logout native date methods, comparator conversion order, and local deletion", async () => {
  await writeObservation(`${JSON.stringify({ contract: "oauth-logout-native", ...await captureOAuthLogoutNative() })}\n`);
});
