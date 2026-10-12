import { test } from "bun:test";
import { captureOAuthLogoutNative } from "./oauth-logout-native-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture provider logout native date methods, comparator conversion order, and local deletion", async () => {
  const serialized = JSON.stringify({ contract: "oauth-logout-native", ...await captureOAuthLogoutNative() });
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/oauth-logout-native-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(JSON.parse(serialized), fixture, "oauth-logout-native");
});
