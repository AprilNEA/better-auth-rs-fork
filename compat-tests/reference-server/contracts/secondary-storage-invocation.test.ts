import { expect, test } from "bun:test";
import { captureSessionSecondaryNative } from "./session-secondary-native-capture.mjs";
import { captureSecondaryNativeWriteUndefined } from "./secondary-native-write-undefined-capture.mjs";
import { captureVerificationNativeReadWrite } from "./verification-native-read-write-capture.mjs";
import { captureSecondaryUserRefreshCases, secondaryUserRefreshScenarios } from "./secondary-user-refresh-capture.mjs";

for (const [contract, capture] of [
  ["session-secondary-native", captureSessionSecondaryNative],
  ["secondary-native-write-undefined", captureSecondaryNativeWriteUndefined],
  ["verification-native-read-write", captureVerificationNativeReadWrite],
] as const) {
  test(`${contract} preserves complete observations with synchronous storage invocation`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/${contract}-1.7.6.json`, import.meta.url)).json();
    expect({ contract, ...await capture(true) }).toStrictEqual(fixture);
  }, 30_000);
}

test("User refresh preserves errors and pending peers with synchronous storage invocation", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/secondary-user-refresh-1.7.6.json", import.meta.url)).json();
  expect(await captureSecondaryUserRefreshCases(secondaryUserRefreshScenarios, true)).toStrictEqual(fixture);
}, 30_000);
