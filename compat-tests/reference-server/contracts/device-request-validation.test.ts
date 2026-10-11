import { expect, test } from "bun:test";
import { captureDeviceRequestValidation } from "./device-request-validation-capture.mjs";

test("Device display fields preserve sync endpoint behavior and explicit async schema results", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/device-request-validation-1.7.6.json", import.meta.url)).json();
  expect(await captureDeviceRequestValidation((name: string, bytes: string) => {
    const reference = expected.syncCases.find((entry: { input: { name: string } }) => entry.input.name === name);
    expect(reference).toBeDefined();
    expect(bytes).toBe(JSON.stringify(reference.body));
  })).toStrictEqual(expected);
});
