import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("capture real password, TwoFactor, and OAuth Proxy native Verification consumers", async () => {
  const hostPaths = new Set([
    "/cases/36/outcome/error/properties/6/1/value",
    "/cases/36/runtime/outcome/error/ownEnumerable/stack",
    "/cases/41/outcome/error/properties/6/1/value",
    "/cases/41/runtime/outcome/error/ownEnumerable/stack",
    "/cases/62/events/2/arguments/properties/0/1/value/properties/6/1/value",
  ]);
  await expectStandaloneObservation(
    new URL("./verification-auth-consumer-native-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/verification-auth-consumer-native-1.7.6.json", import.meta.url),
    "verification-auth-consumer-native",
    hostPaths,
  );
}, 120_000);
