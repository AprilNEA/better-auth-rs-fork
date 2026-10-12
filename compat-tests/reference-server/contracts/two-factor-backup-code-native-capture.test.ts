import { expect, test } from "bun:test";
import { twoFactorBackupCodeNativeCases } from "./two-factor-backup-code-native-capture.mjs";
import { expectStandaloneObservation, readStandaloneFixture } from "./standalone-capture";

test("real TwoFactor backup-code methods preserve evaluation order, native results and failure budgets", async () => {
  const fixture = new URL("../../../tests/fixtures/two-factor-backup-code-native-1.7.6.json", import.meta.url);
  const observation = JSON.parse(readStandaloneFixture(fixture));
  expect(observation.version).toBe("1.7.6");
  expect(observation.contract).toBe("two-factor-backup-code-native");
  expect(observation.cases).toHaveLength(16);
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupCodeNativeCases);
  const hostPaths = new Set([0, 6, 7, 8, 9, 10, 11, 15].flatMap(index => [
    `/cases/${index}/outcome/error/properties/6/1/value`,
    `/cases/${index}/runtime/outcome/error/ownEnumerable/stack`,
  ]));
  await expectStandaloneObservation(
    new URL("./two-factor-backup-code-native-capture.mjs", import.meta.url),
    fixture,
    "two-factor-backup-code-native",
    hostPaths,
  );
}, 120_000);
