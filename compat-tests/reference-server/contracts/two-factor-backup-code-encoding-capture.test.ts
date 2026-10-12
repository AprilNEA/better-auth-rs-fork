import { expect, test } from "bun:test";
import { expectStandaloneObservation, readStandaloneFixture } from "./standalone-capture";
import { twoFactorBackupCodeEncodingCases, twoFactorBackupCodeEncodingRouteCases } from "./two-factor-backup-code-encoding-capture.mjs";

test("real backup-code encoding retains undefined JSON and native encryption failures", async () => {
  const fixture = new URL("../../../tests/fixtures/two-factor-backup-code-encoding-1.7.6.json", import.meta.url);
  const observation = JSON.parse(readStandaloneFixture(fixture));
  expect(observation.contract).toBe("two-factor-backup-code-encoding");
  expect(observation.version).toBe("1.7.6");
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupCodeEncodingRouteCases);
  expect(observation.encodings.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupCodeEncodingCases);
  const hostPaths = new Set([2, 3].flatMap(index => [
    `/encodings/${index}/outcome/error/properties/5/1/value`,
    `/encodings/${index}/outcome/error/properties/6/1/value`,
  ]));
  await expectStandaloneObservation(
    new URL("./two-factor-backup-code-encoding-capture.mjs", import.meta.url),
    fixture,
    "two-factor-backup-code-encoding",
    hostPaths,
  );
}, 120_000);
