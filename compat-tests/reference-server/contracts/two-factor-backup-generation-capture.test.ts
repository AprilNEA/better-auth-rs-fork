import { expect, test } from "bun:test";
import { expectStandaloneObservation, readStandaloneFixture } from "./standalone-capture";
import { twoFactorBackupGenerationCases } from "./two-factor-backup-generation-capture.mjs";

test("native backup generation retains identity and failure persistence", async () => {
  const fixture = new URL("../../../tests/fixtures/two-factor-backup-generation-1.7.6.json", import.meta.url);
  const observation = JSON.parse(readStandaloneFixture(fixture));
  expect(observation.contract).toBe("two-factor-backup-generation");
  expect(observation.version).toBe("1.7.6");
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupGenerationCases);
  // Each capture validates the random ciphertext against the complete TOTP URI before replay.
  const randomPaths = new Set([
    "/cases/11/outcome/result/properties/1/1/value",
    "/cases/11/after/properties/0/1/value/properties/4/1/value/properties/0/1/value/properties/1/1/value",
    "/cases/11/runtime/outcome/result/totpURI",
    "/cases/11/runtime/after/database/twoFactor/0/secret",
  ]);
  await expectStandaloneObservation(
    new URL("./two-factor-backup-generation-capture.mjs", import.meta.url),
    fixture,
    "two-factor-backup-generation",
    randomPaths,
  );
}, 120_000);
