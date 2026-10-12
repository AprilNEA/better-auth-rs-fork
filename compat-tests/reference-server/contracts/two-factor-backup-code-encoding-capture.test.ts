import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runStandaloneCapture } from "./standalone-capture";
import { twoFactorBackupCodeEncodingCases, twoFactorBackupCodeEncodingRouteCases } from "./two-factor-backup-code-encoding-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture the real backup-code undefined JSON encoding boundary", async () => {
  const result = await runStandaloneCapture(new URL("./two-factor-backup-code-encoding-capture.mjs", import.meta.url));
  await writeObservation(result.stdout);
  expect({ status: result.status, stderr: result.stderr }, `Capture evidence: ${result.directory}`).toEqual({ status: 0, stderr: "" });
  const observation = JSON.parse(readFileSync(result.output, "utf8"));
  expect(observation.contract).toBe("two-factor-backup-code-encoding");
  expect(observation.version).toBe("1.7.6");
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupCodeEncodingRouteCases);
  expect(observation.encodings.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupCodeEncodingCases);
}, 120_000);
