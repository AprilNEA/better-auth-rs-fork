import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runStandaloneCapture } from "./standalone-capture";
import { twoFactorBackupGenerationCases } from "./two-factor-backup-generation-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture native backup generation through real enrollment and regeneration", async () => {
  const result = await runStandaloneCapture(new URL("./two-factor-backup-generation-capture.mjs", import.meta.url));
  await writeObservation(result.stdout);
  expect({ status: result.status, stderr: result.stderr }, `Capture evidence: ${result.directory}`).toEqual({ status: 0, stderr: "" });
  const observation = JSON.parse(readFileSync(result.output, "utf8"));
  expect(observation.contract).toBe("two-factor-backup-generation");
  expect(observation.version).toBe("1.7.6");
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupGenerationCases);
}, 120_000);
