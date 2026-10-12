import { expect, test } from "bun:test";
import { readFileSync, rmSync } from "node:fs";
import { twoFactorBackupCodeNativeCases } from "./two-factor-backup-code-native-capture.mjs";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("real TwoFactor backup-code methods preserve evaluation order, native results and failure budgets", async () => {
  const captured = await runStandaloneCapture(new URL("./two-factor-backup-code-native-capture.mjs", import.meta.url));
  const evidence = `Capture evidence: ${captured.directory}`;
  await writeObservation(captured.stdout);
  expect({ status: captured.status, stderr: captured.stderr }, evidence).toStrictEqual({ status: 0, stderr: "" });
  const observation = JSON.parse(readFileSync(captured.output, "utf8"));
  expect(observation.version).toBe("1.7.6");
  expect(observation.contract).toBe("two-factor-backup-code-native");
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(twoFactorBackupCodeNativeCases);
  rmSync(captured.directory, { recursive: true });
}, 120_000);
