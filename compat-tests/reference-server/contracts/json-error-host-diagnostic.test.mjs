import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import { writeObservation } from "./write-observation.mjs";

test("diagnose JSON Error materialization with retained, reflected, and collected callers", async () => {
  const observations = [];
  const probe = fileURLToPath(new URL("./json-error-host-diagnostic.mjs", import.meta.url));
  for (const mode of ["retained", "eager-reflected", "forced-gc"]) {
    const result = Bun.spawnSync({
      cmd: [process.execPath, "--no-install", probe, mode],
      stdout: "pipe",
      stderr: "pipe",
    });
    const execution = {
      contract: "json-error-host-diagnostic-process",
      mode,
      exitCode: result.exitCode,
      signalCode: result.signalCode,
      stdout: result.stdout.toString(),
      stderr: result.stderr.toString(),
    };
    await writeObservation(`${JSON.stringify(execution)}\n`);
    expect(execution.exitCode).toBe(0);
    expect(execution.stderr).toBe("");
    observations.push(JSON.parse(execution.stdout));
  }
  const [retained, eager, forced] = observations;
  const hasCompleteMetadata = observation => {
    const names = observation.after.descriptors.ownKeys;
    return names.includes("originalLine") && names.includes("originalColumn");
  };
  const reproduced = hasCompleteMetadata(retained)
    && hasCompleteMetadata(eager)
    && forced.callerCollected
    && Object.values(forced.signature).every(value => value === true);
  await writeObservation(`${JSON.stringify({
    contract: "json-error-host-diagnostic-result",
    status: reproduced ? "reproduced" : "not-reproduced",
    observations,
  })}\n`);
});
