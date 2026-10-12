import { expect, test } from "bun:test";
import { readFileSync, rmSync } from "node:fs";
import { deleteExpiredCases } from "./api-key-delete-expired-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

const frozen = JSON.parse(readFileSync(new URL("../../../tests/fixtures/api-key-delete-expired-1.7.6.json", import.meta.url), "utf8"));
expect(frozen.cases.map((observation: { name: string }) => observation.name)).toStrictEqual(deleteExpiredCases);

for (const name of deleteExpiredCases) {
  test(`server-only API Key expiration cleanup preserves catch and storage ownership: ${name}`, async () => {
    const result = await runStandaloneCapture(new URL("./api-key-delete-expired-capture.mjs", import.meta.url), [name]);
    const evidence = `Capture evidence: ${result.directory}`;
    await writeObservation(result.stdout);
    expect({ status: result.status, stderr: result.stderr }, evidence).toStrictEqual({ status: 0, stderr: "" });
    const observation = JSON.parse(readFileSync(result.output, "utf8"));
    assertObservationReplay(observation, frozen.cases.find((observation: { name: string }) => observation.name === name), name);
    rmSync(result.directory, { recursive: true });
  }, 60_000);
}
