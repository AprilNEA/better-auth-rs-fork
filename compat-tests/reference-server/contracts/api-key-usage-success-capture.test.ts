import { expect, test } from "bun:test";
import { readFileSync, rmSync } from "node:fs";
import { apiKeyUsageSuccessCases } from "./api-key-usage-success-capture.mjs";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("deferred secondary usage retains the complete fresh merged record", async () => {
  const result = await runStandaloneCapture(new URL("./api-key-usage-success-capture.mjs", import.meta.url));
  const evidence = `Capture evidence: ${result.directory}`;
  await writeObservation(result.stdout);
  expect({ status: result.status, stderr: result.stderr }, evidence).toStrictEqual({ status: 0, stderr: "" });
  const observation = JSON.parse(readFileSync(result.output, "utf8"));
  expect({ version: observation.version, contract: observation.contract }, evidence).toStrictEqual({
    version: "1.7.6", contract: "api-key-usage-success",
  });
  expect(observation.cases.map((scenario: { name: string }) => scenario.name), evidence).toStrictEqual(
    apiKeyUsageSuccessCases.map(timing => `deferred-success/${timing}`),
  );
  rmSync(result.directory, { recursive: true });
}, 120_000);
