import { expect, test } from "bun:test";
import { readFileSync, rmSync } from "node:fs";
import { emailOtpOverrideValueCases } from "./email-otp-override-values-capture.mjs";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("Email OTP override retains the inner endpoint success object", async () => {
  const result = await runStandaloneCapture(new URL("./email-otp-override-values-capture.mjs", import.meta.url));
  const evidence = `Capture evidence: ${result.directory}`;
  await writeObservation(result.stdout);
  expect({ status: result.status, stderr: result.stderr }, evidence).toStrictEqual({ status: 0, stderr: "" });
  const observation = JSON.parse(readFileSync(result.output, "utf8"));
  expect({ version: observation.version, contract: observation.contract }, evidence).toStrictEqual({
    version: "1.7.6", contract: "email-otp-override-values",
  });
  expect(observation.cases.map((scenario: { name: string }) => scenario.name), evidence).toStrictEqual(
    emailOtpOverrideValueCases.map(timing => `email-otp-override/${timing}`),
  );
  rmSync(result.directory, { recursive: true });
}, 120_000);
