import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("password consumers preserve truthiness, query order, and selected-account writes", async () => {
  const capture = new URL("./password-query-order-capture.mjs", import.meta.url);
  const first = await runStandaloneCapture(capture);
  await writeObservation(first.stdout);
  expect({ status: first.status, stderr: first.stderr }, `Capture evidence: ${first.directory}`).toEqual({ status: 0, stderr: "" });
  const second = await runStandaloneCapture(capture);
  expect({ status: second.status, stderr: second.stderr }, `Capture evidence: ${second.directory}`).toEqual({ status: 0, stderr: "" });
  expect(readFileSync(second.output, "utf8"), `Capture evidence: ${second.directory}`).toBe(readFileSync(first.output, "utf8"));
}, 120_000);
