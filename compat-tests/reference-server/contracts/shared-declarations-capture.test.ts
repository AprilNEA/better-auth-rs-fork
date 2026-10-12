import { expect, test } from "bun:test";
import { readFileSync, rmSync } from "node:fs";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("Shared declarations retain complete field order and SQLite catalogs", async () => {
  const capture = new URL("./shared-declarations-capture.mjs", import.meta.url);
  const first = await runStandaloneCapture(capture);
  await writeObservation(first.stdout);
  expect({ status: first.status, stderr: first.stderr }, `Capture evidence: ${first.directory}`).toStrictEqual({ status: 0, stderr: "" });
  expect(readFileSync(first.output, "utf8"), `Capture evidence: ${first.directory}`).toBe(readFileSync(
    new URL("../../../tests/fixtures/shared-declarations-1.7.6.json", import.meta.url), "utf8",
  ));
  const second = await runStandaloneCapture(capture);
  expect({ status: second.status, stderr: second.stderr }, `Capture evidence: ${second.directory}`).toStrictEqual({ status: 0, stderr: "" });
  expect(readFileSync(second.output, "utf8"), `Capture evidence: ${second.directory}`).toBe(readFileSync(first.output, "utf8"));
  rmSync(first.directory, { recursive: true });
  rmSync(second.directory, { recursive: true });
}, 120_000);
