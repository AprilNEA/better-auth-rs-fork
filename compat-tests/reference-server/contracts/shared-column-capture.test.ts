import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runStandaloneCapture } from "./standalone-capture.ts";
import { writeObservation } from "./write-observation.mjs";

for (const backend of ["memory", "sqlite"]) {
  test(`Shared columns retain complete ${backend} declarations, CRUD and callback outcomes`, async () => {
    const capture = new URL("./shared-column-capture.mjs", import.meta.url);
    const first = await runStandaloneCapture(capture, [backend]);
    await writeObservation(first.stdout);
    expect({ status: first.status, stderr: first.stderr }, `Capture evidence: ${first.directory}`).toStrictEqual({ status: 0, stderr: "" });
    const value = JSON.parse(readFileSync(first.output, "utf8"));
    expect(value.version).toBe("1.7.6");
    expect(value.backend).toBe(backend);
    expect(value.cases).toHaveLength(30);
    for (const entry of value.cases) {
      expect(entry.operations.map((operation: { name: string }) => operation.name)).toStrictEqual([
        "create", "read-created", "update-first", "update-undefined", "update-output-error", "read-after-error", "delete", "read-deleted",
      ]);
    }
    const second = await runStandaloneCapture(capture, [backend]);
    expect({ status: second.status, stderr: second.stderr }, `Capture evidence: ${second.directory}`).toStrictEqual({ status: 0, stderr: "" });
    expect(readFileSync(second.output, "utf8"), `Capture evidence: ${second.directory}`).toBe(readFileSync(first.output, "utf8"));
  });
}
