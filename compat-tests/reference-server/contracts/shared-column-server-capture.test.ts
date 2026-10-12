import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runStandaloneCapture } from "./standalone-capture.ts";
import { writeObservation } from "./write-observation.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`Shared columns retain complete ${backend} declarations, CRUD, driver errors and stored values`, async () => {
    const capture = new URL("./shared-column-capture.mjs", import.meta.url);
    const first = await runStandaloneCapture(capture, [backend]);
    await writeObservation(first.stdout);
    expect({ status: first.status, stderr: first.stderr }, `Capture evidence: ${first.directory}`).toStrictEqual({ status: 0, stderr: "" });
    const value = JSON.parse(readFileSync(first.output, "utf8"));
    const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/shared-column-server-1.7.6.json", import.meta.url), "utf8"));
    expect(JSON.stringify(value)).toBe(JSON.stringify(fixture.find((entry: { backend: string }) => entry.backend === backend)));
    expect(value.version).toBe("1.7.6");
    expect(value.backend).toBe(backend);
    expect(value.cases).toHaveLength(30);
    for (const entry of value.cases) {
      expect(entry.catalog.columns.length).toBeGreaterThan(0);
      expect(entry.catalog.migration.initialSql).not.toBe("");
      expect(entry.operations.map((operation: { name: string }) => operation.name)).toStrictEqual([
        "create", "read-created", "update-first", "update-undefined", "update-output-error", "read-after-error", "delete", "read-deleted",
      ]);
    }
    const second = await runStandaloneCapture(capture, [backend]);
    await writeObservation(second.stdout);
    expect({ status: second.status, stderr: second.stderr }, `Capture evidence: ${second.directory}`).toStrictEqual({ status: 0, stderr: "" });
    expect(readFileSync(second.output, "utf8"), `Capture evidence: ${second.directory}`).toBe(readFileSync(first.output, "utf8"));
  }, 120_000);
}
