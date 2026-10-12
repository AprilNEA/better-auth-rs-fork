import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import configurations from "../../schema-consumer/user-plugin-catalog-config.json";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`User plugin declarations and the complete ${backend} catalog retain registration order and replacements`, async () => {
    const capture = new URL("./user-plugin-catalog-capture.mjs", import.meta.url);
    const first = await runStandaloneCapture(capture, [backend]);
    await writeObservation(first.stdout);
    expect({ status: first.status, stderr: first.stderr }, `Capture evidence: ${first.directory}`).toStrictEqual({ status: 0, stderr: "" });
    const observation = JSON.parse(readFileSync(first.output, "utf8"));
    expect(observation.version).toBe("1.7.6");
    expect(observation.database).toBe(backend);
    expect(observation.cases.map((entry: { name: string }) => entry.name)).toStrictEqual(Object.keys(configurations));
    const second = await runStandaloneCapture(capture, [backend]);
    expect({ status: second.status, stderr: second.stderr }, `Capture evidence: ${second.directory}`).toStrictEqual({ status: 0, stderr: "" });
    expect(readFileSync(second.output, "utf8"), `Capture evidence: ${second.directory}`).toBe(readFileSync(first.output, "utf8"));
  });
}
