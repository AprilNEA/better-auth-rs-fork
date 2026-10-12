import { expect, test } from "bun:test";
import { captureApiKeyCleanupReferenceBaseline } from "./api-key-cleanup-fields-sql-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`capture API Key cleanup with valid serial references for ${backend}`, async () => {
    const observation = await captureApiKeyCleanupReferenceBaseline(backend);
    await writeObservation(`${JSON.stringify({ contract: "api-key-cleanup-reference-baseline", ...observation })}\n`);
    expect(observation.cases).toHaveLength(1);
    const [captured] = observation.cases;
    expect(captured.ownerSetup.map(step => step.returned)).toStrictEqual([true, true]);
    expect(captured.setup.map(step => step.returned)).toStrictEqual([true, true, true]);
    expect(captured.steps.map(step => step.attempt)).toStrictEqual([1, 2]);
    expect(captured.steps.map(step => step.events)).toStrictEqual([[], []]);
  });
}
