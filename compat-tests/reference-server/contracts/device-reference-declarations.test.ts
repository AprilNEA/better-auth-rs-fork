import { expect, test } from "bun:test";
import { captureDeviceReferenceDeclarations } from "./device-reference-declarations-capture.mjs";

for (const backend of ["memory", "sqlite", "postgres", "mysql"]) {
  test(`Device replaced reference declarations retain ${backend} ownership, callbacks and persistence`, async () => {
    const observation = await captureDeviceReferenceDeclarations(backend);
    for (const { cases, ...group } of observation.groups) {
      for (const captured of cases) process.stdout.write(`${JSON.stringify({
        contract: "device-reference-declarations", version: observation.version, backend, group, case: captured,
      })}\n`);
    }
    expect(observation.groups.map(group => [group.ownerRefType, group.ownerRefTarget, group.cases.length])).toStrictEqual([
      ["number", "id", 10], ["boolean", "id", 5], ["string[]", "id", 5], ["number[]", "id", 5], ["string", "email", 5],
    ]);
  });
}
