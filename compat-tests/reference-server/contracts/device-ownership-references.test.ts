import { expect, test } from "bun:test";
import { captureDeviceOwnershipCase } from "./device-ownership-capture.mjs";

for (const backend of ["memory", "sqlite"]) {
  test(`Device non-ID references retain ${backend} redemption preparation and failure persistence`, async () => {
    const cases = [];
    for (const field of ["tenantKey", "stored_tenant"]) {
      for (const matches of [true, false]) {
        for (const mode of ["direct", "transaction"]) {
          const captured = await captureDeviceOwnershipCase(backend, mode, {
            name: `${field}-${matches ? "match" : "mismatch"}`,
            ownershipWhere: { field, value: matches ? "owner@device-ownership.test" : "foreign@device-ownership.test" },
            expectedClaim: matches ? "requested" : null,
            fields: { tenantKey: {
              type: "string", fieldName: "stored_tenant", required: false,
              references: { model: "user", field: "email" },
            } },
            initialFields: { tenantKey: "owner@device-ownership.test" },
            preparedFields: { tenantKey: "owner@device-ownership.test", scope: "prepared" },
          });
          process.stdout.write(`${JSON.stringify({ contract: "device-ownership-references", version: "1.7.6", backend, case: captured })}\n`);
          cases.push(captured);
        }
      }
    }
    expect(cases.length).toBe(8);
  });
}
