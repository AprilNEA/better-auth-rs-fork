import { expect, test } from "bun:test";
import { captureDeviceWhereGroup } from "./device-where-capture.mjs";

test("Device Memory consumption resolves the selected ID before resetting a fresh adapter declaration", async () => {
  const groups = [];
  for (const serial of [false, true]) {
    const scenarios = [
      { name: "id-alias-direct", field: "label", stored: "owned", operator: "eq", value: "owned" },
      { name: "id-alias-transaction-commit", field: "label", stored: "owned", operator: "eq", value: "owned", transaction: true },
      { name: "unknown-field", field: "unregistered", stored: "owned", operator: "eq", value: "owned" },
      { name: "unknown-field-transaction-commit", field: "unregistered", stored: "owned", operator: "eq", value: "owned", transaction: true },
    ].map(scenario => ({ ...scenario, serial, guardBindings: true, observeStorage: true }));
    const group = await captureDeviceWhereGroup("memory", serial, scenarios, { idFieldName: "old_id" });
    expect(group.cases.map(captured => [captured.name, captured.error, captured.result === null])).toStrictEqual([
      ["id-alias-direct", null, false],
      ["id-alias-transaction-commit", null, true],
      ["unknown-field", { name: "BetterAuthError", message: "Field unregistered not found in model deviceCode" }, true],
      ["unknown-field-transaction-commit", { name: "BetterAuthError", message: "Field unregistered not found in model deviceCode" }, true],
    ]);
    for (const captured of group.cases) {
      process.stdout.write(`${JSON.stringify({ contract: "device-query-id-state", version: "1.7.6", backend: "memory", idFieldName: "old_id", serial, case: captured })}\n`);
    }
    groups.push(group);
  }
  expect(groups.length).toBe(2);
});
