import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureDeviceWhereGroup } from "./device-where-capture.mjs";

const declarations = [
  { type: "number", target: "id", serial: true, stored: 1, value: "1" },
  { type: "boolean", target: "id", serial: true, stored: true, value: true },
  { type: "string[]", target: "id", serial: true, stored: 1, value: "1" },
  { type: "number[]", target: "id", serial: true, stored: 1, value: "1" },
  { type: "string", target: "email", serial: false, stored: "owner@device-where.test", value: "owner@device-where.test" },
];

function scenarios(declaration) {
  const { type, target, serial, stored, value } = declaration;
  const prefix = `${type}-${target}`;
  const base = { field: "ownerRef", stored, serial, operator: "eq", value, guardBindings: true, observeStorage: true };
  return [
    { ...base, name: `${prefix}-logical-equality` },
    { ...base, name: `${prefix}-physical-membership`, physical: true, operator: "in", value: [value] },
    { ...base, name: `${prefix}-mismatch`, value: serial ? 2 : "other@device-where.test" },
    { ...base, name: `${prefix}-transaction-commit`, transaction: true },
    { ...base, name: `${prefix}-transaction-rollback`, transaction: true, rollback: true },
    ...(type === "number" ? ["id", "deviceCode", "clientId", "userId", "status"].map(field => ({
      ...base, name: `${prefix}-${field}-guard`, guardMismatch: field,
      guardMismatchValue: field === "id" || field === "userId" ? "999" : `${field}-mismatch`,
    })) : []),
  ];
}

export async function captureDeviceReferenceDeclarations(backend) {
  const groups = [];
  for (const declaration of declarations) {
    const { type, target, serial } = declaration;
    const inputs = scenarios(declaration);
    const group = await captureDeviceWhereGroup(backend, serial, inputs, {
      ownerRefType: type, ownerRefTarget: target, replaceOwnerReference: true,
    });
    assert.equal(group.cases.length, inputs.length);
    for (const [index, input] of inputs.entries()) {
      const captured = group.cases[index];
      const mismatched = input.name.endsWith("-mismatch") || input.name.endsWith("-guard");
      assert.equal(captured.name, input.name);
      assert.equal(captured.seeded.ownerRef, serial ? "1" : declaration.stored);
      assert.equal(captured.before[0].stored_ownerRef, serial ? 1 : declaration.stored);
      assert.equal(Object.hasOwn(captured.before[0], "retired_owner_ref"), false);
      for (const model of ["user", "session", "account", "verification"]) {
        assert.deepEqual(captured.storage.after[model], captured.storage.before[model]);
      }
      assert.deepEqual(captured.storage.before.deviceCode, captured.before);
      assert.deepEqual(captured.storage.after.deviceCode, captured.after);
      if (input.rollback) {
        assert.equal(captured.result, null);
        assert.deepEqual(captured.error, { name: "Error", message: "Rollback device reference consumption" });
        assert.deepEqual(captured.rollback, { result: captured.seeded, afterConsume: [], originalError: true });
        assert.deepEqual(captured.after, captured.before);
      } else {
        assert.equal(captured.error, null);
        assert.deepEqual(captured.result, mismatched ? null : captured.seeded);
        assert.deepEqual(captured.after, mismatched ? captured.before : []);
      }
      assert.deepEqual(captured.events, mismatched ? [] : captured.seedEvents.filter(event => event.phase === "output"));
    }
    groups.push({ ownerRefType: type, ownerRefTarget: target, ...group });
  }
  return { version: "1.7.6", backend, groups };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceReferenceDeclarations(backend), null, 2)}\n`);
}
