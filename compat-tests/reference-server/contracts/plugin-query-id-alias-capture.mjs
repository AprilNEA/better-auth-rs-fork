import assert from "node:assert/strict";
import { getAuthTables } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { twoFactor } from "better-auth/plugins";
import { recordTwoFactorFailure, resetTwoFactorFailures } from "../node_modules/better-auth/dist/plugins/two-factor/verify-two-factor.mjs";
import { observeValue } from "./device-where-capture.mjs";
import { nativeInput, nativePlugin } from "./native-plugin-replacements-capture.mjs";

const date = new Date("2030-01-02T03:04:05.000Z");
const deadline = new Date("2030-01-02T03:19:05.000Z");
export const queryIdAliasOperations = [
  ["passkey", "findOne", "counter"],
  ["apikey", "decrement", "remaining"],
  ["apikey", "last-request", "lastRequest"],
  ["twoFactor", "backup-codes", "backupCodes"],
  ["twoFactor", "record-failure", "lockedUntil"],
  ["twoFactor", "reset-failures", "lockedUntil"],
  ["twoFactor", "reset-expired", "lockedUntil"],
  ["deviceCode", "claim", "userId"],
  ["deviceCode", "status-update", "status"],
  ["deviceCode", "status-delete", "status"],
];

function options(memory, model, serial, fields) {
  const plugin = model === "twoFactor"
    ? twoFactor({ accountLockout: { maxFailedAttempts: 1, durationSeconds: 900 } })
    : nativePlugin(model);
  return {
    database: memoryAdapter(memory), baseURL: "http://plugin-query-id.test",
    secret: "ordinary-plugin-query-id-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: serial ? "serial" : ({ model }) => `${model}-query-id` } },
    plugins: [plugin, ...(fields ? [{ id: "query-id-alias", schema: { [model]: { fields } } }] : [])],
  };
}

function request(model, operation, id, owner) {
  const where = [{ field: "id", value: id }];
  if (operation === "findOne") return { method: "findOne", input: { model, where } };
  if (operation === "decrement") return { method: "incrementOne", input: {
    model, where: [...where, { field: "remaining", operator: "gt", value: 0 }], increment: { remaining: -1 },
  } };
  if (operation === "last-request") return { method: "update", input: { model, where, update: { lastRequest: date } } };
  if (operation === "backup-codes") return { method: "incrementOne", input: {
    model, where: [...where, { field: "backupCodes", value: "ordinary-encrypted-codes" }],
    increment: {}, set: { backupCodes: "ordinary-replaced-codes" },
  } };
  if (operation === "record-failure" || operation === "reset-failures") return {
    method: operation, input: { model, twoFactor: { id }, now: date },
  };
  if (operation === "reset-expired") return { method: "incrementOne", input: {
    model, where: [...where, { field: "lockedUntil", operator: "lte", value: deadline }],
    increment: {}, set: { failedVerificationCount: 0, lockedUntil: null },
  } };
  if (operation === "claim") return { method: "incrementOne", input: {
    model, where: [...where, { field: "status", value: "pending" }, { field: "userId", value: null }],
    increment: {}, set: { userId: owner },
  } };
  if (operation === "status-update") return { method: "update", input: {
    model, where: [...where, { field: "status", value: "pending" }], update: { status: "approved" },
  } };
  assert.equal(operation, "status-delete");
  return { method: "delete", input: { model, where: [...where, { field: "status", value: "pending" }] } };
}

async function captureCase(model, operation, field, serial) {
  const memory = { user: [], session: [], account: [], verification: [], [model]: [] };
  const writerOptions = options(memory, model, serial);
  const writer = (await betterAuth(writerOptions).$context).adapter;
  const setup = [];
  const seed = async input => {
    const before = observeValue(memory);
    const result = await writer.create(input);
    setup.push({ input: observeValue(input), before, result: observeValue(result), after: observeValue(memory) });
    return result;
  };
  const owner = await seed({ model: "user", forceAllowId: true, data: {
    id: serial ? "001" : "native-replacement-owner", name: "Native query owner", email: "owner@plugin-query-id.test",
    emailVerified: false, createdAt: date, updatedAt: date,
  } });
  const data = nativeInput(model);
  if (model === "apikey") data.referenceId = owner.id;
  else data.userId = operation === "claim" ? null : owner.id;
  if (operation === "reset-failures" || operation === "reset-expired") {
    data.failedVerificationCount = 3;
    data.lockedUntil = date;
  }
  const selected = await seed({ model, data });
  const events = [];
  const declaration = getAuthTables(writerOptions)[model].fields[field];
  assert.ok(declaration);
  const reader = await betterAuth(options(memory, model, serial, {
    id: { type: "string", fieldName: "old_id" },
    [field]: { ...declaration, transform: {
      input(value) { events.push(["input", field, observeValue(value)]); return value; },
      output(value) { events.push(["output", field, observeValue(value)]); return value; },
    } },
  })).$context;
  const steps = [];
  for (const attempt of [1, 2]) {
    const { method, input } = request(model, operation, selected.id, owner.id);
    const before = observeValue(memory);
    let result;
    if (method === "record-failure") {
      const originalNow = Date.now;
      try {
        Date.now = () => date.getTime();
        result = await recordTwoFactorFailure({ context: reader }, model, input.twoFactor);
      } finally {
        Date.now = originalNow;
      }
    } else if (method === "reset-failures") {
      result = await resetTwoFactorFailures({ context: reader }, model, input.twoFactor);
    } else {
      result = await reader.adapter[method](input);
    }
    const after = observeValue(memory);
    if (attempt === 1) {
      assert.equal(result, ["record-failure", "reset-failures", "delete"].includes(method) ? undefined : null);
      assert.deepEqual(after, before);
    } else if (method === "findOne") {
      assert.deepEqual(result, selected);
    } else {
      assert.notDeepEqual(after, before);
    }
    steps.push({ attempt, method, input: observeValue(input), before, result: observeValue(result), events: events.splice(0), after });
  }
  return { model, operation, field, serial, idFieldName: "old_id", setup, steps };
}

export async function capturePluginQueryIdAliases() {
  const cases = [];
  for (const [model, operation, field] of queryIdAliasOperations) {
    for (const serial of [false, true]) cases.push(await captureCase(model, operation, field, serial));
  }
  return { version: "1.7.6", backend: "memory", cases };
}
