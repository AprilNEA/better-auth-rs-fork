import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getWithHooks } from "../node_modules/better-auth/dist/db/with-hooks.mjs";
import { observeValue } from "./device-where-capture.mjs";

const date = new Date("2030-01-02T03:04:05.000Z");
const changedAt = new Date("2031-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
export const coreQueryIdAliasOperations = [
  ["user", "findOne"],
  ["user", "update"],
  ["user", "delete"],
  ["user", "findMany-in"],
  ["user", "list-count-id"],
  ["user", "list-count-_id"],
  ["user", "list-count-search-id"],
  ["account", "update"],
  ["account", "updateMany-id"],
  ["account", "updateMany-provider-id"],
  ["account", "delete"],
  ["verification", "delete"],
];

function options(memory, model, serial, fields) {
  return {
    database: memoryAdapter(memory), baseURL: "http://core-query-id.test",
    secret: "ordinary-core-query-id-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: serial ? "serial" : ({ model }) => `${model}-query-id` } },
    [model]: { additionalFields: fields },
  };
}

function userData() {
  return {
    name: "Core query owner", email: "owner@core-query-id.test", emailVerified: false,
    image: null, createdAt: date, updatedAt: date,
  };
}

function modelData(model, owner) {
  if (model === "user") return { ...userData(), label: "selected" };
  if (model === "account") return {
    accountId: "ordinary-subject", providerId: "ordinary-provider", userId: owner,
    accessToken: null, refreshToken: null, idToken: null,
    accessTokenExpiresAt: null, refreshTokenExpiresAt: null, scope: null, password: null,
    createdAt: date, updatedAt: date, label: "selected",
  };
  assert.equal(model, "verification");
  return {
    identifier: "ordinary-query-verification", value: "ordinary-query-value",
    expiresAt, createdAt: date, updatedAt: date, label: "selected",
  };
}

function request(model, operation, id) {
  const where = [{ field: "id", value: id }];
  const update = { label: "updated", updatedAt: changedAt };
  if (operation === "findOne") return { method: "findOne", input: { model, where } };
  if (operation === "update") return { method: "update", input: { model, where, update } };
  if (operation === "delete") return {
    method: model === "verification" ? "deleteWithHooks" : "delete",
    input: { model, where },
  };
  if (operation === "findMany-in") return { method: "findMany", input: {
    model, where: [{ field: "id", operator: "in", value: [id] }], limit: 10,
  } };
  if (operation.startsWith("updateMany-")) return { method: "updateMany", input: {
    model, where: operation === "updateMany-provider-id"
      ? [{ field: "providerId", value: "ordinary-provider" }, ...where] : where,
    update,
  } };
  assert.ok(operation.startsWith("list-count-"));
  const conditions = operation === "list-count-search-id"
    ? [{ field: "email", operator: "eq", value: "owner@core-query-id.test" }, { field: "id", operator: "eq", value: id }]
    : [{ field: operation === "list-count-_id" ? "_id" : "id", operator: "eq", value: id }];
  return { method: "listUsers+countTotalUsers", input: {
    findMany: { model, where: conditions, limit: 10, offset: 0 }, count: { model, where: conditions },
  } };
}

async function execute(context, operation, method, input) {
  if (method === "listUsers+countTotalUsers") return {
    users: await context.internalAdapter.listUsers(input.findMany.limit, input.findMany.offset, undefined, input.findMany.where),
    total: await context.internalAdapter.countTotalUsers(input.count.where),
  };
  if (method === "deleteWithHooks") {
    const hooks = getWithHooks(context.adapter, { options: context.options, hooks: [] });
    return await hooks.deleteWithHooks(input.where, input.model);
  }
  if (operation === "delete") {
    if (input.model === "user") return await context.internalAdapter.deleteUser(input.where[0].value);
    return await context.internalAdapter.deleteAccount(input.where[0].value);
  }
  if (method === "updateMany") {
    const hooks = getWithHooks(context.adapter, { options: context.options, hooks: [] });
    return await hooks.updateManyWithHooks(input.update, input.where, input.model);
  }
  if (operation === "update") {
    if (input.model === "user") return await context.internalAdapter.updateUser(input.where[0].value, input.update);
    return await context.internalAdapter.updateAccount(input.where[0].value, input.update);
  }
  return await context.adapter[method](input);
}

async function captureCase(model, operation, serial) {
  const memory = { user: [], session: [], account: [], verification: [] };
  const writer = (await betterAuth(options(memory, model, serial, { label: { type: "string" } })).$context).adapter;
  const setup = [];
  const seed = async input => {
    const before = observeValue(memory);
    const result = await writer.create(input);
    setup.push({ input: observeValue(input), before, result: observeValue(result), after: observeValue(memory) });
    return result;
  };
  let owner;
  if (model === "account") owner = await seed({ model: "user", forceAllowId: true, data: {
    id: serial ? "001" : "ordinary-core-owner", ...userData(),
  } });
  const selected = await seed({ model, data: modelData(model, owner?.id) });
  const events = [];
  const reader = await betterAuth(options(memory, model, serial, {
    id: { type: "string", fieldName: "old_id" },
    label: { type: "string", transform: {
      input(value) { events.push(["input", "label", observeValue(value)]); return value; },
      output(value) { events.push(["output", "label", observeValue(value)]); return value; },
    } },
  })).$context;
  const steps = [];
  for (const attempt of [1, 2]) {
    const { method, input } = request(model, operation, selected.id);
    const before = observeValue(memory);
    const result = await execute(reader, operation, method, input);
    steps.push({ attempt, method, input: observeValue(input), before, result: observeValue(result), events: events.splice(0), after: observeValue(memory) });
  }
  return { model, operation, serial, idFieldName: "old_id", setup, steps };
}

export async function captureCoreQueryIdAliases() {
  const cases = [];
  for (const [model, operation] of coreQueryIdAliasOperations) {
    for (const serial of [false, true]) cases.push(await captureCase(model, operation, serial));
  }
  return { version: "1.7.6", backend: "memory", cases };
}
