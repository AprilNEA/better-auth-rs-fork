import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

const date = new Date("2030-01-02T03:04:05.000Z");
const expiry = new Date("2099-01-02T03:04:05.000Z");
const email = "owner@memory-native-join-grouping.test";
const tables = ["user", "session", "account", "verification"];

export const groupingScenarios = [
  { name: "account-duplicate-owner", model: "account", operation: "owner", parentIds: ["shared", "shared"], ownerIds: ["user-a", "user-b"] },
  { name: "account-number-string-owner", model: "account", operation: "owner", parentIds: [1, "1"], ownerIds: ["user-a", "user-b"] },
  { name: "account-page-limit-after-grouping", model: "account", operation: "page", parentIds: ["shared", "other", "shared"], ownerIds: ["user-a", "user-c", "user-b"], offset: 0, limit: 1 },
  { name: "account-page-offset-after-grouping", model: "account", operation: "page", parentIds: ["shared", "shared", "other"], ownerIds: ["user-a", "user-b", "user-c"], offset: 1, limit: 1 },
  { name: "account-first-parent-snapshot", model: "account", operation: "owner", parentIds: ["shared", { effect: "mutate-first", value: "shared" }], ownerIds: ["user-a", "user-b"] },
  { name: "account-late-key-error", model: "account", operation: "owner", parentIds: ["first", "second", { effect: "throw" }], ownerIds: ["user-a", "user-b", "user-c"] },
  { name: "session-duplicate-owner", model: "session", operation: "session", parentIds: ["shared", "shared"], ownerIds: ["user-a", "user-b"] },
  { name: "session-number-string-owner", model: "session", operation: "session", parentIds: [1, "1"], ownerIds: ["user-a", "user-b"] },
  { name: "session-many-limit-after-grouping", model: "session", operation: "sessions", parentIds: ["shared", "other", "shared"], ownerIds: ["user-a", "user-c", "user-b"], defaultLimit: 1 },
  { name: "session-page-offset-after-grouping", model: "session", operation: "page", parentIds: ["shared", "shared", "other"], ownerIds: ["user-a", "user-b", "user-c"], offset: 1, limit: 1 },
  { name: "session-late-key-error", model: "session", operation: "session", parentIds: ["first", "second", { effect: "throw" }], ownerIds: ["user-a", "user-b", "user-c"] },
  { name: "user-many-duplicate-parents", model: "user", operation: "accounts", parentIds: ["user-a", "user-a"], childIds: ["account-a", "account-a", "account-b"], defaultLimit: 1 },
];

function user(id, index) {
  return { id, name: `User ${index}`, email, emailVerified: true, image: null, createdAt: date, updatedAt: date };
}

function account(id, userId, index) {
  return {
    id, accountId: "external-owner", providerId: "provider", userId, accessToken: `parent-${index}`,
    refreshToken: null, idToken: null, accessTokenExpiresAt: null, refreshTokenExpiresAt: null,
    scope: null, password: null, createdAt: date, updatedAt: date,
  };
}

function session(id, userId, index) {
  return {
    id, token: "shared-token", userId, expiresAt: expiry, createdAt: date, updatedAt: date,
    ipAddress: null, userAgent: `parent-${index}`,
  };
}

function seed(scenario, state) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  memory.user = ["user-a", "user-b", "user-c"].map(user);
  const id = (input, index) => {
    if (input === null || typeof input !== "object") return input;
    const value = { effect: input.effect };
    Object.defineProperty(value, "toString", { value() {
      state.events.push(["group-id", index]);
      if (input.effect === "throw") throw state.failure;
      assert.equal(input.effect, "mutate-first");
      memory[scenario.model][0].accessToken = "parent-0-after";
      state.events.push(["mutate-first", "account.accessToken", "parent-0-after"]);
      return input.value;
    } });
    return value;
  };
  memory[scenario.model] = scenario.parentIds.map((input, index) => {
    const parentId = id(input, index);
    if (scenario.model === "user") return user(parentId, index);
    return (scenario.model === "account" ? account : session)(parentId, scenario.ownerIds[index], index);
  });
  if (scenario.model === "user") memory.account = scenario.childIds.map((id, index) => account(id, "user-a", index));
  return memory;
}

function configuration(scenario, memory, state) {
  const field = name => ({ type: "string", required: false, transform: { output(value) {
    state.events.push(["output", name, observeValue(value)]);
    return value;
  } } });
  return {
    baseURL: "http://memory-native-join-grouping.test",
    secret: "memory-native-join-grouping-contract-at-least-thirty-two-characters",
    database: memoryAdapter(memory), logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins: true, defaultFindManyLimit: scenario.defaultLimit ?? 100 } },
    user: { additionalFields: { name: field("user.name") } },
    session: { additionalFields: { userAgent: field("session.userAgent") } },
    account: { additionalFields: { accessToken: field("account.accessToken") } },
  };
}

function execute(context, scenario) {
  if (scenario.operation === "owner") return context.internalAdapter.findAccountOwnerByKey({ providerId: "provider", accountId: "external-owner" });
  if (scenario.operation === "session") return context.internalAdapter.findSession("shared-token");
  if (scenario.operation === "sessions") return context.internalAdapter.findSessions(["shared-token"]);
  if (scenario.operation === "accounts") return context.internalAdapter.findUserByEmail(email, { includeAccounts: true });
  assert.equal(scenario.operation, "page");
  return context.adapter.findMany({
    model: scenario.model, where: [], join: { user: true }, offset: scenario.offset, limit: scenario.limit,
  });
}

function keyOrder(value, path = []) {
  if (value === null || typeof value !== "object" || value instanceof Date) return [];
  return [{ path, keys: Object.keys(value) }, ...Object.entries(value).flatMap(([key, child]) => keyOrder(child, [...path, key]))];
}

function assertResult(scenario, result) {
  if (scenario.operation === "accounts") {
    assert.equal(result.user.name, "User 0");
    assert.deepEqual(result.accounts.map(row => [row.id, row.accessToken]), [["account-a", "parent-0"], ["account-b", "parent-2"]]);
    return;
  }
  if (scenario.operation === "owner") assert.equal(result.kind, "owned");
  let parent;
  let child;
  if (scenario.operation === "page") {
    assert.equal(result.length, 1);
    parent = result[0];
    child = parent.user;
  } else {
    const entry = scenario.operation === "sessions" ? result[0] : result;
    if (scenario.operation === "sessions") assert.equal(result.length, 1);
    parent = entry[scenario.model];
    child = entry.user;
  }
  const offset = scenario.offset === 1;
  assert.equal(parent.id, offset ? "other" : String(scenario.parentIds[0]));
  assert.equal(parent.userId, offset ? "user-c" : "user-a");
  assert.equal(parent[scenario.model === "account" ? "accessToken" : "userAgent"], offset ? "parent-2" : "parent-0");
  assert.equal(child.id, offset ? "user-c" : "user-b");
}

async function captureCase(scenario) {
  const state = { events: [], failure: new Error("Native parent ID conversion failed") };
  const memory = seed(scenario, state);
  const references = tables.map(model => [model, memory[model], [...memory[model]]]);
  const before = observeValue(memory);
  const context = await betterAuth(configuration(scenario, memory, state)).$context;
  assert.deepEqual(state.events, [], "Initialization must not read or project seeded rows");
  let result;
  let error;
  try { result = await execute(context, scenario); }
  catch (caught) { error = caught; }
  const throws = scenario.parentIds.some(id => typeof id === "object" && id?.effect === "throw");
  let observed;
  if (throws) {
    assert.equal(error, state.failure, "The native grouping error must retain its original identity");
    assert.deepEqual(state.events, [["group-id", 2]], "All parent groups precede pagination and output callbacks");
    observed = { returned: false, error: {
      name: error.name, message: error.message,
      properties: observeValue(Object.fromEntries(Object.entries(error))), keys: Object.keys(error),
    } };
  } else {
    assert.equal(error, undefined);
    assertResult(scenario, result);
    observed = { returned: true, result: observeValue(result), json: JSON.parse(JSON.stringify(result)), keyOrder: keyOrder(result) };
  }
  const after = observeValue(memory);
  const mutates = scenario.parentIds.some(id => typeof id === "object" && id?.effect === "mutate-first");
  if (mutates) {
    assert.deepEqual(state.events.slice(0, 2), [["group-id", 1], ["mutate-first", "account.accessToken", "parent-0-after"]]);
    const expected = structuredClone(before);
    expected.account[0].accessToken = "parent-0-after";
    assert.deepEqual(after, expected, "Only the callback's explicit write persists after the grouped snapshot");
  } else assert.deepEqual(after, before, "Reads and ID conversion failures must preserve all stored tables");
  const identities = {
    tables: references.every(([model, table]) => memory[model] === table),
    rows: references.every(([model, , rows]) => rows.every((row, index) => memory[model][index] === row)),
  };
  assert.deepEqual(identities, { tables: true, rows: true });
  return {
    backend: "memory", joins: true, scenario: scenario.name,
    before, events: state.events, ...observed, originalError: error === state.failure,
    after, storageUnchanged: !mutates, identities,
  };
}

export async function captureMemoryNativeJoinGrouping() {
  const cases = [];
  for (const scenario of groupingScenarios) cases.push(await captureCase(scenario));
  assert.equal(cases.length, 12);
  return { version, scenarios: groupingScenarios, cases };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureMemoryNativeJoinGrouping(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
