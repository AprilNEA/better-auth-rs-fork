import assert from "node:assert/strict";
import { expect, test } from "bun:test";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const date = () => new Date(1_893_456_000_000);

function key(id, remaining) {
  return {
    id, name: "Before", start: null, prefix: null, key: "stored-hash",
    referenceId: "owner", configId: "default", refillInterval: null,
    refillAmount: null, lastRefillAt: null, enabled: true, rateLimitEnabled: true,
    rateLimitTimeWindow: 60_000, rateLimitMax: 3, requestCount: 0, remaining,
    lastRequest: null, expiresAt: null, createdAt: date(), updatedAt: date(),
    permissions: null, metadata: null,
  };
}

function user(name = "Before") {
  return {
    id: "owner", name, email: "owner@memory-graph.test", emailVerified: false,
    image: null, createdAt: date(), updatedAt: date(),
  };
}

const database = (users = [], keys = []) => ({ user: users, session: [], account: [], verification: [], apikey: keys });

async function fixture(events) {
  const memory = database();
  const field = model => ({ type: "string", transform: {
    input(value) { events.push(`input:${model}.name`); return value; },
    output(value) { events.push(`output:${model}.name`); return value; },
  } });
  const { adapter } = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://memory-graph.test",
    secret: "memory-graph-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    user: { additionalFields: { name: field("user") } },
    plugins: [apiKey(), { id: "memory-graph-name", schema: { apikey: { fields: { name: field("apikey") } } } }],
  }).$context;
  expect(events).toStrictEqual([]);
  return { memory, adapter };
}

const where = id => [{ field: "id", value: id }];
const decrement = adapter => adapter.incrementOne({
  model: "apikey", where: [...where("target"), { field: "remaining", operator: "gt", value: 0 }],
  increment: { remaining: -1 },
});

test("Memory transaction keeps repeated top-level API Key rows aliased", async () => {
  const events = [];
  const { memory, adapter } = await fixture(events);
  const target = key("target", 5);
  const captured = memory.apikey;
  captured.push(target, target);
  let result;
  let failure;
  try {
    result = await adapter.transaction(async current => {
      events.push("transaction:enter");
      const updated = await decrement(current);
      const rows = await current.findMany({ model: "apikey", where: [] });
      events.push("transaction:return");
      return { updated, rows };
    });
    events.push("transaction:committed");
  } catch (error) { failure = error; }
  expect(failure).toBeUndefined();
  expect(events).toStrictEqual([
    "transaction:enter", "output:apikey.name", "output:apikey.name", "output:apikey.name",
    "transaction:return", "transaction:committed",
  ]);
  const changed = key("target", 4);
  assert.deepStrictEqual(result, { updated: changed, rows: [changed, changed] });
  assert.deepStrictEqual(memory, database([], [changed, changed]));
  assert.deepStrictEqual(captured, [key("target", 5), key("target", 5)]);
  expect(memory.apikey).not.toBe(captured);
  expect(memory.apikey[0]).toBe(memory.apikey[1]);
  expect(memory.apikey[0]).not.toBe(target);
  expect(captured[0]).toBe(target);
  expect(captured[1]).toBe(target);
  expect(result.updated).not.toBe(memory.apikey[0]);
  expect(result.rows[0]).not.toBe(result.rows[1]);
  expect(result.updated.createdAt).toBe(memory.apikey[0].createdAt);
  expect(result.rows[0].createdAt).toBe(result.rows[1].createdAt);
  expect(memory.apikey[0].createdAt).not.toBe(target.createdAt);
});

test("Memory transaction keeps a field reference to an earlier API Key row", async () => {
  const events = [];
  const { memory, adapter } = await fixture(events);
  const target = key("target", 5);
  const holder = { ...key("holder", 3), name: target };
  const captured = memory.apikey;
  captured.push(target, holder);
  let result;
  let failure;
  try {
    result = await adapter.transaction(async current => {
      events.push("transaction:enter");
      const selected = await current.findOne({ model: "apikey", where: where("holder") });
      expect(selected.name).not.toBe(target);
      selected.name.remaining = 7;
      events.push("graph:mutate-target");
      const updated = await decrement(current);
      const rows = await current.findMany({ model: "apikey", where: [] });
      events.push("transaction:return");
      return { selected, updated, rows };
    });
    events.push("transaction:committed");
  } catch (error) { failure = error; }
  expect(failure).toBeUndefined();
  expect(events).toStrictEqual([
    "transaction:enter", "output:apikey.name", "graph:mutate-target", "output:apikey.name",
    "output:apikey.name", "output:apikey.name", "transaction:return", "transaction:committed",
  ]);
  const changed = key("target", 6);
  const changedHolder = { ...key("holder", 3), name: changed };
  assert.deepStrictEqual(result, { selected: changedHolder, updated: changed, rows: [changed, changedHolder] });
  assert.deepStrictEqual(memory, database([], [changed, changedHolder]));
  assert.deepStrictEqual(captured, [key("target", 5), { ...key("holder", 3), name: key("target", 5) }]);
  expect(memory.apikey[1].name).toBe(memory.apikey[0]);
  expect(result.selected.name).toBe(memory.apikey[0]);
  expect(result.rows[1].name).toBe(memory.apikey[0]);
  expect(result.updated).not.toBe(memory.apikey[0]);
  expect(memory.apikey[0]).not.toBe(target);
  expect(memory.apikey[1]).not.toBe(holder);
  expect(holder.name).toBe(target);
});

test("Memory transaction keeps a User field reference to a later API Key table", async () => {
  const events = [];
  const { memory, adapter } = await fixture(events);
  const target = key("target", 5);
  const owner = user(target);
  const capturedUsers = memory.user;
  const capturedKeys = memory.apikey;
  capturedUsers.push(owner);
  capturedKeys.push(target);
  let result;
  let failure;
  try {
    result = await adapter.transaction(async current => {
      events.push("transaction:enter");
      const selected = await current.findOne({ model: "user", where: where("owner") });
      expect(selected.name).not.toBe(target);
      selected.name.remaining = 7;
      events.push("graph:mutate-target");
      const updated = await decrement(current);
      events.push("transaction:return");
      return { selected, updated };
    });
    events.push("transaction:committed");
  } catch (error) { failure = error; }
  expect(failure).toBeUndefined();
  expect(events).toStrictEqual([
    "transaction:enter", "output:user.name", "graph:mutate-target", "output:apikey.name",
    "transaction:return", "transaction:committed",
  ]);
  const changed = key("target", 6);
  assert.deepStrictEqual(result, { selected: user(changed), updated: changed });
  assert.deepStrictEqual(memory, database([user(changed)], [changed]));
  assert.deepStrictEqual(capturedUsers, [user(key("target", 5))]);
  assert.deepStrictEqual(capturedKeys, [key("target", 5)]);
  expect(memory.user[0].name).toBe(memory.apikey[0]);
  expect(result.selected.name).toBe(memory.apikey[0]);
  expect(result.updated).not.toBe(memory.apikey[0]);
  expect(memory.user[0]).not.toBe(owner);
  expect(memory.apikey[0]).not.toBe(target);
  expect(owner.name).toBe(target);
});

for (const shape of ["row", "object-array"]) {
  test(`Memory ${shape} cycle reaches transaction work and fails only at JSON commit`, async () => {
    const events = [];
    const { memory, adapter } = await fixture(events);
    const target = key("target", 5);
    const expectedTarget = key("target", 5);
    for (const row of [target, expectedTarget]) {
      if (shape === "row") row.name = row;
      else {
        const graph = { label: "graph", nodes: [] };
        graph.nodes.push(graph);
        row.name = graph;
      }
    }
    const owner = user();
    const capturedUsers = memory.user;
    const capturedKeys = memory.apikey;
    capturedUsers.push(owner);
    capturedKeys.push(target);
    let expectedFailure;
    try { JSON.stringify(target); } catch (error) { expectedFailure = error; }
    expect(expectedFailure).toBeInstanceOf(TypeError);
    let callbackValue;
    let result;
    let failure;
    try {
      result = await adapter.transaction(async current => {
        events.push("transaction:enter");
        const selected = await current.findOne({ model: "apikey", where: where("target") });
        expect(selected.name).not.toBe(target.name);
        if (shape === "row") expect(selected.name.name).toBe(selected.name);
        else expect(selected.name.nodes[0]).toBe(selected.name);
        events.push("graph:verified");
        callbackValue = await decrement(current);
        const changedUser = await current.update({
          model: "user", where: where("owner"), update: { name: "Published", updatedAt: date() },
        });
        assert.deepStrictEqual(changedUser, user("Published"));
        events.push("transaction:return");
        return callbackValue;
      });
      events.push("transaction:committed");
    } catch (error) { failure = error; }
    expect(result).toBeUndefined();
    expect(failure).toBeInstanceOf(TypeError);
    expect({ name: failure.name, message: failure.message }).toStrictEqual({
      name: expectedFailure.name, message: expectedFailure.message,
    });
    expect(events).toStrictEqual([
      "transaction:enter", "output:apikey.name", "graph:verified", "output:apikey.name",
      "input:user.name", "output:user.name", "transaction:return",
    ]);
    assert.deepStrictEqual(memory, database([user("Published")], [expectedTarget]));
    assert.deepStrictEqual(capturedUsers, [user()]);
    assert.deepStrictEqual(capturedKeys, [expectedTarget]);
    const expectedClone = key("target", 4);
    if (shape === "row") expectedClone.name = expectedClone;
    else {
      const graph = { label: "graph", nodes: [] };
      graph.nodes.push(graph);
      expectedClone.name = graph;
    }
    assert.deepStrictEqual(callbackValue, { ...expectedClone });
    expect(memory.user).not.toBe(capturedUsers);
    expect(memory.user[0]).not.toBe(owner);
    expect(memory.apikey).toBe(capturedKeys);
    expect(memory.apikey[0]).toBe(target);
    expect(callbackValue.name).not.toBe(target.name);
    expect(callbackValue.createdAt).not.toBe(target.createdAt);
    if (shape === "row") {
      expect(target.name).toBe(target);
      expect(callbackValue.name.name).toBe(callbackValue.name);
      expect(callbackValue.name).not.toBe(callbackValue);
    } else {
      expect(target.name.nodes[0]).toBe(target.name);
      expect(callbackValue.name.nodes[0]).toBe(callbackValue.name);
      expect(callbackValue.name.nodes).not.toBe(target.name.nodes);
    }
  });
}

for (const failAt of [1, 2]) {
  for (const mode of ["function", "throw"]) {
    test(`Memory clone ${failAt} ${mode} failure retains getter writes before transaction work`, async () => {
      const events = [];
      const { memory, adapter } = await fixture(events);
      const owner = user();
      const target = key("target", 5);
      const capturedUsers = memory.user;
      const capturedKeys = memory.apikey;
      capturedUsers.push(owner);
      capturedKeys.push(target);
      const original = new Error("memory-clone-getter-original");
      const unclonable = function () { events.push("unexpected:function:call"); };
      let reads = 0;
      const getter = () => {
        const read = ++reads;
        events.push(`clone:${read}`);
        owner.name = `Live side effect ${read}`;
        events.push(`side-effect:${read}`);
        if (read === failAt) {
          if (mode === "throw") throw original;
          return unclonable;
        }
        return `copied ${read}`;
      };
      const probe = Object.defineProperty({}, "value", { get: getter, enumerable: true, configurable: true });
      target.name = probe;
      let result;
      let failure;
      try {
        result = await adapter.transaction(async () => {
          events.push("transaction:enter");
          return "unexpected transaction result";
        });
      } catch (error) { failure = error; }
      expect(result).toBeUndefined();
      if (mode === "throw") expect(failure).toBe(original);
      else expect({ name: failure.name, message: failure.message }).toStrictEqual({
        name: "DataCloneError", message: "The object can not be cloned.",
      });
      expect(reads).toBe(failAt);
      expect(events).toStrictEqual(failAt === 1
        ? ["clone:1", "side-effect:1"]
        : ["clone:1", "side-effect:1", "clone:2", "side-effect:2"]);
      assert.deepStrictEqual(memory, database([user(`Live side effect ${failAt}`)], [{ ...key("target", 5), name: probe }]));
      expect(Object.getOwnPropertyDescriptors(probe)).toStrictEqual({
        value: { get: getter, set: undefined, enumerable: true, configurable: true },
      });
      expect(memory.user).toBe(capturedUsers);
      expect(memory.apikey).toBe(capturedKeys);
      expect(memory.user[0]).toBe(owner);
      expect(memory.apikey[0]).toBe(target);
      expect(target.name).toBe(probe);
      expect(reads).toBe(failAt);
      expect(events).toStrictEqual(failAt === 1
        ? ["clone:1", "side-effect:1"]
        : ["clone:1", "side-effect:1", "clone:2", "side-effect:2"]);
    });
  }
}
