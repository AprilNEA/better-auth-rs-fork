import assert from "node:assert/strict";
import { expect, test } from "bun:test";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { decrement, key, user, where } from "./memory-graph-clone.mjs";

async function adapterFor(memory) {
  return (await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://memory-root-order.test",
    secret: "memory-root-order-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, plugins: [apiKey()],
  }).$context).adapter;
}

test("Memory root clone uses numeric key order and commits every alias separately", async () => {
  const events = [];
  const counters = new Map();
  const probe = label => Object.defineProperty({}, "value", {
    enumerable: true,
    get() {
      const read = (counters.get(label) ?? 0) + 1;
      counters.set(label, read);
      events.push(`clone:${label}:${read}`);
      return `${label}:${read}`;
    },
  });
  const target = { ...key("target", 5), name: probe("key") };
  const owner = user(probe("user"));
  const shared = [target];
  const single = [{ id: "one", probe: probe("one") }];
  const users = [owner];
  const memory = { extra: shared, 9: shared, 1: single, user: users, apikey: shared };
  const adapter = await adapterFor(memory);
  expect(events).toStrictEqual([]);
  expect(await adapter.transaction(async () => {
    events.push("transaction:enter");
    return "committed";
  })).toBe("committed");
  expect(events).toStrictEqual([
    "clone:one:1", "clone:key:1", "clone:user:1",
    "clone:one:2", "clone:key:2", "clone:user:2", "transaction:enter",
  ]);
  const expectedKey = { ...key("target", 5), name: { value: "key:2" } };
  assert.deepStrictEqual(memory, {
    1: [{ id: "one", probe: { value: "one:2" } }],
    9: [expectedKey], extra: [expectedKey],
    user: [user({ value: "user:2" })], apikey: [expectedKey],
  });
  expect(Object.keys(memory)).toStrictEqual(["1", "9", "extra", "user", "apikey"]);
  for (const name of ["9", "extra", "apikey"]) {
    expect(memory[name]).not.toBe(shared);
    expect(memory[name][0]).toBe(memory.apikey[0]);
    expect(memory[name][0]).not.toBe(target);
  }
  expect(memory[9]).not.toBe(memory.extra);
  expect(memory.extra).not.toBe(memory.apikey);
  expect(memory[9]).not.toBe(memory.apikey);
  expect(memory[1]).not.toBe(single);
  expect(memory.user).not.toBe(users);
  expect(shared[0]).toBe(target);
  expect(users[0]).toBe(owner);
  expect([...counters]).toStrictEqual([["one", 2], ["key", 2], ["user", 2]]);
});

test("Memory root clone snapshots keys once but reads later table bindings live", async () => {
  const events = [];
  const original = [key("target", 5)];
  const replacements = [];
  const owner = user();
  const memory = { user: [owner], apikey: original };
  let userReads = 0;
  let lateReads = 0;
  const late = [{ id: "late", probe: Object.defineProperty({}, "value", {
    enumerable: true,
    get() { events.push(`clone:late:${++lateReads}`); return "copied late"; },
  }) }];
  const getter = () => {
    const read = ++userReads;
    events.push(`clone:user:${read}`);
    const replacement = [key("target", read * 10)];
    replacements.push(replacement);
    memory.apikey = replacement;
    if (read === 1) memory[2] = late;
    return `copied user ${read}`;
  };
  const probe = Object.defineProperty({}, "value", { get: getter, enumerable: true, configurable: true });
  owner.name = probe;
  const capturedUsers = memory.user;
  const adapter = await adapterFor(memory);
  const result = await adapter.transaction(async current => {
    events.push("transaction:enter");
    const selected = await current.findOne({ model: "user", where: where("owner") });
    const updated = await decrement(current);
    return { selected, updated };
  });
  expect(events).toStrictEqual(["clone:user:1", "clone:late:1", "clone:user:2", "transaction:enter"]);
  assert.deepStrictEqual(result, { selected: user({ value: "copied user 2" }), updated: key("target", 19) });
  assert.deepStrictEqual(memory, {
    2: [{ id: "late", probe: { value: "copied late" } }],
    user: [user({ value: "copied user 2" })], apikey: [key("target", 19)],
  });
  expect(Object.keys(memory)).toStrictEqual(["2", "user", "apikey"]);
  assert.deepStrictEqual(original, [key("target", 5)]);
  assert.deepStrictEqual(replacements, [[key("target", 10)], [key("target", 20)]]);
  expect(memory.user).not.toBe(capturedUsers);
  expect(memory.apikey).not.toBe(replacements[1]);
  expect(memory[2]).not.toBe(late);
  expect(capturedUsers[0]).toBe(owner);
  expect(owner.name).toBe(probe);
  expect(Object.getOwnPropertyDescriptor(probe, "value")).toStrictEqual({
    get: getter, set: undefined, enumerable: true, configurable: true,
  });
  expect(userReads).toBe(2);
  expect(lateReads).toBe(1);
});

test("Memory root commit publishes an earlier API Key table before a later User JSON failure", async () => {
  const target = key("target", 5);
  const owner = user();
  owner.name = owner;
  const capturedKeys = [target];
  const capturedUsers = [owner];
  const memory = { apikey: capturedKeys, user: capturedUsers };
  const adapter = await adapterFor(memory);
  let expectedFailure;
  try { JSON.stringify(owner); } catch (error) { expectedFailure = error; }
  expect(expectedFailure).toBeInstanceOf(TypeError);
  let callbackResult;
  let failure;
  try {
    await adapter.transaction(async current => { callbackResult = await decrement(current); });
  } catch (error) { failure = error; }
  expect(failure).toBeInstanceOf(TypeError);
  expect({ name: failure.name, message: failure.message }).toStrictEqual({
    name: expectedFailure.name, message: expectedFailure.message,
  });
  assert.deepStrictEqual(callbackResult, key("target", 4));
  const expectedOwner = user();
  expectedOwner.name = expectedOwner;
  assert.deepStrictEqual(memory, { apikey: [key("target", 4)], user: [expectedOwner] });
  expect(Object.keys(memory)).toStrictEqual(["apikey", "user"]);
  assert.deepStrictEqual(capturedKeys, [key("target", 5)]);
  expect(memory.apikey).not.toBe(capturedKeys);
  expect(memory.apikey[0]).not.toBe(target);
  expect(memory.user).toBe(capturedUsers);
  expect(memory.user[0]).toBe(owner);
  expect(owner.name).toBe(owner);
  expect(callbackResult).not.toBe(memory.apikey[0]);
  expect(callbackResult.createdAt).toBe(memory.apikey[0].createdAt);
});

test("Memory root commit deletes a working-absent key after a concurrent live rebind", async () => {
  const events = [];
  const owner = user();
  const capturedUsers = [owner];
  const target = key("target", 5);
  const capturedKeys = [target];
  const concurrent = key("concurrent", 9);
  const concurrentKeys = [concurrent];
  const memory = { user: capturedUsers, apikey: capturedKeys };
  let reads = 0;
  const getter = () => {
    events.push(`clone:user:${++reads}`);
    if (reads === 2) delete memory.apikey;
    return `copied user ${reads}`;
  };
  const probe = Object.defineProperty({}, "value", { get: getter, enumerable: true });
  owner.name = probe;
  const adapter = await adapterFor(memory);
  const result = await adapter.transaction(async current => {
    events.push("transaction:enter");
    const selected = await current.findOne({ model: "user", where: where("owner") });
    memory.apikey = concurrentKeys;
    events.push("live:rebind");
    return selected;
  });
  expect(events).toStrictEqual(["clone:user:1", "clone:user:2", "transaction:enter", "live:rebind"]);
  assert.deepStrictEqual(result, user({ value: "copied user 2" }));
  assert.deepStrictEqual(memory, { user: [user({ value: "copied user 2" })] });
  expect(Object.keys(memory)).toStrictEqual(["user"]);
  assert.deepStrictEqual(capturedKeys, [key("target", 5)]);
  assert.deepStrictEqual(concurrentKeys, [key("concurrent", 9)]);
  expect(capturedKeys[0]).toBe(target);
  expect(concurrentKeys[0]).toBe(concurrent);
  expect(memory.user).not.toBe(capturedUsers);
  expect(memory.user[0]).not.toBe(owner);
  expect(owner.name).toBe(probe);
  expect(result.name).toBe(memory.user[0].name);
  expect(result.name).not.toBe(probe);
  expect(Object.getOwnPropertyDescriptor(probe, "value")).toStrictEqual({
    get: getter, set: undefined, enumerable: true, configurable: false,
  });
  expect(reads).toBe(2);
});
