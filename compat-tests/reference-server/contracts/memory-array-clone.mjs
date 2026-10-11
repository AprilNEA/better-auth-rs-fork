import assert from "node:assert/strict";
import { expect, test } from "bun:test";
import { database, date, decrement, fixture, key, user, where } from "./memory-graph-clone.mjs";

for (const sharedTable of [false, true]) {
  test(`Memory transaction retains a field table array with shared model table=${sharedTable}`, async () => {
    const events = [];
    const { memory, adapter } = await fixture(events);
    const capturedKeys = memory.apikey;
    const capturedUsers = memory.user;
    const target = key("target", 5);
    const owner = user(capturedKeys);
    capturedKeys.push(target);
    capturedUsers.push(owner);
    if (sharedTable) memory.account = capturedKeys;
    const capturedAccounts = memory.account;
    let result;
    let failure;
    try {
      result = await adapter.transaction(async current => {
        events.push("transaction:enter");
        const selected = await current.findOne({ model: "user", where: where("owner") });
        expect(Array.isArray(selected.name)).toBe(true);
        expect(selected.name).not.toBe(capturedKeys);
        assert.deepStrictEqual(selected.name, [key("target", 5)]);
        const created = await current.create({ model: "apikey", data: key("added", 2), forceAllowId: true });
        expect(selected.name).toHaveLength(2);
        const count = await current.count({ model: "account", where: [] });
        expect(count).toBe(sharedTable ? 2 : 0);
        selected.name[0].remaining = 7;
        events.push("graph:mutate-target");
        const updated = await decrement(current);
        events.push("transaction:return");
        return { selected, created, updated, count };
      });
      events.push("transaction:committed");
    } catch (error) { failure = error; }
    expect(failure).toBeUndefined();
    expect(events).toStrictEqual([
      "transaction:enter", "output:user.name", "input:apikey.name", "output:apikey.name",
      "graph:mutate-target", "output:apikey.name", "transaction:return", "transaction:committed",
    ]);
    const changed = key("target", 6);
    const added = key("added", 2);
    const addedStored = { ...added, metadata: "null" };
    const expectedRows = [changed, addedStored];
    const expectedMemory = database([user(expectedRows)], expectedRows);
    if (sharedTable) expectedMemory.account = expectedRows;
    assert.deepStrictEqual(result, {
      selected: user(expectedRows), created: added, updated: changed, count: sharedTable ? 2 : 0,
    });
    assert.deepStrictEqual(memory, expectedMemory);
    assert.deepStrictEqual(capturedKeys, [key("target", 5)]);
    assert.deepStrictEqual(capturedUsers, [user([key("target", 5)])]);
    assert.deepStrictEqual(capturedAccounts, sharedTable ? [key("target", 5)] : []);
    expect(owner.name).toBe(capturedKeys);
    expect(capturedKeys[0]).toBe(target);
    expect(memory.user).not.toBe(capturedUsers);
    expect(memory.apikey).not.toBe(capturedKeys);
    expect(result.selected.name).toBe(memory.user[0].name);
    expect(result.selected.name).not.toBe(memory.apikey);
    for (const index of [0, 1]) expect(result.selected.name[index]).toBe(memory.apikey[index]);
    expect(result.updated).not.toBe(memory.apikey[0]);
    expect(result.created).not.toBe(memory.apikey[1]);
    expect(result.created.createdAt).toBe(memory.apikey[1].createdAt);
    if (sharedTable) {
      expect(memory.account).not.toBe(memory.apikey);
      expect(memory.account).not.toBe(capturedAccounts);
      for (const index of [0, 1]) expect(memory.account[index]).toBe(memory.apikey[index]);
    }
  });
}

const copiedPayload = stage => ({ stage, missing: undefined, nil: null, date: date(), values: [undefined, null, NaN, -0] });

test("Memory transaction clone reads later array indices after earlier getter writes", async () => {
  const events = [];
  const { memory, adapter } = await fixture(events);
  const owner = user();
  const target = key("target", 5);
  const capturedUsers = memory.user;
  const capturedKeys = memory.apikey;
  capturedUsers.push(owner);
  capturedKeys.push(target);
  const probe = [];
  const payloads = [];
  let reads = 0;
  let later;
  const first = () => {
    const read = ++reads;
    events.push(`clone:${read}:index0`);
    owner.name = `Live side effect ${read}`;
    events.push(`side-effect:${read}`);
    const payload = copiedPayload(read);
    payloads.push(payload);
    later = () => { events.push(`clone:${read}:index1`); return payload; };
    Object.defineProperty(probe, "1", { get: later, enumerable: true, configurable: true });
    return `copied ${read}`;
  };
  Object.defineProperty(probe, "0", { get: first, enumerable: true, configurable: true });
  Object.defineProperty(probe, "1", {
    get() { events.push("unexpected:stale:index1"); return "stale"; },
    enumerable: true, configurable: true,
  });
  target.name = probe;
  let result;
  let failure;
  try {
    result = await adapter.transaction(async current => {
      events.push("transaction:enter");
      const selected = await current.findOne({ model: "apikey", where: where("target") });
      assert.deepStrictEqual(selected, { ...key("target", 5), name: ["copied 2", copiedPayload(2)] });
      events.push("graph:verified");
      const updated = await decrement(current);
      events.push("transaction:return");
      return { selected, updated };
    });
    events.push("transaction:committed");
  } catch (error) { failure = error; }
  expect(failure).toBeUndefined();
  const expectedEvents = [
    "clone:1:index0", "side-effect:1", "clone:1:index1",
    "clone:2:index0", "side-effect:2", "clone:2:index1",
    "transaction:enter", "output:apikey.name", "graph:verified", "output:apikey.name",
    "transaction:return", "transaction:committed",
  ];
  expect(events).toStrictEqual(expectedEvents);
  const name = ["copied 2", copiedPayload(2)];
  const selected = { ...key("target", 5), name };
  const changed = { ...key("target", 4), name };
  assert.deepStrictEqual(result, { selected, updated: changed });
  assert.deepStrictEqual(memory, database([user("Live side effect 1")], [changed]));
  assert.deepStrictEqual(capturedUsers, [user("Live side effect 2")]);
  assert.deepStrictEqual(capturedKeys, [{ ...key("target", 5), name: probe }]);
  expect(memory.user).not.toBe(capturedUsers);
  expect(memory.apikey).not.toBe(capturedKeys);
  expect(capturedUsers[0]).toBe(owner);
  expect(capturedKeys[0]).toBe(target);
  expect(target.name).toBe(probe);
  expect(result.selected.name).toBe(result.updated.name);
  expect(result.updated.name).toBe(memory.apikey[0].name);
  expect(result.selected.name).not.toBe(probe);
  expect(result.selected.name[1]).not.toBe(payloads[1]);
  expect(result.selected.name[1].date).not.toBe(payloads[1].date);
  expect(Object.keys(result.selected.name)).toStrictEqual(["0", "1"]);
  expect(Object.keys(result.selected.name[1])).toStrictEqual(["stage", "missing", "nil", "date", "values"]);
  expect(Object.hasOwn(result.selected.name[1], "missing")).toBe(true);
  expect(Object.getOwnPropertyDescriptors(probe)).toStrictEqual({
    0: { get: first, set: undefined, enumerable: true, configurable: true },
    1: { get: later, set: undefined, enumerable: true, configurable: true },
    length: { value: 2, writable: true, enumerable: false, configurable: false },
  });
  expect(reads).toBe(2);
  expect(events).toStrictEqual(expectedEvents);
});

for (const failAt of [1, 2]) {
  for (const mode of ["function", "throw"]) {
    test(`Memory array clone ${failAt} ${mode} failure stops later indices and transaction work`, async () => {
      const events = [];
      const { memory, adapter } = await fixture(events);
      const owner = user();
      const target = key("target", 5);
      const capturedUsers = memory.user;
      const capturedKeys = memory.apikey;
      capturedUsers.push(owner);
      capturedKeys.push(target);
      const original = new Error("memory-array-getter-original");
      const unclonable = function () { events.push("unexpected:function:call"); };
      let reads = 0;
      const first = () => {
        const read = ++reads;
        events.push(`clone:${read}:index0`);
        owner.name = `Live side effect ${read}`;
        events.push(`side-effect:${read}`);
        if (read === failAt) {
          if (mode === "throw") throw original;
          return unclonable;
        }
        return `copied ${read}`;
      };
      const later = () => { events.push(`clone:${reads}:index1`); return copiedPayload(reads); };
      const probe = Object.defineProperties([], {
        0: { get: first, enumerable: true, configurable: true },
        1: { get: later, enumerable: true, configurable: true },
      });
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
      const expectedEvents = failAt === 1
        ? ["clone:1:index0", "side-effect:1"]
        : ["clone:1:index0", "side-effect:1", "clone:1:index1", "clone:2:index0", "side-effect:2"];
      expect(reads).toBe(failAt);
      expect(events).toStrictEqual(expectedEvents);
      assert.deepStrictEqual(memory, database([user(`Live side effect ${failAt}`)], [{ ...key("target", 5), name: probe }]));
      expect(Object.getOwnPropertyDescriptors(probe)).toStrictEqual({
        0: { get: first, set: undefined, enumerable: true, configurable: true },
        1: { get: later, set: undefined, enumerable: true, configurable: true },
        length: { value: 2, writable: true, enumerable: false, configurable: false },
      });
      expect(memory.user).toBe(capturedUsers);
      expect(memory.apikey).toBe(capturedKeys);
      expect(memory.user[0]).toBe(owner);
      expect(memory.apikey[0]).toBe(target);
      expect(target.name).toBe(probe);
      expect(reads).toBe(failAt);
      expect(events).toStrictEqual(expectedEvents);
    });
  }
}
