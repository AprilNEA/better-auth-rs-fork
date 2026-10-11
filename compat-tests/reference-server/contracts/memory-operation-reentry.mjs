import { expect, test } from "bun:test";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

function key(id, remaining) {
  const date = () => new Date(1_893_456_000_000);
  return {
    id, name: "Before", start: null, prefix: null, key: "stored-hash",
    referenceId: "owner", configId: "default", refillInterval: null,
    refillAmount: null, lastRefillAt: null, enabled: true, rateLimitEnabled: true,
    rateLimitTimeWindow: 60_000, rateLimitMax: 3, requestCount: 0, remaining,
    lastRequest: null, expiresAt: null, createdAt: date(), updatedAt: date(),
    permissions: null, metadata: null,
  };
}

async function fixture(events) {
  const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
  const { adapter } = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://memory-reentry.test",
    secret: "memory-reentry-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [apiKey(), { id: "memory-reentry-name", schema: { apikey: { fields: {
      name: { type: "string", transform: {
        input(value) { events.push("input:name"); return value; },
        output(value) { events.push("output:name"); return value; },
      } },
    } } } }],
  }).$context;
  return { memory, adapter };
}

function operand(events, tag, number, onRead, onCall) {
  const probe = { tag };
  const method = function () {
    events.push(`call:${tag}.valueOf`);
    expect(arguments.length).toBe(0);
    expect(this).toBe(probe);
    const action = onCall;
    onCall = undefined;
    action?.();
    return number;
  };
  Object.defineProperty(probe, "valueOf", { get() {
    events.push(`get:${tag}.valueOf`);
    const action = onRead;
    onRead = undefined;
    action?.();
    return method;
  } });
  return probe;
}

const decrement = (adapter) => adapter.incrementOne({
  model: "apikey", where: [
    { field: "id", value: "target" },
    { field: "remaining", operator: "gt", value: 0 },
  ], increment: { remaining: -1 },
});

test("Memory API Key increment updates the detached selected row", async () => {
  const events = [];
  const { memory, adapter } = await fixture(events);
  const captured = memory.apikey;
  const target = key("target", 5);
  const other = key("other", 4);
  captured.push(target, other);
  const marker = { nested: true };
  target.remaining = operand(events, "first", 5, () => {
    expect(memory.apikey.includes(target)).toBe(true);
    expect(target.name).toBe("Before");
    events.push("get:first.reentry");
  }, () => {
    target.name = marker;
    target.remaining = 7;
    events.push("nested:mutate-retained");
    memory.apikey = memory.apikey.filter(row => row !== target);
    events.push("nested:rebind");
    memory.apikey.push(key("target", 10));
    events.push("nested:append-active");
  });
  const result = await decrement(adapter);
  expect(events).toStrictEqual([
    "get:first.valueOf", "get:first.reentry", "call:first.valueOf",
    "nested:mutate-retained", "nested:rebind", "nested:append-active", "output:name",
  ]);
  const detached = { ...key("target", 6), name: marker };
  expect(result).toStrictEqual(detached);
  expect(result.name).toBe(marker);
  expect(result).not.toBe(target);
  expect(target).toStrictEqual(detached);
  expect(captured).toStrictEqual([detached, key("other", 4)]);
  expect(memory.apikey).toStrictEqual([key("other", 4), key("target", 10)]);
  expect(memory.apikey.includes(target)).toBe(false);
  expect(memory.apikey[0]).toBe(other);
});

test("Memory API Key later predicate error keeps nested writes without decrement", async () => {
  const events = [];
  const { memory, adapter } = await fixture(events);
  const target = key("target", 5);
  const later = key("other", 4);
  memory.apikey.push(target, later);
  const marker = { nested: true };
  target.remaining = operand(events, "first", 5, undefined, () => {
    target.name = marker;
    target.remaining = 7;
    events.push("nested:mutate-retained");
  });
  const original = new Error("later-memory-predicate-original");
  const rejecting = operand(events, "later", 0, undefined, () => { throw original; });
  later.remaining = rejecting;
  let result;
  let failure;
  try { result = await decrement(adapter); } catch (error) { failure = error; }
  expect(result).toBeUndefined();
  expect(failure).toBe(original);
  expect(events).toStrictEqual([
    "get:first.valueOf", "call:first.valueOf", "nested:mutate-retained",
    "get:later.valueOf", "call:later.valueOf",
  ]);
  const first = { ...key("target", 7), name: marker };
  const second = { ...key("other", 4), remaining: rejecting };
  expect(memory.apikey).toStrictEqual([first, second]);
  expect(target).toStrictEqual(first);
  expect(later).toStrictEqual(second);
  expect(target.name).toBe(marker);
  expect(later.remaining).toBe(rejecting);
});

test("Memory API Key expiry deletion publishes the captured array", async () => {
  const events = [];
  const { memory, adapter } = await fixture(events);
  const expired = id => ({ ...key(id, 5), expiresAt: new Date(0) });
  const captured = memory.apikey;
  const target = expired("target");
  const second = expired("second");
  captured.push(target, second);
  const marker = { nested: true };
  let rebound;
  const probe = operand(events, "expiry", 0, undefined, () => {
    target.name = marker;
    events.push("nested:mutate-retained");
    memory.apikey = memory.apikey.filter(row => row !== second);
    events.push("nested:rebind");
    memory.apikey.push(expired("active-append"));
    rebound = memory.apikey;
    events.push("nested:append-active");
    captured.push(expired("captured-append"));
    events.push("nested:append-captured");
  });
  target.expiresAt = probe;
  const deleted = await adapter.deleteMany({ model: "apikey", where: [
    { field: "expiresAt", operator: "lt", value: new Date() },
    { field: "expiresAt", operator: "ne", value: null },
  ] });
  expect(deleted).toBe(2);
  expect(events).toStrictEqual([
    "get:expiry.valueOf", "call:expiry.valueOf", "nested:mutate-retained",
    "nested:rebind", "nested:append-active", "nested:append-captured",
    "get:expiry.valueOf", "call:expiry.valueOf",
  ]);
  const detached = { ...expired("target"), name: marker, expiresAt: probe };
  expect(target).toStrictEqual(detached);
  expect(target.name).toBe(marker);
  expect(captured).toStrictEqual([detached, expired("second"), expired("captured-append")]);
  expect(rebound).toStrictEqual([detached, expired("active-append")]);
  expect(memory.apikey).toStrictEqual([expired("captured-append")]);
  expect(captured[0]).toBe(target);
  expect(captured[1]).toBe(second);
});
