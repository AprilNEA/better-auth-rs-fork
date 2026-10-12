import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion, withSecondarySourceExports } from "./secondary-native-shared.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

const fields = ["createdAt", "updatedAt", "expiresAt", "lastRefillAt", "lastRequest"];
const modes = ["object-string", "object-undefined", "object-result", "date-to-json", "invalid-date-iso", "get-throws", "call-throws"];
export const apiKeyDateMethodCases = [
  ...fields.flatMap(field => modes.map(mode => ({ name: `${field}/${mode}`, field, mode }))),
  { name: "expiresAt/ttl-before-serialization", field: "expiresAt", mode: "ttl-before-serialization" },
];

function seed() {
  return { id: "method-key", key: "method-secret", referenceId: "owner", configId: "default",
    createdAt: new Date(0), updatedAt: new Date(0), expiresAt: null, lastRefillAt: null, lastRequest: null,
    metadata: { retained: true } };
}

async function captureCase(source, scenario) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const original = { cause: "original date method failure" };
  const entries = new Map([["api-key:by-ref:owner", '["older"]']]);
  const key = seed();
  const returned = { marker: "method-result", optional: undefined };
  const receiver = scenario.mode === "date-to-json" ? new Date(0)
    : scenario.mode === "invalid-date-iso" ? new Date(NaN) : {};
  const returnValue = scenario.mode === "object-undefined" ? undefined
    : scenario.mode === "object-result" ? returned : "method-iso";
  if (scenario.mode === "date-to-json") {
    Object.defineProperty(receiver, "toJSON", { configurable: true, get() {
      native.record("get:toJSON", { sameReceiver: this === receiver });
      throw original;
    } });
  } else {
    const method = function (...args) {
      native.call("call:toISOString", this, receiver, args);
      if (scenario.mode === "call-throws") throw original;
      return returnValue;
    };
    Object.defineProperty(receiver, "toISOString", { configurable: true, get() {
      native.record("get:toISOString", { sameReceiver: this === receiver });
      if (scenario.mode === "get-throws") throw original;
      return method;
    } });
  }
  if (scenario.mode === "object-result") {
    Object.defineProperty(returned, "toJSON", { configurable: true, value: function (...args) {
      native.call("call:result.toJSON", this, returned, args);
      return { result: args[0], retained: true };
    } });
  }
  if (scenario.mode === "ttl-before-serialization") {
    Object.defineProperty(receiver, "valueOf", { configurable: true, get() {
      native.record("get:valueOf", { sameReceiver: this === receiver });
      return function (...args) {
        native.call("call:valueOf", this, receiver, args);
        throw original;
      };
    } });
  }
  key[scenario.field] = receiver;
  const before = native.snapshot(key);
  const beforeEntries = [...entries];
  const storage = {
    async get(key) { native.record("storage.get", { key: native.snapshot(key) }); return entries.get(key) ?? null; },
    async set(key, value, ttl) { native.record("storage.set", { key: native.snapshot(key), value: native.snapshot(value), ttl: native.snapshot(ttl) }); entries.set(key, value); },
    async delete(key) { native.record("storage.delete", { key: native.snapshot(key) }); entries.delete(key); },
  };
  const outcome = await native.outcome(
    () => runtime.capture(() => source.setApiKey({}, key, { storage: "secondary-storage", customStorage: storage, fallbackToDatabase: true }), original),
    original,
  );
  const failed = scenario.mode.endsWith("throws") || scenario.mode === "ttl-before-serialization";
  assert.equal(outcome.returned, !failed);
  if (failed) {
    assert.equal(outcome.sameOriginal, true);
    assert.deepEqual([...entries], beforeEntries);
    assert.ok(runtime.events.every(event => !event.phase.startsWith("storage.")));
    if (scenario.mode === "ttl-before-serialization") assert.deepEqual(runtime.events.map(event => event.phase), ["get:valueOf", "call:valueOf"]);
  } else {
    const serialized = entries.get("api-key:method-secret");
    assert.equal(entries.get("api-key:by-id:method-key"), serialized);
    assert.equal(entries.has("api-key:by-ref:owner"), false);
    const expected = { ...seed(), [scenario.field]: scenario.mode === "date-to-json" ? new Date(0)
      : scenario.mode === "object-undefined" ? (scenario.field === "createdAt" || scenario.field === "updatedAt" ? undefined : null)
      : scenario.mode === "object-result" ? { result: scenario.field, retained: true } : "method-iso" };
    assert.equal(serialized, JSON.stringify(expected));
    assert.ok(runtime.events.every(event => event.phase !== "get:toJSON"));
  }
  assert.equal(key[scenario.field], receiver);
  return { ...scenario, audit: { before, after: native.snapshot(key), outcome, events: native.events, functions: native.functions },
    runtime: { before: runtime.value(key), outcome: runtime.outcome, events: runtime.events, entries: [...entries], functionIds: runtime.functionIds } };
}

export async function captureApiKeyDateMethods() {
  assertSecondaryNativeVersions(["@better-auth/api-key"]);
  return withClock(async setClock => {
    setClock(2_000_000_000_000);
    return withSecondarySourceExports("@better-auth/api-key", ["setApiKey"], async (source, provenance) => {
      const cases = [];
      for (const scenario of apiKeyDateMethodCases) cases.push(await captureCase(source, scenario));
      return { contract: "api-key-date-methods", version: secondaryNativeVersion, provenance,
        boundary: "The original secondary-storage setter evaluates TTL before native toISOString methods, then serializes their complete returned values. Every method receiver, callback error identity, cache write, and final entry remains observed. Descriptor metadata remains frozen source evidence.", cases };
    });
  });
}

if (import.meta.main) {
  const observation = await captureApiKeyDateMethods();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
