import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { writeObservation } from "./write-observation.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import {
  assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow,
  secondaryNativeVersion, withSecondarySourceExports,
} from "./secondary-native-shared.mjs";

const referenceKey = "api-key:by-ref:owner";
const hashKey = "api-key:hash";
const idKey = "api-key:by-id:key";

export const apiKeyReferenceNativeCases = [
  { name: "put-own-includes-truthy-object", operation: "put", result: "truthy" },
  { name: "put-own-includes-falsy-string", operation: "put", result: "falsy" },
  { name: "remove-own-filter-native-result", operation: "remove" },
  ...["put", "remove"].flatMap(operation => ["getter", "method"].map(failure => ({
    name: `${operation}-own-${failure}-original-error`, operation, failure,
  }))),
];

async function captureCase(scenario, source) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const id = ["key"];
  const key = { id, key: "hash", referenceId: "owner", configId: "default",
    createdAt: new Date(secondaryNativeNow), updatedAt: new Date(secondaryNativeNow) };
  const index = ["before"];
  const original = { nativeError: scenario.operation, ownUndefined: undefined, detail: { stage: scenario.failure } };
  const values = new Map([[hashKey, "stored-hash"], [idKey, "stored-id"], [referenceKey, index]]);
  const writes = [];
  const storage = {
    async get(key) { native.record("storage.get", { key }); return values.get(key) ?? null; },
    async set(key, value, ttl) {
      writes.push(["set", key, value, ttl]);
      native.record("storage.set", { key, value: native.snapshot(value), ttl: native.snapshot(ttl) });
      values.set(key, value);
    },
    async delete(key) { writes.push(["delete", key]); native.record("storage.delete", { key }); values.delete(key); },
  };
  const predicateResults = [];
  const dynamic = {};
  Object.defineProperties(dynamic, {
    length: { configurable: true, get() {
      native.call("get:length", this, dynamic, []);
      return "0";
    } },
    toJSON: { configurable: true, get() {
      native.call("get:toJSON", this, dynamic, []);
      return function referenceToJSON(...args) {
        native.call("call:toJSON", this, dynamic, args);
        return "custom-reference";
      };
    } },
  });
  const method = scenario.operation === "put" ? "includes" : "filter";
  Object.defineProperty(index, method, { configurable: true, get() {
    native.call(`get:${method}`, this, index, []);
    if (scenario.failure === "getter") throw original;
    return function referenceMethod(...args) {
      native.call(`call:${method}`, this, index, args);
      assert.equal(this, index);
      assert.equal(args.length, 1);
      if (scenario.operation === "put") {
        assert.equal(args[0], id);
        native.record("includes:id", { sameId: args[0] === id });
      } else {
        assert.equal(typeof args[0], "function");
        predicateResults.push(args[0].call("ignored receiver", id, 9, index), args[0].call(index, ["key"]), args[0]());
        native.record("filter:predicate", { results: native.snapshot(predicateResults) });
      }
      if (scenario.failure === "method") throw original;
      this[0] = "changed";
      return scenario.operation === "remove" ? dynamic : scenario.result === "truthy" ? {} : "";
    };
  } });
  const runtimeBefore = runtime.value({ record: key, cache: [...values] });
  const before = native.snapshot({ record: key, cache: [...values], dynamic });
  const operation = () => scenario.operation === "put"
    ? source.setApiKeyInStorage({}, key, storage, undefined, { fallbackToDatabase: false })
    : source.deleteApiKeyFromStorage({}, key, storage, { fallbackToDatabase: false });
  const outcome = await native.outcome(() => runtime.capture(operation, original), original);
  const after = native.snapshot({ record: key, cache: [...values], originalIndex: index, dynamic });
  const runtimeAfter = runtime.value({ record: key, cache: [...values], originalIndex: index,
    indexSameOriginal: values.get(referenceKey) === index });
  assert.equal(outcome.returned, !scenario.failure);
  const serialized = JSON.stringify({ ...key, createdAt: key.createdAt.toISOString(), updatedAt: key.updatedAt.toISOString(),
    expiresAt: null, lastRefillAt: null, lastRequest: null });
  const previous = scenario.operation === "put"
    ? [["set", hashKey, serialized, undefined], ["set", idKey, serialized, undefined]]
    : [["delete", hashKey], ["delete", idKey]];
  if (scenario.failure) {
    assert.equal(outcome.sameOriginal, true);
    assert.equal(values.get(referenceKey), index);
    assert.deepEqual(writes, previous);
  } else {
    const expected = scenario.operation === "remove" ? '"custom-reference"'
      : scenario.result === "truthy" ? '["changed"]' : '["changed",["key"]]';
    assert.equal(values.get(referenceKey), expected);
    assert.deepEqual(writes, [...previous, ["set", referenceKey, expected, undefined]]);
  }
  if (scenario.operation === "remove" && scenario.failure !== "getter") assert.deepEqual(predicateResults, [false, true, true]);
  return { scenario, before, outcome, events: native.events, after, functions: native.functions,
    runtime: { before: runtimeBefore, outcome: runtime.outcome, events: runtime.events, after: runtimeAfter, functionIds: runtime.functionIds } };
}

export async function captureApiKeyReferenceNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key"]);
  return withSecondarySourceExports("@better-auth/api-key", ["setApiKeyInStorage", "deleteApiKeyFromStorage"], async (source, provenance) => {
    const cases = [];
    for (const scenario of apiKeyReferenceNativeCases) cases.push(await captureCase(scenario, source));
    return { version: secondaryNativeVersion, boundary: "API Key internal secondary-storage helpers; HTTP error wrapping is outside this contract.", provenance, cases };
  });
}

if (import.meta.main) {
  const observation = await captureApiKeyReferenceNative();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify({ contract: "api-key-reference-native", ...observation })}\n`);
}
