import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import { writeObservation } from "./write-observation.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import {
  assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow as now,
  secondaryNativeVersion, withSecondarySourceExports,
} from "./secondary-native-shared.mjs";

const apiHashKey = "api-key:hash";
const apiIdKey = "api-key:by-id:key";
const apiIndexKey = "api-key:by-ref:owner";
const sessionIndexKey = "active-sessions-owner";
const tables = ["user", "session", "account", "verification"];
const date = offset => new Date(now + offset);

export const secondaryNativeWriteUndefinedCases = [
  ...["none", "hash", "id"].map(reject => ({
    name: `api-key-record-undefined-reject-${reject}`, domain: "api-key", operation: "put", target: "record", result: "undefined", reject,
  })),
  ...["put", "remove"].flatMap(operation => ["undefined", "function"].flatMap(result => ["none", "index"].map(reject => ({
    name: `api-key-${operation}-reference-${result}-reject-${reject}`, domain: "api-key", operation, target: "reference", result, reject,
  })))),
  ...["update", "delete", "batch-delete"].flatMap(operation => ["undefined", "function"].flatMap(result => ["none", "index"].map(reject => ({
    name: `session-${operation}-index-${result}-reject-${reject}`, domain: "session", operation, target: "index", result, reject,
    storeInDatabase: true,
  })))),
];

function storage(native, cache, original, rejectKey, beforeGet = () => {}) {
  let active = false;
  const writes = [];
  return {
    writes,
    activate() { active = true; },
    async get(key) {
      if (active) beforeGet(key);
      const value = cache.get(key) ?? null;
      if (active) native.record("storage.get", { key, value: native.snapshot(value) });
      return value;
    },
    async set(key, value, ttl) {
      if (active) {
        writes.push({ key, value, ttl });
        native.record("storage.set", { key, value: native.snapshot(value), ttl: native.snapshot(ttl) });
        if (key === rejectKey && value === undefined) {
          native.record("storage.reject", { key, error: native.snapshot(original) });
          throw original;
        }
      }
      cache.set(key, value);
    },
    async delete(key) {
      if (active) native.record("storage.delete", { key });
      cache.delete(key);
    },
  };
}

function method(native, receiver, name, callback) {
  Object.defineProperty(receiver, name, { configurable: true, get() {
    native.call(`get:${name}`, this, receiver, []);
    return callback;
  } });
}

function omittedJSON(native, receiver, result) {
  method(native, receiver, "toJSON", function toJSON(...args) {
    native.call("call:toJSON", this, receiver, args);
    assert.deepEqual(args, [""]);
    native.record("toJSON:result", { value: native.snapshot(result) });
    return result;
  });
}

function snapshots(native, runtime, state) {
  const raw = state();
  const executable = runtime.value(raw);
  return { audit: native.snapshot(raw), executable };
}

function captureResult(scenario, input, before, outcome, after, native, runtime) {
  return {
    scenario, input: native.snapshot(input), before: before.audit, outcome, events: native.events,
    after: after.audit, functions: native.functions,
    runtime: {
      input: runtime.value(input), before: before.executable, outcome: runtime.outcome,
      events: runtime.events, after: after.executable, functionIds: runtime.functionIds,
    },
  };
}

async function captureApiKey(scenario, source) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const id = ["key"];
  const record = { id, key: "hash", referenceId: "owner", configId: "default", createdAt: date(0), updatedAt: date(0) };
  const index = scenario.target === "record" ? ["before"] : scenario.operation === "put" ? [id] : ["keep", id];
  const original = { rejected: scenario.name, ownUndefined: undefined };
  const cache = new Map([[apiHashKey, "stored-hash"], [apiIdKey, "stored-id"], [apiIndexKey, index]]);
  const rejectKey = { hash: apiHashKey, id: apiIdKey, index: apiIndexKey }[scenario.reject];
  const backend = storage(native, cache, original, rejectKey);
  const roots = { index };
  if (scenario.target === "record") {
    record.toJSON = function recordToJSON(...args) {
      native.call("record:toJSON", this, record, args);
      assert.notEqual(this, record);
      assert.deepEqual(args, [""]);
      native.record("record:receiver", { value: native.snapshot(this), sameId: this.id === id });
      return undefined;
    };
  } else {
    const result = scenario.result === "function" ? function omittedReference() {} : undefined;
    if (scenario.operation === "put") {
      omittedJSON(native, index, result);
    } else {
      const referenceResult = ["keep"];
      roots.referenceResult = referenceResult;
      omittedJSON(native, referenceResult, result);
      method(native, index, "filter", function filter(...args) {
        native.call("call:filter", this, index, args);
        const [predicate] = args;
        assert.equal(args.length, 1);
        assert.equal(typeof predicate, "function");
        const results = [predicate.call("ignored receiver", "keep", 0, index), predicate.call(index, id, 1, index)];
        native.record("filter:predicate", { results: native.snapshot(results) });
        return referenceResult;
      });
    }
    roots.toJSONResult = result;
  }
  const keys = [apiHashKey, apiIdKey, apiIndexKey];
  const state = () => ({ record, cache: [...cache], roots, storageHas: keys.map(key => [key, cache.has(key)]) });
  const before = snapshots(native, runtime, state);
  backend.activate();
  const operation = () => scenario.operation === "put"
    ? source.setApiKeyInStorage({}, record, backend, undefined, { fallbackToDatabase: false })
    : source.deleteApiKeyFromStorage({}, record, backend, { fallbackToDatabase: false });
  const outcome = await native.outcome(() => runtime.capture(operation, original), original);
  const after = snapshots(native, runtime, () => ({ ...state(), indexSameOriginal: cache.get(apiIndexKey) === index }));
  const undefinedWrites = backend.writes.filter(write => write.value === undefined);
  assert.equal(undefinedWrites.length, scenario.target === "record" ? 2 : 1);
  assert.equal(outcome.returned, scenario.reject === "none");
  if (scenario.reject !== "none") assert.equal(outcome.sameOriginal, true);
  for (const { key } of undefinedWrites) {
    assert.equal(cache.has(key), true);
    if (key !== rejectKey) assert.equal(cache.get(key), undefined);
  }
  return captureResult(scenario, { record }, before, outcome, after, native, runtime);
}

function session(token, expiration) {
  return { id: `session-${token}`, token, userId: "owner", expiresAt: date(expiration),
    createdAt: date(-2000), updatedAt: date(-1000), ipAddress: "stored-ip", userAgent: "stored-agent" };
}

function sessionRoots(native, scenario, references) {
  const index = function nativeIndex() {};
  const filtered = function filteredIndex() {};
  const sorted = [];
  const result = scenario.result === "function" ? function omittedIndex() {} : undefined;
  omittedJSON(native, sorted, result);
  method(native, index, "filter", function filter(...args) {
    native.call("call:filter", this, index, args);
    const [predicate] = args;
    assert.equal(args.length, 1);
    assert.equal(typeof predicate, "function");
    const keep = references.map((reference, offset) => predicate.call("ignored receiver", reference, offset, index));
    native.record("filter:predicate", { results: native.snapshot(keep) });
    sorted.push(...references.filter((_, offset) => keep[offset]));
    return scenario.operation === "update" ? filtered : sorted;
  });
  if (scenario.operation === "update") {
    method(native, filtered, "concat", function concat(...args) {
      native.call("call:concat", this, filtered, args);
      assert.equal(args.length, 1);
      sorted.push(...args[0]);
      return sorted;
    });
  }
  return { index, filtered, sorted, toJSONResult: result };
}

async function captureSession(scenario) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const owner = { id: "owner", name: "Owner", email: "owner@secondary-native.test", emailVerified: true,
    image: null, createdAt: date(-2000), updatedAt: date(-1000) };
  const target = session("target", 60_000);
  const retained = session("retained", 90_000);
  const concurrent = session("concurrent", 180_000);
  const reference = stored => ({ token: stored.token, expiresAt: stored.expiresAt.getTime(), extra: { retained: stored.token } });
  const references = [reference(target), reference(retained)];
  const original = { rejected: scenario.name, ownUndefined: undefined };
  const roots = sessionRoots(native, scenario, scenario.operation === "batch-delete" ? [reference(concurrent)] : references);
  const database = Object.fromEntries(tables.map(table => [table, []]));
  database.user.push(structuredClone(owner));
  database.session.push(structuredClone(target), structuredClone(retained));
  const initialIndex = scenario.operation === "batch-delete" ? JSON.stringify(references) : roots.index;
  const cache = new Map([
    [sessionIndexKey, initialIndex],
    ["target", JSON.stringify({ session: target, user: owner })],
    ["retained", JSON.stringify({ session: retained, user: owner })],
    ["concurrent", JSON.stringify({ session: concurrent, user: owner })],
  ]);
  let indexReads = 0;
  let active = false;
  const backend = storage(native, cache, original, scenario.reject === "index" ? sessionIndexKey : undefined, key => {
    if (key === sessionIndexKey && ++indexReads === 2 && scenario.operation === "batch-delete") {
      cache.set(sessionIndexKey, roots.index);
      native.record("concurrent:index-replacement", { value: native.snapshot(roots.index) });
    }
  });
  const hooks = Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
    before(data) { if (active) native.record(`hook:${operation}:before`, { data: native.snapshot(data) }); },
    after(data) { if (active) native.record(`hook:${operation}:after`, { data: native.snapshot(data) }); },
  }]));
  const context = await betterAuth({
    database: memoryAdapter(database), baseURL: "http://secondary-native-write.test",
    secret: "secondary-native-write-contract-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "debug", log(level, message, ...args) {
      if (active) native.record("logger", { level, message, arguments: native.snapshot(args), sameOriginal: args.some(argument => argument === original) });
    } },
    advanced: { database: { generateId: ({ model }) => `${model}-generated` } },
    session: { storeSessionInDatabase: scenario.storeInDatabase },
    secondaryStorage: backend, databaseHooks: { session: hooks },
  }).$context;
  const input = scenario.operation === "update"
    ? { token: "target", data: { ipAddress: "updated-ip", expiresAt: date(120_000), updatedAt: date(1000) } }
    : scenario.operation === "delete" ? { token: "target" } : { userId: "owner" };
  const keys = [sessionIndexKey, "target", "retained", "concurrent"];
  const state = () => ({ database, cache: [...cache], roots, storageHas: keys.map(key => [key, cache.has(key)]) });
  const before = snapshots(native, runtime, state);
  active = true;
  backend.activate();
  const operation = () => scenario.operation === "update"
    ? context.internalAdapter.updateSession(input.token, input.data)
    : scenario.operation === "delete" ? context.internalAdapter.deleteSession(input.token)
      : context.internalAdapter.deleteUserSessions(input.userId);
  const outcome = await native.outcome(() => runtime.capture(operation, original), original);
  const after = snapshots(native, runtime, () => ({ ...state(), indexReads, indexSameOriginal: cache.get(sessionIndexKey) === initialIndex }));
  const undefinedWrites = backend.writes.filter(write => write.value === undefined);
  assert.equal(undefinedWrites.length, 1);
  assert.equal(undefinedWrites[0].key, sessionIndexKey);
  assert.equal(cache.has(sessionIndexKey), true);
  if (scenario.reject === "none") {
    assert.equal(outcome.returned, true);
    assert.equal(cache.get(sessionIndexKey), undefined);
  }
  return captureResult(scenario, input, before, outcome, after, native, runtime);
}

export async function captureSecondaryNativeWriteUndefined() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key"]);
  const sessionProvenance = ["better-auth/dist/db/internal-adapter.mjs", "@better-auth/core/dist/utils/json.mjs"].map(path => ({
    path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    return withSecondarySourceExports("@better-auth/api-key", ["setApiKeyInStorage", "deleteApiKeyFromStorage"], async (source, apiKeyProvenance) => {
      const cases = [];
      for (const scenario of secondaryNativeWriteUndefinedCases) {
        cases.push(await (scenario.domain === "api-key" ? captureApiKey(scenario, source) : captureSession(scenario)));
      }
      return {
        version: secondaryNativeVersion, backend: "memory", provenance: { apiKey: apiKeyProvenance, session: sessionProvenance },
        boundary: "Actual API Key helpers and Session internalAdapter pass JSON.stringify results to native storage. Session create and refresh construct fresh root containers; root undefined would require global prototype changes and is outside these cases. Runtime observations retain all native values, events, errors, and storage. JavaScript descriptor and function reflection remain in the source audit.",
        cases,
      };
    });
  });
}

if (import.meta.main) {
  const observation = await captureSecondaryNativeWriteUndefined();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify({ contract: "secondary-native-write-undefined", ...observation })}\n`);
}
