import { secondaryStorageInvocation } from "./secondary-storage-invocation.mjs";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { assertObservationReplay } from "./observation-replay.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { writeObservation } from "./write-observation.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import {
  assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow as now, secondaryNativeVersion,
} from "./secondary-native-shared.mjs";

const indexKey = "active-sessions-owner";
const tables = ["user", "session", "account", "verification"];
const date = offset => new Date(now + offset);
const user = () => ({ id: "owner", name: "Owner", email: "owner@secondary-native.test", emailVerified: true,
  image: null, createdAt: date(-2000), updatedAt: date(-1000) });
const session = (token, expiration) => ({ id: `session-${token}`, token, userId: "owner", expiresAt: date(expiration),
  createdAt: date(-2000), updatedAt: date(-1000), ipAddress: "stored-ip", userAgent: "stored-agent" });
const retainedReference = () => ({ 7: "integer-key", before: "keep", token: "retained", expiresAt: now + 90_000,
  extra: { nested: [1, { own: null }] }, after: "tail" });

export const sessionSecondaryNativeCases = [
  ...[false, true].flatMap(storeInDatabase => ["create", "update", "delete", "batch-delete"].map(operation => ({
    name: `${operation}-retained-record-database-${storeInDatabase}`, operation, storeInDatabase,
  }))),
  ...["function", "date"].map(root => ({ name: `update-native-${root}-method-chain`, operation: "update", root })),
  ...["getter", "method"].map(failure => ({ name: `update-filter-${failure}-prior-write`, operation: "update", failure, storeInDatabase: true })),
  { name: "refresh-date-session-native-get-time", operation: "refresh", expiry: "date" },
  { name: "refresh-date-session-object-get-time", operation: "refresh", expiry: "object" },
  ...["getter", "method"].map(failure => ({ name: `refresh-date-get-time-${failure}-original-error`, operation: "refresh", expiry: "date", failure })),
];

function property(native, root, name, method) {
  Object.defineProperty(root, name, { configurable: true, get() {
    native.call(`get:${name}`, this, root, []);
    return method;
  } });
}

function updateChain(native, rootKind, references) {
  const root = rootKind === "date" ? date(-3000) : function indexRoot() {};
  const filtered = date(-4000);
  const concatenated = function concatenatedRoot() {};
  const sorted = [];
  property(native, root, "filter", function filter(...args) {
    native.call("call:filter", this, root, args);
    assert.equal(args.length, 1);
    assert.equal(typeof args[0], "function");
    const results = references.map((entry, index) => args[0].call("ignored receiver", entry, index, root));
    native.record("filter:predicate", { results: native.snapshot(results) });
    assert.deepEqual(results, [true, false, false]);
    return filtered;
  });
  property(native, filtered, "concat", function concat(...args) {
    native.call("call:concat", this, filtered, args);
    assert.equal(args.length, 1);
    assert.deepEqual(args[0], [{ token: "target", expiresAt: now + 120_000 }]);
    sorted.push(references[0], ...args[0]);
    return concatenated;
  });
  property(native, concatenated, "sort", function sort(...args) {
    native.call("call:sort", this, concatenated, args);
    assert.equal(args.length, 1);
    const compared = args[0].call("ignored receiver", ...sorted);
    native.record("sort:compare", { result: native.snapshot(compared) });
    assert.equal(compared, -30_000);
    return sorted;
  });
  property(native, sorted, "at", function at(...args) {
    native.call("call:at", this, sorted, args);
    assert.deepEqual(args, [-1]);
    return Array.prototype.at.apply(this, args);
  });
  return { root, filtered, concatenated, sorted };
}

async function captureCase(scenario, synchronousStorage) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const owner = user();
  const target = session("target", 60_000);
  const retained = retainedReference();
  const expired = { token: "expired", expiresAt: now - 1000, extra: "expired" };
  const targeted = { token: "target", expiresAt: now + 60_000, extra: "target-replaced" };
  const concurrent = { before: "new", token: "concurrent", expiresAt: now + 180_000,
    extra: { pending: ["entire", "record"] }, after: "new-tail" };
  const references = [retained, expired, targeted];
  const database = Object.fromEntries(tables.map(table => [table, []]));
  database.user.push(structuredClone(owner));
  database.session.push(structuredClone(target), session("retained", 90_000));
  const cache = new Map([
    [indexKey, JSON.stringify(references)],
    ["target", JSON.stringify({ session: target, user: owner, discardedEnvelopeField: "before" })],
    ["retained", JSON.stringify({ session: session("retained", 90_000), user: owner })],
    ["expired", JSON.stringify({ session: session("expired", -1000), user: owner })],
    ["concurrent", JSON.stringify({ session: session("concurrent", 180_000), user: owner })],
  ]);
  const original = { nativeError: scenario.name, ownUndefined: undefined };
  let active = false;
  let indexReads = 0;
  let roots = {};
  const storage = secondaryStorageInvocation({
    get(key) {
      if (active && key === indexKey && ++indexReads === 2 && scenario.operation === "batch-delete") {
        cache.set(indexKey, JSON.stringify([...references, concurrent]));
        native.record("concurrent:index-replacement", { value: native.snapshot(cache.get(indexKey)) });
      }
      const value = cache.get(key) ?? null;
      if (active) native.record("cache.get", { key, value: native.snapshot(value) });
      return value;
    },
    set(key, value, ttl) {
      if (active) native.record("cache.set", { key, value: native.snapshot(value), ttl: native.snapshot(ttl) });
      cache.set(key, value);
    },
    delete(key) { if (active) native.record("cache.delete", { key }); cache.delete(key); },
  }, synchronousStorage);
  if (scenario.root) {
    retained.extra.native = function retainedChild() {};
    retained.extra.date = date(-5000);
    roots = updateChain(native, scenario.root, references);
    cache.set(indexKey, roots.root);
  } else if (scenario.operation === "update" && scenario.failure) {
    const envelope = function sessionEnvelope() {};
    Object.assign(envelope, { session: target, user: owner, discardedEnvelopeField: "native-before" });
    const root = function failingIndex() {};
    Object.defineProperty(root, "filter", { configurable: true, get() {
      native.call("get:filter", this, root, []);
      if (scenario.failure === "getter") throw original;
      return function filter(...args) {
        native.call("call:filter", this, root, args);
        assert.equal(args.length, 1);
        throw original;
      };
    } });
    roots = { envelope, root };
    cache.set("target", envelope);
    cache.set(indexKey, root);
  } else if (scenario.operation === "refresh") {
    const reference = date(-6000);
    Object.assign(reference, { token: "target", expiresAt: now + 60_000, extra: retained.extra });
    const expiry = scenario.expiry === "date" ? date(60_000) : {};
    const nativeSession = date(-7000);
    Object.assign(nativeSession, { expiresAt: expiry, token: "target", marker: "preserved-date-root" });
    const envelope = function cachedEnvelope() {};
    Object.assign(envelope, { session: nativeSession, user: owner, discardedEnvelopeField: "native" });
    const milliseconds = {};
    property(native, milliseconds, "valueOf", function valueOf(...args) {
      native.call("call:valueOf", this, milliseconds, args);
      assert.deepEqual(args, []);
      return now + 59_999;
    });
    Object.defineProperty(expiry, "getTime", { configurable: true, get() {
      native.call("get:getTime", this, expiry, []);
      if (scenario.failure === "getter") throw original;
      return function getTime(...args) {
        native.call("call:getTime", this, expiry, args);
        assert.deepEqual(args, []);
        if (scenario.failure === "method") throw original;
        return milliseconds;
      };
    } });
    roots = { reference, expiry, nativeSession, envelope, milliseconds };
    cache.set(indexKey, [reference]);
    cache.set("target", envelope);
  }
  const hooks = Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
    before(data) { if (active) native.record(`hook:${operation}:before`, { data: native.snapshot(data) }); },
    after(data) { if (active) native.record(`hook:${operation}:after`, { data: native.snapshot(data) }); },
  }]));
  const context = await betterAuth({
    database: memoryAdapter(database), baseURL: "http://secondary-native.test",
    secret: "secondary-native-contract-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "debug", log(level, message, ...args) {
      if (active) native.record("logger", { level, message, arguments: native.snapshot(args) });
    } },
    advanced: { database: { generateId: ({ model }) => `${model}-generated` } },
    session: { storeSessionInDatabase: scenario.storeInDatabase === true },
    secondaryStorage: storage, databaseHooks: { session: hooks },
  }).$context;
  const snapshot = () => native.snapshot({ database, cache: [...cache], roots });
  const runtimeSnapshot = () => ({ database: runtime.value(database), cache: runtime.value([...cache]),
    rootData: Object.fromEntries(Object.entries(roots).map(([name, root]) => [name, runtime.ownValues(root)])) });
  const initialIndex = cache.get(indexKey);
  const before = snapshot();
  const runtimeBefore = runtimeSnapshot();
  active = true;
  const input = scenario.operation === "create" ? { userId: "owner", dontRememberMe: false, override: session("created", 30_000), overrideAll: true }
    : scenario.operation === "update" ? { token: "target", data: { ipAddress: "updated-ip", expiresAt: date(120_000), updatedAt: date(1000) } }
    : scenario.operation === "refresh" ? { user: { ...owner, name: "Refreshed", native: function refreshedChild() {}, seenAt: date(-8000) } }
    : scenario.operation === "delete" ? { token: "target" } : { userId: "owner" };
  const operation = () => {
    switch (scenario.operation) {
      case "create": return context.internalAdapter.createSession(input.userId, input.dontRememberMe, input.override, input.overrideAll);
      case "update": return context.internalAdapter.updateSession(input.token, input.data);
      case "delete": return context.internalAdapter.deleteSession(input.token);
      case "batch-delete": return context.internalAdapter.deleteUserSessions(input.userId);
      case "refresh": return context.internalAdapter.refreshUserSessions(input.user);
      default: throw new Error(`Unknown session secondary operation: ${scenario.operation}`);
    }
  };
  const outcome = await native.outcome(() => runtime.capture(operation, original), original);
  const after = snapshot();
  const runtimeAfter = { ...runtimeSnapshot(), indexSameOriginal: cache.get(indexKey) === initialIndex };
  assert.equal(outcome.returned, !scenario.failure, JSON.stringify(outcome));
  if (scenario.failure) {
    assert.equal(outcome.sameOriginal, true);
    assert.equal(cache.get(indexKey), initialIndex);
    if (scenario.operation === "update") {
      const envelope = JSON.parse(cache.get("target"));
      assert.deepEqual(Object.keys(envelope), ["session", "user"]);
      assert.equal(envelope.session.ipAddress, "updated-ip");
      assert.equal(native.events.filter(event => event.phase === "cache.set").length, 1);
    } else assert.equal(native.events.filter(event => event.phase === "cache.set").length, 0);
  } else if (scenario.operation === "refresh") {
    const expected = JSON.stringify({ session: roots.nativeSession, user: input.user });
    assert.equal(cache.get("target"), expected);
    const writes = native.events.filter(event => event.phase === "cache.set");
    assert.equal(writes.length, 1);
    assert.equal(writes[0].ttl, 59);
    assert.equal(cache.get(indexKey)[0], roots.reference);
  } else {
    const finalIndex = JSON.parse(cache.get(indexKey));
    const expected = scenario.operation === "batch-delete" ? concurrent : retained;
    assertObservationReplay(finalIndex.find(entry => entry.token === expected.token), JSON.parse(JSON.stringify(expected)), `${scenario.name}: retained complete reference`);
    if (scenario.operation === "batch-delete") {
      assert.equal(indexReads, 2);
      assert.equal(cache.has("target"), false);
      assert.equal(cache.has("retained"), false);
      assert.equal(cache.has("concurrent"), true);
      assert.deepEqual(finalIndex, [concurrent]);
    }
    if (scenario.operation === "delete") assert.equal(cache.has("target"), false);
    if (scenario.operation === "update") assert.deepEqual(Object.keys(JSON.parse(cache.get("target"))), ["session", "user"]);
    if (scenario.root) {
      assert.deepEqual(native.events.filter(event => event.phase.startsWith("get:") || event.phase.startsWith("call:")).map(event => event.phase),
        ["get:filter", "call:filter", "get:concat", "call:concat", "get:sort", "call:sort", "get:at", "call:at"]);
    }
  }
  for (const event of native.events) if (Object.hasOwn(event, "sameReceiver")) assert.equal(event.sameReceiver, true);
  return { scenario, input: native.snapshot(input), before, outcome, events: native.events, after, functions: native.functions,
    runtime: { input: runtime.value(input), before: runtimeBefore, outcome: runtime.outcome,
      events: runtime.events, after: runtimeAfter, functionIds: runtime.functionIds } };
}

export async function captureSessionSecondaryNative(synchronousStorage = false) {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["better-auth/dist/db/internal-adapter.mjs", "@better-auth/core/dist/utils/json.mjs"].map(path => ({
    path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of sessionSecondaryNativeCases) cases.push(await captureCase(scenario, synchronousStorage));
    return { version: secondaryNativeVersion, backend: "memory", boundary: "Session internalAdapter with native secondary-storage values; each case records complete memory tables and cache values.", provenance, cases };
  });
}

if (import.meta.main) {
  const observation = await captureSessionSecondaryNative();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify({ contract: "session-secondary-native", ...observation })}\n`);
}
