import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { runWithEndpointContext } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import { writeObservation } from "./write-observation.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow as now,
  secondaryNativeVersion } from "./secondary-native-shared.mjs";

export const verificationNativeReadWriteCases = [
  ...["empty", "null", "undefined", "false", "true", "number", "date", "function", "array", "object",
    "map-object", "map-function", "map-date", "map-number", "map-error", "string-object", "string-true", "string-empty"].map(input => ({
    name: `find-${input}`, operation: "find", input,
  })),
  ...["date", "function", "map-object", "map-expiry", "map-date-method", "toJSON-mutate", "toJSON-undefined", "toJSON-error", "set-error"].map(input => ({
    name: `update-${input}`, operation: "update", input,
  })),
];

const key = "verification:subject";
const iso = "2030-01-02T03:04:05.000Z";
const date = offset => new Date(now + offset);

function inputFor(scenario, native) {
  const original = { failure: scenario.name, ownUndefined: undefined };
  let mapResult;
  let serializedReceiver;
  const nested = { iso, date: date(-1_000), callback: function retainedCallback() {} };
  const record = () => ({ id: "native-row", identifier: "subject", value: iso, expiresAt: date(60_000), nested });
  const method = (root, name, callback) => Object.defineProperty(root, name, { configurable: true, get() {
    native.call(`get:${name}`, this, root, []);
    return callback;
  } });
  let input;
  switch (scenario.input) {
    case "empty": input = ""; break;
    case "null": input = null; break;
    case "undefined": input = undefined; break;
    case "false": input = false; break;
    case "true": input = true; break;
    case "number": input = 42; break;
    case "date": input = Object.assign(date(-2_000), record()); break;
    case "function": input = Object.assign(function nativeVerification() {}, record()); break;
    case "array": input = [iso, nested]; break;
    case "object": input = record(); break;
    case "string-object": input = JSON.stringify(record()); break;
    case "string-true": input = "true"; break;
    case "string-empty": input = '""'; break;
    default: {
      if (scenario.input.startsWith("map-")) {
        input = [iso];
        if (scenario.input === "map-function") mapResult = Object.assign(function mapVerification() {}, record());
        else if (scenario.input === "map-date") mapResult = Object.assign(date(-2_000), record());
        else if (scenario.input === "map-number") mapResult = 42;
        else mapResult = { ...record(), expiresAt: iso };
        if (scenario.input === "map-expiry") {
          Object.defineProperty(mapResult, "expiresAt", { enumerable: false, configurable: true, get() {
            native.call("get:expiresAt", this, mapResult, []);
            return date(60_000);
          } });
        }
        if (scenario.input === "map-date-method") {
          const expires = date(60_000);
          method(expires, "getTime", function getTime(...args) {
            native.call("call:getTime", this, expires, args);
            return now + 45_999;
          });
          mapResult.expiresAt = expires;
        }
        method(input, "map", function map(...args) {
          native.call("call:map", this, input, args);
          assert.equal(args.length, 1);
          const revived = args[0].call("ignored receiver", iso, 0, input);
          native.record("map:callback", { value: native.snapshot(revived) });
          if (scenario.input === "map-error") throw original;
          return mapResult;
        });
      } else {
        input = record();
        input.toJSON = function toJSON(...args) {
          native.call("call:toJSON", this, input, args);
          assert.deepEqual(args, [""]);
          assert.notEqual(this, input);
          serializedReceiver = this;
          this.mutation = "retained-after-serialization";
          this.value = "mutated-by-toJSON";
          if (scenario.input === "toJSON-error") throw original;
          if (scenario.input === "toJSON-undefined") return undefined;
          return { stored: "custom", value: this.value };
        };
      }
    }
  }
  const patch = { value: "updated-value" };
  if (scenario.input === "map-expiry") patch.expiresAt = null;
  return { input, original, patch, mapResult,
    identities(result) { return {
      sameInput: result === input,
      sameMapResult: mapResult !== undefined && result === mapResult,
      sameSerializedReceiver: serializedReceiver !== undefined && result === serializedReceiver,
      sameNested: result?.nested === nested,
    }; },
    verify(outcome, result) {
      if (scenario.operation === "find") {
        assert.equal(outcome.returned, true);
        if (["empty", "null", "undefined", "false", "map-error", "string-empty"].includes(scenario.input)) assert.equal(result, null);
        if (["date", "function"].includes(scenario.input)) assert.equal(result, input);
        if (scenario.input.startsWith("map-") && scenario.input !== "map-error") assert.equal(result, mapResult);
        if (scenario.input === "map-object") assert.equal(result.value, iso);
        if (["object", "string-object"].includes(scenario.input)) assert.equal(result.value instanceof Date, true);
        if (["true", "string-true"].includes(scenario.input)) assert.equal(result, true);
        if (scenario.input === "number") assert.equal(result, 42);
        if (scenario.input === "array") {
          assert.notEqual(result, input);
          assert.equal(result[0].toISOString(), iso);
          assert.equal(result[1].iso.toISOString(), iso);
        }
      } else {
        const failed = ["toJSON-error", "set-error"].includes(scenario.input);
        assert.equal(outcome.returned, !failed);
        if (failed) assert.equal(outcome.sameOriginal, true);
        else if (scenario.input.startsWith("toJSON-")) {
          assert.equal(result, serializedReceiver);
          assert.equal(result.value, "mutated-by-toJSON");
          assert.equal(result.mutation, "retained-after-serialization");
        } else {
          assert.notEqual(result, input);
          assert.equal(result.value, "updated-value");
          assert.equal(result.id, "native-row");
          if (scenario.input === "map-object") assert.equal(result.expiresAt, iso);
          if (scenario.input === "map-expiry") assert.equal(result.expiresAt, null);
        }
      }
    },
  };
}

async function captureCase(scenario) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const root = inputFor(scenario, native);
  const cache = new Map([[key, root.input], ["unrelated", "retained"]]);
  const database = { user: [], session: [], account: [], verification: [] };
  let active = false;
  const storage = {
    async get(requested) {
      const value = cache.get(requested) ?? null;
      if (active) native.record("storage.get", { key: requested, value: native.snapshot(value) });
      return value;
    },
    async set(requested, value, ttl) {
      if (active) {
        native.record("storage.set", { key: requested, value: native.snapshot(value), ttl: native.snapshot(ttl) });
        if (scenario.input === "set-error") {
          native.record("storage.reject", { error: native.snapshot(root.original) });
          throw root.original;
        }
      }
      cache.set(requested, value);
    },
    async delete(requested) {
      if (active) native.record("storage.delete", { key: requested });
      cache.delete(requested);
    },
    async getAndDelete() { throw new assert.AssertionError({ message: "Read and update must not consume verification values" }); },
  };
  const hooks = Object.fromEntries(["before", "after"].map(phase => [phase, data => {
    if (active) native.record(`hook:update:${phase}`, { data: native.snapshot(data) });
  }]));
  const context = await betterAuth({
    database: memoryAdapter(database), baseURL: "http://verification-native-read-write.test",
    secret: "verification-native-read-write-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, rateLimit: { enabled: false }, logger: { disabled: true },
    verification: { storeInDatabase: false, storeIdentifier: "plain" },
    secondaryStorage: storage, databaseHooks: { verification: { update: hooks } },
  }).$context;
  const state = () => ({ database, cache: [...cache] });
  const runtimeBefore = runtime.value(state());
  const before = native.snapshot(state());
  const logger = { error(message, ...args) {
    native.record("logger:error", { message, arguments: native.snapshot(args), sameOriginal: args[0]?.error === root.original });
  } };
  active = true;
  let result;
  const outcome = await native.outcome(() => runtime.capture(async () => {
    result = await runWithEndpointContext({ context: { logger } }, () => scenario.operation === "find"
      ? context.internalAdapter.findVerificationValue("subject")
      : context.internalAdapter.updateVerificationByIdentifier("subject", root.patch));
    return result;
  }, root.original), root.original);
  root.verify(outcome, result);
  const reads = native.events.filter(event => event.phase === "storage.get");
  const writes = native.events.filter(event => event.phase === "storage.set");
  assert.equal(reads.length, 1);
  assert.equal(reads[0].key, key);
  assert.equal(native.events.some(event => event.phase.startsWith("hook:") || event.phase === "storage.delete"), false);
  assert.equal(native.events.filter(event => event.phase === "logger:error").length, scenario.input === "map-error" ? 1 : 0);
  if (scenario.operation === "find") {
    assert.equal(writes.length, 0);
    assert.equal(cache.get(key), root.input);
  } else {
    const writesCache = !["map-object", "toJSON-error"].includes(scenario.input);
    assert.equal(writes.length, writesCache ? 1 : 0);
    if (writesCache) {
      assert.equal(writes[0].key, key);
      assert.equal(writes[0].ttl, scenario.input === "map-date-method" ? 45 : 60);
    }
    if (scenario.input === "toJSON-undefined") {
      assert.equal(cache.has(key), true);
      assert.equal(cache.get(key), undefined);
    }
    if (["map-object", "toJSON-error", "set-error"].includes(scenario.input)) assert.equal(cache.get(key), root.input);
  }
  assert.equal(cache.get("unrelated"), "retained");
  assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
  const runtimeAfter = runtime.value(state());
  return { scenario, input: native.snapshot(root.input), patch: native.snapshot(root.patch), before,
    outcome, events: native.events, after: native.snapshot(state()), functions: native.functions,
    runtime: { before: runtimeBefore, outcome: runtime.outcome, events: runtime.events,
      identities: root.identities(result), after: runtimeAfter, functionIds: runtime.functionIds },
  };
}

export async function captureVerificationNativeReadWrite() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["better-auth/dist/db/internal-adapter.mjs", "@better-auth/core/dist/utils/json.mjs"].map(path => ({
    path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of verificationNativeReadWriteCases) cases.push(await captureCase(scenario));
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Real findVerificationValue and updateVerificationByIdentifier with native secondary values. Read keeps raw truthiness and one safeJSONParse result. Update preserves spread, nullish expiry, Date getTime, JSON callback identity, errors, and storage. Reflection remains in source audit; runtime compares complete returned values and ordered state.", cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "verification-native-read-write", ...await captureVerificationNativeReadWrite() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
