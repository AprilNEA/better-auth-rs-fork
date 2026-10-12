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
import { verificationConsumeInput, verificationConsumeNativeCases } from "./verification-consume-native-values.mjs";

export { verificationConsumeNativeCases } from "./verification-consume-native-values.mjs";

const targetKey = "verification:subject";
const retainedKey = "verification:retained";

async function captureCase(name) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver();
  const events = [];
  const logs = [];
  const cache = new Map();
  const event = (phase, fields = {}, auditFields = fields) => {
    native.record(phase, auditFields);
    events.push({ phase, ...fields });
  };
  const root = verificationConsumeInput(name, event, runtime, () => cache.has(targetKey));
  const retained = { id: "retained-row", value: "unchanged", expiresAt: new Date(now + 90_000),
    nested: { ownUndefined: undefined, order: ["first", "last"] } };
  cache.set(targetKey, root.input);
  cache.set(retainedKey, retained);
  const database = { user: [], session: [], account: [], verification: [] };
  let active = false;
  let consumedCalls = 0;
  const storage = {
    async get(key) {
      if (active) throw new assert.AssertionError({ message: "Verification consumption must not call non-atomic get" });
      return cache.has(key) ? cache.get(key) : null;
    },
    async set(key, value, ttl) {
      if (active) event("storage.set", { key, value: runtime.value(value), ttl: runtime.value(ttl) });
      cache.set(key, value);
    },
    async delete(key) {
      if (active) event("storage.delete", { key });
      cache.delete(key);
    },
    async getAndDelete(key) {
      consumedCalls += 1;
      const present = cache.has(key);
      const value = present ? cache.get(key) : null;
      cache.delete(key);
      const fields = { key, present, sameInput: value === root.input, remainingKeys: [...cache.keys()] };
      event("storage.getAndDelete", fields, { ...fields, value: native.snapshot(value) });
      return value;
    },
  };
  const hooks = Object.fromEntries(["before", "after"].map(phase => [phase, data => {
    if (active) event(`hook:delete:${phase}`, { data: runtime.value(data) });
  }]));
  const context = await betterAuth({
    database: memoryAdapter(database), baseURL: "http://verification-consume-native.test",
    secret: "verification-consume-native-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, rateLimit: { enabled: false }, logger: { disabled: true },
    verification: { storeInDatabase: false, storeIdentifier: "plain" },
    secondaryStorage: storage, databaseHooks: { verification: { delete: hooks } },
  }).$context;
  const state = () => ({ database, cache: [...cache], targetPresent: cache.has(targetKey), retainedSameObject: cache.get(retainedKey) === retained });
  const input = native.snapshot(root.input);
  const before = native.snapshot(state());
  const runtimeBefore = { database: runtime.value(database), storageKeys: [...cache.keys()], targetPresent: cache.has(targetKey),
    retained: runtime.value(retained), retainedSameObject: cache.get(retainedKey) === retained };
  const logger = { error(message, ...args) {
    const error = args[0]?.error;
    const fields = { message, argumentCount: args.length, argumentKeys: Object.keys(args[0]), sameOriginal: error === root.original,
      error: error instanceof Error ? { name: error.name, message: error.message } : runtime.value(error) };
    logs.push({ ...fields, arguments: native.snapshot(args) });
    event("logger:error", fields, logs.at(-1));
  } };
  active = true;
  let result;
  const outcome = await native.outcome(() => runtime.capture(async () => {
    result = await runWithEndpointContext({ context: { logger } }, () => context.internalAdapter.consumeVerificationValue("subject"));
    return result;
  }, root.original), root.original);
  root.verify(outcome, result);
  assert.equal(consumedCalls, 1);
  assert.equal(cache.has(targetKey), false);
  assert.equal(cache.get(retainedKey), retained);
  assert.equal(cache.size, 1);
  assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
  assert.equal(events.some(event => event.phase.startsWith("hook:") || event.phase === "storage.set" || event.phase === "storage.delete"), false);
  assert.equal(logs.length, name === "string-malformed" ? 1 : 0);
  if (logs.length) assert.equal(logs[0].message, "Error parsing JSON");
  const after = native.snapshot(state());
  return {
    name, input, before, outcome, events: native.events, logs, after,
    inputAfter: native.snapshot(root.input), functions: native.functions,
    runtime: { before: runtimeBefore, outcome: runtime.outcome, events, identities: root.identities(result),
      inputState: root.state(), after: runtime.value(state()), functionIds: runtime.functionIds },
  };
}

export async function captureVerificationConsumeNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["better-auth/dist/db/internal-adapter.mjs", "@better-auth/core/dist/utils/json.mjs"].map(path => ({
    path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const name of verificationConsumeNativeCases) cases.push(await captureCase(name));
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Real internalAdapter.consumeVerificationValue with native atomic secondary storage and the endpoint-scoped safeJSONParse logger. Complete input and cache descriptors remain in the source audit without evaluating getters. Runtime observations compare the complete result, callback and error order, identity assertions, atomic removal, and complete remaining storage. Native object hydration and String JSON revival remain distinct.", cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "verification-consume-native", ...await captureVerificationConsumeNative() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
