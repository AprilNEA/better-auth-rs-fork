import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const HASH = "api-key:usage-secret";
const BY_ID = "api-key:by-id:usage-key";
const OLD_REF = "api-key:by-ref:owner";
const FRESH_REF = "api-key:by-ref:fresh-owner";
const epoch = 2_000_000_000_000;
const nextTurn = () => new Promise(resolve => setTimeout(resolve, 0));
export const apiKeyUsageSuccessCases = ["ready", "pending"];

function seed() {
  return {
    id: "usage-key", name: "Before eviction", start: null, prefix: null,
    key: "usage-secret", referenceId: "owner", configId: "default",
    refillInterval: null, refillAmount: null, lastRefillAt: null,
    enabled: true, rateLimitEnabled: false, rateLimitTimeWindow: 60_000,
    rateLimitMax: 3, requestCount: 0, remaining: 5, lastRequest: null,
    expiresAt: null, createdAt: "2030-01-02T03:04:05.000Z",
    updatedAt: "2030-01-02T03:04:05.000Z", permissions: null, metadata: null,
  };
}

async function captureCase(timing) {
  const native = createSecondaryNativeObserver();
  const original = seed();
  const fresh = { ...original, name: "Fresh record", referenceId: "fresh-owner", requestCount: 41,
    remaining: 99, freshOnly: { marker: "preserved", nullable: null } };
  const values = new Map([
    [HASH, JSON.stringify(original)], [BY_ID, JSON.stringify(original)],
    [OLD_REF, '["usage-key"]'], [FRESH_REF, '["peer"]'],
  ]);
  const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
  const before = [...values];
  const storageEvents = [];
  const events = [];
  const logs = [];
  const tasks = [];
  const taskStates = [];
  const completions = [];
  const settlements = [];
  const started = Promise.withResolvers();
  const gate = Promise.withResolvers();
  let hashReads = 0;
  const customStorage = {
    async get(key) {
      storageEvents.push(["get", key]);
      if (key === HASH && ++hashReads === 2) {
        started.resolve();
        if (timing === "pending") await gate.promise;
        return JSON.stringify(fresh);
      }
      return values.get(key) ?? null;
    },
    async set(key, value, ttl) {
      storageEvents.push(["set", key, value, ttl]);
      values.set(key, value);
    },
    async delete(key) {
      storageEvents.push(["delete", key]);
      values.delete(key);
    },
  };
  const auth = betterAuth({
    database: memoryAdapter(memory), baseURL: "https://api-key-usage-success.test",
    secret: "api-key-usage-success-contract-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "error", disableColors: true, log(level, message, ...args) {
      logs.push({ level, message, arguments: native.snapshot(args) });
    } },
    advanced: { backgroundTasks: { handler(task) {
      const index = tasks.length;
      tasks.push(task);
      taskStates.push({ status: "pending" });
      events.push({ phase: "handler:received", index, isPromise: task instanceof Promise });
      settlements.push(task.then(value => {
        completions[index] = value;
        taskStates[index] = { status: "fulfilled", value: native.snapshot(value) };
        events.push({ phase: "task:fulfilled", index, ...taskStates[index] });
      }));
    } } },
    plugins: [apiKey({ storage: "secondary-storage", customStorage, disableKeyHashing: true, deferUpdates: true })],
  });
  await auth.$context;
  try {
    const verification = auth.api.verifyApiKey({ body: { key: "usage-secret" } });
    await started.promise;
    const result = await verification;
    events.push({ phase: "verification:fulfilled", value: native.snapshot(result) });
    await nextTurn();
    const snapshot = () => ({ taskStates: structuredClone(taskStates), storageEvents: native.snapshot(storageEvents),
      cacheEntries: [...values], database: native.snapshot(memory) });
    const beforeRelease = snapshot();
    assert.equal(tasks.length, 2);
    if (timing === "pending") {
      assert.equal(taskStates[0].status, "pending");
      assert.deepEqual(storageEvents, [["get", HASH], ["get", HASH]]);
      assert.deepEqual([...values], before);
    }
    events.push({ phase: "gate:release" });
    gate.resolve();
    await Promise.all(settlements);
    const afterSettlement = snapshot();
    const { key: _private, ...publicSeed } = original;
    const mutations = { remaining: 4, lastRefillAt: null, lastRequest: new Date(epoch), updatedAt: new Date(epoch) };
    assert.deepEqual(result, { valid: true, error: null, key: {
      ...publicSeed, ...mutations, createdAt: new Date(original.createdAt),
    } });
    const merged = { ...fresh, ...mutations, createdAt: new Date(fresh.createdAt) };
    assert.deepEqual(completions[0], merged);
    assert.deepEqual(Reflect.ownKeys(completions[0]), Reflect.ownKeys(merged));
    assert.notEqual(completions[0].lastRequest, completions[0].updatedAt);
    assert.equal(completions[0].lastRequest.getTime(), completions[0].updatedAt.getTime());
    assert.equal(completions[0].lastRequest, result.key.lastRequest);
    assert.equal(completions[0].updatedAt, result.key.updatedAt);
    assert.notEqual(completions[0].createdAt, result.key.createdAt);
    assert.equal(completions[1], undefined);
    const serialized = JSON.stringify(merged);
    assert.deepEqual(storageEvents, [
      ["get", HASH], ["get", HASH], ["set", HASH, serialized, undefined],
      ["set", BY_ID, serialized, undefined], ["get", FRESH_REF],
      ["set", FRESH_REF, '["peer","usage-key"]', undefined],
    ]);
    assert.deepEqual([...values], [[HASH, serialized], [BY_ID, serialized], [OLD_REF, '["usage-key"]'], [FRESH_REF, '["peer","usage-key"]']]);
    assert.deepEqual(memory, { user: [], session: [], account: [], verification: [], apikey: [] });
    assert.deepEqual(logs, []);
    return { name: `deferred-success/${timing}`, timing, original, fresh, before,
      result: native.snapshot(result), beforeRelease, afterSettlement, events, logs, functions: native.functions };
  } catch (error) {
    await writeObservation(`${JSON.stringify({ contract: "api-key-usage-success-failure", timing, before,
      storageEvents: native.snapshot(storageEvents), cacheEntries: [...values], taskStates,
      events, logs, failure: native.snapshot(error) })}\n`);
    throw error;
  } finally { gate.resolve(); }
}

export async function captureApiKeyUsageSuccess() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key"]);
  const provenance = ["better-auth/dist/context/create-context.mjs", "@better-auth/api-key/dist/index.mjs"].map(path => ({ path,
    sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex") }));
  return withClock(async setClock => {
    setClock(epoch);
    const cases = [];
    for (const timing of apiKeyUsageSuccessCases) cases.push(await captureCase(timing));
    return { contract: "api-key-usage-success", version: secondaryNativeVersion,
      runtime: { name: "bun", version: Bun.version }, provenance,
      boundary: "Real verifyApiKey with deferred secondary-storage usage. The second cache read supplies a complete fresh serialized record. Retained usage completion preserves the full fresh merged record; public verification returns the original snapshot plus usage mutations. All cache calls, serialized writes, index state, Memory rows, and task results remain observed. JSON cache decoding creates new object identities. JavaScript task reaction order is source evidence, not Tokio scheduling equivalence.", cases };
  });
}

if (import.meta.main) {
  const observation = await captureApiKeyUsageSuccess();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
