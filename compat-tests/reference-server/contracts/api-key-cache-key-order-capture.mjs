import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import {
  assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow,
  secondaryNativeVersion, withSecondarySourceExports,
} from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const cacheKeys = { reference: "api-key:by-ref:owner", hash: "api-key:hash", id: "api-key:by-id:key" };
const suffixes = { reference: "owner", hash: "hash", id: "key" };
const nextTurn = () => new Promise(resolve => setTimeout(resolve, 0));

export function apiKeyCacheKeyOrderCases() {
  const cases = [];
  for (const operation of ["put", "remove"]) for (const fallback of [false, true]) {
    const add = scenario => cases.push({ operation, fallback, ...scenario });
    add({ kind: "success" });
    for (const slot of ["reference", "hash", "id"]) {
      for (const phase of ["primitive-get", "primitive-call"]) add({ kind: "key-error", slot, phase });
    }
    for (const slot of ["hash", "id"]) {
      for (const failure of ["throw", "reject"]) add({ kind: "storage-error", slot, failure });
    }
    for (const timing of ["ready", "pending"]) {
      for (const completion of ["resolve", "reject"]) add({ kind: "orphan", slot: "id", phase: "primitive-call", timing, completion });
    }
    for (const completion of ["resolve", "reject"]) add({ kind: "retained", completion });
  }
  return cases.map(scenario => ({ name: Object.values(scenario).join("/"), ...scenario }));
}

function storagePlan(scenario, slot) {
  if (scenario.kind === "storage-error" && scenario.slot === slot) return scenario.failure === "throw" ? "throw" : "ready-reject";
  if (scenario.kind === "orphan" && slot === "hash") return `${scenario.timing}-${scenario.completion}`;
  if (scenario.kind === "retained") {
    if (slot === "hash") return "ready-reject";
    if (slot === "id") return `pending-${scenario.completion}`;
  }
  return "ready-resolve";
}

function expectedPrefix(scenario) {
  const trace = [];
  const method = scenario.operation === "put" ? "set" : "delete";
  for (const slot of ["reference", "hash", "id"]) {
    const fails = ["key-error", "orphan"].includes(scenario.kind) && scenario.slot === slot;
    trace.push(`primitive:get:${slot}`);
    if (fails && scenario.phase === "primitive-get") return trace;
    trace.push(`primitive:call:${slot}`);
    if (fails && scenario.phase === "primitive-call") return trace;
    if (slot !== "reference") {
      trace.push(`storage:${method}:${slot}`);
      if (storagePlan(scenario, slot) === "throw") return trace;
    }
  }
  if (scenario.fallback) trace.push("storage:delete:reference");
  return trace;
}

async function captureCase(scenario, source) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const errors = Object.fromEntries(["key", "storage", "peer", "repeatedReference"].map(kind => {
    const value = { kind, ownUndefined: undefined, detail: { scenario: scenario.name } };
    Object.defineProperty(value, "token", { value: { owner: kind }, enumerable: false });
    return [kind, value];
  }));
  const original = ["storage-error", "retained"].includes(scenario.kind) ? errors.storage : errors.key;
  const errorIdentity = error => Object.fromEntries(Object.entries(errors).map(([kind, value]) => [kind, error === value]));
  const trace = [];
  const counts = Object.fromEntries(["reference", "hash", "id"].map(slot => [slot, { getter: 0, method: 0 }]));
  const fields = Object.fromEntries(["reference", "hash", "id"].map(slot => {
    const value = { slot };
    Object.defineProperty(value, "toString", { configurable: true, get() {
      counts[slot].getter++;
      trace.push(`primitive:get:${slot}`);
      native.call(`get:${slot}.toString`, this, value, []);
      if (["key-error", "orphan"].includes(scenario.kind) && scenario.slot === slot && scenario.phase === "primitive-get") throw errors.key;
      return function cacheKeyPrimitive(...args) {
        counts[slot].method++;
        trace.push(`primitive:call:${slot}`);
        native.call(`call:${slot}.toString`, this, value, args);
        assert.equal(this, value);
        assert.deepEqual(args, []);
        if (slot === "reference" && counts[slot].method > 1) throw errors.repeatedReference;
        if (["key-error", "orphan"].includes(scenario.kind) && scenario.slot === slot && scenario.phase === "primitive-call") throw errors.key;
        return suffixes[slot];
      };
    } });
    return [slot, value];
  }));
  const record = { id: fields.id, key: fields.hash, referenceId: fields.reference, configId: "default",
    createdAt: new Date(secondaryNativeNow), updatedAt: new Date(secondaryNativeNow) };
  const key = record;
  const initialReference = scenario.operation === "put" ? ["kept"] : [fields.id, "kept"];
  const values = new Map([
    [cacheKeys.hash, "stored-hash"], [cacheKeys.id, "stored-id"],
    [cacheKeys.reference, initialReference], ["unrelated", { retained: true, ownUndefined: undefined }],
  ]);
  const initialValues = new Map(values);
  const tasks = [];
  const hostEvents = [];
  let settled = false;
  let observedOutcome;
  const snapshotState = () => ({ record: key, cache: [...values], counts: structuredClone(counts), settled,
    calls: tasks.map(({ slot, method, plan, state, returnedPromise, reason }) => ({ slot, method, plan, state, returnedPromise, reason })) });
  const snapshot = () => ({ native: native.snapshot(snapshotState()), runtime: runtime.value(snapshotState()) });
  function mutate(method, cacheKey, value) {
    if (method === "set") values.set(cacheKey, value);
    else values.delete(cacheKey);
    native.record("storage:mutated", { method, key: cacheKey, value: native.snapshot(value) });
  }
  function invoke(method, cacheKey, value, args) {
    const slot = Object.entries(cacheKeys).find(([, key]) => key === cacheKey)?.[0];
    assert.ok(slot, `Unexpected cache key ${cacheKey}`);
    trace.push(`storage:${method}:${slot}`);
    native.call(`storage.${method}:${slot}`, storage, storage, args);
    if (method === "get") {
      const result = values.get(cacheKey) ?? null;
      native.record("storage:get:fulfilled", { slot, result: native.snapshot(result) });
      return Promise.resolve(result);
    }
    const plan = storagePlan(scenario, slot);
    const task = { slot, method, plan, state: "pending", returnedPromise: false, reason: undefined,
      gate: Promise.withResolvers(), done: Promise.withResolvers(), promise: undefined };
    tasks.push(task);
    const failure = scenario.kind === "retained" && slot === "id" ? errors.peer : errors.storage;
    const reject = () => {
      task.state = "rejected";
      task.reason = failure;
      native.record("storage:rejected", { slot, identity: errorIdentity(failure), error: native.snapshot(failure) });
      task.done.resolve();
      return failure;
    };
    const resolve = () => {
      mutate(method, cacheKey, value);
      task.state = "fulfilled";
      native.record("storage:fulfilled", { slot, result: native.snapshot(undefined) });
      task.done.resolve();
    };
    if (plan === "throw") throw reject();
    if (plan.startsWith("pending")) {
      task.promise = (async () => {
        await task.gate.promise;
        if (plan.endsWith("reject")) throw reject();
        resolve();
      })();
    } else if (plan.endsWith("reject")) task.promise = Promise.reject(reject());
    else {
      resolve();
      task.promise = Promise.resolve();
    }
    task.returnedPromise = true;
    return task.promise;
  }
  const storage = {
    get(...args) { assert.equal(this, storage); return invoke("get", args[0], undefined, args); },
    set(...args) { assert.equal(this, storage); return invoke("set", args[0], args[1], args); },
    delete(...args) { assert.equal(this, storage); return invoke("delete", args[0], undefined, args); },
  };
  const onUnhandled = (reason, promise) => {
    const event = { phase: "unhandledRejection", task: tasks.findIndex(task => task.promise === promise),
      identity: errorIdentity(reason), reason: native.snapshot(reason) };
    hostEvents.push(event);
    native.record("host:event", { event });
  };
  const onHandled = promise => {
    const event = { phase: "rejectionHandled", task: tasks.findIndex(task => task.promise === promise) };
    hostEvents.push(event);
    native.record("host:event", { event });
  };
  const before = snapshot();
  const errorsBefore = native.snapshot(errors);
  process.on("unhandledRejection", onUnhandled);
  process.on("rejectionHandled", onHandled);
  let beforeRelease;
  let prefix;
  try {
    const operation = () => scenario.operation === "put"
      ? source.setApiKeyInStorage({}, key, storage, undefined, { fallbackToDatabase: scenario.fallback })
      : source.deleteApiKeyFromStorage({}, key, storage, { fallbackToDatabase: scenario.fallback });
    const pending = native.outcome(() => runtime.capture(operation, original), original).then(outcome => {
      settled = true;
      observedOutcome = outcome;
      native.record("operation:settled", { returned: outcome.returned, sameOriginal: outcome.sameOriginal });
      return outcome;
    });
    prefix = [...trace];
    assert.deepEqual(prefix, expectedPrefix(scenario));
    native.record("operation:returned-to-caller");
    await nextTurn();
    native.record("host:checkpoint", { checkpoint: "before-release" });
    beforeRelease = snapshot();
    if (scenario.kind === "orphan" || scenario.kind === "retained") {
      assert.equal(settled, true, "A later key error or first storage rejection must return before a pending peer");
    }
    for (const task of tasks) if (task.plan.startsWith("pending")) {
      native.record("gate:release", { slot: task.slot });
      task.gate.resolve();
    }
    const outcome = await pending;
    // Observe completion without adding a rejection handler to a source storage Promise.
    await Promise.all(tasks.map(task => task.done.promise));
    for (let checkpoint = 1; checkpoint <= 2; checkpoint++) {
      await nextTurn();
      native.record("host:checkpoint", { checkpoint });
    }
    const returned = scenario.kind === "success";
    assert.equal(outcome.returned, returned);
    if (returned) assert.deepEqual(outcome.result, native.snapshot(undefined));
    else assert.equal(outcome.sameOriginal, true);
    assert.equal(tasks.every(task => task.state !== "pending"), true);
    assert.ok(counts.reference.method <= 1, "The source must reuse one reference-key conversion");

    const expected = new Map(initialValues);
    const serialized = JSON.stringify({ ...record,
      createdAt: record.createdAt.toISOString(), updatedAt: record.updatedAt.toISOString(),
      expiresAt: null, lastRefillAt: null, lastRequest: null,
    });
    const method = scenario.operation === "put" ? "set" : "delete";
    for (const slot of ["hash", "id"]) {
      if (expectedPrefix(scenario).includes(`storage:${method}:${slot}`) && storagePlan(scenario, slot).endsWith("resolve")) {
        if (method === "set") expected.set(cacheKeys[slot], serialized);
        else expected.delete(cacheKeys[slot]);
      }
    }
    const arrayBuilt = !["key-error", "orphan"].includes(scenario.kind)
      && !(scenario.kind === "storage-error" && scenario.failure === "throw");
    if (arrayBuilt && (scenario.fallback || scenario.operation === "remove" || returned)) {
      if (scenario.fallback) expected.delete(cacheKeys.reference);
      else expected.set(cacheKeys.reference, scenario.operation === "put" ? '["kept",{"slot":"id"}]' : '["kept"]');
    }
    if (!scenario.fallback && arrayBuilt && (scenario.operation === "remove" || returned)) {
      const read = native.events.findIndex(event => event.phase === "storage.get:reference");
      const caller = native.events.findIndex(event => event.phase === "operation:returned-to-caller");
      assert.ok(read > caller, "The reference lock must defer its storage read beyond the synchronous storage prefixes");
      assert.equal(prefix.includes("storage:get:reference"), false);
    }
    assert.deepEqual([...values], [...expected]);
    const unhandled = hostEvents.filter(event => event.phase === "unhandledRejection");
    const expectedOrphan = scenario.kind === "orphan" && scenario.completion === "reject";
    assert.equal(unhandled.length, expectedOrphan ? 1 : 0);
    if (expectedOrphan) {
      assert.equal(unhandled[0].task, 0);
      assert.equal(unhandled[0].identity.storage, true);
    }
    assert.deepEqual(hostEvents.filter(event => event.phase === "rejectionHandled"), []);
    assert.deepEqual(native.snapshot(errors), errorsBefore);
    const after = snapshot();
    return { scenario, before, prefix, beforeRelease, outcome, after, trace, events: native.events,
      hostEvents, errorsBefore, errorsAfter: native.snapshot(errors), functions: native.functions,
      runtime: { before: before.runtime, beforeRelease: beforeRelease.runtime, outcome: runtime.outcome,
        events: runtime.events, after: after.runtime, functionIds: runtime.functionIds } };
  } catch (error) {
    await writeObservation(`${JSON.stringify({ contract: "api-key-cache-key-order-failure", scenario, before, prefix,
      beforeRelease, outcome: observedOutcome, after: snapshot(), trace, events: native.events, hostEvents,
      failure: native.snapshot(error), functions: native.functions })}\n`);
    throw error;
  } finally {
    for (const task of tasks) task.gate.resolve();
    process.off("unhandledRejection", onUnhandled);
    process.off("rejectionHandled", onHandled);
  }
}

export async function captureApiKeyCacheKeyOrder() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key"]);
  return withSecondarySourceExports("@better-auth/api-key", ["setApiKeyInStorage", "deleteApiKeyFromStorage"], async (source, provenance) => {
    const cases = [];
    for (const scenario of apiKeyCacheKeyOrderCases()) cases.push(await captureCase(scenario, source));
    return { contract: "api-key-cache-key-order", version: secondaryNativeVersion, runtime: { name: "bun", version: Bun.version },
      provenance, boundary: "Original API Key internal cache helpers. The capture retains complete native values, key/property callbacks, synchronous storage prefixes, peer completion, original errors, and host rejection events. HTTP wrapping, database commits, arbitrary thenables, and host-runtime equivalence are separate boundaries.", cases };
  });
}

if (import.meta.main) {
  const observation = await captureApiKeyCacheKeyOrder();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
