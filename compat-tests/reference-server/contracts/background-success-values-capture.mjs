import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const nextTurn = () => new Promise(resolve => setTimeout(resolve, 0));

export function backgroundSuccessValueCases() {
  const cases = [];
  for (const timing of ["ready", "pending"]) {
    for (const value of ["undefined", "null", "object"]) {
      for (const [primitive, handler] of [
        ["runInBackgroundOrAwait", "none"],
        ["runInBackgroundOrAwait", "retain"],
        ["runInBackground", "retain"],
      ]) cases.push({ name: [primitive, handler, timing, value].join("/"), primitive, handler, timing, value });
    }
  }
  return cases;
}

function successValue(kind) {
  if (kind === "undefined") return undefined;
  if (kind === "null") return null;
  const value = { marker: "producer-result", missing: undefined, nullable: null, nested: { token: "retained" } };
  Object.defineProperty(value, "hidden", { value: { token: "non-enumerable" }, enumerable: false });
  return value;
}

async function captureCase(scenario) {
  const native = createSecondaryNativeObserver();
  const gate = Promise.withResolvers();
  const original = successValue(scenario.value);
  const valueBefore = native.snapshot(original);
  const database = { user: [], session: [], account: [], verification: [] };
  const databaseBefore = native.snapshot(database);
  const events = [];
  const logs = [];
  const tasks = [];
  const taskStates = [];
  const ownedSettlements = [];
  const handlerObservations = [];
  let input;
  let rawState = "not-started";
  let currentCall = { status: "pending" };
  let invocation;
  const record = (phase, fields = {}) => events.push({ phase, ...fields });
  const completion = value => ({ status: "fulfilled", value: native.snapshot(value), sameOriginal: Object.is(value, original) });
  const options = {
    baseURL: "https://background-success-values.test",
    secret: "background-success-values-contract-secret-at-least-thirty-two-characters",
    database: memoryAdapter(database), telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "error", disableColors: true, log(level, message, ...args) {
      logs.push({ level, message, arguments: native.snapshot(args) });
    } },
  };
  if (scenario.handler === "retain") options.advanced = { backgroundTasks: { handler(promise) {
    const index = tasks.length;
    tasks.push(promise);
    taskStates.push({ status: "pending" });
    const observation = { index, isPromise: promise instanceof Promise, sameInput: promise === input };
    handlerObservations.push(observation);
    record("handler:received", observation);
    ownedSettlements.push(promise.then(value => {
      taskStates[index] = completion(value);
      record("owned-task:fulfilled", { index, ...taskStates[index] });
    }));
  } } };
  const context = await betterAuth(options).$context;
  try {
    input = (async () => {
      rawState = "started";
      record("task:start");
      if (scenario.timing === "pending") {
        await gate.promise;
        record("task:resume");
      }
      rawState = "fulfillment-produced";
      record("task:fulfill", { value: native.snapshot(original) });
      return original;
    })();
    const operation = (async () => {
      const returned = context[scenario.primitive](input);
      invocation = { isPromise: returned instanceof Promise, value: native.snapshot(returned) };
      record("call:returned", invocation);
      const value = await returned;
      currentCall = { status: "fulfilled", value: native.snapshot(value) };
      record("call:fulfilled", currentCall);
      assert.equal(value, undefined);
    })();
    const snapshot = () => ({ rawState, currentCall, taskStates: structuredClone(taskStates), value: native.snapshot(original) });
    if (scenario.handler === "retain" || scenario.timing === "ready") await operation;
    await nextTurn();
    const beforeRelease = snapshot();
    record("gate:release");
    gate.resolve();
    await operation;
    await Promise.all(ownedSettlements);
    const rawResult = await input;
    const afterSettlement = snapshot();
    assert.ok(Object.is(rawResult, original));
    assert.equal(invocation.isPromise, scenario.primitive === "runInBackgroundOrAwait");
    assert.equal(tasks.length, scenario.handler === "retain" ? 1 : 0);
    for (const observation of handlerObservations) {
      assert.equal(observation.isPromise, true);
      assert.equal(observation.sameInput, scenario.primitive === "runInBackground");
    }
    for (const state of taskStates) {
      assert.deepEqual(state, completion(original));
      assert.equal(state.sameOriginal, true);
    }
    if (scenario.timing === "pending") {
      assert.equal(beforeRelease.rawState, "started");
      assert.equal(beforeRelease.currentCall.status, scenario.handler === "retain" ? "fulfilled" : "pending");
      assert.ok(beforeRelease.taskStates.every(state => state.status === "pending"));
    }
    assert.deepEqual(logs, []);
    assert.deepEqual(native.snapshot(original), valueBefore);
    assert.deepEqual(native.snapshot(database), databaseBefore);
    return { ...scenario, invocation, beforeRelease, afterSettlement, handlerObservations,
      rawCompletion: completion(rawResult), valueBefore, valueAfter: native.snapshot(original),
      databaseBefore, databaseAfter: native.snapshot(database), events, logs, functions: native.functions };
  } catch (error) {
    await writeObservation(`${JSON.stringify({ contract: "background-success-values-failure", scenario,
      rawState, currentCall, invocation, taskStates, handlerObservations, valueBefore,
      valueAfter: native.snapshot(original), events, logs, failure: native.snapshot(error) })}\n`);
    throw error;
  } finally {
    gate.resolve();
  }
}

export async function captureBackgroundSuccessValues() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const source = "better-auth/dist/context/create-context.mjs";
  const provenance = [{ path: source,
    sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${source}`, import.meta.url))).digest("hex") }];
  return withClock(async setClock => {
    setClock(2_000_000_000_000);
    const cases = [];
    for (const scenario of backgroundSuccessValueCases()) cases.push(await captureCase(scenario));
    return { contract: "background-success-values", version: secondaryNativeVersion,
      runtime: { name: "bun", version: Bun.version }, provenance,
      boundary: "Real shared context primitives. Compare scheduling-call completion separately from successful task completion. The handler retains the exact supplied Promise. Source Promise identity and reaction order remain raw evidence; Rust pairs task value, object identity, gate state, and absence of logger calls. Existing failure-ownership fixtures remain unchanged. The default detached primitive exposes no retained successful value and stays outside this supplemental matrix.", cases };
  });
}

if (import.meta.main) {
  const observation = await captureBackgroundSuccessValues();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
