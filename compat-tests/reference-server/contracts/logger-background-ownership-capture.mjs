import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const backgroundMessage = "Failed to run background task:";
const callerMessage = "Caller task failed:";
const nextTurn = () => new Promise(resolve => setTimeout(resolve, 0));

export function loggerBackgroundOwnershipCases() {
  const cases = [];
  for (const timing of ["ready", "pending"]) {
    for (const handler of ["none", "retain"]) cases.push({ primitive: "runInBackgroundOrAwait", timing, handler, loggerFailure: "task" });
    for (const loggerFailure of ["task", "handler", "both"]) cases.push({ primitive: "runInBackgroundOrAwait", timing, handler: "throw", loggerFailure });
    for (const handler of ["none", "retain", "throw"]) cases.push({ primitive: "runInBackground", timing, handler, loggerFailure: "task" });
  }
  return cases.map(scenario => ({ name: Object.values(scenario).join("/"), ...scenario }));
}

async function captureCase(scenario) {
  const native = createSecondaryNativeObserver();
  const gate = Promise.withResolvers();
  const errors = Object.fromEntries(["task", "handler", "taskLogger", "handlerLogger"].map(name => {
    const error = { code: `BACKGROUND_${name}`, message: `${name} original failure` };
    Object.defineProperty(error, "token", { value: { owner: name }, enumerable: false });
    return [name, error];
  }));
  const errorBefore = native.snapshot(errors);
  const errorIdentity = error => Object.fromEntries(Object.entries(errors).map(([name, original]) => [name, error === original]));
  const rejection = error => ({ status: "rejected", identity: errorIdentity(error), error: native.snapshot(error) });
  const events = [];
  const logs = [];
  const hostEvents = [];
  const tasks = [];
  const taskStates = [];
  const ownedSettlements = [];
  const database = { user: [], session: [], account: [], verification: [] };
  const application = { started: 0, mutations: [], currentCallContinued: 0 };
  let rawProducerState = "not-started";
  let inputCatchState = { status: "not-entered" };
  let currentCall = { status: "pending" };
  let invocation = { kind: "not-started" };
  let input;
  let raw;
  const record = (phase, fields = {}) => { events.push({ phase, ...fields }); };
  const options = {
    baseURL: "https://logger-background-ownership.test",
    secret: "logger-background-ownership-secret-at-least-thirty-two-characters",
    database: memoryAdapter(database), telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "error", disableColors: true, log(level, message, ...args) {
      const [error] = args;
      const owner = error === errors.task ? "task" : error === errors.handler ? "handler" : "unknown";
      const observation = { level, message, arguments: native.snapshot(args), identity: errorIdentity(error), sameReceiver: this === options.logger };
      logs.push(observation);
      record("logger:call", { index: logs.length - 1, ...observation });
      assert.notEqual(owner, "unknown");
      assert.equal(message, scenario.primitive === "runInBackground" ? callerMessage : backgroundMessage);
      if (scenario.loggerFailure === owner || scenario.loggerFailure === "both") {
        const failure = errors[`${owner}Logger`];
        record("logger:throw", { identity: errorIdentity(failure), error: native.snapshot(failure) });
        throw failure;
      }
      record("logger:return", { result: native.snapshot(undefined) });
    } },
  };
  if (scenario.handler !== "none") options.advanced = { backgroundTasks: { handler(promise) {
    const index = tasks.length;
    tasks.push(promise);
    taskStates.push({ status: "pending" });
    record("handler:received", { index, isPromise: promise instanceof Promise, sameInput: promise === input, sameRaw: promise === raw,
      sameOptionsReceiver: this === options.advanced.backgroundTasks, sameContextReceiver: this === context });
    // The application attaches both settlement callbacks before its handler can throw.
    ownedSettlements.push(promise.then(value => {
      taskStates[index] = { status: "fulfilled", value: native.snapshot(value) };
      record("owned-task:fulfilled", { index, ...taskStates[index] });
    }, error => {
      taskStates[index] = rejection(error);
      record("owned-task:rejected", { index, ...taskStates[index] });
    }));
    if (scenario.handler === "throw") {
      record("handler:throw", { identity: errorIdentity(errors.handler), error: native.snapshot(errors.handler) });
      throw errors.handler;
    }
    record("handler:return", { result: native.snapshot(undefined) });
  } } };
  const context = await betterAuth(options).$context;
  const onUnhandled = (reason, promise) => {
    const event = { phase: "unhandledRejection", identity: errorIdentity(reason), reason: native.snapshot(reason),
      sameRaw: promise === raw, sameInput: promise === input, ownedTaskIndex: tasks.indexOf(promise) };
    hostEvents.push(event);
    record("host:event", { event });
  };
  const onHandled = promise => {
    const event = { phase: "rejectionHandled", sameRaw: promise === raw, sameInput: promise === input, ownedTaskIndex: tasks.indexOf(promise) };
    hostEvents.push(event);
    record("host:event", { event });
  };
  process.on("unhandledRejection", onUnhandled);
  process.on("rejectionHandled", onHandled);
  try {
    raw = (async () => {
      rawProducerState = "started";
      application.started += 1;
      record("task:start");
      if (scenario.timing === "pending") {
        await gate.promise;
        record("task:resume");
      }
      application.mutations.push({ phase: "before-reject", value: "persisted" });
      rawProducerState = "rejection-produced";
      record("task:reject", { identity: errorIdentity(errors.task), error: native.snapshot(errors.task) });
      throw errors.task;
    })();
    // The direct primitive receives an already-wrapped caller task, as its public contract requires.
    input = scenario.primitive === "runInBackground" ? raw.catch(error => {
      record("input-catch:entered", { identity: errorIdentity(error), error: native.snapshot(error) });
      try {
        context.logger.error(callerMessage, error);
        inputCatchState = { status: "fulfilled", value: native.snapshot(undefined) };
      } catch (failure) {
        inputCatchState = rejection(failure);
        record("input-catch:throw", inputCatchState);
        throw failure;
      }
    }) : raw;
    const operation = (async () => {
      record("call:start");
      let returned;
      try {
        returned = context[scenario.primitive](input);
        invocation = { kind: "returned", isPromise: returned instanceof Promise, value: native.snapshot(returned) };
        record("call:returned", invocation);
      } catch (error) {
        invocation = { kind: "threw-synchronously", ...rejection(error) };
        currentCall = rejection(error);
        record("call:threw-synchronously", invocation);
        return;
      }
      try {
        const value = await returned;
        application.currentCallContinued += 1;
        currentCall = { status: "fulfilled", value: native.snapshot(value) };
        record("call:fulfilled", currentCall);
      } catch (error) {
        currentCall = rejection(error);
        record("call:rejected", currentCall);
      }
    })();
    const snapshot = () => ({ currentCall, taskStates: structuredClone(taskStates), rawProducerState,
      inputCatchState, application: structuredClone(application), database: native.snapshot(database) });
    if (scenario.handler !== "none" || scenario.primitive === "runInBackground") await operation;
    await nextTurn();
    const beforeRelease = snapshot();
    record("gate:release");
    gate.resolve();
    await operation;
    await Promise.all(ownedSettlements);
    for (let checkpoint = 1; checkpoint <= 2; checkpoint += 1) {
      await nextTurn();
      record("host:checkpoint", { checkpoint });
    }
    const afterSettlement = snapshot();
    assert.deepEqual(hostEvents, []);
    assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
    assert.deepEqual(native.snapshot(errors), errorBefore);
    assert.equal(application.started, 1);
    assert.deepEqual(application.mutations, [{ phase: "before-reject", value: "persisted" }]);
    assert.equal(tasks.length, scenario.handler === "none" ? 0 : 1);
    const taskLoggerThrows = scenario.loggerFailure === "task" || scenario.loggerFailure === "both";
    const handlerLoggerThrows = scenario.loggerFailure === "handler" || scenario.loggerFailure === "both";
    const currentError = scenario.primitive === "runInBackground"
      ? scenario.handler === "throw" ? "handler" : null
      : scenario.handler === "none" ? "taskLogger" : scenario.handler === "throw" && handlerLoggerThrows ? "handlerLogger" : null;
    assert.equal(invocation.kind, scenario.primitive === "runInBackground" && scenario.handler === "throw" ? "threw-synchronously" : "returned");
    if (invocation.kind === "returned") assert.equal(invocation.isPromise, scenario.primitive === "runInBackgroundOrAwait");
    assert.equal(currentCall.status, currentError ? "rejected" : "fulfilled");
    if (currentError) assert.equal(currentCall.identity[currentError], true);
    assert.equal(application.currentCallContinued, currentError ? 0 : 1);
    for (const task of taskStates) {
      assert.equal(task.status, taskLoggerThrows ? "rejected" : "fulfilled");
      if (taskLoggerThrows) assert.equal(task.identity.taskLogger, true);
    }
    assert.equal(logs.length, scenario.primitive === "runInBackgroundOrAwait" && scenario.handler === "throw" ? 2 : 1);
    if (scenario.timing === "pending") {
      assert.deepEqual(beforeRelease.application.mutations, []);
      assert.equal(beforeRelease.currentCall.status === "pending", scenario.primitive === "runInBackgroundOrAwait" && scenario.handler === "none");
      assert.ok(beforeRelease.taskStates.every(task => task.status === "pending"));
    }
    return { ...scenario, invocation, beforeRelease, afterSettlement, events, logs, hostEvents,
      errorsBefore: errorBefore, errorsAfter: native.snapshot(errors), functions: native.functions };
  } catch (error) {
    await writeObservation(`${JSON.stringify({ contract: "logger-background-ownership-failure", scenario,
      invocation, currentCall, taskStates, rawProducerState, inputCatchState, application,
      database: native.snapshot(database), events, logs, hostEvents, errorsBefore: errorBefore,
      errorsAfter: native.snapshot(errors), failure: native.snapshot(error), functions: native.functions })}\n`);
    throw error;
  } finally {
    gate.resolve();
    process.off("unhandledRejection", onUnhandled);
    process.off("rejectionHandled", onHandled);
  }
}

export async function captureLoggerBackgroundOwnership() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["better-auth/dist/context/create-context.mjs", "@better-auth/core/dist/env/logger.mjs"].map(path => ({
    path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(2_000_000_000_000);
    const cases = [];
    for (const scenario of loggerBackgroundOwnershipCases()) cases.push(await captureCase(scenario));
    return { contract: "logger-background-ownership", version: secondaryNativeVersion, runtime: { name: "bun", version: Bun.version }, provenance,
      boundary: "Real shared context primitives and instance Logger. Configured handlers retain and observe the exact supplied Promise before returning or throwing. Direct runInBackground receives a caller-created logger catch; this is not an API Key endpoint capture. Application side effects are deterministic harness state, not database acceptance. Source host events remain complete; the no-handler direct suppression is observed through two event-loop checkpoints. Unowned tasks, late rejection handling, plugin-specific catches, endpoint error policy, and Rust host-runtime equivalence remain outside this contract.", cases };
  });
}

if (import.meta.main) {
  const observation = await captureLoggerBackgroundOwnership();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
