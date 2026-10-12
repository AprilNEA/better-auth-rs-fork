import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, withSecondarySourceExports } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const epoch = 2_000_000_000_000;
const cleanupMessage = "Failed to delete expired API keys:";
const endpointMessage = "[API KEY PLUGIN] Failed to delete expired API keys:";
export const deleteExpiredCases = ["success", "database-error", "first-logger-error", "second-logger-error", "before-stop", "after-replacement", "bypass", "shared-clock"];

async function captureCase(name, source, setClock) {
  const native = createSecondaryNativeObserver();
  const errors = Object.fromEntries(["database", "firstLogger", "secondLogger"].map(owner => [owner, { owner }]));
  const events = [];
  const states = [];
  const inputBody = { native: true };
  const inputQuery = { ignored: true };
  const replacement = { success: "hook value", error: undefined, nested: { retained: true } };
  let loggerCalls = 0;
  const identity = value => Object.fromEntries(Object.entries(errors).map(([owner, error]) => [owner, value === error]));
  const record = (phase, fields = {}) => events.push({ phase, ...fields });
  const failing = ["database-error", "first-logger-error", "second-logger-error"].includes(name);
  async function build(label) {
    const expiration = failing ? { valueOf() {
      record("database:throw", { instance: label, identity: identity(errors.database) });
      throw errors.database;
    } } : new Date(epoch - 1);
    const rows = [
      { id: "expired", expiresAt: expiration },
      { id: "boundary", expiresAt: new Date(epoch) },
      { id: "live", expiresAt: new Date(epoch + 100_000) },
      { id: "never", expiresAt: null },
    ];
    const memory = { user: [], session: [], account: [], verification: [], apikey: rows };
    const logger = { level: "error", disableColors: true, log(level, message, ...args) {
      loggerCalls += 1;
      assert.equal(this, logger);
      assert.equal(level, "error");
      assert.equal(message, loggerCalls === 1 ? cleanupMessage : endpointMessage);
      assert.equal(args.length, 1);
      assert.equal(args[0], loggerCalls === 1 ? errors.database : errors.firstLogger);
      record("logger", { instance: label, call: loggerCalls, level, message, arguments: native.snapshot(args), identity: identity(args[0]) });
      if (loggerCalls === 1 && name !== "database-error") throw errors.firstLogger;
      if (loggerCalls === 2 && name === "second-logger-error") throw errors.secondLogger;
    } };
    const auth = betterAuth({
      baseURL: "https://api-key-delete-expired.test",
      secret: "api-key-delete-expired-contract-secret-at-least-thirty-two-characters",
      database: memoryAdapter(memory), telemetry: { enabled: false }, rateLimit: { enabled: false }, logger,
      plugins: [source.apiKey()],
      hooks: {
        before: createAuthMiddleware(async ctx => {
          record("before", { instance: label, path: native.snapshot(ctx.path), body: native.snapshot(ctx.body), query: native.snapshot(ctx.query), request: ctx.request?.url, headers: [...ctx.headers] });
          assert.equal(ctx.path, undefined);
          assert.equal(ctx.body, inputBody);
          assert.equal(ctx.query, inputQuery);
          assert.equal(ctx.request.url, "https://api-key-delete-expired.test/original");
          assert.deepEqual([...ctx.headers], []);
          if (name === "before-stop") return ctx.json(replacement);
        }),
        after: createAuthMiddleware(async ctx => {
          record("after", { instance: label, returned: native.snapshot(ctx.context.returned) });
          const expected = name === "first-logger-error" ? { success: false, error: errors.firstLogger } : { success: true, error: null };
          assert.deepEqual(ctx.context.returned, expected);
          assert.deepEqual(Reflect.ownKeys(ctx.context.returned), ["success", "error"]);
          assert.equal(ctx.context.returned.error, expected.error);
          if (name === "after-replacement") return ctx.json(replacement);
        }),
      },
    });
    const context = await auth.$context;
    const original = context.adapter.deleteMany;
    const state = { label, auth, context, memory, calls: 0 };
    context.adapter.deleteMany = async function(input) {
      state.calls += 1;
      assert.deepEqual(input, { model: "apikey", where: [
        { field: "expiresAt", operator: "lt", value: new Date() },
        { field: "expiresAt", operator: "ne", value: null },
      ] });
      record("adapter:deleteMany", { instance: label, input: native.snapshot(input), before: native.snapshot(memory) });
      const result = await original.call(this, input);
      record("adapter:returned", { instance: label, result: native.snapshot(result), after: native.snapshot(memory) });
      return result;
    };
    states.push(state);
    return state;
  }
  const beforeErrors = native.snapshot(errors);
  const first = await build("first");
  const steps = [];
  const invoke = async (state, endpoint = true) => {
    const before = native.snapshot(state.memory);
    const from = events.length;
    const beforeCalls = state.calls;
    let outcome;
    try {
      const result = endpoint ? await state.auth.api.deleteAllExpiredApiKeys({ asResponse: false,
        request: new Request("https://api-key-delete-expired.test/original", { method: "POST" }),
        headers: new Headers(), body: inputBody, query: inputQuery })
        : await source.deleteAllExpiredApiKeys(state.context);
      outcome = { returned: true, result: native.snapshot(result), errorIdentity: identity(result?.error), sameReplacement: result === replacement };
      if (endpoint) {
        if (["before-stop", "after-replacement"].includes(name)) assert.equal(result, replacement);
        else assert.deepEqual(result, name === "first-logger-error" ? { success: false, error: errors.firstLogger } : { success: true, error: null });
      } else assert.equal(result, undefined);
    } catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      assert.equal(name, "second-logger-error");
      assert.equal(error, errors.secondLogger);
      outcome = { returned: false, error: native.snapshot(error), identity: identity(error) };
    }
    const stepEvents = events.slice(from);
    const phases = endpoint ? ["before"] : [];
    if (state.calls !== beforeCalls) {
      assert.equal(state.calls, beforeCalls + 1);
      phases.push("adapter:deleteMany");
      if (failing) {
        phases.push("database:throw", "logger");
        if (name !== "database-error") phases.push("logger");
      } else phases.push("adapter:returned");
      if (endpoint && name !== "second-logger-error") phases.push("after");
    }
    assert.deepEqual(stepEvents.map(event => event.phase), phases);
    steps.push({ instance: state.label, endpoint, clock: Date.now(), before, outcome, events: stepEvents, after: native.snapshot(state.memory), calls: state.calls });
  };
  if (name === "shared-clock") {
    const second = await build("second");
    await invoke(first, false);
    await invoke(second, false);
    setClock(epoch - 1);
    await invoke(second, false);
    setClock(epoch + 9_999);
    await invoke(second, false);
    assert.equal(second.calls, 0);
    setClock(epoch + 10_000);
    await invoke(second, false);
    assert.equal(second.calls, 1);
    setClock(epoch + 10_001);
    await invoke(first);
    setClock(epoch + 20_000);
    await invoke(second, false);
    assert.equal(second.calls, 1);
    setClock(epoch + 20_001);
    await invoke(second, false);
    assert.equal(second.calls, 2);
    assert.deepEqual(steps.map(step => step.calls), [1, 0, 0, 0, 1, 2, 1, 2]);
    for (const state of states) assert.deepEqual(state.memory.apikey, [{ id: "live", expiresAt: new Date(epoch + 100_000) }, { id: "never", expiresAt: null }]);
  } else {
    await invoke(first);
    if (name === "bypass") {
      first.memory.apikey.push({ id: "expired-again", expiresAt: new Date(epoch - 2) });
      await invoke(first);
      await invoke(first, false);
      assert.deepEqual(steps.map(step => step.calls), [1, 2, 2]);
    }
    assert.equal(first.calls, name === "before-stop" ? 0 : name === "bypass" ? 2 : 1);
    assert.equal(loggerCalls, name === "database-error" ? 1 : ["first-logger-error", "second-logger-error"].includes(name) ? 2 : 0);
    if (failing || name === "before-stop") assert.deepEqual(native.snapshot(first.memory), steps[0].before);
    else assert.deepEqual(first.memory.apikey, [
      { id: "boundary", expiresAt: new Date(epoch) },
      { id: "live", expiresAt: new Date(epoch + 100_000) },
      { id: "never", expiresAt: null },
    ]);
    assert.equal(steps[0].outcome.returned, name !== "second-logger-error");
    if (name === "first-logger-error") assert.equal(steps[0].outcome.errorIdentity.firstLogger, true);
  }
  assert.deepEqual(native.snapshot(errors), beforeErrors);
  for (const state of states) for (const table of ["user", "session", "account", "verification"]) assert.deepEqual(state.memory[table], []);
  return { name, steps, events, loggerCalls, errorsBefore: beforeErrors, errorsAfter: native.snapshot(errors), functions: native.functions };
}

export async function captureDeleteExpired(name) {
  assert.ok(deleteExpiredCases.includes(name));
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key"]);
  return withClock(async setClock => {
    setClock(epoch);
    return withSecondarySourceExports("@better-auth/api-key", ["deleteAllExpiredApiKeys"], async (source, provenance) => ({
      contract: "api-key-delete-expired", version: "1.7.6", provenance,
      boundary: "The public server-only endpoint and the unchanged cleanup helper share the same pinned module. Real Memory adapter comparisons produce database failures. Logger failures retain original objects. The source-only shared-clock case observes module-wide Date throttling, clock rollback, and endpoint bypass refresh; Rust still uses per-plugin Instant throttling. No SQL or JavaScript Promise timing equivalence is asserted.",
      ...(await captureCase(name, source, setClock)),
    }));
  });
}

if (import.meta.main) {
  const observation = await captureDeleteExpired(process.argv[2]);
  if (process.argv[3]) writeFileSync(process.argv[3], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
