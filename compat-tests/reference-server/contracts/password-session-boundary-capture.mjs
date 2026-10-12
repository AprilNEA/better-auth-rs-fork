import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { serializeSignedCookie } from "better-call";
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const baseURL = "http://password-session.test";
const secret = "password-session-contract-secret-at-least-thirty-two";
const password = "CorrectHorseBattery1!";
const now = 2_000_000_000_000;
const tables = ["user", "session", "account", "verification"];
const options = {
  baseURL, secret, logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
  session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
};

function session(id, userId) {
  return { id, token: id, userId, expiresAt: new Date(now + 3_600_000),
    createdAt: new Date(now), updatedAt: new Date(now), ipAddress: null, userAgent: null };
}

function account(userId) {
  return { id: "credential", userId, accountId: userId, providerId: "credential", password: "stored-hash",
    createdAt: new Date(now), updatedAt: new Date(now) };
}

function user() {
  return { id: "owner", name: "Owner", email: "owner@password-session.test", emailVerified: true,
    image: null, createdAt: new Date(now), updatedAt: new Date(now) };
}

async function observeOperation(operation, errors) {
  try { return { returned: true, value: await operation() }; }
  catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    return { returned: false, value: error, error: errors.error(error) };
  }
}

async function captureNativeOwner(deletionError) {
  const native = createSecondaryNativeObserver();
  const errors = createProtectedFunctionObserver();
  const original = { failure: "after-delete" };
  const projected = { marker: "projected-hash" };
  const injected = { session: session("target", 7), user: { id: 7, name: "Native owner" } };
  let recording = false;
  const auth = betterAuth({
    ...options,
    session: { ...options.session, additionalFields: { userId: { type: "string" } } },
    account: { additionalFields: {
      userId: { type: "string" },
      password: { type: "string", required: false, returned: false, transform: { output(value) {
        if (!recording) return value;
        native.record("projection", { value: native.snapshot(value) });
        assert.ok(["stored-hash", "new-hash"].includes(value));
        return projected;
      } } },
    } },
    emailAndPassword: { enabled: true, password: {
      async hash(value) { native.record("hash", { value }); assert.equal(value, password); return "new-hash"; },
      async verify(data) {
        native.record("verify", { arguments: native.snapshot(data), sameHash: data.hash === projected });
        assert.equal(data.hash, projected); assert.equal(data.password, password); return true;
      },
    } },
    hooks: { before: createAuthMiddleware(async ctx => { if (recording) ctx.context.session = injected; }) },
    databaseHooks: { session: {
      delete: {
        before(data) { native.record("delete-before", { data: native.snapshot(data) }); },
        after(data) {
          native.record("delete-after", { data: native.snapshot(data) });
          if (deletionError) throw original;
        },
      },
      create: { before(data) {
        assert.equal(data.userId, 7);
        // The hook cancels the write before the generated token can affect the observation.
        native.record("create-cancel", { userId: data.userId });
        return false;
      } },
    } },
  });
  const context = await auth.$context;
  assert.equal(Boolean(context.options.database || context.options.secondaryStorage), false);
  for (const [model, data] of [["account", account(7)], ["session", injected.session], ["session", session("foreign", "7")]]) {
    await context.adapter.create({ model, data, forceAllowId: true });
  }
  const storage = async () => Object.fromEntries(await Promise.all(tables.map(async model => [model, await context.adapter.findMany({ model })])));
  const before = await storage();
  recording = true;
  const outcome = await observeOperation(() => auth.api.changePassword({
    body: { currentPassword: password, newPassword: password, revokeOtherSessions: true },
  }), errors);
  recording = false;
  assert.equal(outcome.returned, false);
  if (deletionError) assert.equal(outcome.value, original);
  else {
    assert.equal(outcome.value.statusCode, 500);
    assert.deepEqual(outcome.value.body, { code: "FAILED_TO_GET_SESSION", message: "Failed to get session" });
  }
  assert.deepEqual(native.events.map(event => event.phase), [
    "projection", "hash", "verify", "projection", "delete-before", "delete-after",
    ...deletionError ? [] : ["create-cancel"],
  ]);
  const stored = await storage();
  const expected = structuredClone(before);
  expected.account[0].password = "new-hash";
  expected.session = expected.session.filter(row => row.id === "foreign");
  assert.deepEqual(stored, expected);
  return { name: deletionError ? "native-owner-after-delete-error" : "native-owner-create-cancelled",
    boundary: "stateless-trusted-session", outcome: { returned: false, sameOriginal: outcome.value === original, error: outcome.error },
    events: native.events, stored: native.snapshot(stored), functions: native.functions, errorFunctions: errors.functions };
}

async function captureCredentialIdentity(shape, sameIdentity) {
  const native = createSecondaryNativeObserver();
  const errors = createProtectedFunctionObserver();
  const memory = { user: [user()], session: [], account: [account("owner")], verification: [] };
  const before = structuredClone(memory);
  const id = shape === "object" ? { id: 7 } : shape === "array" ? [7] : new Date(now);
  const accountId = sameIdentity ? id : structuredClone(id);
  const hash = { marker: "native-password" };
  let replaced = 0;
  const auth = betterAuth({
    ...options,
    database: config => {
      const adapter = memoryAdapter(memory)(config);
      return { ...adapter, async findOne(query) {
        const result = await adapter.findOne(query);
        if (query.model === "user" && query.join?.account && result) {
          assert.equal(result.account.length, 1);
          result.id = id; result.account[0].accountId = accountId; result.account[0].password = hash;
          replaced++;
          native.record("adapter-output", { result: native.snapshot(result), sameIdentity: result.id === result.account[0].accountId });
        }
        return result;
      } };
    },
    emailAndPassword: { enabled: true, password: {
      async hash(value) { native.record("hash", { value }); assert.equal(value, password); return "timing-hash"; },
      async verify(data) {
        native.record("verify", { arguments: native.snapshot(data), sameHash: data.hash === hash });
        assert.equal(data.hash, hash); assert.equal(data.password, password); return false;
      },
    } },
  });
  await auth.$context;
  const outcome = await observeOperation(() => auth.api.signInEmail({ body: { email: user().email, password } }), errors);
  assert.equal(outcome.returned, false);
  assert.equal(outcome.value.statusCode, 401);
  assert.deepEqual(outcome.value.body, { code: "INVALID_EMAIL_OR_PASSWORD", message: "Invalid email or password" });
  assert.equal(replaced, 1);
  assert.deepEqual(native.events.map(event => event.phase), ["adapter-output", sameIdentity ? "verify" : "hash"]);
  assert.deepEqual(memory, before);
  return { name: `credential-${shape}-${sameIdentity ? "same" : "distinct"}-identity`, boundary: "custom-adapter-output",
    outcome: { returned: false, error: outcome.error }, events: native.events, stored: native.snapshot(memory),
    functions: native.functions, errorFunctions: errors.functions };
}

async function captureAuthoritativeSession(operation) {
  const native = createSecondaryNativeObserver();
  const errors = createProtectedFunctionObserver();
  const memory = { user: [user()], session: [session("current", "owner")], account: [account("owner")], verification: [] };
  const before = structuredClone(memory);
  let userReads = 0;
  const auth = betterAuth({
    ...options, database: memoryAdapter(memory), advanced: { database: { joins: true } },
    user: { additionalFields: { name: { type: "string", transform: { output(value) {
      userReads++; assert.equal(userReads, 1); assert.equal(value, "Owner");
      native.record("user-projection", { value }); return 17;
    } } } } },
    session: { ...options.session, additionalFields: { userId: {
      type: "string", required: true, references: { model: "user", field: "id" },
      transform: { output(value) { assert.equal(value, "owner"); native.record("session-owner-projection", { value }); return "unrelated"; } },
    } } },
    emailAndPassword: { enabled: true, password: {
      async hash(value) { native.record("hash", { value }); assert.equal(value, password); return "new-hash"; },
      async verify(data) { native.record("verify", { arguments: native.snapshot(data) }); assert.deepEqual(data, { hash: "stored-hash", password }); return true; },
    } },
    hooks: { before: createAuthMiddleware(async ctx => {
      ctx.context.session = { session: session("stale", "stale-owner"), user: { id: "stale-owner" } };
    }) },
  });
  await auth.$context;
  const cookie = (await serializeSignedCookie("better-auth.session_token", "current", secret)).split(";", 1)[0];
  const headers = new Headers({ cookie });
  const outcome = await observeOperation(() => operation === "change"
    ? auth.api.changePassword({ headers, body: { currentPassword: password, newPassword: password } })
    : auth.api.verifyPassword({ headers, body: { password } }), errors);
  assert.equal(outcome.returned, true);
  assert.equal(userReads, 1);
  assert.deepEqual(outcome.value, operation === "change" ? { token: null, user: { ...user(), name: 17 } } : { status: true });
  const expected = structuredClone(before);
  if (operation === "change") expected.account[0].password = "new-hash";
  assert.deepEqual(memory, expected);
  return { name: `${operation}-authoritative-joined-user`, boundary: "stateful-memory-adapter",
    outcome: { returned: true, result: native.snapshot(outcome.value) }, events: native.events,
    stored: native.snapshot(memory), functions: native.functions, errorFunctions: errors.functions };
}

assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
const OriginalDate = globalThis.Date;
globalThis.Date = new Proxy(OriginalDate, {
  construct(target, args, newTarget) { return Reflect.construct(target, args.length ? args : [now], newTarget); },
  apply() { return new OriginalDate(now).toString(); },
  get(target, key, receiver) { return key === "now" ? () => now : Reflect.get(target, key, receiver); },
});
try {
  const cases = [];
  for (const deletionError of [false, true]) cases.push(await captureNativeOwner(deletionError));
  for (const shape of ["object", "array", "date"]) for (const same of [false, true]) cases.push(await captureCredentialIdentity(shape, same));
  for (const operation of ["change", "verify"]) cases.push(await captureAuthoritativeSession(operation));
  const serialized = `${JSON.stringify({ version: "1.7.6", now, cases }, null, 2)}\n`;
  writeFileSync(process.argv[2], serialized);
  await writeObservation(serialized);
} finally { globalThis.Date = OriginalDate; }
