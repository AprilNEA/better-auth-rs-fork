import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver } from "./secondary-native-shared.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

const now = 2_000_000_000_000;
const password = "CorrectHorseBattery1!";
const tables = ["user", "session", "account", "verification"];

async function capture(shape, throwsAt, changing) {
  const native = createSecondaryNativeObserver();
  const errors = createProtectedFunctionObserver();
  const original = { kind: "selected-user-id-error", shape, throwsAt };
  const changed = { marker: "third-read-owner" };
  let reads = 0;
  let recording = false;
  let user;
  function readId() {
    reads++;
    native.record("user-id", { read: reads, sameReceiver: this === user });
    assert.equal(this, user);
    if (reads === throwsAt) throw original;
    return changing && reads === 3 ? changed : 7;
  }
  user = shape === "array" ? [] : shape === "function" ? function selectedUser() {} : shape === "date" ? new Date(now) : {};
  Object.defineProperty(user, "id", { get: readId, enumerable: true, configurable: true });
  const current = { id: "current", token: "current", userId: 7, expiresAt: new Date(now + 3_600_000),
    createdAt: new Date(now), updatedAt: new Date(now), ipAddress: null, userAgent: null };
  const account = { id: "credential", userId: 7, accountId: 7, providerId: "credential", password: "stored-hash",
    createdAt: new Date(now), updatedAt: new Date(now) };
  const auth = betterAuth({
    baseURL: "http://selected-user-property.test", secret: "selected-user-property-contract-at-least-thirty-two",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { disableSessionRefresh: true, cookieCache: { enabled: false }, additionalFields: { userId: { type: "string" } } },
    account: { additionalFields: { userId: { type: "string" } } },
    emailAndPassword: { enabled: true, password: {
      async hash(value) { native.record("hash", { value }); assert.equal(value, password); return "new-hash"; },
      async verify(data) { native.record("verify", { arguments: native.snapshot(data) }); assert.deepEqual(data, { hash: "stored-hash", password }); return true; },
    } },
    hooks: { before: createAuthMiddleware(async ctx => {
      if (recording) ctx.context.session = { session: current, user };
    }) },
    databaseHooks: { session: {
      delete: {
        before(data) { native.record("delete-before", { arguments: native.snapshot([data]) }); },
        after(data) { native.record("delete-after", { arguments: native.snapshot([data]) }); },
      },
      create: { before(data) {
        native.record("create-cancel", { arguments: native.snapshot([data]), sameOwner: data.userId === (changing ? changed : 7) });
        assert.equal(data.userId, changing ? changed : 7);
        return false;
      } },
    } },
  });
  const context = await auth.$context;
  for (const [model, data] of [["account", account], ["session", current]]) {
    await context.adapter.create({ model, data, forceAllowId: true });
  }
  const storage = async () => Object.fromEntries(await Promise.all(tables.map(async model => [model, await context.adapter.findMany({ model })])));
  const before = await storage();
  const userBefore = native.snapshot(user);
  recording = true;
  let outcome;
  let thrown;
  try {
    const result = await auth.api.changePassword({ body: { currentPassword: password, newPassword: password, revokeOtherSessions: true } });
    outcome = { returned: true, result: native.snapshot(result) };
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    thrown = error;
    outcome = { returned: false, sameOriginal: error === original, error: errors.error(error) };
  }
  recording = false;
  const after = await storage();
  const expected = structuredClone(before);
  if (throwsAt !== 1) expected.account[0].password = "new-hash";
  if (throwsAt === 0 || throwsAt === 3) expected.session = [];
  assert.deepEqual(after, expected);
  assert.equal(reads, throwsAt || 3);
  assert.equal(outcome.returned, false);
  if (throwsAt) assert.equal(thrown, original);
  else {
    assert.equal(thrown.statusCode, 500);
    assert.deepEqual(thrown.body, { code: "FAILED_TO_GET_SESSION", message: "Failed to get session" });
  }
  return { shape, throwsAt, changing, reads, userBefore, before: native.snapshot(before), outcome,
    after: native.snapshot(after), userAfter: native.snapshot(user), events: native.events,
    functions: native.functions, errorFunctions: errors.functions };
}

assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
const output = process.argv[2];
assert.ok(output, "Pass the selected User property capture output path");
const observed = { version: "1.7.6", now, entropy: "The standalone harness supplies byte 1 to crypto.getRandomValues; the complete generated callback arguments are retained.", cases: [] };
const entropyDescriptor = Object.getOwnPropertyDescriptor(globalThis.crypto, "getRandomValues");
Object.defineProperty(globalThis.crypto, "getRandomValues", {
  configurable: true,
  value(array) {
    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(1);
    return array;
  },
});
try {
  await withClock(async setClock => {
    setClock(now);
    for (const shape of ["object", "array", "function", "date"]) {
      for (const throwsAt of [0, 1, 2, 3]) observed.cases.push(await capture(shape, throwsAt, false));
      observed.cases.push(await capture(shape, 0, true));
    }
  });
  assert.equal(observed.cases.length, 20);
  writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
} finally {
  if (entropyDescriptor) Object.defineProperty(globalThis.crypto, "getRandomValues", entropyDescriptor);
  else delete globalThis.crypto.getRandomValues;
  const serialized = `${JSON.stringify(observed, null, 2)}\n`;
  writeFileSync(`${output}.raw.json`, serialized);
  await writeObservation(serialized);
}
