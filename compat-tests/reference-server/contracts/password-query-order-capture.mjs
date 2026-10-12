import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { serializeSignedCookie } from "better-call";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { phoneNumber, twoFactor } from "better-auth/plugins";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const baseURL = "http://password-query.test";
const secret = "password-query-contract-secret-at-least-thirty-two";
const password = "CorrectHorseBattery1!";
const date = "2033-05-18T03:33:20.000Z";
const now = 2_000_000_000_000;

const scenarios = [
  { name: "passwordless-presence-and-verification-query", operation: "two-factor", allowPasswordless: true, password: "provided", projections: 2, verifications: 1 },
  { name: "required-password-one-verification-query", operation: "two-factor", allowPasswordless: false, password: "provided", projections: 1, verifications: 1 },
  { name: "required-empty-password-before-query", operation: "two-factor", allowPasswordless: false, password: "empty", projections: 0, verifications: 0 },
  { name: "required-length-before-query", operation: "two-factor", allowPasswordless: false, password: "long", projections: 0, verifications: 0 },
  { name: "passwordless-presence-before-length", operation: "two-factor", allowPasswordless: true, password: "long", projections: 1, verifications: 0 },
  { name: "passwordless-second-projection-controls-verification", operation: "two-factor", allowPasswordless: true, password: "provided", secondHash: "false", projections: 2, verifications: 0 },
  ...["false", "zero", "nan", "empty", "null", "undefined", "object", "array", "number"].map(hash => ({ name: `phone-password-${hash}`, operation: "phone", hash })),
  ...["none", "provider", "replacement"].map(mutation => ({ name: `change-password-retains-selected-account-${mutation}`, operation: "change", mutation })),
];

function projectedHash(name, native) {
  switch (name) {
    case "false": return false;
    case "zero": return 0;
    case "nan": return NaN;
    case "empty": return "";
    case "null": return null;
    case "undefined": return undefined;
    case "array": return ["projected-hash"];
    case "number": return 17;
    case "object": return { marker: "projected-hash", toString() {
      native.record("hash.toString");
      throw new Error("The password consumer must not stringify the hash");
    } };
    default: throw new Error(`Unknown password projection: ${name}`);
  }
}

async function captureCase(scenario) {
  const native = createSecondaryNativeObserver();
  const errors = createProtectedFunctionObserver();
  const projected = projectedHash(scenario.hash ?? "object", native);
  const memory = {
    user: [{ id: "owner", name: "Owner", email: "owner@password-query.test", emailVerified: true,
      image: null, twoFactorEnabled: false, phoneNumber: "+12025550123", phoneNumberVerified: true,
      createdAt: new Date(date), updatedAt: new Date(date) }],
    session: [{ id: "session", token: "session-token", userId: "owner",
      expiresAt: new Date("2099-01-01T00:00:00.000Z"), createdAt: new Date(date), updatedAt: new Date(date),
      ipAddress: null, userAgent: null }],
    account: [{ id: "credential", userId: "owner", accountId: "owner", providerId: "credential", password: "stored-hash",
      createdAt: new Date(date), updatedAt: new Date(date) }],
    verification: [], twoFactor: [],
  };
  const stored = structuredClone(memory);
  let projections = 0;
  let verifications = 0;
  let hashCalls = 0;
  const auth = betterAuth({
    baseURL, secret, database: memoryAdapter(memory),
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
    emailAndPassword: { enabled: true, password: {
      async hash(value) {
        hashCalls++;
        native.record("hash", { value: native.snapshot(value) });
        assert.equal(value, password);
        return "new-hash";
      },
      async verify(data) {
        verifications++;
        native.record("verify", { arguments: native.snapshot(data), sameHash: data.hash === projected });
        assert.equal(data.hash, projected);
        assert.deepEqual(Object.keys(data), ["hash", "password"]);
        assert.equal(data.password, password);
        if (scenario.mutation === "provider") {
          memory.account[0].providerId = "changed-provider";
          native.record("mutate-provider", { stored: native.snapshot(memory.account) });
        } else if (scenario.mutation === "replacement") {
          memory.account.splice(0, 1, { ...memory.account[0], id: "replacement", password: "replacement-hash" });
          native.record("replace-account", { stored: native.snapshot(memory.account) });
        }
        return scenario.operation !== "phone";
      },
    } },
    account: { additionalFields: { password: {
      type: "string", required: false, returned: false,
      transform: { output(value) {
        projections++;
        native.record("projection", { input: native.snapshot(value) });
        assert.ok(["stored-hash", "new-hash"].includes(value));
        return scenario.secondHash === "false" && projections === 2 ? false : projected;
      } },
    } } },
    plugins: [phoneNumber(), twoFactor({ allowPasswordless: scenario.allowPasswordless ?? false, totpOptions: { disable: true } })],
  });
  await auth.$context;
  const cookie = (await serializeSignedCookie("better-auth.session_token", "session-token", secret)).split(";", 1)[0];
  const headers = new Headers({ cookie });
  let returned;
  let caught;
  try {
    if (scenario.operation === "phone") returned = await auth.api.signInPhoneNumber({ body: { phoneNumber: "+12025550123", password } });
    else if (scenario.operation === "change") returned = await auth.api.changePassword({ headers, body: { currentPassword: password, newPassword: password } });
    else returned = await auth.api.enableTwoFactor({ headers, body: { password: scenario.password === "long" ? "x".repeat(129) : scenario.password === "empty" ? "" : password } });
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    caught = error;
  }
  assert.equal(native.events.some(event => event.phase === "hash.toString"), false);
  if (scenario.operation === "change") {
    assert.equal(caught, undefined);
    assert.equal(hashCalls, 1);
    assert.equal(verifications, 1);
    assert.equal(projections, scenario.mutation === "replacement" ? 1 : 2);
    assert.deepEqual(native.events.map(event => event.phase), scenario.mutation === "replacement"
      ? ["projection", "hash", "verify", "replace-account"]
      : scenario.mutation === "provider"
        ? ["projection", "hash", "verify", "mutate-provider", "projection"]
        : ["projection", "hash", "verify", "projection"]);
    assert.deepEqual(returned, { token: null, user: stored.user[0] });
    const expected = structuredClone(stored);
    if (scenario.mutation === "replacement") {
      expected.account[0].id = "replacement";
      expected.account[0].password = "replacement-hash";
    } else {
      expected.account[0].password = "new-hash";
      expected.account[0].updatedAt = new Date(now);
      if (scenario.mutation === "provider") expected.account[0].providerId = "changed-provider";
    }
    assert.deepEqual(memory, expected);
  } else {
    assert.equal(hashCalls, 0);
    assert.notEqual(caught, undefined);
    if (scenario.operation === "phone") {
      assert.equal(projections, 1);
      assert.equal(verifications, projected ? 1 : 0);
      assert.deepEqual(native.events.map(event => event.phase), projected ? ["projection", "verify"] : ["projection"]);
      assert.equal(caught.statusCode, 401);
      assert.deepEqual(caught.body, projected
        ? { code: "INVALID_PHONE_NUMBER_OR_PASSWORD", message: "Invalid phone number or password" }
        : { code: "UNEXPECTED_ERROR", message: "Unexpected error" });
    } else {
      assert.equal(projections, scenario.projections);
      assert.equal(verifications, scenario.verifications);
      assert.deepEqual(native.events.map(event => event.phase), [
        ...Array(scenario.projections).fill("projection"),
        ...Array(scenario.verifications).fill("verify"),
      ]);
      assert.equal(caught.statusCode, 400);
      assert.deepEqual(caught.body, scenario.password === "long"
        ? { code: "PASSWORD_TOO_LONG", message: "Password too long" }
        : scenario.password === "empty" || scenario.secondHash === "false"
          ? { code: "INVALID_PASSWORD", message: "Invalid password" }
          : { code: "TOTP_NOT_CONFIGURED", message: "TOTP is not available" });
    }
    assert.deepEqual(memory, stored);
  }
  return {
    ...scenario,
    projected: native.snapshot(projected),
    outcome: caught === undefined
      ? { returned: true, result: native.snapshot(returned) }
      : { returned: false, error: errors.error(caught) },
    events: native.events, functions: native.functions, errorFunctions: errors.functions,
    stored: native.snapshot(memory),
  };
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
  for (const scenario of scenarios) cases.push(await captureCase(scenario));
  const serialized = `${JSON.stringify({ version: "1.7.6", now, cases }, null, 2)}\n`;
  writeFileSync(process.argv[2], serialized);
  await writeObservation(serialized);
} finally { globalThis.Date = OriginalDate; }
