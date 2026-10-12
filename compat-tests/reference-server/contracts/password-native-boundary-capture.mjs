import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { serializeSignedCookie } from "better-call";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { twoFactor } from "better-auth/plugins";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const baseURL = "http://password-native.test";
const secret = "password-native-contract-secret-at-least-thirty-two";
const password = "CorrectHorseBattery1!";
const date = "2033-05-18T03:33:20.000Z";

export const passwordNativeBoundaryCases = [
  ...["string", "object", "number", "array"].map(hash => ({ name: `verify-${hash}-hash`, operation: "verify", hash, result: "true" })),
  ...["false", "object", "array", "false-string", "zero", "undefined"].map(result => ({ name: `verify-result-${result}`, operation: "verify", hash: "object", result })),
  { name: "verify-original-error", operation: "verify", hash: "object", result: "throws" },
  ...["array", "string", "empty", "number-key", "number-salt", "missing", "non-callable", "throws"].map(split => ({ name: `default-split-${split}`, operation: "default", hash: "object", split })),
  ...["object", "array", "number", "false", "undefined"].map(hash => ({ name: `require-password-${hash}`, operation: "require", hash })),
];

function resultValue(name) {
  switch (name) {
    case "true": return true;
    case "false": return false;
    case "object": return { accepted: false, ownUndefined: undefined };
    case "array": return [];
    case "false-string": return "false";
    case "zero": return 0;
    case "undefined": return undefined;
    case "throws": return undefined;
    default: throw new Error(`Unknown verification result: ${name}`);
  }
}

async function captureCase(scenario) {
  const native = createSecondaryNativeObserver();
  const errors = createProtectedFunctionObserver();
  const original = { reason: "verification callback failed", ownUndefined: undefined, nested: { retained: true } };
  let projected;
  switch (scenario.hash) {
    case "string": projected = "projected-hash"; break;
    case "number": projected = 17; break;
    case "array": projected = ["projected-hash"]; break;
    case "false": projected = false; break;
    case "undefined": projected = undefined; break;
    case "object": projected = { marker: "projected-hash", toString() {
      native.record("hash.toString");
      throw new Error("The password consumer must not stringify the hash");
    } }; break;
    default: throw new Error(`Unknown password projection: ${scenario.hash}`);
  }
  if (scenario.operation === "default" && scenario.split !== "missing") {
    projected.split = scenario.split === "non-callable" ? false : function (...args) {
      native.call("hash.split", this, projected, args);
      assert.equal(this, projected);
      assert.deepEqual(args, [":"]);
      if (scenario.split === "throws") throw original;
      if (scenario.split === "empty") return [];
      if (scenario.split === "string") return "ab";
      if (scenario.split === "number-key") return ["salt", 17];
      if (scenario.split === "number-salt") return [17, "wrong-key"];
      return ["salt", "wrong-key"];
    };
  }
  const memory = {
    user: [{ id: "owner", name: "Owner", email: "owner@password-native.test", emailVerified: true,
      image: null, twoFactorEnabled: false, createdAt: new Date(date), updatedAt: new Date(date) }],
    session: [{ id: "session", token: "session-token", userId: "owner",
      expiresAt: new Date("2099-01-01T00:00:00.000Z"), createdAt: new Date(date), updatedAt: new Date(date),
      ipAddress: null, userAgent: null }],
    account: [{ id: "credential", userId: "owner", accountId: "owner", providerId: "credential", password: "stored-hash",
      createdAt: new Date(date), updatedAt: new Date(date) }],
    verification: [], twoFactor: [],
  };
  const stored = structuredClone(memory);
  const verifierResult = scenario.operation === "verify" ? resultValue(scenario.result) : true;
  let verifierCalls = 0;
  let hashCalls = 0;
  const auth = betterAuth({
    baseURL, secret, database: memoryAdapter(memory),
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
    emailAndPassword: {
      enabled: true,
      password: {
        async hash(value) {
          hashCalls++;
          native.record("hash", { value: native.snapshot(value) });
          return "unused-hash";
        },
        ...(scenario.operation === "default" ? {} : { async verify(data) {
          verifierCalls++;
          native.record("verify", { arguments: native.snapshot(data), sameHash: data.hash === projected });
          assert.equal(data.hash, projected);
          assert.deepEqual(Object.keys(data), ["hash", "password"]);
          assert.equal(data.password, password);
          if (scenario.result === "throws") throw original;
          return verifierResult;
        } }),
      },
    },
    account: { additionalFields: { password: {
      type: "string", required: false, returned: false,
      transform: { output(value) {
        native.record("projection", { input: native.snapshot(value) });
        assert.equal(value, "stored-hash");
        return projected;
      } },
    } } },
    plugins: [twoFactor({ allowPasswordless: true, totpOptions: { disable: true } })],
  });
  await auth.$context;
  const cookie = (await serializeSignedCookie("better-auth.session_token", "session-token", secret)).split(";", 1)[0];
  const headers = new Headers({ cookie });
  let returned;
  let caught;
  try {
    returned = scenario.operation === "require"
      ? await auth.api.enableTwoFactor({ headers, body: {} })
      : await auth.api.verifyPassword({ headers, body: { password } });
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    caught = error;
  }
  assert.equal(hashCalls, 0);
  assert.equal(native.events.some(event => event.phase === "hash.toString"), false);
  assert.equal(native.events.filter(event => event.phase === "projection").length, 1);
  if (scenario.operation === "verify") {
    assert.equal(verifierCalls, 1);
    if (scenario.result === "throws") assert.equal(caught, original);
    else if (verifierResult) {
      assert.equal(caught, undefined);
      assert.deepEqual(returned, { status: true });
    } else {
      assert.equal(caught.statusCode, 400);
      assert.deepEqual(caught.body, { code: "INVALID_PASSWORD", message: "Invalid password" });
    }
  } else if (scenario.operation === "require") {
    assert.equal(verifierCalls, 0);
    assert.equal(caught.statusCode, 400);
    assert.deepEqual(caught.body, projected
      ? { code: "INVALID_PASSWORD", message: "Invalid password" }
      : { code: "TOTP_NOT_CONFIGURED", message: "TOTP is not available" });
  } else {
    assert.equal(verifierCalls, 0);
    assert.equal(native.events.filter(event => event.phase === "hash.split").length,
      ["missing", "non-callable"].includes(scenario.split) ? 0 : 1);
    assert.notEqual(caught, undefined);
    if (scenario.split === "throws") assert.equal(caught, original);
    else if (["array", "string", "number-key"].includes(scenario.split)) {
      assert.equal(caught.statusCode, 400);
      assert.deepEqual(caught.body, { code: "INVALID_PASSWORD", message: "Invalid password" });
    } else if (scenario.split === "empty") {
      assert.equal(caught.name, "Error");
      assert.equal(caught.message, "Invalid password hash");
    } else assert.equal(caught.name, "TypeError");
  }
  assert.deepEqual(memory, stored);
  return {
    ...scenario,
    contract: scenario.operation === "verify" && !["true", "false", "throws"].includes(scenario.result)
      ? "outside-declared-verifier-return-type" : "declared-field-transform-range",
    projected: native.snapshot(projected),
    verifierResult: native.snapshot(verifierResult),
    outcome: caught === undefined
      ? { returned: true, result: native.snapshot(returned) }
      : { returned: false, sameOriginal: caught === original, error: errors.error(caught) },
    events: native.events, functions: native.functions, errorFunctions: errors.functions,
    stored: native.snapshot(memory),
  };
}

export async function capturePasswordNativeBoundaries() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const cases = [];
  for (const scenario of passwordNativeBoundaryCases) cases.push(await captureCase(scenario));
  return {
    version: "1.7.6",
    types: {
      verifier: "({ hash: string, password: string }) => Promise<boolean>",
      transform: "(value: DBPrimitive) => Awaitable<DBPrimitive>",
      runtimeReturns: "Non-boolean verifier results record JavaScript behavior outside the declared configuration type.",
      hostErrorBoundary: "The shared observer excludes stack paths; complete error names, messages, and other own properties remain.",
    },
    cases,
  };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await capturePasswordNativeBoundaries(), null, 2)}\n`;
  writeFileSync(process.argv[2], serialized);
  await writeObservation(serialized);
}
