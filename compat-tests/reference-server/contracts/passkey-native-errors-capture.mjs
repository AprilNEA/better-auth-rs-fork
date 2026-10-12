import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { passkey, PASSKEY_ERROR_CODES } from "@better-auth/passkey";
import { APIError } from "@better-auth/core/error";
import { APIError as EndpointAPIError, kAPIErrorHeaderSymbol, serializeSignedCookie } from "better-call";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { withRestoredSchema } from "./schema-isolation.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow as now } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const origin = "http://passkey-native-errors.test";
const rpID = "passkey-native-errors.test";
const secret = "passkey-native-errors-secret-at-least-thirty-two-characters";
const registrationChallenge = Buffer.from("native-registration-challenge").toString("base64url");
const authenticationChallenge = Buffer.from("native-authentication-challenge").toString("base64url");
const userData = { id: "owner", name: "owner@passkey-native-errors.test", displayName: "Owner" };

export const passkeyNativeErrorCases = [
  ...["registration", "authentication"].flatMap(operation => [
    "missing-origin", "missing-cookie", "invalid-cookie", "missing-challenge", "consumed-challenge", "wrong-ceremony", "invalid-json",
    "consume-after-original", "callback-api-error", "callback-object-error",
  ].map(failure => ({ name: `${operation}-${failure}`, operation, failure }))),
  ...["missing-passkey", "wrong-signature", "null-session", "missing-user", "query-original", "update-after-original",
    "id-missing", "id-undefined", "id-null", "id-number", "id-empty", "malformed-existing", "malformed-nonexistent",
  ].map(failure => ({ name: `authentication-${failure}`, operation: "authentication", failure })),
];

function owner() {
  return { id: "owner", name: "Owner", email: userData.name, emailVerified: true, image: null,
    createdAt: new Date(now), updatedAt: new Date(now) };
}

function verification(operation, value) {
  return { id: `${operation}-challenge`, identifier: `${operation}-verification-token`, value,
    expiresAt: new Date(now + 300_000), createdAt: new Date(now), updatedAt: new Date(now) };
}

function challengeValue(operation) {
  return JSON.stringify({ type: operation, expectedChallenge: operation === "registration" ? registrationChallenge : authenticationChallenge,
    ...(operation === "registration" ? { userData, context: null } : {}) });
}

function revive(value) {
  if (Array.isArray(value)) return value.map(revive);
  if (value !== null && typeof value === "object") {
    if (value.type === "undefined" && Object.keys(value).length === 1) return undefined;
    if (value.type === "date" && Object.keys(value).length === 2) return new Date(value.value);
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, revive(child)]));
  }
  return value;
}

function options(memory, plugin, logger = { disabled: true }) {
  let generated = 0;
  return { baseURL: origin, secret, database: memoryAdapter(memory),
    logger, telemetry: { enabled: false }, rateLimit: { enabled: false },
    experimental: { instrumentation: { enabled: false } },
    session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
    advanced: { database: { generateId: ({ model }) => `${model}-${++generated}` } }, plugins: [plugin] };
}

const pluginOptions = { rpID, rpName: "Native errors", registration: { requireSession: false, resolveUser: () => userData } };

async function prepareSeed() {
  // The existing signer generates its key once. Frozen replay never imports the signer or replaces its recorded bytes.
  const { authenticator } = await import("../../client-tests/tests/phase8/authenticator.ts");
  const key = authenticator("native-error-credential");
  const response = key.register({ challenge: registrationChallenge, rp: { id: rpID }, user: { id: Buffer.from("owner").toString("base64url") } }, origin, false);
  const memory = { user: [owner()], session: [], account: [], verification: [verification("registration", challengeValue("registration"))], passkey: [] };
  const auth = betterAuth(options(memory, passkey(pluginOptions)));
  const context = await auth.$context;
  const cookieName = context.createAuthCookie("better-auth-passkey").name;
  const cookie = (await serializeSignedCookie(cookieName, "registration-verification-token", secret)).split(";", 1)[0];
  await auth.api.verifyPasskeyRegistration({ headers: new Headers({ origin, cookie }), body: { response, name: "Owner key" } });
  assert.equal(memory.passkey.length, 1);
  assert.equal(memory.verification.length, 0);
  const runtime = createSecondaryRuntimeObserver();
  return { credential: runtime.value(memory.passkey[0]), registrationResponse: runtime.value(response),
    authenticationResponse: runtime.value(key.authenticate({ challenge: authenticationChallenge, rpId: rpID }, origin, 1, 0x01, Buffer.from("owner").toString("base64url"))) };
}

async function createInput(scenario, seed, context) {
  const runtime = createSecondaryRuntimeObserver();
  let response = revive(scenario.operation === "registration" ? seed.registrationResponse : seed.authenticationResponse);
  if (scenario.failure === "wrong-signature") {
    const signature = Buffer.from(response.response.signature, "base64url");
    assert.equal(signature[0], 0x30);
    signature[signature.length - 1] ^= 1;
    response.response.signature = signature.toString("base64url");
  }
  if (scenario.failure.startsWith("id-") || scenario.failure.startsWith("malformed-")) {
    response = scenario.failure === "id-missing" ? {} : { id: {
      "id-undefined": undefined, "id-null": null, "id-number": 17, "id-empty": "",
      "malformed-existing": seed.credential.credentialID, "malformed-nonexistent": "missing-credential",
    }[scenario.failure] };
  }
  const challenge = verification(scenario.operation, scenario.failure === "invalid-json" ? '{"type":'
    : challengeValue(scenario.failure === "wrong-ceremony" ? scenario.operation === "registration" ? "authentication" : "registration" : scenario.operation));
  const cookieName = context.createAuthCookie("better-auth-passkey").name;
  const signedCookie = (await serializeSignedCookie(cookieName, challenge.identifier, secret)).split(";", 1)[0];
  const headers = new Headers({ "user-agent": "passkey-native-contract", "x-forwarded-for": "203.0.113.8" });
  if (scenario.failure !== "missing-origin") headers.set("origin", origin);
  if (scenario.failure !== "missing-cookie") headers.set("cookie", scenario.failure === "invalid-cookie" ? `${signedCookie}invalid` : signedCookie);
  return { response: runtime.value(response), credential: scenario.operation === "authentication" && scenario.failure !== "missing-passkey" ? seed.credential : null,
    challenge: runtime.value(challenge), signedCookie, headers: [...headers], sessionToken: `${scenario.name}-session-token` };
}

async function captureCase(scenario, seed, frozenInput) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver();
  const errors = createProtectedFunctionObserver();
  const events = [];
  const logs = [];
  const originalBody = { marker: scenario.name, ownUndefined: undefined, message: "Original verification callback failure" };
  const original = scenario.failure === "callback-api-error" ? new APIError("CONFLICT", originalBody)
    : { marker: scenario.name, ownUndefined: undefined, nested: { retained: true } };
  const memory = { user: [owner()], session: [], account: [], verification: [], passkey: [] };
  let active = false;
  const record = (phase, value) => {
    if (!active) return;
    events.push({ phase, value: runtime.value(value) });
    native.record(phase, { value: native.snapshot(value) });
  };
  const afterVerification = ({ verification: verified, clientData }) => {
    assert.equal(verified.verified, true);
    record("verification", { verification: verified, clientData,
      credentialPublicKeyIsUint8Array: verified.registrationInfo?.credential.publicKey instanceof Uint8Array });
    if (scenario.failure.startsWith("callback-")) throw original;
  };
  const plugin = passkey({ ...pluginOptions,
    registration: { ...pluginOptions.registration, afterVerification }, authentication: { afterVerification } });
  const auth = betterAuth(options(memory, plugin, { level: "error", log(level, message, ...args) {
    if (!active) return;
    logs.push({ level, message, arguments: args.map(value => errors.error(value)), sameOriginal: args.map(value => value === original) });
    native.record("logger", { level, message, arguments: native.snapshot(args), sameOriginal: args.map(value => value === original) });
  } }));
  const context = await auth.$context;
  const input = frozenInput ?? await createInput(scenario, seed, context);
  const response = revive(input.response);
  const challenge = revive(input.challenge);
  memory.passkey = input.credential === null ? [] : [revive(input.credential)];
  if (scenario.failure !== "missing-challenge") memory.verification.push(challenge);
  let setupConsumption;
  if (scenario.failure === "consumed-challenge") setupConsumption = await context.internalAdapter.consumeVerificationValue(challenge.identifier);
  const before = runtime.value(memory);
  const beforeNative = native.snapshot(memory);
  const originalBefore = native.snapshot(original);
  for (const method of ["findOne", "findMany", "create", "update", "consumeOne"]) {
    const implementation = context.adapter[method];
    assert.equal(typeof implementation, "function", `The pinned adapter implements ${method}`);
    context.adapter[method] = async function (...args) {
      record(`adapter:${method}:call`, args);
      try {
        if (method === "findOne" && args[0].model === "passkey" && scenario.failure === "query-original") throw original;
        const result = method === "findOne" && args[0].model === "user" && scenario.failure === "missing-user"
          ? null : await Reflect.apply(implementation, this, args);
        record(`adapter:${method}:return`, result);
        if (method === "update" && args[0].model === "passkey" && scenario.failure === "update-after-original") throw original;
        return result;
      } catch (error) {
        record(`adapter:${method}:throw`, { sameOriginal: error === original });
        throw error;
      }
    };
  }
  for (const method of ["consumeVerificationValue", "createSession", "findUserById"]) {
    const implementation = context.internalAdapter[method];
    context.internalAdapter[method] = async function (...args) {
      record(`internal:${method}:call`, args);
      try {
        const forwarded = method === "createSession" ? [args[0], args[1], { ...args[2], token: input.sessionToken }, true, args[4]] : args;
        if (method === "createSession") record("internal:createSession:forward", forwarded);
        const result = method === "createSession" && scenario.failure === "null-session" ? null : await Reflect.apply(implementation, this, forwarded);
        record(`internal:${method}:return`, result);
        if (method === "consumeVerificationValue" && scenario.failure === "consume-after-original") throw original;
        return result;
      } catch (error) {
        record(`internal:${method}:throw`, { sameOriginal: error === original });
        throw error;
      }
    };
  }
  active = true;
  let caught;
  let returned = false;
  let result;
  try {
    result = await auth.api[scenario.operation === "registration" ? "verifyPasskeyRegistration" : "verifyPasskeyAuthentication"]({
      headers: new Headers(input.headers), body: { response, ...(scenario.operation === "registration" ? { name: "Owner key" } : {}) },
    });
    returned = true;
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    caught = error;
  }
  active = false;
  assert.equal(returned, false, `${scenario.name} must fail`);
  const headers = caught?.[kAPIErrorHeaderSymbol];
  const errorCookies = headers?.getSetCookie() ?? [];
  assert.equal(errorCookies.some(cookie => cookie.startsWith(`${context.authCookies.sessionToken.name}=`)), false);
  const after = runtime.value(memory);
  const skippedConsume = ["missing-origin", "missing-cookie", "invalid-cookie"].includes(scenario.failure);
  assert.equal(events.filter(event => event.phase === "internal:consumeVerificationValue:call").length, skippedConsume ? 0 : 1);
  assert.equal(memory.verification.length, skippedConsume ? 1 : 0);
  assert.deepEqual(memory.user, [owner()]);
  assert.deepEqual(memory.account, []);
  const committedCounter = ["null-session", "missing-user", "update-after-original"].includes(scenario.failure);
  assert.deepEqual(after.passkey, before.passkey.map(row => committedCounter ? { ...row, counter: 1 } : row));
  assert.equal(memory.session.length, scenario.failure === "missing-user" ? 1 : 0);
  if (memory.session.length) {
    assert.equal(memory.session[0].userId, "owner");
    assert.equal(memory.session[0].token, input.sessionToken);
  }
  const expected = (status, key) => {
    assert.ok(caught instanceof APIError);
    assert.equal(caught.statusCode, status);
    const { message, code } = PASSKEY_ERROR_CODES[key];
    assert.deepEqual(caught.body, { message, code });
    assert.deepEqual(Object.keys(caught.body), ["message", "code"]);
  };
  if (scenario.failure === "missing-origin") {
    if (scenario.operation === "registration") expected(400, "FAILED_TO_VERIFY_REGISTRATION");
    else { assert.ok(caught instanceof APIError); assert.equal(caught.statusCode, 400); assert.deepEqual(caught.body, { message: "origin missing" }); }
  } else if (["missing-cookie", "invalid-cookie", "missing-challenge", "consumed-challenge", "wrong-ceremony"].includes(scenario.failure)) expected(400, "CHALLENGE_NOT_FOUND");
  else if (scenario.failure === "invalid-json") assert.ok(caught instanceof SyntaxError);
  else if (["consume-after-original", "query-original", "callback-api-error"].includes(scenario.failure)) assert.equal(caught, original);
  else if (["missing-passkey", "malformed-nonexistent"].includes(scenario.failure)) expected(401, "PASSKEY_NOT_FOUND");
  else if (scenario.failure === "wrong-signature") expected(401, "AUTHENTICATION_FAILED");
  else if (scenario.failure === "null-session") expected(500, "UNABLE_TO_CREATE_SESSION");
  else if (scenario.failure === "missing-user") { assert.ok(caught instanceof APIError); assert.equal(caught.statusCode, 500); assert.deepEqual(caught.body, { message: "User not found" }); }
  else if (["callback-object-error", "update-after-original", "malformed-existing"].includes(scenario.failure)) expected(scenario.operation === "registration" ? 500 : 400,
    scenario.operation === "registration" ? "FAILED_TO_VERIFY_REGISTRATION" : "AUTHENTICATION_FAILED");
  const queriedPasskey = events.filter(event => event.phase === "adapter:findOne:call" && event.value[0].model === "passkey");
  if (scenario.failure.startsWith("id-") || scenario.failure.startsWith("malformed-")) {
    assert.equal(queriedPasskey.length, 1);
    assert.deepEqual(queriedPasskey[0].value[0], runtime.value({ model: "passkey", where: [{ field: "credentialID", value: response.id }] }));
  }
  const hasVerification = committedCounter || scenario.failure.startsWith("callback-");
  assert.equal(events.filter(event => event.phase === "verification").length, hasVerification ? 1 : 0);
  if (hasVerification && committedCounter) assert.ok(events.findIndex(event => event.phase === "verification") < events.findIndex(event => event.phase === "adapter:update:call"));
  const hasOriginalLog = ["callback-object-error", "update-after-original"].includes(scenario.failure);
  if (hasOriginalLog) {
    assert.equal(logs.length, 1);
    assert.deepEqual(logs[0].sameOriginal, [true]);
    assert.notEqual(caught, original);
  }
  if (skippedConsume || ["missing-challenge", "consumed-challenge", "wrong-ceremony", "invalid-json", "consume-after-original", "query-original", "callback-api-error"].includes(scenario.failure)) assert.deepEqual(logs, []);
  const outcome = { returned, error: errors.error(caught), coreAPIError: caught instanceof APIError,
    endpointAPIError: caught instanceof EndpointAPIError, syntaxError: caught instanceof SyntaxError,
    ownKeys: Reflect.ownKeys(caught).map(errors.observe), enumerableKeys: Object.keys(caught),
    bodyKeys: caught.body === undefined ? null : Object.keys(caught.body), sameOriginal: caught === original,
    sameOriginalBody: caught.body === originalBody, headers: headers ? [...headers] : null, cookies: errorCookies };
  return { name: scenario.name, scenario, input, runtime: { before, setupConsumption: runtime.value(setupConsumption), events, logs, outcome, after },
    raw: { before: beforeNative, challenge: native.snapshot(challenge), setupConsumption: native.snapshot(setupConsumption),
      events: native.events, result: native.snapshot(result), error: native.snapshot(caught), stack: runtime.value(caught.stack), errorStack: runtime.value(caught.errorStack),
      originalBefore, originalAfter: native.snapshot(original), after: native.snapshot(memory), functions: native.functions, errorFunctions: errors.functions } };
}

export async function capturePasskeyNativeErrors(frozen) {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/passkey"]);
  if (frozen !== undefined) {
    assert.equal(frozen.contract, "passkey-native-errors");
    assert.equal(frozen.version, "1.7.6");
    assert.deepEqual(frozen.cases.map(({ scenario }) => scenario), passkeyNativeErrorCases);
    for (const entry of frozen.cases) assert.ok(entry.input, `Missing frozen input for ${entry.name}`);
  }
  const paths = ["@better-auth/passkey/dist/index.mjs", "better-auth/dist/db/internal-adapter.mjs", "@better-auth/core/dist/error/index.mjs", "better-call/dist/error.mjs"];
  const provenance = paths.map(path => ({ path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex") }));
  return withClock(async setClock => {
    setClock(now);
    return withRestoredSchema(passkey().schema, async () => {
      const seed = frozen === undefined ? await prepareSeed() : undefined;
      const cases = [];
      for (const [index, scenario] of passkeyNativeErrorCases.entries()) cases.push(await captureCase(scenario, seed, frozen?.cases[index].input));
      return { contract: "passkey-native-errors", version: "1.7.6", backend: "memory", provenance,
        boundary: "Real, unmodified native auth.api Passkey routes and SimpleWebAuthn verification. Registration uses the documented requireSession:false and resolveUser configuration. The first capture uses the existing authenticator only to prepare valid key material and signed assertions; replay uses every frozen input byte and never imports that signer. Real signed cookies and internal verification consumption remain active. Adapter recorders inject only the declared failures; missing-user projects the User query to null without deleting the stored User. The createSession recorder forwards a fixed token through the supported overrideAll argument and retains real session persistence. Complete request, challenge JSON, storage, errors, descriptors, key order, identities and raw stacks are retained. The runtime observation excludes host stack text and descriptor internals; raw observations retain both. Browser transport, default registration session middleware, SQL transactions and the Rust WebAuthn engine's private challenge payload are separate, unpaired boundaries. Existing captures are neither resampled nor replaced.", cases };
    });
  });
}

if (import.meta.main) {
  const args = process.argv.slice(2);
  assert.ok(args.length === 1 || args.length === 2, "Pass an output path, or a frozen fixture followed by an output path");
  const frozen = args.length === 2 ? JSON.parse(readFileSync(args[0], "utf8")) : undefined;
  const observation = await capturePasskeyNativeErrors(frozen);
  const serialized = `${JSON.stringify(observation, null, 2)}\n`;
  writeFileSync(args.at(-1), serialized);
  await writeObservation(serialized);
}
