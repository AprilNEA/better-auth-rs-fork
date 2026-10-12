import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { serializeSignedCookie } from "better-call";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { createSecondaryNativeObserver, assertSecondaryNativeVersions, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

const origin = "http://oauth-logout-native.test";
const secret = "oauth-logout-native-contract-secret-at-least-32-characters";
const now = 2_000_000_000_000;
const token = "logout-native-session";
export const oauthLogoutNativeCases = [
  "builtin-dates", "date-own-get-time", "object-get-time", "deferred-number-conversion",
  "get-time-getter-error", "get-time-method-error", "later-method-precedes-conversion-error",
  "value-of-error", "nan-stable-order", "infinity-stable-order",
];

function tables() {
  return {
    user: [{ id: "owner", name: "Logout Owner", email: "owner@oauth-logout-native.test", emailVerified: true,
      image: null, createdAt: new Date(now), updatedAt: new Date(now) }],
    session: [{ id: "session", token, userId: "owner", expiresAt: new Date("2100-01-01T00:00:00.000Z"),
      createdAt: new Date(now), updatedAt: new Date(now), ipAddress: "", userAgent: "logout-native" }],
    account: ["first", "second", "excluded"].map((label, index) => ({
      id: `account-${label}`, accountId: `subject-${label}`, providerId: label === "excluded" ? "excluded" : "alpha",
      userId: "owner", idToken: `id-token-${label}`, createdAt: new Date(now), updatedAt: new Date(now + index),
      retainedExtra: { label, ownUndefined: undefined },
    })),
    verification: [],
  };
}

async function captureCase(name) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver(native);
  const original = { failure: name, ownUndefined: undefined };
  const conversionFailure = { conversionFailure: name, original };
  let methodCalls = 0;
  const projected = ["first", "second", "excluded"].map((label, index) => {
    if (name === "builtin-dates") return new Date(now + index);
    const value = name === "date-own-get-time" ? new Date(now + index) : { label };
    const numberResult = {};
    Object.defineProperty(numberResult, "valueOf", { configurable: true, get() {
      native.record(`get:valueOf:${label}`, { sameReceiver: this === numberResult });
      return function valueOf(...args) {
        native.call(`call:valueOf:${label}`, this, numberResult, args);
        native.record(`number:${label}`, { methodCalls });
        if (index === 0 && name === "value-of-error") throw original;
        if (index === 0 && name === "later-method-precedes-conversion-error") throw conversionFailure;
        return index === 0 ? methodCalls < 2 ? 100 : 0 : 10;
      };
    } });
    Object.defineProperty(value, "getTime", { configurable: true, get() {
      native.record(`get:getTime:${label}`, { sameReceiver: this === value });
      assert.notEqual(label, "excluded", "Provider filtering must precede timestamp consumption");
      if (index === 0 && name === "get-time-getter-error") throw original;
      return function getTime(...args) {
        native.call(`call:getTime:${label}`, this, value, args);
        methodCalls += 1;
        if (index === 0 && name === "get-time-method-error"
          || index === 1 && name === "later-method-precedes-conversion-error") throw original;
        if (["deferred-number-conversion", "value-of-error", "later-method-precedes-conversion-error"].includes(name)) return numberResult;
        if (name === "nan-stable-order") return undefined;
        if (name === "infinity-stable-order") return Infinity;
        return index === 0 ? "5" : "9";
      };
    } });
    return value;
  });
  const data = tables();
  const before = native.snapshot(data);
  const runtimeBefore = runtime.value(data);
  const auth = betterAuth({
    database: memoryAdapter(data), baseURL: origin, secret,
    telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "error", log(level, message, ...args) {
      const error = args[0];
      native.record("logger", { level, message, arguments: native.snapshot(args), sameOriginal: error === original });
    } },
    account: { additionalFields: { updatedAt: { type: "date", transform: { output(value) {
      const index = Date.prototype.getTime.call(value) - now;
      assert.ok(index >= 0 && index < projected.length);
      native.record("output:updatedAt", { index, input: native.snapshot(value), result: native.snapshot(projected[index]) });
      return projected[index];
    } } } } },
    plugins: [genericOAuth({ config: [{ providerId: "alpha", clientId: "logout-client",
      authorizationUrl: "https://idp.example.test/authorize", tokenUrl: "https://idp.example.test/token",
      endSessionEndpoint: "https://idp.example.test/logout" }] })],
  });
  const context = await auth.$context;
  const cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, token, secret)).split(";", 1)[0];
  const response = await auth.handler(new Request(`${origin}/api/auth/sign-out`, {
    method: "POST", headers: { cookie, origin, "content-type": "application/json" },
    body: JSON.stringify({ disableRedirect: true }),
  }));
  const text = await response.text();
  const body = JSON.parse(text);
  const responseAudit = { status: response.status, statusText: response.statusText, headers: [...response.headers],
    cookies: response.headers.getSetCookie(), body: text };
  const responseRuntime = { status: response.status, body, location: response.headers.get("location"), cookies: response.headers.getSetCookie() };
  assert.equal(response.status, 200);
  assert.equal(data.session.length, 0, "Provider logout errors must not undo local session deletion");
  const failed = name.endsWith("error");
  if (failed) {
    assert.deepEqual(body, { success: true });
    const logged = runtime.events.filter(event => event.phase === "logger");
    assert.equal(logged.length, 1);
    assert.equal(logged[0].sameOriginal, true);
    assert.equal(logged[0].message, "Failed to create provider logout URL");
  } else {
    const selected = name === "nan-stable-order" || name === "infinity-stable-order" ? "first" : "second";
    assert.deepEqual(body, { success: true, url: `https://idp.example.test/logout?id_token_hint=id-token-${selected}`, redirect: false });
  }
  if (name === "deferred-number-conversion") {
    assert.deepEqual(runtime.events.filter(event => event.phase.startsWith("number:")).map(event => event.methodCalls), [2, 2]);
  }
  if (name === "later-method-precedes-conversion-error") {
    assert.equal(runtime.events.some(event => event.phase.includes("valueOf")), false);
  }
  const after = native.snapshot(data);
  return { name, before, response: responseAudit, events: native.events, after, projected: native.snapshot(projected),
    functions: native.functions,
    runtime: { before: runtimeBefore, response: responseRuntime, events: runtime.events, after: runtime.value(data), functionIds: runtime.functionIds } };
}

export async function captureOAuthLogoutNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const path = "better-auth/dist/api/routes/sign-out.mjs";
  const provenance = { path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex") };
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const name of oauthLogoutNativeCases) cases.push(await captureCase(name));
    return { version: secondaryNativeVersion, boundary: "Real /sign-out HTTP handler with native Account.updatedAt output transformations and complete Memory storage; JavaScript descriptor reflection and transport header metadata remain source audit observations.", provenance, cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "oauth-logout-native", ...await captureOAuthLogoutNative() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
