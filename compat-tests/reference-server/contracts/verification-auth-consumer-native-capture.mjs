import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { serializeSignedCookie } from "better-call";
import { createAuthEndpoint } from "@better-auth/core/api";
import { createHMAC } from "@better-auth/utils/hmac";
import { oAuthProxy } from "better-auth/plugins/oauth-proxy";
import { twoFactor } from "better-auth/plugins/two-factor";
import { verifyTwoFactor } from "../node_modules/better-auth/dist/plugins/two-factor/verify-two-factor.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, secondaryNativeNow as now, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { createConsumerHarness, consumerOrigin, consumerSecret, consumerUser } from "./verification-consumer-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

export function verificationAuthConsumerCases() {
  const cases = [];
  const add = (consumer, suffix, fields = {}) => cases.push({ name: `${consumer}-${suffix}`, consumer, ...fields });
  for (const consumer of ["password-redirect", "two-factor-resolve", "two-factor-rearm"]) {
    for (const expiry of ["future", "equal", "expired", "missing", "undefined", "null", "nan", "invalid-date", "object", "conversion-error"])
      add(consumer, `expiry-${expiry}`, { expiry, value: "owner" });
    add(consumer, "expiry-getter-error", { value: "owner", fail: "expiry:get" });
    add(consumer, "value-getter-error", { value: "owner", fail: "value:get" });
  }
  add("two-factor-resolve", "unknown-user-skips-expiry", { value: "other-user", fail: "expiry:get" });
  add("two-factor-resolve", "function-root", { root: "function", value: "owner", fail: "expiry:get" });
  add("two-factor-rearm", "restore", { value: "owner", restore: true });
  add("two-factor-rearm", "set-error-after-persistence-is-swallowed", { value: "owner", fail: "set:after" });
  add("two-factor-rearm", "expiry-getter-error-after-attempt-consume", { value: "owner", fail: "expiry:get" });
  add("two-factor-rearm", "exhausted-consumes-challenge", { value: "owner", exhausted: true });
  for (const expiry of ["equal", "expired", "missing", "undefined", "null", "nan", "invalid-date"])
    add("two-factor-trust", `expiry-${expiry}-session-delete-error`, { value: "owner", expiry, fail: "session-delete:after" });
  add("two-factor-trust", "value-mismatch-skips-expiry", { value: "other-user", fail: "session-delete:after", unreadExpiry: true });
  add("two-factor-trust", "value-getter-error", { value: "owner", fail: "value:get" });
  add("two-factor-trust", "expiry-getter-error", { value: "owner", fail: "expiry:get" });
  add("two-factor-trust", "expiry-conversion-error", { value: "owner", expiry: "conversion-error" });
  add("two-factor-trust", "valid-trust-delete-error-persists-removal", { value: "owner", fail: "delete:after" });
  for (const value of ["undefined", "null", "false", "zero", "nan", "empty"])
    add("oauth-proxy", `value-${value}-skips-expiry`, { value, fail: "expiry:get" });
  add("oauth-proxy", "value-getter-error-is-logged", { value: "owner", fail: "value:get" });
  add("oauth-proxy", "truthy-value-key-error-is-logged", { value: "owner", fail: "expiry:get", keyError: true });
  add("oauth-proxy", "truthy-native-value-encryption-type-error-is-logged", { value: "object", fail: "expiry:get" });
  return cases;
}

const cookiePair = async (name, value) => (await serializeSignedCookie(name, value, consumerSecret)).split(";", 1)[0];

async function capturePassword(scenario) {
  const harness = createConsumerHarness(scenario, "reset-password:native-token");
  const captured = await harness.capture([], async auth => {
    const callbackURL = `${consumerOrigin}/reset?kept=1`;
    const response = await auth.handler(new Request(`${consumerOrigin}/api/auth/reset-password/native-token?${new URLSearchParams({ callbackURL })}`));
    return { status: response.status, headers: [...response.headers], cookies: response.headers.getSetCookie(), body: await response.text() };
  });
  assert.equal(harness.counts.value, 0);
  assert.equal(captured.observation.runtime.after.targetSameRoot, true);
  if (scenario.fail !== "expiry:get" && scenario.expiry !== "conversion-error") {
    assert.equal(captured.result.status, 302);
    const location = new Map(captured.result.headers).get("location");
    assert.equal(location, `${consumerOrigin}/reset?kept=1&${scenario.expiry === "expired" || scenario.expiry === "null" ? "error=INVALID_TOKEN" : "token=native-token"}`);
  }
  return captured.observation;
}

async function captureTwoFactor(scenario) {
  const identifier = "2fa-native";
  const harness = createConsumerHarness(scenario, identifier);
  const attemptsIdentifier = `2fa-attempts-${identifier}`;
  if (scenario.consumer === "two-factor-rearm") harness.cache.set(`verification:${attemptsIdentifier}`, JSON.stringify({
    id: "attempts-row", identifier: attemptsIdentifier, value: scenario.exhausted ? "3" : "0",
    expiresAt: new Date(now + 60_000), createdAt: new Date(now), updatedAt: new Date(now),
  }));
  const probe = {
    id: "verification-consumer-probe",
    endpoints: { captureNativeVerification: createAuthEndpoint.serverOnly({ method: "POST" }, async ctx => {
      try {
        const verification = await verifyTwoFactor(ctx);
        harness.event("consumer:resolved", { key: verification.key });
        if (scenario.consumer === "two-factor-resolve") return verification;
        const attempt = await verification.beginAttempt(3);
        harness.event("consumer:attempt-consumed");
        const result = scenario.restore ? await attempt.restore() : await attempt.recordFailure();
        harness.event("consumer:rearmed", { result: harness.runtime.value(result) });
        return { verification, attempt, result };
      } finally {
        harness.event("consumer:two-factor-finally", { headers: [...ctx.responseHeaders], cookies: ctx.responseHeaders.getSetCookie() });
      }
    }) },
  };
  const captured = await harness.capture([twoFactor(), probe], async (auth, context) => {
    const cookie = await cookiePair(context.createAuthCookie("two_factor").name, identifier);
    return auth.api.captureNativeVerification({ body: {}, headers: new Headers({ cookie }) });
  });
  const { events, after } = captured.observation.runtime;
  if (scenario.consumer === "two-factor-resolve") {
    assert.equal(harness.counts.expiry, 0);
    assert.equal(after.targetSameRoot, true);
    if (scenario.value === "owner" && scenario.fail !== "value:get") {
      assert.equal(captured.caught, undefined);
      assert.equal(captured.result.key, identifier);
      assert.equal(captured.result.session.user.id, "owner");
    }
  } else {
    const consumedAt = events.findIndex(event => event.phase === "storage.getAndDelete" && event.key === `verification:${attemptsIdentifier}`);
    const expiryAt = events.findIndex(event => event.phase === "get:expiresAt");
    if (expiryAt >= 0) assert.ok(consumedAt >= 0 && consumedAt < expiryAt);
    if (scenario.fail === "expiry:get") {
      assert.equal(captured.caught, harness.original);
      assert.equal(harness.cache.has(`verification:${attemptsIdentifier}`), false);
      assert.equal(after.targetSameRoot, true);
    }
    if (scenario.fail === "set:after") {
      assert.equal(captured.caught, undefined);
      assert.equal(harness.cache.has(`verification:${attemptsIdentifier}`), true);
      assert.ok(events.some(event => event.phase === "throw:storage.set:after"));
    }
    if (scenario.exhausted) assert.equal(after.targetPresent, false);
  }
  return captured.observation;
}

async function captureTrust(scenario) {
  const identifier = "trust-device-native";
  const harness = createConsumerHarness(scenario, identifier);
  if (scenario.unreadExpiry) Object.defineProperty(harness.root, "expiresAt", { configurable: true, enumerable: true,
    get() { harness.counts.expiry += 1; return harness.fail("unexpected:trust-expiry"); } });
  const plugin = twoFactor();
  const newSession = { user: consumerUser(), session: { id: "new-session-id", token: "new-session", userId: "owner",
    createdAt: new Date(now), updatedAt: new Date(now), expiresAt: new Date(now + 60_000), ipAddress: null, userAgent: null } };
  harness.cache.set("new-session", JSON.stringify(newSession));
  harness.cache.set("active-sessions-owner", JSON.stringify([{ token: "new-session", expiresAt: now + 60_000 }]));
  const captured = await harness.capture([plugin], async (_auth, context) => {
    context.newSession = newSession;
    const token = await createHMAC("SHA-256", "base64urlnopad").sign(consumerSecret, `owner!${identifier}`);
    const cookie = await cookiePair(context.createAuthCookie("trust_device").name, `${token}!${identifier}`);
    const hook = plugin.hooks.after.find(candidate => candidate.matcher({ path: "/sign-in/email" }));
    assert.ok(hook);
    let middlewareContext;
    // Observe the actual middleware context before the official handler uses its cookie helpers.
    hook.handler.options.use.push(async input => { middlewareContext = input; return {}; });
    const request = { path: "/sign-in/email", method: "POST", body: {}, headers: new Headers({ cookie }), context };
    try { return await hook.handler(request); }
    finally {
      assert.ok(middlewareContext);
      harness.event("consumer:trust-finally", { newSessionSameObject: context.newSession === newSession,
        newSession: harness.runtime.value(context.newSession), headers: [...middlewareContext.responseHeaders],
        cookies: middlewareContext.responseHeaders.getSetCookie(),
        contextHeaders: context.responseHeaders ? [...context.responseHeaders] : [] });
    }
  });
  assert.equal(captured.caught, harness.original);
  const { events, after } = captured.observation.runtime;
  const valueAt = events.findIndex(event => event.phase === "get:value");
  const expiryAt = events.findIndex(event => event.phase === "get:expiresAt");
  assert.ok(valueAt >= 0);
  if (expiryAt >= 0) assert.ok(valueAt < expiryAt);
  if (scenario.unreadExpiry || scenario.fail === "value:get") assert.equal(harness.counts.expiry, 0);
  if (scenario.fail === "delete:after") {
    assert.equal(after.targetPresent, false);
    assert.equal(harness.cache.has("new-session"), true);
  }
  if (scenario.fail === "session-delete:after") {
    assert.equal(after.targetSameRoot, true);
    assert.equal(harness.cache.has("new-session"), false);
    assert.equal(harness.cache.has("active-sessions-owner"), false);
  }
  return captured.observation;
}

async function captureProxy(scenario) {
  const harness = createConsumerHarness(scenario, "native-oauth-state");
  const options = { productionURL: "https://production.verification-consumer.test", currentURL: consumerOrigin };
  if (scenario.keyError) Object.defineProperty(options, "secret", { enumerable: true, get() { return harness.fail("throw:proxy-key"); } });
  const plugin = oAuthProxy(options);
  const response = { url: "https://provider.verification-consumer.test/authorize?state=native-oauth-state&kept=1", redirect: true };
  const captured = await harness.capture([plugin], async (_auth, context) => {
    context.oauthConfig.storeStateStrategy = "database";
    context.returned = response;
    const hook = plugin.hooks.after.find(candidate => candidate.matcher({ path: "/sign-in/social" }));
    assert.ok(hook);
    const result = await hook.handler({ path: "/sign-in/social", method: "POST", body: { provider: "fixture" }, context });
    return { result, response: context.returned, sameResponse: context.returned === response };
  });
  assert.equal(captured.caught, undefined);
  assert.equal(captured.result.sameResponse, true);
  assert.equal(harness.counts.expiry, 0);
  assert.equal(captured.observation.runtime.after.targetSameRoot, true);
  const logs = captured.observation.runtime.events.filter(event => event.phase.startsWith("logger:"));
  assert.equal(logs.length, 1);
  assert.equal(logs[0].phase, scenario.fail === "value:get" || scenario.keyError || scenario.value === "object" ? "logger:error" : "logger:warn");
  return captured.observation;
}

export async function captureVerificationAuthConsumerNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["plugins/two-factor/verify-two-factor.mjs", "plugins/two-factor/index.mjs",
    "plugins/oauth-proxy/index.mjs", "api/routes/password.mjs", "db/internal-adapter.mjs"].map(path => ({
    path: `better-auth/dist/${path}`, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/better-auth/dist/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of verificationAuthConsumerCases()) {
      const capture = scenario.consumer === "password-redirect" ? capturePassword
        : scenario.consumer === "two-factor-trust" ? captureTrust : scenario.consumer === "oauth-proxy" ? captureProxy : captureTwoFactor;
      cases.push(await capture(scenario));
    }
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Real password reset HTTP redirect; real verifyTwoFactor helper called inside a real server endpoint; real TwoFactor sign-in and OAuth Proxy after hooks. Trust cases inject an explicit secondary-storage failure after deletion and retain complete prior persistence and cookie observations. Trust success rotation and successful proxy ciphertext are outside this contract; no random identifiers or ciphertext are normalized. Complete native descriptor audits and runtime values remain separate.", cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "verification-auth-consumer-native", ...await captureVerificationAuthConsumerNative() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
