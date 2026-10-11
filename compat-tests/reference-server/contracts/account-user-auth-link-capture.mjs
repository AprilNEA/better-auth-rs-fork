import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createAuthMiddleware } from "better-auth/api";
import { symmetricDecrypt } from "better-auth/crypto";
import { kAPIErrorHeaderSymbol } from "better-call";
import { captureAccountUserAuthCases } from "./account-user-auth-boundary-capture.mjs";
import { prepareCallbackOverride } from "./account-user-auth-boundary-override.mjs";
import { observeValue } from "./device-where-capture.mjs";

const secret = "account-user-auth-boundary-fixture-secret-at-least-32-characters";
const ownerToken = "link-owner-session-token";
const ownerCookie = `better-auth.session_token=${encodeURIComponent(`${ownerToken}.${createHmac("sha256", secret).update(ownerToken).digest("base64")}`)}`;
const definitions = [
  ...["success", "lookup-api", "before-api", "after-error", "cancel", "admission-coded", "admission-uncoded"]
    .map(mode => ({ branch: "existing", mode, callback: true })),
  ...["success", "before-api", "after-error", "cancel"]
    .map(mode => ({ branch: "implicit", mode, callback: true })),
  { branch: "existing", mode: "success", callback: false },
  { branch: "implicit", mode: "success", callback: false },
  { branch: "implicit", mode: "before-api", callback: false },
];
const scenarios = definitions.flatMap(definition => ["http", "native"].map(invocation => ({
  name: `link-${definition.callback ? "callback" : "id-token"}-${definition.branch}-${definition.mode}-${invocation}`,
  route: "social", relation: "default", linking: true, invocation, ...definition,
})));

function headers(value) {
  if (value === undefined) return observeValue(value);
  const result = new Headers(value);
  return { entries: [...result], cookies: result.getSetCookie() };
}

function errorObservation(error, failure) {
  return {
    sameObject: error === failure,
    sameBody: error.body === failure.body,
    sameHeaders: error.headers === failure.headers,
    name: observeValue(error.name), message: observeValue(error.message),
    status: observeValue(error.status), statusCode: observeValue(error.statusCode),
    body: observeValue(error.body), headers: headers(error.headers),
    capturedHeaders: headers(error[kAPIErrorHeaderSymbol]),
  };
}

function configure(scenario, options, record) {
  let armed = false;
  const failure = scenario.mode === "after-error" ? new Error("link runtime failure") : {
    name: "APIError", message: "link rejection", status: "CONFLICT", statusCode: 409,
    body: { code: scenario.mode === "admission-uncoded" ? "" : "LINK_REJECTED", message: "link rejection", details: { mode: scenario.mode } },
    headers: { "x-link-error": "1" },
  };
  options.advanced.database.generateId = ({ model }) => `zz-link-${model}`;
  options.session.disableSessionRefresh = true;
  options.account.encryptOAuthTokens = true;
  options.account.storeAccountCookie = true;
  const originalProfile = options.socialProviders.google.getUserInfo;
  options.socialProviders.google.getUserInfo = async tokens => {
    const result = await originalProfile(tokens);
    if (scenario.branch === "implicit") result.data.sub = "external-implicit";
    return result;
  };
  const admission = options.user.validateUserInfo;
  options.user.validateUserInfo = async (...args) => {
    const result = await admission(...args);
    if (scenario.mode.startsWith("admission-")) throw failure;
    return result;
  };
  if (scenario.mode === "lookup-api") {
    const output = options.account.additionalFields.accountId.transform.output;
    options.account.additionalFields.accountId.transform.output = value => {
      const result = output(value);
      if (!armed) return result;
      throw failure;
    };
  }
  for (const [model, operations] of Object.entries(options.databaseHooks)) {
    for (const [operation, callbacks] of Object.entries(operations)) {
      for (const phase of ["before", "after"]) callbacks[phase] = (data, context) => {
        record({ kind: "hook-headers", model, operation, phase, cookies: context?.responseHeaders?.getSetCookie() ?? [] });
        record({ kind: "hook", model, operation, phase, keys: data === null ? [] : Object.keys(data), data });
        if (model !== "account") return;
        if (scenario.mode === "before-api" && phase === "before" || scenario.mode === "after-error" && phase === "after") throw failure;
        if (scenario.mode === "cancel" && phase === "before") return false;
      };
    }
  }
  options.hooks = { after: createAuthMiddleware(async context => {
    record({ kind: "endpoint-after", rawErrorIdentity: context.context.returned === failure,
      cookies: context.context.responseHeaders?.getSetCookie() ?? [] });
  }) };
  options.onAPIError.onError = error => record({ kind: "api-error", error: errorObservation(error, failure) });
  return {
    async seed(adapter) {
      await adapter.create({ model: "session", forceAllowId: true, data: {
        id: "zz-link-session", userId: "user-a", token: ownerToken,
        createdAt: new Date("2030-01-02T03:04:05.000Z"), updatedAt: new Date("2030-01-02T03:04:05.000Z"),
        expiresAt: new Date("2100-01-02T03:04:05.000Z"), ipAddress: "", userAgent: "",
      } });
    },
    async prepareCallback(auth, recorder, parameters) {
      const callback = await prepareCallbackOverride(auth, recorder, {
        ...parameters, route: "link-social", requestHeaders: { ...parameters.requestHeaders, cookie: ownerCookie },
      });
      armed = true;
      return callback;
    },
    input(input) {
      if (scenario.branch === "existing") input.idToken.accessToken = "direct-access";
    },
    request({ origin, requestHeaders, input }) {
      return new Request(`${origin}/api/auth/link-social`, {
        method: "POST", headers: { ...requestHeaders, cookie: ownerCookie }, body: JSON.stringify(input),
      });
    },
    ...(scenario.invocation === "native" ? { async invokeNative(auth, request) {
      try {
        const result = scenario.callback
          ? await auth.api.callbackOAuth({ method: "GET", params: { id: "google" }, query: Object.fromEntries(new URL(request.url).searchParams), request, headers: request.headers, asResponse: false, returnHeaders: true, returnStatus: true })
          : await auth.api.linkSocialAccount({ body: await request.clone().json(), request, headers: request.headers, asResponse: false, returnHeaders: true, returnStatus: true });
        return { rejected: false, value: observeValue(result.response), status: observeValue(result.status), headers: headers(result.headers) };
      } catch (error) {
        return { rejected: true, error: errorObservation(error, failure) };
      }
    } } : {}),
  };
}

function normalize(value, replacements) {
  if (typeof value === "string") return [...replacements].sort(([left], [right]) => right.length - left.length)
    .reduce((text, [from, to]) => text.replaceAll(from, to), value);
  if (value instanceof Date || value === undefined) return observeValue(value);
  if (Array.isArray(value)) return value.map(child => normalize(child, replacements));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value)
    .map(([key, child]) => [key, normalize(child, replacements)]));
  return value;
}

async function verify({ scenario, before, after, response, body, events, requestWindow, milliseconds, callback, nativeResult }) {
  const replacements = new Map(callback?.replacements);
  const dates = new Map();
  const tokens = new Set();
  const hooks = events.filter(event => event.kind === "hook" && event.model === "account");
  assert.deepEqual(after.user, before.user);
  assert.deepEqual(after.session, before.session);
  assert.deepEqual(after.verification, before.verification);
  assert.equal(before.session.length, 1);
  assert.equal(before.session[0].token, ownerToken);
  for (const row of [...hooks.map(event => event.data), ...after.account]) {
    if (!row) continue;
    for (const field of ["createdAt", "updatedAt"]) {
      if (row[field] === undefined || row[field] === null) continue;
      const instant = milliseconds(row[field]);
      if (instant === Date.parse("2030-01-02T03:04:05.000Z")) continue;
      assert.ok(requestWindow.start <= instant && instant <= requestWindow.end, `account.${field} must originate inside the request`);
      if (dates.has(field)) assert.equal(dates.get(field), instant);
      else dates.set(field, instant);
    }
    if (row.id && !before.account.some(seed => seed.id === row.id)) assert.equal(row.id, "zz-link-account");
    for (const field of ["accessToken", "refreshToken"]) {
      const token = row[field];
      if (token && token !== "user-a" && token !== "user-b") tokens.add(token);
    }
  }
  for (const token of tokens) {
    const plaintext = await symmetricDecrypt({ key: secret, data: token });
    assert.equal(plaintext, scenario.callback ? "callback-access" : "direct-access");
    assert.notEqual(plaintext, token);
    replacements.set(token, "<encrypted-access-token>");
  }
  assert.ok(tokens.size <= 1, "One incoming token must retain one ciphertext through hooks and storage");
  const mutated = scenario.mode === "success" || scenario.mode === "after-error";
  if (!mutated) assert.deepEqual(after.account, before.account);
  else if (scenario.branch === "implicit") assert.equal(after.account.length, before.account.length + 1);
  else assert.equal(after.account.length, before.account.length);
  if (scenario.mode === "before-api" || scenario.mode === "cancel") assert.equal(hooks.some(event => event.phase === "after"), false);
  if (scenario.mode === "after-error") assert.equal(hooks.some(event => event.phase === "after"), true);
  for (const cookie of [...(response?.headers.getSetCookie() ?? []), ...events.flatMap(event => event.cookies ?? [])]) {
    assert.equal(cookie.startsWith("better-auth.account_data="), false);
    assert.equal(cookie.startsWith("better-auth.session_token="), false);
  }
  if (callback) assert.equal(callback.exchanges(), 1);
  if (scenario.invocation === "native") {
    assert.equal(response, undefined);
    assert.equal(nativeResult.rejected, scenario.callback || scenario.mode !== "success");
    if (["lookup-api", "before-api", "after-error"].includes(scenario.mode) && scenario.callback) {
      assert.equal(nativeResult.error.sameObject, true, "Account lookup and write errors must retain their original objects");
    }
    if (scenario.mode.startsWith("admission-")) {
      const location = "http://account-user-auth-boundary.test/api/auth/error?error=validation_failed&error_description=User+validation+failed";
      const cookies = ["better-auth.oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"];
      const expectedHeaders = { entries: [["location", location], ["set-cookie", cookies[0]]], cookies };
      assert.deepEqual(nativeResult.error, {
        sameObject: false, sameBody: false, sameHeaders: false,
        name: "APIError", message: "", status: "FOUND", statusCode: 302,
        body: observeValue(undefined), headers: expectedHeaders, capturedHeaders: expectedHeaders,
      }, "The admission boundary wraps application throws as validation_failed before callback redirection");
    }
    if (!scenario.callback && scenario.mode === "before-api") {
      assert.equal(nativeResult.error.statusCode, 417);
      assert.equal(nativeResult.error.sameObject, false);
    }
  } else assert.equal(nativeResult, undefined);
  const record = (model, row) => {
    if (model !== "account" || row === null) return normalize(row, replacements);
    return Object.fromEntries(Object.entries(row).map(([field, value]) => {
      if (dates.has(field) && value !== undefined && value !== null && milliseconds(value) === dates.get(field)) {
        const label = `<account.${field}>`;
        return [field, value instanceof Date ? { type: "date", value: label } : label];
      }
      return [field, normalize(value, replacements)];
    }));
  };
  return {
    dynamic: {}, replacements, cookie: null, embeddedStrings: true, normalizeRecord: record,
    normalizedBody: body, normalizeHeaders: value => normalize(value, replacements), normalizeCookies: value => normalize(value, replacements),
    checked: { completeStorage: true, completeHookKeys: true, encryptedTokenVerified: tokens.size > 0,
      ownerSessionUnchanged: true, oauthStateAndCodeVerifierVerified: Boolean(callback), nativeInvocation: scenario.invocation === "native" },
  };
}

export async function captureAccountUserAuthLink() {
  const result = await captureAccountUserAuthCases(scenarios, { configure, verify, joins: [false] });
  assert.equal(result.cases.length, 56);
  return result;
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureAccountUserAuthLink(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
