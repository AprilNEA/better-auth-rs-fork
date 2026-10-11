import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createAuthMiddleware } from "better-auth/api";
import { symmetricDecrypt } from "better-auth/crypto";
import { captureAccountUserAuthCases } from "./account-user-auth-boundary-capture.mjs";
import { observeValue } from "./device-where-capture.mjs";

const { symmetricDecodeJWT } = await import(new URL("./crypto/jwt.mjs", import.meta.resolve("better-auth")).href);
const cookieFailure = "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.";
const scenarios = [
  ...["existing", "implicit", "new"].flatMap(branch => [
    "success", ...(branch === "existing" ? ["update-disabled", "cancel-before"] : []),
    "raw-before", "raw-after", "cookie-failure",
  ].map(mode => ({ name: `social-order-${branch}-${mode}`, route: "social", relation: "default", branch, mode }))),
  { name: "social-order-existing-callback-raw-after", route: "social", relation: "default", branch: "existing", mode: "raw-after", callback: true },
];

function rawError(mode) {
  return { name: "APIError", status: "CONFLICT", statusCode: 409,
    body: { code: "ORDER_REJECTED", message: "order rejection", details: { phase: mode.slice(4) } },
    headers: { "x-order-error": "1" } };
}

function configure(scenario, options, record) {
  options.advanced.database.generateId = ({ model }) => `zz-order-${model}`;
  Object.assign(options.account, { encryptOAuthTokens: true, storeAccountCookie: true,
    updateAccountOnSignIn: scenario.mode !== "update-disabled" });
  if (scenario.mode === "cookie-failure") options.advanced.cookies = {
    account_data: { attributes: { maxAge: 34_560_001 } },
  };
  const original = options.socialProviders.google.getUserInfo;
  options.socialProviders.google.getUserInfo = async tokens => {
    const result = await original(tokens);
    result.data.sub = scenario.branch === "existing" ? "external-owner" : `external-${scenario.branch}`;
    if (scenario.branch === "new") result.user.email = result.data.email = "fresh@account-user-auth-boundary.test";
    return result;
  };
  const failure = rawError(scenario.mode);
  for (const [model, operations] of Object.entries(options.databaseHooks)) {
    for (const [operation, callbacks] of Object.entries(operations)) {
      for (const phase of ["before", "after"]) callbacks[phase] = (data, context) => {
        record({ kind: "hook-headers", model, operation, phase, cookies: context?.responseHeaders?.getSetCookie() ?? [] });
        record({ kind: "hook", model, operation, phase, keys: data === null ? [] : Object.keys(data), data });
        if (model !== "account" || operation !== (scenario.branch === "existing" ? "update" : "create")) return;
        if (scenario.mode === `raw-${phase}`) throw failure;
        if (scenario.mode === "cancel-before" && phase === "before") return false;
      };
    }
  }
  options.hooks = { after: createAuthMiddleware(async context => {
    record({ kind: "endpoint-after", rawErrorIdentity: context.context.returned === failure,
      cookies: context.context.responseHeaders?.getSetCookie() ?? [] });
  }) };
  options.onAPIError.onError = error => record({ kind: "api-error", error: { name: error.name, message: error.message } });
  return { input(input) { input.idToken.accessToken = "fresh-access"; } };
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

async function verify({ backend, scenario, before, after, response, body, events, requestWindow,
  milliseconds, secret, expiresIn, callback }) {
  const replacements = new Map(callback?.replacements);
  const dates = new Map();
  const hooks = events.filter(event => event.kind === "hook");
  const hook = (model, phase) => hooks.find(event => event.model === model && event.phase === phase)?.data;
  const plaintext = scenario.callback ? "callback-access" : "fresh-access";
  const tokenValues = new Set();
  const activeAccount = after.account.find(row => scenario.branch === "existing" ? row.id === "account-a" : !before.account.some(seed => seed.id === row.id));
  const newUser = after.user.find(row => !before.user.some(seed => seed.id === row.id));
  const issued = hook("session", "before");
  const complete = hook("session", "after");
  const accountBefore = hook("account", "before");
  const accountAfter = hook("account", "after");
  assert.equal(Boolean(issued), ["success", "update-disabled"].includes(scenario.mode));
  assert.equal(Boolean(complete), Boolean(issued));
  assert.equal(after.session.length, issued ? 1 : 0);
  assert.deepEqual(after.verification, before.verification);
  for (const model of ["user", "account", "session"]) {
    const candidates = [...hooks.filter(event => event.model === model).map(event => event.data), ...after[model]];
    for (const row of candidates) {
      if (!row || typeof row !== "object") continue;
      for (const field of ["createdAt", "updatedAt", "expiresAt"]) {
        if (row[field] === undefined || row[field] === null) continue;
        const instant = milliseconds(row[field]);
        if (instant === Date.parse("2030-01-02T03:04:05.000Z")) continue;
        const base = field === "expiresAt" ? instant - expiresIn * 1000 : instant;
        assert.ok(requestWindow.start <= base && base <= requestWindow.end, `${model}.${field} must originate inside the request`);
        const key = `${model}.${field}`;
        if (dates.has(key)) assert.equal(dates.get(key), instant, `${key} must retain the same timestamp across callbacks and storage`);
        else dates.set(key, instant);
      }
      if (model === "account" && row.accessToken && row.accessToken !== "user-b" && row.accessToken !== "user-a") tokenValues.add(row.accessToken);
      if (row.id && !before[model].some(seed => seed.id === row.id)) {
        assert.equal(row.id, `zz-order-${model}`);
        replacements.set(row.id, `<${model}-id>`);
      }
    }
  }
  if (issued) {
    assert.equal(typeof issued.token, "string");
    assert.match(issued.token, /^[A-Za-z0-9]{32}$/);
    assert.equal(complete.token, issued.token);
    assert.equal(after.session[0].token, issued.token);
    assert.equal(issued.userId, scenario.branch === "new" ? newUser.id : "user-a");
    replacements.set(issued.token, "<session-token>");
  }
  for (const model of ["user", "account", "session"]) {
    const created = dates.get(`${model}.createdAt`);
    const updated = dates.get(`${model}.updatedAt`);
    if (created !== undefined && updated !== undefined) assert.ok(created <= updated, `${model} timestamp evaluation order`);
  }
  if (dates.has("user.updatedAt") && dates.has("account.createdAt")) assert.ok(dates.get("user.updatedAt") <= dates.get("account.createdAt"));
  if (issued) {
    if (dates.has("account.updatedAt")) assert.ok(dates.get("account.updatedAt") <= dates.get("session.createdAt"));
    assert.ok(dates.get("session.expiresAt") - expiresIn * 1000 <= dates.get("session.createdAt"));
  }
  const record = (model, row) => {
    if (row === null) return null;
    return Object.fromEntries(Object.entries(row).map(([field, value]) => {
      const instant = dates.get(`${model}.${field}`);
      if (instant !== undefined && value !== undefined && value !== null && milliseconds(value) === instant) {
        const label = `<${model}.${field}>`;
        return [field, value instanceof Date ? { type: "date", value: label } : label];
      }
      return [field, normalize(value, replacements)];
    }));
  };
  const cookies = response.headers.getSetCookie();
  const accountCookies = new Set([...cookies, ...events.flatMap(event => event.cookies ?? [])]
    .filter(cookie => cookie.startsWith("better-auth.account_data=")));
  assert.equal(accountCookies.size, scenario.mode === "cookie-failure" || scenario.branch !== "existing" && scenario.mode.startsWith("raw-") ? 0 : 1);
  const cookiePayloads = [];
  for (const cookie of accountCookies) {
    const separator = cookie.indexOf(";");
    const token = decodeURIComponent(cookie.slice("better-auth.account_data=".length, separator));
    const claims = await symmetricDecodeJWT(token, secret, "better-auth-account");
    assert.ok(claims);
    const { iat, exp, jti, ...account } = claims;
    assert.ok(Number.isInteger(iat) && Math.floor(requestWindow.start / 1000) <= iat && iat <= Math.floor(requestWindow.end / 1000));
    assert.ok(Number.isInteger(exp) && Math.floor(requestWindow.start / 1000) <= exp - 300 && exp - 300 <= Math.floor(requestWindow.end / 1000));
    assert.match(jti, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    if (account.accessToken !== "user-b") tokenValues.add(account.accessToken);
    const expected = scenario.branch === "existing"
      ? { ...before.account.find(row => row.id === "account-a"), ...(scenario.mode === "update-disabled" ? {} : {
        providerId: "google", idToken: "account-user-auth-fixture-id-token", accessToken: account.accessToken,
      }) } : accountAfter;
    assert.deepEqual(account, JSON.parse(JSON.stringify(expected)), "Account Cookie must preserve the entire branch-selected record");
    assert.equal(cookie.slice(separator), "; Max-Age=300; Path=/; HttpOnly; SameSite=Lax");
    cookiePayloads.push({ keys: Object.keys(claims), account: record("account", account), iat: "<cookie.iat>", exp: "<cookie.exp>", jti: "<cookie.jti>" });
    replacements.set(cookie, "better-auth.account_data=<verified-account-cookie>; Max-Age=300; Path=/; HttpOnly; SameSite=Lax");
  }
  for (const token of tokenValues) {
    assert.equal(await symmetricDecrypt({ key: secret, data: token }), plaintext);
    assert.notEqual(token, plaintext);
    replacements.set(token, "<encrypted-access-token>");
  }
  assert.ok(tokenValues.size <= 1, "Cookie and Account write must retain the same encrypted token, without a second encryption");
  const sessionCookies = cookies.filter(cookie => cookie.startsWith("better-auth.session_token="));
  assert.equal(sessionCookies.length, complete ? 1 : 0);
  for (const cookie of sessionCookies) {
    assert.ok(issued && complete);
    const separator = cookie.indexOf(";");
    const signature = createHmac("sha256", secret).update(issued.token).digest("base64");
    assert.equal(cookie.slice(0, separator), `better-auth.session_token=${encodeURIComponent(`${issued.token}.${signature}`)}`);
    assert.equal(cookie.slice(separator), "; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax");
    replacements.set(cookie, `better-auth.session_token=<verified-signed-session-token>${cookie.slice(separator)}`);
  }
  const accountHookCookies = events.filter(event => event.kind === "hook-headers" && event.model === "account");
  for (const event of accountHookCookies) {
    assert.equal(event.cookies.some(cookie => cookie.startsWith("better-auth.account_data=")), scenario.branch === "existing");
  }
  if (scenario.mode === "update-disabled" || scenario.mode === "cancel-before" || scenario.mode === "raw-before" && scenario.branch === "existing" || scenario.mode === "cookie-failure" && scenario.branch === "existing") {
    assert.deepEqual(after.account, before.account);
  }
  if (scenario.mode === "raw-after") assert.ok(accountAfter && activeAccount, "An after-hook error must preserve its completed Account write");
  if (scenario.mode === "cookie-failure" && scenario.branch !== "existing") assert.ok(accountAfter && activeAccount);
  if (scenario.mode === "cancel-before") assert.ok(accountBefore && !accountAfter);
  if (scenario.mode === "cookie-failure" && scenario.branch === "existing") {
    assert.equal(response.status, 500);
    assert.deepEqual(events.filter(event => event.kind === "api-error"), [{ kind: "api-error", error: { name: "Error", message: cookieFailure } }]);
  } else if (scenario.mode.startsWith("raw-") && !scenario.callback) {
    assert.equal(response.status, 409);
    assert.deepEqual(JSON.parse(body), rawError(scenario.mode).body);
    assert.equal(response.headers.get("x-order-error"), "1");
    assert.equal(events.find(event => event.kind === "endpoint-after").rawErrorIdentity, true);
  } else if (issued) assert.equal(response.status, 200);
  else if (!scenario.callback) assert.equal(response.status, 401);
  if (callback) {
    assert.equal(callback.exchanges(), 1);
    assert.equal(response.status, 302);
    assert.match(response.headers.get("location"), /error=ORDER_REJECTED/);
    assert.equal(cookies[0], "better-auth.oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
    assert.ok(cookies[1].startsWith("better-auth.account_data="));
  }
  let normalizedBody = body;
  if (body) {
    const parsed = JSON.parse(body);
    if (parsed.user) parsed.user = record("user", parsed.user);
    normalizedBody = JSON.stringify(normalize(parsed, replacements));
  }
  return { dynamic: {}, replacements: new Map([...replacements].sort(([left], [right]) => right.length - left.length)), cookie: null, embeddedStrings: true, normalizeRecord: record,
    normalizeEvent: event => event.kind === "admission" && scenario.branch === "new"
      ? { ...event, data: { ...event.data, user: record("user", event.data.user) } } : event,
    normalizedBody, normalizeHeaders: headers => normalize(headers, replacements), normalizeCookies: values => normalize(values, replacements),
    observations: { accountCookies: cookiePayloads },
    checked: { noNetwork: true, completeStorage: true, completeHookKeys: true, encryptedTokenVerified: tokenValues.size > 0,
      accountCookieVerified: accountCookies.size > 0, sessionCookieMatchesStoredToken: Boolean(complete),
      oauthStateAndCodeVerifierVerified: Boolean(callback) } };
}

export async function captureAccountUserAuthOrder() {
  const result = await captureAccountUserAuthCases(scenarios, { configure, verify });
  assert.equal(result.cases.length, 60);
  return result;
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureAccountUserAuthOrder(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
