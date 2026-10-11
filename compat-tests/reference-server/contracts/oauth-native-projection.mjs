import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { symmetricEncrypt } from "better-auth/crypto";
import { oneTap, oAuthProxy } from "better-auth/plugins";
import { getCurrentAuthEndpointContext } from "@better-auth/core/context";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const origin = "http://oauth-projection.test";
const callbackURL = `${origin}/complete`;
const secret = "oauth-projection-contract-secret-at-least-thirty-two-characters";
const email = "owner@oauth-projection.test";
const image = "https://images.example.test/owner.png";
const flows = ["direct", "one-tap", "callback", "proxy"];
const returnsUser = flow => flow === "direct" || flow === "one-tap";

async function signedGoogle(run) {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "oauth-projection-contract" };
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    sub: "projection-owner", email, email_verified: true, name: "Projection Owner", picture: image,
    nonce: "projection-nonce", iss: "https://accounts.google.com", aud: "client", iat: now, exp: now + 3600,
  }).setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
  const original = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    if (request.url === "https://www.googleapis.com/oauth2/v3/certs") return Response.json({ keys: [jwk] });
    assert.equal(request.url, "https://oauth2.googleapis.com/token");
    assert.equal(request.method, "POST");
    return Response.json({ id_token: token, access_token: "normal-access", expires_in: 3600 });
  }, original);
  try { await run(token); }
  finally { globalThis.fetch = original; }
}

function setup({ field, cache, mutation, getters = false }) {
  const database = { user: [], account: [], session: [], verification: [] };
  let endpoint;
  let functionCalls = 0;
  let versions = 0;
  const getterEvents = [];
  const replacement = mutation === "function" ? () => { functionCalls += 1; }
    : "After cookie payload";
  const declaration = {
    type: "string", required: false, returned: false,
    transform: { output: () => () => { functionCalls += 1; } },
  };
  const getterDeclaration = model => ({
    type: "string", required: false, returned: false,
    transform: { output: () => ({ get value() {
      const context = getCurrentAuthEndpointContext();
      getterEvents.push({
        model,
        cookie: context.responseHeaders.getSetCookie().some(value => value.startsWith("better-auth.session_token=")),
        snapshot: Boolean(context.context.newSession),
      });
      return model;
    } }) },
  });
  const auth = betterAuth({
    baseURL: origin, secret, database: memoryAdapter(database),
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    socialProviders: { google: { clientId: "client", clientSecret: "secret" } },
    user: getters ? { additionalFields: { image: getterDeclaration("user") } }
      : field === "user" ? { additionalFields: { image: declaration } } : undefined,
    session: {
      ...(getters ? { additionalFields: { userAgent: getterDeclaration("session") } }
        : field === "session" ? { additionalFields: { userAgent: declaration } } : {}),
      cookieCache: {
        enabled: cache,
        version(session, user) {
          versions += 1;
          if (getters) getterEvents.push("version");
          if (mutation) user.name = replacement;
          return "projection";
        },
      },
    },
    databaseHooks: { session: { create: { after() { endpoint = getCurrentAuthEndpointContext(); } } } },
    plugins: [oneTap({ clientId: "client" }), oAuthProxy({ currentURL: origin, productionURL: origin })],
  });
  return {
    auth, database, replacement, getterEvents,
    get endpoint() { assert.ok(endpoint, "Session creation must precede OAuth output"); return endpoint; },
    get functionCalls() { return functionCalls; },
    get versions() { return versions; },
  };
}

async function invoke(flow, sample, token) {
  const { auth } = sample;
  const headers = new Headers({ "user-agent": "oauth-projection-contract" });
  if (returnsUser(flow)) return flow === "direct"
    ? auth.api.signInSocial({ headers, returnHeaders: true, body: {
      provider: "google", idToken: { token, nonce: "projection-nonce" },
    } })
    : auth.api.oneTapCallback({ headers, returnHeaders: true, body: { idToken: token } });
  const start = await auth.api.signInSocial({ headers, returnHeaders: true, body: {
    provider: "google", callbackURL, disableRedirect: true,
  } });
  const state = new URL(start.response.url).searchParams.get("state");
  assert.ok(state);
  headers.set("cookie", start.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; "));
  if (flow === "callback") return auth.api.callbackOAuth({
    headers, asResponse: true, params: { id: "google" }, query: { code: "projection-code", state },
  });
  const profile = await symmetricEncrypt({ key: secret, data: JSON.stringify({
    userInfo: { id: "projection-owner", email, emailVerified: true, name: "Projection Owner", image },
    account: { accountId: "projection-owner", providerId: "google" },
    state, callbackURL, timestamp: Date.now(),
  }) });
  return auth.api.oAuthProxy({ headers, asResponse: true, query: { callbackURL, profile } });
}

function assertStorage(sample) {
  const { database } = sample;
  for (const model of ["user", "account", "session"]) assert.equal(database[model].length, 1, model);
  assert.equal(database.verification.length, 0);
  const [user] = database.user;
  const [session] = database.session;
  const [account] = database.account;
  assert.equal(user.name, "Projection Owner");
  assert.equal(user.image, image);
  assert.equal(user.email, email);
  assert.equal(account.accountId, "projection-owner");
  assert.equal(account.providerId, "google");
  assert.equal(account.userId, user.id);
  assert.equal(session.userId, user.id);
  assert.equal(session.userAgent, "oauth-projection-contract");
  const cookies = sample.endpoint.responseHeaders.getSetCookie().map(value => {
    const pair = value.split(";", 1)[0];
    const split = pair.indexOf("=");
    return [pair.slice(0, split), decodeURIComponent(pair.slice(split + 1))];
  });
  const token = cookies.find(([name]) => name === "better-auth.session_token");
  assert.ok(token, "Session token cookie must precede public projection");
  assert.equal(token[1], `${session.token}.${createHmac("sha256", secret).update(session.token).digest("base64")}`);
  return { user, session, cookies };
}

function assertResponse(flow, response, user, session, hideImage = false) {
  if (returnsUser(flow)) {
    const publicUser = structuredClone(user);
    if (hideImage) delete publicUser.image;
    const expected = flow === "direct"
      ? { redirect: false, token: session.token, url: undefined, user: publicUser }
      : { token: session.token, user: publicUser };
    assert.deepEqual(response.response, expected);
    assert.deepEqual(Object.keys(response.response), Object.keys(expected));
  } else {
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), callbackURL);
  }
}

test("native clone failures preserve OAuth cookie, snapshot, and persistence order", async () => {
  await signedGoogle(async token => {
    for (const flow of flows) for (const field of ["session", "user"]) for (const cache of [false, true]) {
      const sample = setup({ field, cache });
      let response;
      let error;
      try { response = await invoke(flow, sample, token); }
      catch (caught) { error = caught; }
      const { user, session, cookies } = assertStorage(sample);
      assert.ok(cookies.every(([name]) => name !== "better-auth.session_data"));
      assert.equal(Boolean(sample.endpoint.context.newSession), !cache, `${flow}/${field}/${cache}`);
      if (cache || field === "user" && returnsUser(flow)) {
        assert.ok(error instanceof DOMException, `${flow}/${field}/${cache}: ${error}`);
        assert.equal(error.name, "DataCloneError");
      } else {
        assert.equal(error, undefined);
        assertResponse(flow, response, user, session, field === "user");
      }
      assert.equal(sample.functionCalls, 0);
      assert.equal(sample.versions, 0);
    }
  });
});

test("cookie version mutation is visible only to later OAuth User projection", async () => {
  await signedGoogle(async token => {
    for (const flow of flows) for (const mutation of ["string", "function"]) {
      const sample = setup({ cache: true, mutation });
      let response;
      let error;
      try { response = await invoke(flow, sample, token); }
      catch (caught) { error = caught; }
      const { user, session, cookies } = assertStorage(sample);
      const cache = cookies.find(([name]) => name === "better-auth.session_data");
      assert.ok(cache, "Cookie cache must precede OAuth public User projection");
      const payload = JSON.parse(Buffer.from(cache[1], "base64url").toString("utf8"));
      assert.equal(payload.session.user.name, "Projection Owner");
      assert.equal(sample.endpoint.context.newSession.user.name, sample.replacement);
      assert.equal(sample.versions, 1);
      if (mutation === "function" && returnsUser(flow)) {
        assert.ok(error instanceof DOMException, `${flow}: ${error}`);
        assert.equal(error.name, "DataCloneError");
      } else {
        assert.equal(error, undefined);
        assertResponse(flow, response, { ...user, name: sample.replacement }, session);
      }
      assert.equal(sample.functionCalls, 0);
    }
  });
});

test("OAuth getter clones observe cookie and issuance boundaries in upstream order", async () => {
  await signedGoogle(async token => {
    for (const flow of flows) for (const cache of [false, true]) {
      const sample = setup({ cache, getters: true });
      const response = await invoke(flow, sample, token);
      const { user, session } = assertStorage(sample);
      const expected = cache ? [
        { model: "session", cookie: true, snapshot: false },
        { model: "user", cookie: true, snapshot: false },
        "version",
      ] : [];
      if (returnsUser(flow)) expected.push({ model: "user", cookie: true, snapshot: true });
      assert.deepEqual(sample.getterEvents, expected, `${flow}/${cache}`);
      assertResponse(flow, response, user, session, true);
      assert.ok(sample.endpoint.context.newSession);
    }
  });
});
