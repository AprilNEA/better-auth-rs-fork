import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { resolveOAuthAccountKey } from "../node_modules/better-auth/dist/oauth2/account-key.mjs";
import { observeValue } from "./device-where-capture.mjs";
import { email, origin, secret, tables, timestamp } from "./oauth-native-profile-values.mjs";

const accessToken = "native-profile-access";
const idToken = "native-profile-id-token";
const cookiePairs = headers => headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");

function rememberRandom(state, value, label) {
  assert.equal(typeof value, "string");
  assert.ok(value.length > 0, `${label} must be present`);
  state.replacements.set(value, `<${label}>`);
}

export async function setup(state) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const generated = new Map();
  const scenario = state.scenario;
  const providerId = scenario.provider === "generic" ? "generic" : "google";
  const generic = {
    providerId, clientId: "client", authorizationUrl: "https://provider.example.test/authorize",
    async getToken(input) {
      rememberRandom(state, input.codeVerifier, "code-verifier");
      state.record({ kind: "token", input: observeValue(input) });
      return { accessToken, scopes: ["profile"] };
    },
    async getUserInfo(tokens) {
      state.record({ kind: "get-user-info", tokens: observeValue(tokens) });
      return state.raw;
    },
    async mapProfileToUser(raw) {
      state.mapperInput = raw;
      state.record({ kind: "mapper", sameProfile: raw === state.raw });
      if (scenario.shape === "mapper-error") throw state.failure;
      if (scenario.shape === "identity") raw.mapperMarker = state.marker;
      return state.mapped;
    },
    async accountSubject({ profile, tokens }) {
      state.subjectInput = profile;
      state.record({ kind: "generic-subject", sameProfile: profile === state.raw, tokens: observeValue(tokens) });
      if (scenario.operation === "account-info") throw state.failure;
      if (scenario.shape === "identity") {
        assert.equal(profile.mapperMarker, state.marker);
        profile.subjectMarker = state.marker;
        return 23;
      }
      return profile.id;
    },
  };
  const social = {
    clientId: "client", clientSecret: "secret",
    async verifyIdToken(token, nonce, context) {
      state.record({ kind: "verify", token, nonce, path: context.path });
      return true;
    },
    async getUserInfo(tokens) {
      state.record({ kind: "get-user-info", tokens: observeValue(tokens) });
      return state.socialResponse;
    },
    async mapProfileToUser() {
      state.record({ kind: "unexpected-social-mapper" });
      throw state.failure;
    },
  };
  const options = {
    baseURL: origin, secret, database: memoryAdapter(memory),
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    advanced: { database: { generateId({ model }) {
      const next = (generated.get(model) ?? 0) + 1;
      generated.set(model, next);
      return `${model}-${next}`;
    } } },
    account: { storeStateStrategy: "database" },
    user: {
      additionalFields: { profileExtra: { type: "json", required: false } },
      validateUserInfo(data, context) {
        const profile = data.source.oauth?.profile;
        state.admissions.push(data);
        state.record({ kind: "admission", path: context.path, action: data.source.action,
          method: data.source.method, providerId: data.source.oauth?.providerId,
          sameProfile: profile === state.raw, sameMapperProfile: profile === state.mapperInput,
          sameSubjectProfile: profile === state.subjectInput, user: observeValue(data.user) });
        if (scenario.shape === "identity") {
          assert.equal(profile, state.mapperInput);
          assert.equal(profile, state.subjectInput);
          assert.equal(profile.subjectMarker, state.marker);
          profile.admissionMarker = state.marker;
        }
      },
    },
    databaseHooks: Object.fromEntries(["user", "account", "session"].map(model => [model, {
      create: {
        before(data) {
          if (model === "session") {
            rememberRandom(state, data.token, "session-token");
            state.sessionToken = data.token;
          }
          state.record({ kind: "hook", model, phaseInHook: "before", data: observeValue(data) });
        },
        after(data) { state.record({ kind: "hook", model, phaseInHook: "after", data: observeValue(data) }); },
      },
    }])),
    ...(scenario.provider === "generic" ? { plugins: [genericOAuth({ config: [generic] })] }
      : { socialProviders: { google: social } }),
  };
  const auth = betterAuth(options);
  const context = await auth.$context;
  const provider = context.socialProviders.find(value => value.id === providerId);
  assert.ok(provider);
  const get = provider.getUserInfo.bind(provider);
  provider.getUserInfo = async tokens => {
    const response = await get(tokens);
    state.info = response;
    return response;
  };
  const subject = provider.accountSubject.bind(provider);
  provider.accountSubject = input => {
    state.subjectInput = input.profile;
    state.record({ kind: "subject", sameProfile: input.profile === state.raw, tokens: observeValue(input.tokens) });
    return subject(input);
  };
  if (scenario.operation === "account-info") {
    const date = new Date(timestamp);
    memory.user.push({ id: "owner", name: "Stored User", email, emailVerified: true, image: null, createdAt: date, updatedAt: date });
    memory.account.push({ id: "stored-account", userId: "owner", providerId, accountId: "stored-provider-id",
      accessToken, refreshToken: null, idToken: null, accessTokenExpiresAt: null, refreshTokenExpiresAt: null,
      scope: "profile", password: null, createdAt: date, updatedAt: date });
  }
  state.events.length = 0;
  return { auth, context, provider, providerId, memory };
}

export async function invoke(sample, state) {
  const { auth, provider, providerId } = sample;
  const operation = state.scenario.operation;
  if (operation === "helper") {
    const tokens = { accessToken };
    const info = await provider.getUserInfo(tokens);
    const accountKey = await resolveOAuthAccountKey(provider, tokens, info.data);
    return { kind: "native", value: { info, accountKey } };
  }
  if (operation === "account-info") {
    const result = await auth.api.accountInfo({ query: { accountId: "stored-account", userId: "owner" }, returnHeaders: true });
    return { kind: "native", value: result.response, headers: result.headers };
  }
  const headers = new Headers({ origin, "user-agent": "native-profile-contract" });
  if (operation === "direct") {
    const result = await auth.api.signInSocial({ headers, returnHeaders: true, body: {
      provider: providerId, idToken: { token: idToken, nonce: "native-profile-nonce", accessToken },
    } });
    return { kind: "native", value: result.response, headers: result.headers };
  }
  assert.equal(operation, "callback");
  const start = await auth.api.signInSocial({ headers, returnHeaders: true, body: {
    provider: providerId, callbackURL: `${origin}/complete`, errorCallbackURL: `${origin}/failed`, disableRedirect: true,
  } });
  const stateId = new URL(start.response.url).searchParams.get("state");
  rememberRandom(state, stateId, "oauth-state");
  headers.set("cookie", cookiePairs(start.headers));
  const response = await auth.api.callbackOAuth({
    headers, asResponse: true, params: { id: providerId }, query: { code: "native-profile-code", state: stateId },
  });
  return { kind: "http", status: response.status, text: await response.text(), headers: response.headers };
}

export function observeHeaders(headers, state) {
  if (!headers) return null;
  const cookies = headers.getSetCookie();
  let sessionPair;
  for (const cookie of cookies) {
    const separator = cookie.indexOf(";");
    const pair = separator < 0 ? cookie : cookie.slice(0, separator);
    if (!pair.startsWith("better-auth.session_token=")) {
      assert.ok(pair.endsWith("="), `Only empty state cookies may accompany the Session cookie: ${pair}`);
      continue;
    }
    assert.equal(typeof state.sessionToken, "string");
    const signature = createHmac("sha256", secret).update(state.sessionToken).digest("base64");
    assert.equal(pair, `better-auth.session_token=${encodeURIComponent(`${state.sessionToken}.${signature}`)}`);
    sessionPair = pair;
    state.replacements.set(cookie, `better-auth.session_token=<verified-session-token>${separator < 0 ? "" : cookie.slice(separator)}`);
  }
  const entries = [...headers.entries()].map(([name, value]) => [name,
    name === "set-cookie" && sessionPair ? value.replaceAll(sessionPair, "better-auth.session_token=<verified-session-token>") : value,
  ]);
  return { entries, cookies };
}

export async function withProviderFetch(state, run) {
  const original = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    assert.equal(state.scenario.provider, "social");
    assert.equal(request.url, "https://oauth2.googleapis.com/token");
    assert.equal(request.method, "POST");
    const body = Object.fromEntries(new URLSearchParams(await request.text()));
    assert.equal(body.code, "native-profile-code");
    rememberRandom(state, body.code_verifier, "code-verifier");
    state.record({ kind: "token-http", url: request.url, method: request.method, headers: [...request.headers], body });
    return Response.json({ access_token: accessToken, id_token: idToken, scope: "profile", expires_in: 3600 });
  }, original);
  try { return await run(); }
  finally { globalThis.fetch = original; }
}
