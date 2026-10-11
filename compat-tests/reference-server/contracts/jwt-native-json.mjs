import { expect, test } from "bun:test";
import { compactVerify, exportJWK, generateKeyPair } from "jose";
import { getJwtToken } from "better-auth/plugins/jwt";
import { createCookieCacheSigner } from "../node_modules/better-auth/dist/plugins/jwt/cookie-cache.mjs";
import { signJWT } from "../node_modules/better-auth/dist/plugins/jwt/sign.mjs";

const baseURL = "http://jwt-native-json.test";
const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
const key = {
  id: "native-json-key", alg: "EdDSA", crv: "Ed25519", createdAt: new Date(0),
  publicKey: JSON.stringify(await exportJWK(publicKey)),
  privateKey: JSON.stringify(await exportJWK(privateKey)),
};

function setup(events, user = { id: "owner" }) {
  return {
    ctx: { context: {
      options: { baseURL }, baseURL, adapter: {},
      session: { session: { id: "session", token: "token", userId: "owner" }, user },
      logger: { debug() {} },
    } },
    options: {
      jwks: { disablePrivateKeyEncryption: true },
      adapter: { async getJwks() { events.push("keys"); return [key]; } },
    },
  };
}

async function decoded(token) {
  const result = await compactVerify(token, publicKey);
  const source = new TextDecoder().decode(result.payload);
  return { source, claims: JSON.parse(source), header: result.protectedHeader };
}

test("JWT native Date claims reach JOSE setters before JSON conversion", async () => {
  const events = [];
  const user = {
    id: "owner", iat: new Date(1_700_000_000_999), exp: new Date(1_900_000_000_999),
    nbf: new Date(-1), jti: 0, nativeString: "\ud800",
  };
  const { ctx, options } = setup(events, user);
  const result = await decoded(await getJwtToken(ctx, options));
  expect(result.source).toBe(JSON.stringify({
    iat: 1_700_000_000, id: "owner", exp: 1_900_000_000, nbf: -1,
    jti: 0, nativeString: "\ud800", sub: "owner", iss: baseURL, aud: baseURL,
  }));
  expect(result.header).toStrictEqual({ alg: "EdDSA", kid: key.id });
  expect(events).toStrictEqual(["keys"]);
  expect(user.iat).toBeInstanceOf(Date);
  expect(user.iat.getTime()).toBe(1_700_000_000_999);
  expect(user.exp.getTime()).toBe(1_900_000_000_999);
  expect(user.nbf.getTime()).toBe(-1);
});

for (const cookie of [false, true]) {
  test(`${cookie ? "cookie" : "session"} JWT resolves keys before clone failure without invoking toJSON`, async () => {
    const events = [];
    const native = { toJSON() { events.push("toJSON"); return "converted"; } };
    const { ctx, options } = setup(events, { id: "owner", native });
    let caught;
    try {
      if (cookie) await createCookieCacheSigner(options).sign(ctx, ctx.context.session, 60);
      else await getJwtToken(ctx, options);
    } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(DOMException);
    expect(caught.name).toBe("DataCloneError");
    expect(events).toStrictEqual(["keys"]);
    expect(ctx.context.session.user.native).toBe(native);
  });
}

test("cookie JWT checks the native subject and retains unset sid and untouched claims", async () => {
  const events = [];
  const { ctx, options } = setup(events);
  const signer = createCookieCacheSigner(options);
  const payload = { session: {}, user: { id: new Date(0) }, nbf: "untouched", jti: 17 };
  let caught;
  try { await signer.sign(ctx, payload, 60); } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(TypeError);
  expect(caught.message).toBe('"sub" claim must be a string');
  expect(events).toStrictEqual(["keys"]);
  payload.user = { id: "owner" };
  const started = Math.floor(Date.now() / 1000);
  const result = await decoded(await signer.sign(ctx, payload, 60));
  const finished = Math.floor(Date.now() / 1000);
  expect(result.claims).toStrictEqual({
    session: {}, user: { id: "owner" }, nbf: "untouched", jti: 17,
    iat: result.claims.iat, exp: result.claims.exp, iss: baseURL,
    aud: "better-auth:session-cache", sub: "owner",
  });
  expect(result.claims.iat).toBeGreaterThanOrEqual(started);
  expect(result.claims.iat).toBeLessThanOrEqual(finished);
  expect(result.claims.exp).toBeGreaterThanOrEqual(started + 60);
  expect(result.claims.exp).toBeLessThanOrEqual(finished + 60);
  expect(Object.hasOwn(result.claims, "sid")).toBe(false);
  expect(result.header).toStrictEqual({ alg: "EdDSA", kid: key.id, typ: "better-auth.session-cache+jwt" });
  expect(events).toStrictEqual(["keys", "keys"]);
  expect(payload).toStrictEqual({ session: {}, user: { id: "owner" }, nbf: "untouched", jti: 17 });
});

for (const [claim, value, message] of [
  ["exp", Infinity, "Invalid setExpirationTime input"],
  ["iat", NaN, '"iat" claim must be a finite number'],
  ["nbf", new Date(NaN), "Invalid setNotBefore input"],
]) {
  test(`native JWT ${claim} fails at its JOSE boundary after resolving keys`, async () => {
    const events = [];
    const { ctx, options } = setup(events, { id: "owner", exp: 1_900_000_000, [claim]: value });
    let caught;
    try { await getJwtToken(ctx, options); } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught.message).toBe(message);
    expect(events).toStrictEqual(["keys"]);
    expect(ctx.context.session.user[claim]).toBe(value);
  });
}

test("cookie JWT reads original sid before cloning and original subject after cloning", async () => {
  const events = [];
  const { ctx, options } = setup(events);
  let tokenReads = 0;
  let subjectReads = 0;
  const payload = {
    session: { get token() { events.push("session.token"); return ++tokenReads === 1 ? "sid-token" : "cloned-token"; } },
    user: { get id() { events.push("user.id"); return ++subjectReads === 1 ? "cloned-owner" : "subject-owner"; } },
  };
  const started = Math.floor(Date.now() / 1000);
  const result = await decoded(await createCookieCacheSigner(options).sign(ctx, payload, 60));
  const finished = Math.floor(Date.now() / 1000);
  expect(events).toStrictEqual(["keys", "session.token", "session.token", "user.id", "user.id"]);
  expect(result.claims).toStrictEqual({
    session: { token: "cloned-token" }, user: { id: "cloned-owner" }, sid: "sid-token",
    iat: result.claims.iat, exp: result.claims.exp, iss: baseURL,
    aud: "better-auth:session-cache", sub: "subject-owner",
  });
  expect(result.claims.iat).toBeGreaterThanOrEqual(started);
  expect(result.claims.iat).toBeLessThanOrEqual(finished);
  expect(result.claims.exp).toBeGreaterThanOrEqual(started + 60);
  expect(result.claims.exp).toBeLessThanOrEqual(finished + 60);
  expect(tokenReads).toBe(2);
  expect(subjectReads).toBe(2);
});

test("JOSE checks final native claims before serializing protected header extensions", async () => {
  const events = [];
  const { ctx, options } = setup(events);
  const extension = { toJSON(key) {
    expect(this).toBe(extension);
    expect(key).toBe("extension");
    events.push("header-json");
    return "encoded";
  } };
  let caught;
  try {
    await signJWT(ctx, { options, payload: { iat: NaN, exp: 1_900_000_000 }, header: { extension } });
  } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(TypeError);
  expect(caught.message).toBe('"iat" claim must be a finite number');
  expect(events).toStrictEqual(["keys"]);
  const result = await decoded(await signJWT(ctx, {
    options, payload: { iat: 1_700_000_000, exp: 1_900_000_000 }, header: { extension },
  }));
  expect(result.header).toStrictEqual({ extension: "encoded", alg: "EdDSA", kid: key.id });
  expect(result.source).toBe(JSON.stringify({ iat: 1_700_000_000, exp: 1_900_000_000, iss: baseURL, aud: baseURL }));
  expect(events).toStrictEqual(["keys", "keys", "header-json"]);
});
