import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import { jwt } from "better-auth/plugins";
import { createJwk, signJWT, toExpJWT } from "better-auth/plugins/jwt";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { getJwksAdapter } from "../node_modules/better-auth/dist/plugins/jwt/adapter.mjs";

expect(JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version).toBe("1.7.6");

const baseURL = "http://jwt-native-options.test";
const context = () => ({ context: { options: { baseURL }, baseURL, adapter: {} } });
const claims = { iat: 10, exp: 2_000_000_000 };

function fixture(options: any, before?: (ctx: any) => void) {
  const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], jwks: [] };
  const auth = betterAuth({
    baseURL, secret: "jwt-native-options-secret-at-least-thirty-two-characters",
    database: memoryAdapter(memory), telemetry: { enabled: false },
    logger: { disabled: true }, rateLimit: { enabled: false },
    hooks: before ? { before: createAuthMiddleware(async ctx => { before(ctx); }) } : undefined,
    plugins: [jwt(options)],
  });
  return { auth, memory };
}

for (const mode of ["empty", "undefined", "sign-undefined", "replacement"]) {
  test(`signJWT before hook replaces the complete jwt options group: ${mode}`, async () => {
    const events: string[] = [];
    const fallback = { fallback: true };
    const token = { replacement: true };
    const replacement = { sign(this: unknown, payload: any) {
      events.push("replacement.sign");
      expect(this).toBe(replacement);
      expect(payload).toStrictEqual({ ...claims, nbf: undefined, iss: baseURL, aud: baseURL });
      return token;
    } };
    const group = mode === "empty" ? {} : mode === "undefined" ? undefined
      : mode === "sign-undefined" ? { sign: undefined } : replacement;
    const { auth, memory } = fixture({
      jwks: { remoteUrl: `${baseURL}/keys`, keyPairConfig: { alg: "EdDSA" } },
      jwt: { sign() { throw new Error("The replaced sign callback must not run"); } },
      adapter: { getJwks() { events.push("fallback.getJwks"); throw fallback; } },
    }, ctx => {
      events.push("before");
      ctx.body.overrideOptions = { jwt: group };
    });
    if (mode === "replacement") {
      const result = await auth.api.signJWT({ body: { payload: claims } });
      expect(result).toStrictEqual({ token });
      expect(result.token).toBe(token);
      expect(events).toStrictEqual(["before", "replacement.sign"]);
    } else {
      let caught: unknown;
      try { await auth.api.signJWT({ body: { payload: claims } }); }
      catch (error) { caught = error; }
      expect(caught).toBe(fallback);
      expect(events).toStrictEqual(["before", "fallback.getJwks"]);
    }
    expect(memory).toStrictEqual({ user: [], session: [], account: [], verification: [], jwks: [] });
  });
}

for (const mode of ["empty", "undefined", "callbacks-undefined", "replacement"]) {
  test(`signJWT before hook replaces the complete adapter options group: ${mode}`, async () => {
    const events: string[] = [];
    let created: any;
    const replacement = {
      getJwks(this: unknown, ctx: any) {
        events.push("replacement.getJwks");
        expect(this).toBe(replacement);
        expect(ctx.context.options.baseURL).toBe(baseURL);
        return [];
      },
      createJwk(this: unknown, key: any, ctx: any) {
        events.push("replacement.createJwk");
        expect(this).toBe(replacement);
        expect(ctx.context.options.baseURL).toBe(baseURL);
        expect(Object.keys(key)).toStrictEqual(["alg", "crv", "publicKey", "privateKey", "createdAt"]);
        created = { ...key, id: "replacement-key" };
        return created;
      },
    };
    const group = mode === "empty" ? {} : mode === "undefined" ? undefined
      : mode === "callbacks-undefined" ? { getJwks: undefined, createJwk: undefined } : replacement;
    const { auth, memory } = fixture({
      jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" }, disablePrivateKeyEncryption: true },
      adapter: {
        getJwks() { throw new Error("The replaced getJwks callback must not run"); },
        createJwk() { throw new Error("The replaced createJwk callback must not run"); },
      },
    }, ctx => {
      events.push("before");
      ctx.body.overrideOptions = { adapter: group };
    });
    const result = await auth.api.signJWT({ body: { payload: claims } });
    expect(Object.keys(result)).toStrictEqual(["token"]);
    expect(typeof result.token).toBe("string");
    expect(memory.jwks).toHaveLength(mode === "replacement" ? 0 : 1);
    const key = mode === "replacement" ? created : memory.jwks[0];
    expect(decodeProtectedHeader(result.token)).toStrictEqual({ alg: "EdDSA", kid: key.id });
    const verified = await jwtVerify(result.token, await importJWK(JSON.parse(key.publicKey), "EdDSA"), {
      currentDate: new Date(1_700_000_000_000), issuer: baseURL, audience: baseURL,
    });
    expect(verified.payload).toStrictEqual({ ...claims, iss: baseURL, aud: baseURL });
    expect(events).toStrictEqual(mode === "replacement"
      ? ["before", "replacement.getJwks", "replacement.getJwks", "replacement.createJwk"]
      : ["before"]);
    for (const name of ["user", "session", "account", "verification"]) expect(memory[name]).toStrictEqual([]);
  });
}

test("signJWT reads populated-claim defaults and rereads the replaced sign receiver after spread", async () => {
  const events: string[] = [];
  const child = { retained: true };
  const header = { retained: child };
  const token = { signed: child };
  const values: Record<string, unknown> = { iat: 10, exp: 70, nbf: undefined, iss: "payload-issuer", aud: child, child };
  const payload = Object.fromEntries(Object.keys(values).map(name => [name, undefined]));
  for (const name of Object.keys(values)) Object.defineProperty(payload, name, { enumerable: true, get() {
    events.push(`payload.${name}`); return values[name];
  } });
  const replacement = { get sign() {
    events.push("sign:2");
    return function(this: unknown, actual: any, actualHeader: any, selection: any) {
      events.push("sign.call");
      expect(this).toBe(replacement);
      expect(actual).toStrictEqual(values);
      expect(actual.aud).toBe(child);
      expect(actual.child).toBe(child);
      expect(actualHeader).toBe(header);
      expect(selection).toStrictEqual({ signingKeyId: "selected-key", signingAlgorithm: undefined });
      return token;
    };
  } };
  let current: any = {
    get expirationTime() { events.push("expirationTime"); return 999; },
    get issuer() { events.push("issuer"); return "unused-issuer"; },
    get audience() { events.push("audience"); return "unused-audience"; },
    get sign() {
      events.push("sign:1"); current = replacement;
      return () => { throw new Error("The first sign value must not be called"); };
    },
  };
  const options = { get jwt() { events.push("jwt"); return current; } };
  const result = await signJWT(context() as any, { options, payload, header, signingKeyId: "selected-key" } as any);
  expect(result).toBe(token);
  expect(events).toStrictEqual([
    "payload.iat", "payload.exp", "jwt", "expirationTime", "payload.nbf", "payload.iss", "jwt", "issuer",
    "payload.aud", "jwt", "audience", "jwt", "sign:1",
    "payload.iat", "payload.exp", "payload.nbf", "payload.iss", "payload.aud", "payload.child",
    "jwt", "sign:2", "sign.call",
  ]);
});

for (const phase of ["expirationTime", "issuer", "audience"]) {
  test(`populated JWT claims do not suppress the ${phase} default getter error`, async () => {
    const events: string[] = [];
    const failure = { phase };
    const options = { jwt: Object.fromEntries(["expirationTime", "issuer", "audience"].map(name => [name, undefined])) };
    for (const name of ["expirationTime", "issuer", "audience"]) Object.defineProperty(options.jwt, name, { get() {
      events.push(name);
      if (name === phase) throw failure;
      return name === "expirationTime" ? 999 : "unused-default";
    } });
    Object.assign(options.jwt, { sign() { throw new Error("Signing must not follow a default getter error"); } });
    let caught: unknown;
    try { await signJWT(context() as any, { options, payload: { ...claims, iss: "present", aud: "present" } } as any); }
    catch (error) { caught = error; }
    expect(caught).toBe(failure);
    expect(events).toStrictEqual(["expirationTime", "issuer", "audience"].slice(0, ["expirationTime", "issuer", "audience"].indexOf(phase) + 1));
  });
}

for (const mode of ["false-zero", "zero-object", "object-false"]) {
  test(`JWT defaults preserve falsy values and object identity: ${mode}`, async () => {
    const native = { retained: true };
    const issuer = mode === "false-zero" ? false : mode === "zero-object" ? 0 : native;
    const audience = mode === "false-zero" ? 0 : mode === "zero-object" ? native : false;
    const result = await signJWT(context() as any, { payload: { iat: 10 }, options: { jwt: {
      issuer, audience, sign: (payload: any) => payload,
    } } } as any);
    expect(result).toStrictEqual({ iat: 10, exp: 910, nbf: undefined, iss: issuer, aud: audience });
    expect((result as any).iss).toBe(issuer);
    expect((result as any).aud).toBe(audience);
  });
}

for (const mode of ["getter", "toJSON"]) {
  test(`custom sign does not inspect unused jwks ${mode}`, async () => {
    const events: string[] = [];
    const token = { signed: true };
    const unused = () => { events.push(`jwks.${mode}`); throw new Error("Unused jwks must not be inspected"); };
    const options: any = { jwt: { sign(payload: any) {
      events.push("sign");
      expect(payload).toStrictEqual({ iat: 10, exp: 910, nbf: undefined, iss: baseURL, aud: baseURL });
      return token;
    } } };
    if (mode === "getter") Object.defineProperty(options, "jwks", { enumerable: true, get: unused });
    else options.jwks = { toJSON: unused };
    expect(await signJWT(context() as any, { options, payload: { iat: 10 } } as any)).toBe(token);
    expect(events).toStrictEqual(["sign"]);
  });
}

test("getLatestKeyByAlg reads keyPairConfig after the custom keyring mutates it", async () => {
  const events: string[] = [];
  const legacy = { id: "legacy", alg: null, createdAt: new Date(20) };
  const older = { id: "older", alg: "ES256", createdAt: new Date(10) };
  const expired = { id: "expired", alg: "ES256", createdAt: new Date(30), expiresAt: new Date(0) };
  let selected = { alg: "EdDSA" };
  const options: any = {
    jwks: { get keyPairConfig() { events.push(`keyPairConfig:${selected.alg}`); return selected; } },
    adapter: { getJwks(this: unknown, ctx: unknown) {
      events.push("getJwks"); expect(this).toBe(options.adapter); expect(ctx).toBe(endpoint);
      selected = { alg: "ES256" };
      return [older, legacy, expired];
    } },
  };
  const endpoint = context();
  expect(await getJwksAdapter({}, options).getLatestKeyByAlg(endpoint, "ES256")).toBe(legacy);
  expect(events).toStrictEqual(["getJwks", "keyPairConfig:ES256"]);
});

test("getJwks endpoint uses the keyPairConfig changed by its custom keyring", async () => {
  const events: string[] = [];
  const options: any = {
    jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
    adapter: { getJwks(this: unknown) {
      events.push("getJwks"); expect(this).toBe(options.adapter);
      options.jwks.keyPairConfig = { alg: "ES256", crv: "P-256" };
      return [{ id: "legacy", publicKey: "{}", createdAt: new Date(0) }];
    } },
  };
  const { auth, memory } = fixture(options);
  expect(await auth.api.getJwks()).toStrictEqual({ keys: [{ alg: "ES256", crv: "P-256", kid: "legacy" }] });
  expect(events).toStrictEqual(["getJwks"]);
  expect(memory.jwks).toStrictEqual([]);
});

test("JWT expiration retains native number, Date method and string addition semantics", async () => {
  for (const number of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) expect(toExpJWT(number, 10)).toBe(number);
  const events: string[] = [];
  const expiration = Object.defineProperty(new Date(0), "getTime", { get() {
    events.push("getTime.get");
    return function(this: unknown) {
      events.push("getTime.call"); expect(this).toBe(expiration);
      return { valueOf() { events.push("milliseconds.valueOf"); return "12345"; } };
    };
  } });
  expect(toExpJWT(expiration, 10)).toBe(12);
  expect(events).toStrictEqual(["getTime.get", "getTime.call", "milliseconds.valueOf"]);
  events.length = 0;
  const duration = { toString() { events.push("duration.toString"); return "2 seconds"; } };
  const audience = { native: true };
  const result = await signJWT(context() as any, {
    payload: { iat: "10" }, options: { jwt: {
      expirationTime: duration, issuer: false, audience,
      sign(payload: any) { events.push("sign"); return payload; },
    } },
  } as any);
  expect(result).toStrictEqual({ iat: "10", exp: "102", nbf: undefined, iss: false, aud: audience });
  expect((result as any).aud).toBe(audience);
  expect(events).toStrictEqual(["duration.toString", "sign"]);
});

test("invalid expiration stringification preserves the second conversion failure", () => {
  const events: string[] = [];
  const failure = { conversion: true };
  const duration = { toString() {
    events.push("toString");
    if (events.length === 2) throw failure;
    return "invalid-duration";
  } };
  let caught: unknown;
  try { toExpJWT(duration as any, 10); } catch (error) { caught = error; }
  expect(caught).toBe(failure);
  expect(events).toStrictEqual(["toString", "toString"]);
});

for (const mode of ["zero", "nan", "string-zero", "object", "negative", "failure"]) {
  test(`JWK rotation preserves truthiness, repeated reads and native multiplication: ${mode}`, async () => {
    const events: string[] = [];
    const failure = { rotation: true };
    const token = { created: true };
    const originalNow = Date.now;
    let reads = 0;
    const value = mode === "zero" ? 0 : mode === "nan" ? Number.NaN : mode === "string-zero" ? "0"
      : mode === "negative" ? -2 : { valueOf() {
        events.push("rotation.valueOf");
        if (mode === "failure") throw failure;
        return "2";
      } };
    const options: any = {
      jwks: {
        keyPairConfig: { alg: "EdDSA", crv: "Ed25519" }, disablePrivateKeyEncryption: true,
        get rotationInterval() { events.push(`rotation:${++reads}`); return value; },
      },
      adapter: { createJwk(this: unknown, key: any, ctx: unknown) {
        events.push("createJwk"); expect(this).toBe(options.adapter); expect(ctx).toBe(endpoint);
        const expiring = mode !== "zero" && mode !== "nan";
        expect(Object.keys(key)).toStrictEqual(["alg", "crv", "publicKey", "privateKey", "createdAt", ...(expiring ? ["expiresAt"] : [])]);
        expect(key.createdAt).toBeInstanceOf(Date);
        if (expiring) expect(key.expiresAt.getTime()).toBe(mode === "negative" ? -1000 : mode === "string-zero" ? 1000 : 3000);
        return token;
      } },
    };
    const endpoint = context();
    Date.now = () => { events.push("clock"); return 1000; };
    try {
      if (mode === "failure") {
        let caught: unknown;
        try { await createJwk(endpoint as any, options); } catch (error) { caught = error; }
        expect(caught).toBe(failure);
        expect(events).toStrictEqual(["rotation:1", "clock", "rotation:2", "rotation.valueOf"]);
      } else {
        expect(await createJwk(endpoint as any, options)).toBe(token);
        expect(events).toStrictEqual(mode === "zero" || mode === "nan" ? ["rotation:1", "createJwk"]
          : ["rotation:1", "clock", "rotation:2", ...(mode === "object" ? ["rotation.valueOf"] : []), "createJwk"]);
      }
    } finally { Date.now = originalNow; }
  });
}
