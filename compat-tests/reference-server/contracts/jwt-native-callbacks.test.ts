import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { getJwtToken, signJWT } from "better-auth/plugins/jwt";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { jwt } from "better-auth/plugins";
import * as z from "zod";
import { expectStandaloneCapture } from "./standalone-capture";

for (const name of ["better-auth", "@better-auth/core"]) {
  expect(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version).toBe("1.7.6");
}
const baseURL = "http://jwt-native-callbacks.test";
const context = (session: unknown) => ({ context: { session, options: { baseURL }, baseURL, adapter: {} } });

test("JWT callbacks retain one root, observe replacement, and sample the clock at both signing boundaries", async () => {
  const events: string[] = [];
  const oldUser = { id: "old" };
  const child = { retained: true };
  const user = { id: "replacement", child, iat: undefined };
  const root = { session: { token: "before" }, user: oldUser, extra: child };
  const result = { signed: true };
  const originalNow = Date.now;
  let reads = 0;
  Date.now = () => { events.push("clock"); return [1_700_000_000_123, 1_700_000_005_999][reads++]; };
  try {
    const token = await getJwtToken(context(root) as any, { jwt: {
      async definePayload(data: any) {
        events.push("payload");
        expect(data).toBe(root);
        expect(data.extra).toBe(child);
        data.session.token = "after";
        data.user = user;
        return user;
      },
      async getSubject(data: any) {
        events.push("subject");
        expect(data).toBe(root);
        expect(data.user).toBe(user);
        data.user.id = "final";
        return null;
      },
      async sign(payload: any, header: any, selection: any) {
        events.push("sign");
        expect(payload).toStrictEqual({ id: "replacement", child, iat: undefined, sub: "final", exp: 1_700_000_905, nbf: undefined, iss: baseURL, aud: baseURL });
        expect(payload.child).toBe(child);
        expect(Object.keys(payload)).toStrictEqual(["iat", "id", "child", "sub", "exp", "nbf", "iss", "aud"]);
        expect(header).toBeUndefined();
        expect(Object.keys(selection)).toStrictEqual(["signingKeyId", "signingAlgorithm"]);
        expect(selection).toStrictEqual({ signingKeyId: undefined, signingAlgorithm: undefined });
        return result;
      },
    } } as any);
    expect(token).toBe(result);
    expect(root.session.token).toBe("after");
    expect(root.user).toBe(user);
    expect(oldUser.id).toBe("old");
    expect(events).toStrictEqual(["payload", "clock", "subject", "clock", "sign"]);
    expect(reads).toBe(2);
  } finally { Date.now = originalNow; }
});

for (const subject of [undefined, null, false, 0, ""]) {
  test(`JWT subject uses nullish fallback: ${String(subject)}`, async () => {
    const root = { session: {}, user: { id: "owner" } };
    const token = await getJwtToken(context(root) as any, { jwt: {
      getSubject: async (data: any) => { expect(data).toBe(root); return subject; },
      sign: async (payload: any) => payload.sub,
    } } as any);
    expect(token).toBe(subject ?? "owner");
  });
}

for (const phase of ["payload", "spread", "subject", "sign"]) {
  test(`JWT callback failure keeps identity and completed mutations: ${phase}`, async () => {
    const events: string[] = [];
    const failure = { phase };
    const root = { session: {}, user: { id: "owner" }, changed: false };
    const originalNow = Date.now;
    Date.now = () => { events.push("clock"); return 1_700_000_000_000; };
    try {
      const payload = Object.defineProperty({}, "value", { enumerable: true, get() {
        events.push("spread");
        if (phase === "spread") throw failure;
        return true;
      } });
      let caught;
      try { await getJwtToken(context(root) as any, { jwt: {
        definePayload: async (data: any) => { events.push("payload"); data.changed = true; if (phase === "payload") throw failure; return payload; },
        getSubject: async () => { events.push("subject"); if (phase === "subject") throw failure; return "owner"; },
        sign: async () => { events.push("sign"); throw failure; },
      } } as any); } catch (error) { caught = error; }
      expect(caught).toBe(failure);
      expect(root.changed).toBe(true);
      const order = ["payload", "clock", "spread", "subject", "clock", "sign"];
      expect(events).toStrictEqual(order.slice(0, order.indexOf(phase) + 1));
    } finally { Date.now = originalNow; }
  });
}

test("signJWT reads defaults before spread and preserves cached values, native leaves and its return value", async () => {
  const events: string[] = [];
  const child = { leaf: true };
  const values: Record<string, any> = { iat: 10, exp: null, nbf: undefined, iss: null, aud: undefined, child };
  const counts = new Map<string, number>();
  const payload = Object.fromEntries(Object.keys(values).map(name => [name, undefined]));
  for (const name of Object.keys(values)) Object.defineProperty(payload, name, { enumerable: true, get() {
    events.push(name);
    counts.set(name, (counts.get(name) ?? 0) + 1);
    return name === "iat" && counts.get(name) === 2 ? 20 : values[name];
  } });
  const result = { signed: true };
  const token = await signJWT(context(null) as any, { payload, options: { jwt: { sign: async (claims: any) => {
    expect(claims).toStrictEqual({ iat: 10, exp: 910, nbf: undefined, iss: baseURL, aud: baseURL, child });
    expect(claims.child).toBe(child);
    return result;
  } } } } as any);
  expect(token).toBe(result);
  expect(events).toStrictEqual(["iat", "exp", "nbf", "iss", "aud", "iat", "exp", "nbf", "iss", "aud", "child"]);
});

test("native signJWT endpoint clones the validated record and retains its leaf identities and undefined values", async () => {
  const child = { retained: true };
  const payload = { child, absent: undefined };
  const token = { native: true };
  let calls = 0;
  const auth = betterAuth({
    baseURL, secret: "jwt-native-callbacks-secret-at-least-thirty-two-characters",
    database: memoryAdapter({ user: [], session: [], account: [], verification: [], jwks: [] }),
    telemetry: { enabled: false }, logger: { disabled: true }, rateLimit: { enabled: false },
    plugins: [jwt({ jwks: { remoteUrl: `${baseURL}/keys`, keyPairConfig: { alg: "EdDSA" } }, jwt: { sign: async (claims, header, selection) => {
      calls++;
      expect(claims).not.toBe(payload);
      expect(claims.child).toBe(child);
      expect(Object.hasOwn(claims, "absent")).toBe(true);
      expect(header).toBeUndefined();
      expect(selection).toStrictEqual({ signingKeyId: undefined, signingAlgorithm: undefined });
      return token as any;
    } } })],
  });
  const result = await auth.api.signJWT({ body: { payload } });
  expect(result.token).toBe(token);
  expect(payload).toStrictEqual({ child, absent: undefined });
  expect(calls).toBe(1);
});


test("JWT native Session retains the existing complete 34-case frozen capture", async () => {
  await expectStandaloneCapture(
    new URL("./jwt-native-session-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/jwt-native-session-1.7.6.json", import.meta.url),
  );
}, 120_000);

test("Zod record validation reads constructor before keys and skips __proto__ before its getter", () => {
  const events: string[] = [];
  const child = { retained: true };
  const input = Object.defineProperties({}, {
    constructor: { get() { events.push("constructor"); return undefined; } },
    ["__proto__"]: { enumerable: true, get() { throw new Error("Skipped __proto__ must not be read"); } },
    hidden: { get() { throw new Error("Hidden fields must not be read"); } },
    value: { enumerable: true, get() { events.push("value"); return child; } },
  });
  expect(Object.getOwnPropertyNames(input)).toStrictEqual(["constructor", "__proto__", "hidden", "value"]);
  const result = z.record(z.string(), z.any()).parse(input);
  expect(result).toStrictEqual({ value: child });
  expect(result.value).toBe(child);
  expect(events).toStrictEqual(["constructor", "value"]);
  const body = Object.assign(new Date(0), { payload: { child } });
  const parsed = z.object({ payload: z.record(z.string(), z.any()) }).parse(body);
  expect(parsed.payload.child).toBe(child);
  expect(z.record(z.string(), z.any()).safeParse(new Date(0)).success).toBe(false);
  expect(z.record(z.string(), z.any()).parse(Object.assign(new Date(0), { constructor: undefined, child }))).toStrictEqual({ constructor: undefined, child });
});
