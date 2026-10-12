import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { compactVerify, exportJWK, generateKeyPair } from "jose";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { jwt } from "better-auth/plugins";
import { getJwksAdapter } from "../node_modules/better-auth/dist/plugins/jwt/adapter.mjs";
import { signJWT } from "../node_modules/better-auth/dist/plugins/jwt/sign.mjs";

for (const name of ["better-auth", "@better-auth/core"]) {
  expect(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version).toBe("1.7.6");
}

const baseURL = "http://jwk-native-date.test";
const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
const key = {
  id: "key", alg: "EdDSA", createdAt: new Date(0),
  publicKey: JSON.stringify(await exportJWK(publicKey)),
  privateKey: JSON.stringify(await exportJWK(privateKey)),
};
type Events = [string, string][];

function returnedNumber(label: string, number: number, failure: Error | undefined, events: Events) {
  return {
    label,
    valueOf(...args: unknown[]) {
      expect(this.label).toBe(label);
      expect(args).toStrictEqual([]);
      events.push([label, "valueOf"]);
      if (failure) throw failure;
      return number;
    },
  };
}

function timeMethod(label: string, result: unknown, events: Events) {
  return {
    label,
    getTime(...args: unknown[]) {
      expect(this.label).toBe(label);
      expect(args).toStrictEqual([]);
      events.push([label, "getTime"]);
      return result;
    },
  };
}

function expectSubtraction(events: Events, failure = false) {
  expect(events.map(([, method]) => method)).toStrictEqual(failure
    ? ["getTime", "getTime", "valueOf"]
    : ["getTime", "getTime", "valueOf", "valueOf"]);
  expect(events[0][0]).not.toBe(events[1][0]);
  expect(events[2][0]).toBe(events[0][0]);
  if (!failure) expect(events[3][0]).toBe(events[1][0]);
}

for (const signingAlgorithm of [undefined, "EdDSA"]) {
  test(`JWK signing calls both getTime methods before subtraction: ${signingAlgorithm ?? "default"}`, async () => {
    const events: Events = [];
    const rows = [
      { ...key, id: "older", createdAt: timeMethod("older", returnedNumber("older", 1, undefined, events), events) },
      { ...key, id: "newer", createdAt: timeMethod("newer", returnedNumber("newer", 2, undefined, events), events) },
    ];
    const before = rows.map(row => ({ ...row }));
    let reads = 0;
    const ctx = { context: { options: { baseURL }, baseURL, adapter: {} } };
    const options = {
      jwks: { disablePrivateKeyEncryption: true },
      adapter: { async getJwks() { reads++; return rows; } },
    };
    const token = await signJWT(ctx, { options, payload: { sub: "owner" }, signingAlgorithm });
    const verified = await compactVerify(token, publicKey);
    expect(verified.protectedHeader).toStrictEqual({ alg: "EdDSA", kid: "newer" });
    expect(JSON.parse(new TextDecoder().decode(verified.payload)).sub).toBe("owner");
    expect(reads).toBe(1);
    expectSubtraction(events);
    expect(rows).toStrictEqual(before);
  });
}

for (const algorithm of [undefined, "EdDSA"]) {
  test(`JWK selection calls both getTime methods before failed coercion: ${algorithm ?? "any"}`, async () => {
    const events: Events = [];
    const failure = new TypeError("JWK time conversion failed");
    const rows = [
      { ...key, id: "older", createdAt: timeMethod("older", returnedNumber("older", 1, failure, events), events) },
      { ...key, id: "newer", createdAt: timeMethod("newer", returnedNumber("newer", 2, failure, events), events) },
    ];
    const before = rows.map(row => ({ ...row }));
    const adapter = getJwksAdapter({}, { adapter: { async getJwks() { return rows; } } });
    let caught: unknown;
    try {
      if (algorithm) await adapter.getLatestKeyByAlg({}, algorithm);
      else await adapter.getLatestKey({});
    } catch (error) { caught = error; }
    expect(caught).toBe(failure);
    expectSubtraction(events, true);
    expect(rows).toStrictEqual(before);
  });
}

test("JWKS discovery preserves string addition and rejects a shadowed Date getTime", async () => {
  const events: Events = [];
  const rows = [
    { ...key, id: "string", expiresAt: timeMethod("string", "2000", events) },
    { ...key, id: "numeric", expiresAt: timeMethod("numeric", 2000, events) },
  ];
  const before = rows.map(row => ({ ...row }));
  const memory = { user: [], session: [], account: [], verification: [], jwks: [] };
  let reads = 0;
  let selected: unknown[] = rows;
  const auth = betterAuth({
    database: memoryAdapter(memory), baseURL,
    secret: "jwk-native-date-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    plugins: [jwt({ adapter: { async getJwks() { reads++; return selected as any; } } })],
  });
  expect(await auth.api.getJwks()).toStrictEqual({
    keys: [{ alg: "EdDSA", crv: undefined, ...JSON.parse(key.publicKey), kid: "string" }],
  });
  expect(events).toStrictEqual([["string", "getTime"], ["numeric", "getTime"]]);
  expect(reads).toBe(1);
  expect(rows).toStrictEqual(before);
  const expiry = Object.assign(new Date(4_102_444_800_000), { getTime: false });
  selected = [{ ...key, expiresAt: expiry }];
  await expect(auth.api.getJwks()).rejects.toBeInstanceOf(TypeError);
  expect(reads).toBe(2);
  expect(expiry.getTime).toBe(false);
  expect(memory).toStrictEqual({ user: [], session: [], account: [], verification: [], jwks: [] });
});
