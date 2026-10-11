import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createHmac } from "node:crypto";

const { setCookieCache } = await import(new URL("./cookies/index.mjs", import.meta.resolve("better-auth")).href);

for (const strategy of ["compact", "jwt", "jwe"]) {
  for (const stage of ["session-getter", "user-getter", "version", "session-cycle", "user-cycle"]) {
    test(`${strategy} cookie cache preserves ${stage} failure order`, async () => {
      const events = [];
      const failure = new Error("cookie cache original error");
      const probe = model => {
        if (stage === `${model}-cycle`) {
          const cycle = {};
          cycle.self = cycle;
          return cycle;
        }
        return {
          get value() {
            events.push(`${model}.value`);
            if (stage === `${model}-getter`) throw failure;
            return "value";
          },
          get later() { events.push(`${model}.later`); return "later"; },
        };
      };
      const data = {
        session: { id: "session", token: "token", userId: "owner", payload: probe("session") },
        user: { id: "owner", name: probe("user") },
      };
      const auth = betterAuth({
        database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
        baseURL: "http://cookie-json.test",
        secret: "cookie-json-contract-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        session: {
          additionalFields: {},
          cookieCache: {
            enabled: true, strategy,
            version() {
              events.push("version");
              if (stage === "version") throw failure;
              return "v2";
            },
          },
        },
      });
      const context = await auth.$context;
      const cookies = [];
      let caught;
      try {
        await setCookieCache({ context, headers: new Headers(), setCookie: (...args) => cookies.push(args) }, data, false);
      } catch (error) { caught = error; }
      if (stage.endsWith("cycle")) expect(caught).toBeInstanceOf(TypeError);
      else expect(caught).toBe(failure);
      expect(events).toStrictEqual({
        "session-getter": ["session.value"],
        "user-getter": ["session.value", "session.later", "user.value"],
        version: ["session.value", "session.later", "user.value", "user.later", "version"],
        "session-cycle": ["user.value", "user.later", "version"],
        "user-cycle": ["session.value", "session.later", "version"],
      }[stage]);
      expect(cookies).toStrictEqual([]);
    });
  }
}

test("Compact cookie cache serializes live session children twice after version resolution", async () => {
  const events = [];
  const secret = "cookie-live-contract-secret-at-least-thirty-two-characters";
  const child = { serial: 0, toJSON(key) {
    expect(this).toBe(child);
    expect(key).toBe("payload");
    this.serial += 1;
    events.push(`payload:${this.serial}`);
    return { serial: this.serial };
  } };
  const data = {
    session: { id: "session", token: "token", userId: "owner", payload: child },
    user: { id: "owner", name: "Owner" },
  };
  const auth = betterAuth({
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    baseURL: "http://cookie-json.test", secret,
    logger: { disabled: true }, telemetry: { enabled: false },
    session: { cookieCache: { enabled: true, strategy: "compact", maxAge: 60,
      version(session, user) {
        expect(session).toBe(data.session);
        expect(user).toBe(data.user);
        events.push("version");
        return "live";
      },
    } },
  });
  const context = await auth.$context;
  const cookies = [];
  const started = Date.now();
  await setCookieCache({ context, headers: new Headers(), setCookie: (...args) => cookies.push(args) }, data, false);
  const finished = Date.now();
  expect(events).toStrictEqual(["version", "payload:1", "payload:2"]);
  expect(child.serial).toBe(2);
  expect(cookies).toHaveLength(1);
  expect(cookies[0][0]).toBe(context.authCookies.sessionData.name);
  expect(cookies[0][2].maxAge).toBe(60);
  const envelope = JSON.parse(Buffer.from(cookies[0][1], "base64url").toString("utf8"));
  expect(Object.keys(envelope)).toStrictEqual(["session", "expiresAt", "signature"]);
  expect(envelope.session).toStrictEqual({
    session: { id: "session", token: "token", userId: "owner", payload: { serial: 2 } },
    user: { id: "owner", name: "Owner" }, updatedAt: envelope.session.updatedAt, version: "live",
  });
  expect(envelope.session.updatedAt).toBeGreaterThanOrEqual(started);
  expect(envelope.session.updatedAt).toBeLessThanOrEqual(finished);
  expect(envelope.expiresAt).toBeGreaterThanOrEqual(started + 60_000);
  expect(envelope.expiresAt).toBeLessThanOrEqual(finished + 60_000);
  const signed = structuredClone(envelope.session);
  signed.session.payload.serial = 1;
  signed.expiresAt = envelope.expiresAt;
  expect(envelope.signature).toBe(createHmac("sha256", secret).update(JSON.stringify(signed)).digest("base64url"));
});

for (const strategy of ["compact", "jwt", "jwe"]) {
  for (const declared of [false, true]) {
    test(`${strategy} cookie cache ${declared ? "explicit empty" : "absent"} session declaration preserves clone and JSON phases`, async () => {
      const events = [];
      const payload = { toJSON(key) {
        expect(this).toBe(payload);
        expect(key).toBe("payload");
        events.push("toJSON");
        return "encoded";
      } };
      const data = {
        session: { id: "session", token: "token", userId: "owner", payload },
        user: { id: "owner", name: "Owner" },
      };
      const context = await betterAuth({
        database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
        baseURL: "http://cookie-json.test",
        secret: "cookie-clone-contract-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        session: {
          ...(declared ? { additionalFields: {} } : {}),
          cookieCache: { enabled: true, strategy, version() { events.push("version"); return "native"; } },
        },
      }).$context;
      const cookies = [];
      let caught;
      try {
        await setCookieCache({ context, headers: new Headers(), setCookie: (...args) => cookies.push(args) }, data, false);
      } catch (error) { caught = error; }
      if (!declared && strategy === "compact") {
        expect(caught).toBeUndefined();
        expect(events).toStrictEqual(["version", "toJSON", "toJSON"]);
        expect(cookies).toHaveLength(1);
        const envelope = JSON.parse(Buffer.from(cookies[0][1], "base64url").toString("utf8"));
        expect(envelope.session.session.payload).toBe("encoded");
      } else {
        expect(caught).toBeInstanceOf(DOMException);
        expect(caught.name).toBe("DataCloneError");
        expect(events).toStrictEqual(declared ? [] : ["version"]);
        expect(cookies).toStrictEqual([]);
      }
      expect(data.session.payload).toBe(payload);
      expect(typeof payload.toJSON).toBe("function");
    });
  }
}
