import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

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
