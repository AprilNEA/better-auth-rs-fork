import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import type { AuthContext } from "@better-auth/core";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import { oAuthProxy } from "better-auth/plugins";

const origin = "http://preview.proxy-input.test";
const production = "http://production.proxy-input.test";
const baseURL = `${origin}/api/auth`;
const secret = "oauth-proxy-native-input-secret-at-least-32-characters";

for (const name of ["missing", "null", "false", "number", "string", "array", "empty", "provider-null", "provider-false", "provider-zero", "provider-empty", "ordinary", "numeric", "boolean", "dynamic", "get-provider", "get-callback", "convert-provider", "convert-callback", "set-callback"] as const) {
  test(`OAuth Proxy preserves native before-hook input: ${name}`, async () => {
    const database = { user: [], session: [], account: [], verification: [] };
    const events: string[] = [];
    const sentinel = new APIError("CONFLICT", { message: "proxy input sentinel" });
    const blocker = new APIError("CONFLICT", { message: "following hook" });
    const child = { ownUndefined: undefined, date: new Date(NaN) };
    let written: unknown;
    let retained!: AuthContext;
    const observed = ["dynamic", "get-provider", "get-callback", "convert-provider", "convert-callback", "set-callback"].includes(name);
    const input = (() => {
      switch (name) {
        case "missing": return undefined;
        case "null": return null;
        case "false": return false;
        case "number": return 7;
        case "string": return "text";
        case "array": return [];
        case "empty": return {};
        case "provider-null": return { provider: null };
        case "provider-false": return { provider: false };
        case "provider-zero": return { provider: 0 };
        case "provider-empty": return { provider: "" };
        case "ordinary": return { provider: "google", callbackURL: "/complete", child, absent: undefined };
        case "numeric": return { provider: 7, callbackURL: null };
        case "boolean": return { provider: true, callbackURL: "" };
        default: return {
          child,
          get unread(): never { throw new Error("Proxy initiation must not enumerate the body"); },
          get provider() {
            events.push("get:provider");
            if (name === "get-provider") throw sentinel;
            return { toString() {
              events.push("toString:provider");
              if (name === "convert-provider") throw sentinel;
              return "provider ?#segment";
            } };
          },
          get callbackURL() {
            events.push("get:callbackURL");
            if (name === "get-callback") throw sentinel;
            return { toString() {
              events.push("toString:callbackURL");
              if (name === "convert-callback") throw sentinel;
              return "/complete?x=1&y=~";
            } };
          },
          set callbackURL(value: unknown) {
            events.push("set:callbackURL");
            if (name === "set-callback") throw sentinel;
            written = value;
          },
        };
      }
    })();
    const rewritten = ["ordinary", "numeric", "boolean", "dynamic"].includes(name);
    const expectedCallback = name === "ordinary" ? "/complete"
      : name === "dynamic" ? "/complete?x=1&y=~" : baseURL;
    const expectedProvider = name === "ordinary" ? "google"
      : name === "numeric" ? "7" : name === "boolean" ? "true" : "provider ?#segment";
    const expectedURL = `${baseURL}/callback/${expectedProvider}/oauth-proxy?callbackURL=${encodeURIComponent(expectedCallback)}`;
    const auth = betterAuth({
      baseURL: origin, secret, database: memoryAdapter(database), telemetry: { enabled: false },
      hooks: { before: createAuthMiddleware(async ctx => { retained = ctx.context; }) },
      plugins: [oAuthProxy({ currentURL: origin, productionURL: production }), {
        id: "observe-proxy-input",
        hooks: { before: [{ matcher: ctx => ctx.path === "/sign-in/social", handler: createAuthMiddleware(async ctx => {
          events.push("following");
          expect(ctx.body).toBe(input);
          expect(ctx.context.baseURL).toBe(rewritten ? `${production}/api/auth` : baseURL);
          if (rewritten) {
            expect(name === "dynamic" ? written : (input as any).callbackURL).toBe(expectedURL);
            if (name === "ordinary" || name === "dynamic") expect((input as any).child).toBe(child);
          }
          throw blocker;
        }) }] },
      }],
    });
    let caught: unknown;
    try { await auth.api.signInSocial({ body: input as any }); }
    catch (error) { caught = error; }
    const fails = ["get-provider", "get-callback", "convert-provider", "convert-callback", "set-callback"].includes(name);
    expect(caught).toBe(fails ? sentinel : blocker);
    const redirected = rewritten || ["convert-provider", "convert-callback", "set-callback"].includes(name);
    expect(retained.baseURL).toBe(redirected ? `${production}/api/auth` : baseURL);
    expect((await auth.$context).baseURL).toBe(baseURL);
    const reads = ["get:provider", "get:callbackURL", "toString:provider", "toString:callbackURL", "set:callbackURL"];
    const last = name === "get-provider" ? 1 : name === "get-callback" ? 2
      : name === "convert-provider" ? 3 : name === "convert-callback" ? 4 : 5;
    expect(events).toStrictEqual(observed ? [...reads.slice(0, last), ...(!fails ? ["following"] : [])] : ["following"]);
    if (name === "ordinary") {
      expect(Object.keys(input as object)).toStrictEqual(["provider", "callbackURL", "child", "absent"]);
      expect(Object.hasOwn(input as object, "absent")).toBe(true);
    }
    if (fails) expect(written).toBeUndefined();
    expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  });
}
