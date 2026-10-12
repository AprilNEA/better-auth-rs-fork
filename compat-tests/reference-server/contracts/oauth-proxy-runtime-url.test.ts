import { expect, test } from "bun:test";
import type { BetterAuthOptions } from "better-auth";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { oAuthProxy } from "better-auth/plugins";

const origin = "https://configured.proxy-runtime.test";
const runtime = "https://runtime.proxy-runtime.test/custom/auth";
const production = "https://production.proxy-runtime.test";
const secret = "oauth-proxy-runtime-secret-at-least-thirty-two-characters";
const dynamic = { allowedHosts: ["*.proxy-runtime.test"] };
const warn = "OAuth proxy: cross-origin callback reached after hook unexpectedly";
const missing = "OAuth proxy callback missing profile data";
const redirected = (base: string, query = "%2Fcomplete") => `${base}/oauth-proxy?callbackURL=${query}`;

type Selection = {
  optionURL: BetterAuthOptions["baseURL"];
  runtimeURL: string;
  productionURL?: string;
};
type CallbackCase = Selection & {
  name: string;
  location?: string;
  expected?: string;
  warns?: boolean;
  invalid?: boolean;
};
const callbackCases: CallbackCase[] = [
  { name: "production wins", optionURL: origin, runtimeURL: runtime, productionURL: production, location: redirected(production), expected: "/complete" },
  { name: "static wins", optionURL: origin, runtimeURL: runtime, location: redirected(origin), expected: "/complete" },
  { name: "empty production uses static", optionURL: origin, runtimeURL: runtime, productionURL: "", location: redirected(origin), expected: "/complete" },
  { name: "empty static uses runtime", optionURL: "", runtimeURL: runtime, location: redirected(runtime), expected: "/complete" },
  { name: "dynamic uses runtime", optionURL: dynamic, runtimeURL: runtime, location: redirected(runtime), expected: "/complete" },
  { name: "absent uses runtime", optionURL: undefined, runtimeURL: runtime, location: redirected(runtime), expected: "/complete" },
  { name: "invalid production warns", optionURL: origin, runtimeURL: runtime, productionURL: "invalid", location: redirected(origin), warns: true },
  { name: "invalid static wins", optionURL: "invalid", runtimeURL: runtime, location: redirected(runtime), warns: true },
  { name: "invalid runtime warns", optionURL: dynamic, runtimeURL: "invalid", location: redirected(origin), warns: true },
  { name: "cross origin warns", optionURL: origin, runtimeURL: runtime, location: redirected(production), warns: true },
  { name: "missing location", optionURL: origin, runtimeURL: runtime },
  { name: "missing marker", optionURL: origin, runtimeURL: runtime, location: `${origin}/complete` },
  { name: "relative location", optionURL: origin, runtimeURL: runtime, location: "/oauth-proxy?callbackURL=%2Fcomplete" },
  { name: "uppercase scheme", optionURL: origin, runtimeURL: runtime, location: redirected(origin).replace("https:", "HTTPS:") },
  { name: "non-http scheme", optionURL: origin, runtimeURL: runtime, location: redirected(origin).replace("https:", "ftp:") },
  { name: "invalid location throws", optionURL: "invalid", runtimeURL: runtime, location: "http://[/oauth-proxy?callbackURL=%2Fcomplete", invalid: true },
  { name: "empty callback stays", optionURL: origin, runtimeURL: runtime, location: redirected(origin, "") },
  { name: "first empty callback stays", optionURL: origin, runtimeURL: runtime, location: redirected(origin, "&callbackURL=%2Fsecond") },
  { name: "first callback wins", optionURL: origin, runtimeURL: runtime, location: redirected(origin, "%2Ffirst&callbackURL=%2Fsecond"), expected: "/first" },
  { name: "legacy marker", optionURL: origin, runtimeURL: runtime, location: `${origin}/oauth-proxy-callback?callbackURL=%2Fcomplete`, expected: "/complete" },
  { name: "opaque http prefix warns", optionURL: "invalid", runtimeURL: runtime, location: "http+opaque:body/oauth-proxy?callbackURL=%2Fcomplete", warns: true },
];

for (const scenario of callbackCases) {
  test(`OAuth Proxy callback runtime URL: ${scenario.name}`, async () => {
    const database = { user: [], session: [], account: [], verification: [] };
    const logs: unknown[] = [];
    const original = { kept: undefined, child: { date: new Date(NaN) } };
    const proxy = oAuthProxy({ productionURL: scenario.productionURL });
    const auth = betterAuth({
      baseURL: origin, secret, database: memoryAdapter(database), telemetry: { enabled: false },
      logger: { log(level, message, ...args) { logs.push([level, message, args]); } },
      hooks: { before: createAuthMiddleware(async ctx => {
        ctx.context.baseURL = scenario.runtimeURL;
        ctx.context.options = { ...ctx.context.options, baseURL: scenario.optionURL };
      }) },
      plugins: [{
        id: "proxy-runtime-callback",
        endpoints: { runtimeCallback: createAuthEndpoint("/callback/:id", { method: "GET" }, async ctx => {
          ctx.setStatus(201);
          ctx.setHeader("x-proxy", "kept");
          if (scenario.location !== undefined) ctx.setHeader("location", scenario.location);
          return original;
        }) },
        hooks: { after: proxy.hooks.after },
      }],
    });
    const root = await auth.$context;
    logs.length = 0;
    const invoke = () => auth.api.runtimeCallback({ params: { id: "test" }, returnHeaders: true, returnStatus: true });
    if (scenario.invalid) {
      await expect(invoke()).rejects.toBeInstanceOf(TypeError);
    } else {
      const result = await invoke();
      expect(Object.keys(result)).toStrictEqual(["headers", "response", "status"]);
      expect(result.response).toBe(original);
      expect(result.response.child).toBe(original.child);
      expect(Object.keys(result.response)).toStrictEqual(["kept", "child"]);
      expect(result.status).toBe(201);
      expect([...result.headers]).toStrictEqual([
        ...(scenario.location === undefined ? [] : [["location", scenario.expected ?? scenario.location]]),
        ["x-proxy", "kept"],
      ]);
    }
    expect(logs).toStrictEqual(scenario.warns ? [["warn", warn, []]] : []);
    expect(root.baseURL).toBe(`${origin}/api/auth`);
    expect(root.options.baseURL).toBe(origin);
    expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  });
}

const completionCases: (Selection & { name: string; errorURL?: string; expected: string; invalid?: boolean })[] = [
  { name: "static wins", optionURL: origin, runtimeURL: runtime, expected: `${origin}/api/auth/error` },
  { name: "static path retained", optionURL: `${origin}/tenant///`, runtimeURL: runtime, expected: `${origin}/tenant/api/auth/error` },
  { name: "static empty retained", optionURL: "", runtimeURL: runtime, expected: "/api/auth/error" },
  { name: "invalid static retained", optionURL: "invalid", runtimeURL: runtime, expected: "invalid/api/auth/error", invalid: true },
  { name: "dynamic runtime origin", optionURL: dynamic, runtimeURL: runtime, expected: "https://runtime.proxy-runtime.test/api/auth/error" },
  { name: "absent runtime origin", optionURL: undefined, runtimeURL: runtime, expected: "https://runtime.proxy-runtime.test/api/auth/error" },
  { name: "invalid runtime empty origin", optionURL: dynamic, runtimeURL: "invalid", expected: "/api/auth/error" },
  { name: "opaque runtime empty origin", optionURL: dynamic, runtimeURL: "data:text/plain,opaque", expected: "/api/auth/error" },
  { name: "empty runtime empty origin", optionURL: undefined, runtimeURL: "", expected: "/api/auth/error" },
  { name: "explicit error URL wins", optionURL: origin, runtimeURL: runtime, errorURL: "/custom-error?retained=1", expected: "/custom-error?retained=1" },
  { name: "empty error URL falls through", optionURL: origin, runtimeURL: runtime, errorURL: "", expected: `${origin}/api/auth/error` },
];

for (const scenario of completionCases) {
  test(`OAuth Proxy completion runtime URL: ${scenario.name}`, async () => {
    const database = { user: [], session: [], account: [], verification: [] };
    const logs: [string, unknown, unknown[]][] = [];
    const auth = betterAuth({
      baseURL: origin, basePath: "/custom-auth", secret,
      database: memoryAdapter(database), telemetry: { enabled: false },
      onAPIError: { errorURL: scenario.errorURL },
      logger: { log(level, message, ...args) { logs.push([level, message, args]); } },
      hooks: { before: createAuthMiddleware(async ctx => {
        ctx.context.baseURL = scenario.runtimeURL;
        ctx.context.options = { ...ctx.context.options, baseURL: scenario.optionURL };
      }) },
      plugins: [oAuthProxy()],
    });
    const root = await auth.$context;
    logs.length = 0;
    const response = await auth.handler(new Request(`${origin}/custom-auth/callback/test/oauth-proxy?callbackURL=%2Fcomplete`));
    expect(response.status).toBe(scenario.invalid ? 500 : 302);
    expect([...response.headers]).toStrictEqual(scenario.invalid ? [] : [
      ["content-type", "application/json"],
      ["location", `${scenario.expected}${scenario.expected.includes("?") ? "&" : "?"}error=missing_profile`],
    ]);
    expect(await response.text()).toBe("");
    if (scenario.invalid) {
      expect(logs).toHaveLength(2);
      const cause = logs[1]?.[2][0];
      expect(cause).toBeInstanceOf(TypeError);
      expect(cause).toHaveProperty("message", "Invalid URL");
      expect(logs).toStrictEqual([["error", missing, []], ["error", "TypeError", [cause]]]);
    } else {
      expect(logs).toStrictEqual([["error", missing, []]]);
    }
    expect(root.baseURL).toBe(`${origin}/custom-auth`);
    expect(root.options.baseURL).toBe(origin);
    expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  });
}

test("OAuth Proxy skip distinguishes empty URL from nonempty invalid origins", async () => {
  const { checkSkipProxy } = await import(new URL("../node_modules/better-auth/dist/plugins/oauth-proxy/utils.mjs", import.meta.url).href);
  expect(process.env.BETTER_AUTH_URL || "").toBe("");
  for (const [runtimeURL, currentURL, expected] of [
    ["", "invalid-current", false],
    ["invalid-runtime", "invalid-current", true],
    ["data:text/plain,runtime", "data:text/plain,current", true],
    ["invalid-runtime", origin, false],
  ] as const) {
    expect(checkSkipProxy({ context: { baseURL: runtimeURL } }, { currentURL })).toBe(expected);
  }
});

test("shared redirect query composition validates before preserving an empty query", async () => {
  const { appendQueryParams } = await import(new URL("../node_modules/@better-auth/core/dist/utils/url.mjs", import.meta.url).href);
  for (const [input, params, expected] of [
    ["https://query.proxy-runtime.test/a b?one=1&", "", "https://query.proxy-runtime.test/a b?one=1&"],
    ["/a b?one=1&#fragment", "", "/a b?one=1&#fragment"],
    ["/space path+keep?one=1&#fragment", "two=2", "/space%20path+keep?one=1&two=2#fragment"],
  ]) {
    expect(appendQueryParams(input, new URLSearchParams(params))).toBe(expected);
  }
  for (const [input, message] of [
    ["invalid/api/auth/error", "Invalid URL"],
    ["//other.example/error", "Expected an absolute or root-relative URL"],
    ["/\\other.example/error", "Expected an absolute or root-relative URL"],
  ]) {
    for (const params of ["", "error=missing_profile"]) {
      expect(() => appendQueryParams(input, new URLSearchParams(params))).toThrow(TypeError);
      expect(() => appendQueryParams(input, new URLSearchParams(params))).toThrow(message);
    }
  }
});
