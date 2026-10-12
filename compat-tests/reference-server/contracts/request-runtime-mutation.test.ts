import { expect, test } from "bun:test";
import type { AuthContext, BetterAuthOptions } from "@better-auth/core";
import { getCurrentAuthEndpointContext, tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { APIError, createAuthEndpoint, createAuthMiddleware, dispatchAuthEndpoint } from "better-auth/api";

const origin = "https://preview.runtime.test";
const basePath = "/api/runtime";
const initialURL = `${origin}${basePath}`;
const secret = "request-runtime-mutation-secret-at-least-32-characters";
const changed = (phase: string) => `http://${phase}.runtime.test/changed`;
const emptyDatabase = () => ({ user: [], session: [], account: [], verification: [] });

function fixture<Options extends BetterAuthOptions>(options: Options) {
  const database = emptyDatabase();
  const auth = betterAuth({
    baseURL: origin, basePath, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    ...options, database: memoryAdapter(database),
  });
  return { auth, database };
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

for (const http of [false, true]) {
  test(`runtime URL shares one dispatch across hooks, database callbacks and handler: http=${http}`, async () => {
    const events: string[] = [];
    let retained!: AuthContext;
    let original!: string;
    const row = {
      id: "runtime-verification", identifier: "runtime", value: "stored",
      createdAt: new Date(1_893_456_000_000), updatedAt: new Date(1_893_456_000_001),
      expiresAt: new Date(1_893_456_060_000),
    };
    const observe = (phase: string, context: AuthContext, expected: string) => {
      events.push(phase);
      expect(context).toBe(retained);
      expect(getCurrentAuthEndpointContext().context).toBe(context);
      expect(context.baseURL).toBe(expected);
      expect(original).toBe(initialURL);
    };
    const { auth, database } = fixture({
      hooks: {
        before: createAuthMiddleware(async ctx => {
          retained = ctx.context;
          original = ctx.context.baseURL;
          observe("before", ctx.context, initialURL);
          ctx.context.baseURL = changed("before");
        }),
        after: createAuthMiddleware(async ctx => {
          observe("after", ctx.context, changed("database-after"));
          ctx.context.baseURL = changed("after");
        }),
      },
      databaseHooks: { verification: { create: {
        async before(_data, ctx) {
          observe("database-before", ctx!.context, changed("handler"));
          ctx!.context.baseURL = changed("database-before");
        },
        async after(_data, ctx) {
          observe("database-after", ctx!.context, changed("database-before"));
          ctx!.context.baseURL = changed("database-after");
        },
      } } },
      plugins: [{ id: "runtime-shared", hooks: { before: [{
        matcher: ctx => ctx.path === "/runtime-shared",
        handler: createAuthMiddleware(async ctx => {
          observe("plugin-before", ctx.context, changed("before"));
          ctx.context.baseURL = changed("plugin-before");
        }),
      }] }, endpoints: {
        runtimeShared: createAuthEndpoint("/runtime-shared", { method: "GET" }, async ctx => {
          observe("handler", ctx.context, changed("plugin-before"));
          ctx.context.baseURL = changed("handler");
          const stored = await ctx.context.internalAdapter.createVerificationValue(row);
          expect(stored).toStrictEqual(row);
          observe("handler-after-write", ctx.context, changed("database-after"));
          return ctx.json({ baseURL: ctx.context.baseURL, original });
        }),
      } }],
    });
    const root = await auth.$context;
    const response = http
      ? await auth.handler(new Request(`${initialURL}/runtime-shared`))
      : await auth.api.runtimeShared({ asResponse: true });
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({ baseURL: changed("database-after"), original: initialURL });
    expect(events).toStrictEqual(["before", "plugin-before", "handler", "database-before", "database-after", "handler-after-write", "after"]);
    expect(retained).not.toBe(root);
    expect(retained.baseURL).toBe(changed("after"));
    expect(root.baseURL).toBe(initialURL);
    expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
    expect(database).toStrictEqual({ ...emptyDatabase(), verification: [row] });
  });
}

for (const mode of ["root-api", "explicit-dispatch", "raw-endpoint"] as const) {
  for (const failure of [false, true]) {
    test(`runtime URL distinguishes ${mode} from its parent: failure=${failure}`, async () => {
      const sentinel = new APIError("CONFLICT", { message: "child failed" });
      const events: string[] = [];
      let parent!: AuthContext;
      let childContext!: AuthContext;
      let rootChild!: () => Promise<unknown>;
      const child = createAuthEndpoint("/runtime-child", { method: "GET" }, async ctx => {
        events.push("child-handler");
        childContext = ctx.context;
        expect(getCurrentAuthEndpointContext().context).toBe(childContext);
        expect(getCurrentAuthEndpointContext().path).toBe("/runtime-child");
        const before = ctx.context.baseURL;
        ctx.context.baseURL = changed("child");
        if (failure) throw sentinel;
        return ctx.json({ before, after: ctx.context.baseURL });
      });
      const { auth, database } = fixture({
        hooks: {
          before: createAuthMiddleware(async ctx => {
            if (ctx.path === "/runtime-child") events.push("child-before");
          }),
          after: createAuthMiddleware(async ctx => {
            if (ctx.path !== "/runtime-child") return;
            events.push("child-after");
            expect(ctx.context).toBe(childContext);
            expect(ctx.context.baseURL).toBe(changed("child"));
            if (failure) expect(ctx.context.returned).toBe(sentinel);
          }),
        },
        plugins: [{ id: "runtime-nested", endpoints: {
          runtimeChild: child,
          runtimeParent: createAuthEndpoint("/runtime-parent", { method: "GET" }, async ctx => {
            parent = ctx.context;
            parent.baseURL = changed("parent");
            let result: unknown;
            let error: unknown;
            try {
              result = mode === "root-api" ? await rootChild()
                : mode === "explicit-dispatch" ? await dispatchAuthEndpoint(child, { context: ctx.context })
                : await child({ context: ctx.context });
            } catch (caught) { error = caught; }
            expect(error).toBe(failure ? sentinel : undefined);
            expect(getCurrentAuthEndpointContext().context).toBe(parent);
            expect(getCurrentAuthEndpointContext().path).toBe("/runtime-parent");
            events.push("parent-restored");
            return ctx.json({ result: failure ? null : result, failed: error === sentinel, baseURL: parent.baseURL });
          }),
        } }],
      });
      rootChild = () => auth.api.runtimeChild();
      const root = await auth.$context;
      expect(await auth.api.runtimeParent()).toStrictEqual({
        result: failure ? null : { before: mode === "root-api" ? initialURL : changed("parent"), after: changed("child") },
        failed: failure, baseURL: mode === "raw-endpoint" ? changed("child") : changed("parent"),
      });
      expect(childContext === parent).toBe(mode === "raw-endpoint");
      expect(childContext).not.toBe(root);
      expect(root.baseURL).toBe(initialURL);
      expect(events).toStrictEqual(mode === "raw-endpoint"
        ? ["child-handler", "parent-restored"]
        : ["child-before", "child-handler", "child-after", "parent-restored"]);
      expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
      expect(database).toStrictEqual(emptyDatabase());
    });
  }
}

for (const nested of [false, true]) {
  test(`runtime URL isolates concurrent dispatches from the same source: nested=${nested}`, async () => {
    const entered = [deferred(), deferred()];
    const release = [deferred(), deferred()];
    const finished = [deferred(), deferred()];
    const contexts: AuthContext[] = [];
    const events: string[] = [];
    const peer = createAuthEndpoint("/runtime-peer", { method: "GET" }, async ctx => {
      const index = Number(ctx.headers!.get("x-peer"));
      const before = ctx.context.baseURL;
      contexts[index] = ctx.context;
      ctx.context.baseURL = changed(`peer-${index}`);
      events.push(`start:${index}`);
      entered[index].resolve();
      await release[index].promise;
      expect(getCurrentAuthEndpointContext().context).toBe(ctx.context);
      expect(ctx.context.baseURL).toBe(changed(`peer-${index}`));
      events.push(`finish:${index}`);
      finished[index].resolve();
      return ctx.json({ before, after: ctx.context.baseURL });
    });
    const { auth, database } = fixture({ plugins: [{ id: "runtime-concurrent", endpoints: {
      runtimePeer: peer,
      runtimeConcurrent: createAuthEndpoint("/runtime-concurrent", { method: "GET" }, async ctx => {
        ctx.context.baseURL = changed("parent");
        const values = await Promise.all([0, 1].map(index => dispatchAuthEndpoint(peer, {
          context: ctx.context, headers: new Headers({ "x-peer": String(index) }),
        })));
        expect(getCurrentAuthEndpointContext().context).toBe(ctx.context);
        expect(ctx.context.baseURL).toBe(changed("parent"));
        return ctx.json(values);
      }),
    } }] });
    const root = await auth.$context;
    const operation = nested ? auth.api.runtimeConcurrent()
      : Promise.all([0, 1].map(index => auth.api.runtimePeer({ headers: new Headers({ "x-peer": String(index) }) })));
    try {
      await Promise.race([
        Promise.all(entered.map(gate => gate.promise)),
        operation.then(() => { throw new Error("Dispatch completed before both peers entered"); }),
      ]);
      expect(contexts[0]).not.toBe(contexts[1]);
      expect(contexts.every(context => context !== root)).toBe(true);
      release[1].resolve();
      await Promise.race([
        finished[1].promise,
        operation.then(() => { throw new Error("Dispatch completed before the first peer finished"); }),
      ]);
      release[0].resolve();
      expect(await operation).toStrictEqual([0, 1].map(index => ({
        before: nested ? changed("parent") : initialURL, after: changed(`peer-${index}`),
      })));
      expect(events.slice(0, 2).sort()).toStrictEqual(["start:0", "start:1"]);
      expect(events.slice(2)).toStrictEqual(["finish:1", "finish:0"]);
      expect(root.baseURL).toBe(initialURL);
      expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
      expect(database).toStrictEqual(emptyDatabase());
    } finally {
      release.forEach(gate => gate.resolve());
      await operation;
    }
  });
}

test("runtime URL retained by a background callback sees later endpoint writes after the response", async () => {
  const release = deferred();
  const tasks: Promise<unknown>[] = [];
  const events: string[] = [];
  const observations: unknown[] = [];
  let retained!: AuthContext;
  const { auth, database } = fixture({
    advanced: { backgroundTasks: { handler(task) { events.push("scheduled"); tasks.push(task); } } },
    hooks: { after: createAuthMiddleware(async ctx => {
      events.push("after");
      expect(ctx.context).toBe(retained);
      ctx.context.baseURL = changed("after");
    }) },
    plugins: [{ id: "runtime-background", endpoints: {
      runtimeBackground: createAuthEndpoint("/runtime-background", { method: "GET" }, async ctx => {
        retained = ctx.context;
        retained.baseURL = changed("handler");
        const snapshot = retained.baseURL;
        const task = (async () => {
          events.push("background-start");
          await release.promise;
          const active = getCurrentAuthEndpointContext();
          observations.push({ sameContext: active.context === retained, sameEndpoint: active === ctx, baseURL: active.context.baseURL, snapshot });
          events.push("background-resume");
          active.context.baseURL = changed("background");
        })();
        await ctx.context.runInBackgroundOrAwait(task);
        events.push("handler-return");
        return ctx.json({ baseURL: retained.baseURL });
      }),
    } }],
  });
  const root = await auth.$context;
  try {
    expect(await auth.api.runtimeBackground()).toStrictEqual({ baseURL: changed("handler") });
    events.push("response");
    expect(retained.baseURL).toBe(changed("after"));
    expect(root.baseURL).toBe(initialURL);
    expect(tasks).toHaveLength(1);
    release.resolve();
    await Promise.all(tasks);
    expect(observations).toStrictEqual([{ sameContext: true, sameEndpoint: true, baseURL: changed("after"), snapshot: changed("handler") }]);
    expect(events).toStrictEqual(["background-start", "scheduled", "handler-return", "after", "response", "background-resume"]);
    expect(retained.baseURL).toBe(changed("background"));
    expect(root.baseURL).toBe(initialURL);
    expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
    expect(database).toStrictEqual(emptyDatabase());
  } finally {
    release.resolve();
    await Promise.all(tasks);
  }
});

for (const dynamic of [false, true]) {
  test(`HTTP URL writes preserve routing, options, trust and cookies: dynamic=${dynamic}`, async () => {
    const resolutions: string[] = [];
    const observations: unknown[] = [];
    let outer!: AuthContext;
    let endpoint!: AuthContext;
    const policy = (context: AuthContext) => ({
      baseURL: context.baseURL,
      optionURL: context.options.baseURL, optionPath: context.options.basePath,
      origins: [...context.trustedOrigins], providers: [...context.trustedProviders],
      cookie: context.createAuthCookie("runtime"),
    });
    const { auth, database } = fixture({
      baseURL: dynamic ? { allowedHosts: ["preview.runtime.test"], protocol: "https" } : origin,
      trustedOrigins(request) { resolutions.push(`origins:${request?.url ?? "none"}`); return ["https://trusted.runtime.test"]; },
      account: { accountLinking: { trustedProviders(request) { resolutions.push(`providers:${request?.url ?? "none"}`); return ["google"]; } } },
      advanced: { crossSubDomainCookies: { enabled: true } },
      hooks: {
        before: createAuthMiddleware(async ctx => {
          endpoint = ctx.context;
          expect(endpoint).not.toBe(outer);
          expect(endpoint.options).toBe(outer.options);
          expect(endpoint.createAuthCookie).toBe(outer.createAuthCookie);
          expect(endpoint.authCookies).toBe(outer.authCookies);
          expect(endpoint.trustedOrigins).toBe(outer.trustedOrigins);
          expect(endpoint.trustedProviders).toBe(outer.trustedProviders);
          observations.push({ phase: "before", ...policy(endpoint) });
          endpoint.baseURL = changed("endpoint");
        }),
        after: createAuthMiddleware(async ctx => {
          expect(ctx.context).toBe(endpoint);
          observations.push({ phase: "after", ...policy(ctx.context) });
          ctx.context.baseURL = changed("endpoint-after");
        }),
      },
      plugins: [{ id: "runtime-http", async onRequest(_request, context) {
        outer = context;
        observations.push({ phase: "onRequest", ...policy(context) });
        context.baseURL = changed("http");
      }, async onResponse(_response, context) {
        expect(context).toBe(outer);
        observations.push({ phase: "onResponse", ...policy(context) });
        context.baseURL = changed("response");
      }, endpoints: {
        runtimeHTTP: createAuthEndpoint("/runtime-http", { method: "GET" }, async ctx => {
          expect(ctx.context).toBe(endpoint);
          expect(getCurrentAuthEndpointContext().context).toBe(endpoint);
          return ctx.json(policy(ctx.context));
        }),
      } }, { id: "runtime-http-response-observer", async onResponse(_response, context) {
        expect(context).toBe(outer);
        observations.push({ phase: "following-onResponse", ...policy(context) });
      } }],
    });
    const root = await auth.$context;
    const expected = {
      optionURL: origin, optionPath: basePath,
      origins: [origin, "https://trusted.runtime.test"], providers: ["google"],
      cookie: { name: "__Secure-better-auth.runtime", attributes: {
        secure: true, sameSite: "lax", path: "/", httpOnly: true, domain: "preview.runtime.test",
      } },
    };
    const requestURL = `${initialURL}/runtime-http`;
    for (let index = 0; index < 2; index++) {
      const response = await auth.handler(new Request(requestURL));
      expect(response.status).toBe(200);
      expect(await response.json()).toStrictEqual({ baseURL: changed("endpoint"), ...expected });
      expect(endpoint.baseURL).toBe(changed("endpoint-after"));
      expect(outer.baseURL).toBe(changed("response"));
      expect(root.baseURL).toBe(dynamic ? "" : initialURL);
      expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
    }
    expect(observations).toStrictEqual([0, 1].flatMap(() => [
      { phase: "onRequest", baseURL: initialURL, ...expected },
      { phase: "before", baseURL: changed("http"), ...expected },
      { phase: "after", baseURL: changed("endpoint"), ...expected },
      { phase: "onResponse", baseURL: changed("http"), ...expected },
      { phase: "following-onResponse", baseURL: changed("response"), ...expected },
    ]));
    expect(resolutions).toStrictEqual([
      "origins:none", "providers:none",
      `origins:${requestURL}`, `providers:${requestURL}`,
      `origins:${requestURL}`, `providers:${requestURL}`,
    ]);
    expect(database).toStrictEqual(emptyDatabase());
  });
}

for (const stage of ["before", "handler", "after"] as const) {
  test(`runtime URL assignment remains visible after ${stage} throws`, async () => {
    const sentinel = new APIError("CONFLICT", { message: "runtime failure" });
    const events: string[] = [];
    let retained!: AuthContext;
    const observe = (phase: typeof stage, context: AuthContext) => {
      events.push(phase);
      expect(getCurrentAuthEndpointContext().context).toBe(context);
      if (phase === stage) {
        context.baseURL = changed(stage);
        throw sentinel;
      }
    };
    const { auth, database } = fixture({
      hooks: {
        before: createAuthMiddleware(async ctx => { retained = ctx.context; observe("before", ctx.context); }),
        after: createAuthMiddleware(async ctx => { expect(ctx.context).toBe(retained); observe("after", ctx.context); }),
      },
      plugins: [{ id: "runtime-failure", endpoints: {
        runtimeFailure: createAuthEndpoint("/runtime-failure", { method: "GET" }, async ctx => {
          expect(ctx.context).toBe(retained);
          observe("handler", ctx.context);
          return ctx.json({ ok: true });
        }),
      } }],
    });
    let error: unknown;
    try { await auth.api.runtimeFailure(); } catch (caught) { error = caught; }
    expect(error).toBe(sentinel);
    expect(retained.baseURL).toBe(changed(stage));
    expect((await auth.$context).baseURL).toBe(initialURL);
    expect(events).toStrictEqual(stage === "before" ? ["before"] : ["before", "handler", "after"]);
    expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
    expect(database).toStrictEqual(emptyDatabase());
  });
}
