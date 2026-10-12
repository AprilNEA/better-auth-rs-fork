import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { captureDetachedOwnership, settle } from "./detached-ownership-capture.mjs";

await captureDetachedOwnership(async ({ name, unhandled }) => {
  const [source, timing] = name.split(":");
  assert.ok(["callback", "logger"].includes(source));
  assert.ok(["sync", "ready", "pending"].includes(timing));
  const failure = new Error(`${source} failure`);
  const original = new APIError("BAD_REQUEST", {
    message: "Original endpoint failure", code: "ORIGINAL_FAILURE",
  }, { "x-original": "retained" });
  const gate = Promise.withResolvers();
  const database = { user: [], session: [], account: [], verification: [] };
  const events = [];
  const logs = [];
  let returnedTask;
  let callbackCalls = 0;
  let handlerCalls = 0;
  const origin = "https://on-api-error-detached.test";
  const auth = betterAuth({
    baseURL: origin,
    secret: "on-api-error-detached-secret-at-least-thirty-two-characters",
    database: memoryAdapter(database), telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "error", disableColors: true, log(...args) {
      events.push("log");
      logs.push(args);
      throw failure;
    } },
    onAPIError: { onError(error, context) {
      callbackCalls++;
      events.push("callback");
      assert.equal(error, original);
      const fail = () => {
        events.push("failure");
        if (source === "logger") return context.logger.error("onAPIError ownership", original);
        throw failure;
      };
      if (timing === "sync") return fail();
      returnedTask = (async () => {
        if (timing === "pending") await gate.promise;
        fail();
      })();
      return returnedTask;
    } },
    plugins: [{ id: "on-api-error-detached", middlewares: [{
      path: "/failure",
      middleware: Object.assign(async () => {
        events.push("middleware");
        throw original;
      }, { options: {} }),
    }], endpoints: {
      failure: createAuthEndpoint("/failure", { method: "GET" }, async () => {
        handlerCalls++;
        return { unexpected: true };
      }),
    } }],
  });
  await auth.$context;
  const caller = await settle(() => auth.handler(new Request(`${origin}/api/auth/failure`)));
  events.push("caller");
  if (timing === "sync") {
    assert.equal(caller.status, "rejected");
    assert.equal(caller.reason, failure);
    assert.equal(returnedTask, undefined);
  } else {
    assert.equal(caller.status, "fulfilled");
    const response = caller.value;
    assert.deepEqual({
      status: response.status, statusText: response.statusText,
      headers: [...response.headers], cookies: response.headers.getSetCookie(), body: await response.text(),
    }, {
      status: 400, statusText: "BAD_REQUEST",
      headers: [["content-type", "application/json"], ["x-original", "retained"]], cookies: [],
      body: JSON.stringify(original.body),
    });
    assert.ok(returnedTask instanceof Promise);
  }
  if (timing === "pending") {
    assert.deepEqual(events, ["middleware", "callback", "caller"]);
    assert.deepEqual(logs, []);
    assert.deepEqual(unhandled, []);
    events.push("release");
    gate.resolve();
  }

  return () => {
    assert.equal(callbackCalls, 1);
    assert.equal(handlerCalls, 0);
    assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
    const failureEvents = ["failure", ...(source === "logger" ? ["log"] : [])];
    assert.deepEqual(events, timing === "pending"
      ? ["middleware", "callback", "caller", "release", ...failureEvents]
      : ["middleware", "callback", ...failureEvents, "caller"]);
    assert.deepEqual(logs, source === "logger" ? [["error", "onAPIError ownership", original]] : []);
    if (source === "logger") assert.equal(logs[0][2], original);
    assert.equal(unhandled.length, timing === "sync" ? 0 : 1);
    if (timing !== "sync") {
      assert.equal(unhandled[0].reason, failure);
      assert.equal(unhandled[0].promise, returnedTask);
    }
  };
});
