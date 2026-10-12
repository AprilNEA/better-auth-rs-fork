import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthEndpoint } from "better-auth/api";

const origin = "https://http-error-logging.test";
const emptyDatabase = () => ({ user: [], session: [], account: [], verification: [] });
const cases = [
  { name: "ordinary", message: "ordinary failure", errorName: "RuntimeFailure" },
  { name: "native-name", message: "ordinary failure", errorName: { kind: "native-name" } },
  { name: "missing-name", message: "ordinary failure", errorName: undefined },
  { name: "disabled", message: "ordinary failure", errorName: "RuntimeFailure", disabled: true },
  { name: "callback", message: "ordinary failure", errorName: "RuntimeFailure", callback: true },
  { name: "throw", message: "ordinary failure", errorName: "RuntimeFailure", throwError: true },
  { name: "name-getter-error", message: "ordinary failure", errorName: "RuntimeFailure", failure: "name" },
  { name: "message-getter-error", message: "ordinary failure", errorName: "RuntimeFailure", failure: "message" },
  ...["no column", "column", "relation", "table", "does not exist"].map(keyword => ({
    name: `database-${keyword}`, message: `diagnostic: ${keyword}`, errorName: "RuntimeFailure", database: true,
  })),
] as const;

for (const scenario of cases) {
  test(`HTTP error logging preserves ordinary error observations: ${scenario.name}`, async () => {
    const events: string[] = [];
    const logs: [string, unknown, unknown[]][] = [];
    const outer: unknown[][] = [];
    const replacement = new Error("logger property failed");
    let logging = false;
    let selectedName = false;
    const target: Record<string, unknown> = { message: scenario.message };
    if (scenario.errorName !== undefined) target.name = scenario.errorName;
    const cause = new Proxy(target, {
      has(value, property) {
        if (property === "name" || property === "message") events.push(`has:${property}`);
        if (property === "message") logging = true;
        if (property === "name" && logging) selectedName = true;
        return Reflect.has(value, property);
      },
      get(value, property, receiver) {
        if (property === "name" || property === "message") events.push(`get:${property}`);
        if (logging && "failure" in scenario && (scenario.failure === "message" && property === "message"
          || scenario.failure === "name" && property === "name" && selectedName)) throw replacement;
        return Reflect.get(value, property, receiver);
      },
    });
    const database = emptyDatabase();
    const auth = betterAuth({
      baseURL: origin, secret: "http-error-logging-secret-at-least-32-characters",
      database: memoryAdapter(database), telemetry: { enabled: false }, rateLimit: { enabled: false },
      logger: { disabled: "disabled" in scenario && scenario.disabled,
        log(level, message, ...args) { events.push("log"); logs.push([level, message, args]); } },
      onAPIError: {
        throw: "throwError" in scenario && scenario.throwError,
        ...("callback" in scenario && scenario.callback ? { onError(error: unknown) {
          expect(error).toBe(cause); events.push("callback");
        } } : {}),
      },
      plugins: [{ id: "http-error-logging", middlewares: [{
        path: "/logging-failure",
        middleware: Object.assign(async () => { events.push("middleware"); throw cause; }, { options: {} }),
      }], endpoints: {
        loggingFailure: createAuthEndpoint("/logging-failure", { method: "GET" }, async () => {
          throw new Error("The failed middleware must prevent the endpoint handler");
        }),
      } }],
    });
    await auth.$context;
    events.length = 0;
    logs.length = 0;
    const originalConsole = console.error;
    console.error = (...args: unknown[]) => { events.push("console"); outer.push(args); };
    let response: Response | undefined;
    let caught: unknown;
    try {
      response = await auth.handler(new Request(`${origin}/api/auth/logging-failure`));
    } catch (error) { caught = error; }
    finally { console.error = originalConsole; }
    const http = response ? { status: response.status, headers: [...response.headers], body: await response.text() } : null;
    process.stdout.write(`${JSON.stringify({ case: "http-error-logging", name: scenario.name, events,
      logs: logs.map(([level, message, args]) => [level, message, args.map(argument => argument === cause ? "original" : "replacement")]),
      outer: outer.map(args => [args[0], args[1] === cause ? "original" : "replacement"]),
      outcome: caught === replacement ? "replacement" : caught === cause ? "original" : http?.status,
      response: http })}\n`);
    if ("failure" in scenario || "throwError" in scenario) {
      expect(caught).toBe("failure" in scenario ? replacement : cause);
      expect(response).toBeUndefined();
      expect(logs).toStrictEqual([]);
      expect(outer).toStrictEqual([]);
    } else {
      expect(caught).toBeUndefined();
      expect(http).toStrictEqual({ status: 500, headers: [], body: "" });
      expect(outer).toStrictEqual([["# SERVER_ERROR: ", cause]]);
      if ("disabled" in scenario || "callback" in scenario) {
        expect(logs).toStrictEqual([]);
      } else if ("database" in scenario) {
        expect(logs).toStrictEqual([["error", scenario.message, []]]);
      } else {
        expect(logs).toStrictEqual([["error", scenario.errorName === undefined ? "" : scenario.errorName, [cause]]]);
        expect(logs[0]![2][0]).toBe(cause);
        if (scenario.name === "native-name") expect(logs[0]![1]).toBe(scenario.errorName);
      }
    }
    const expected = ["middleware", "has:name", ...(scenario.errorName === undefined ? [] : ["get:name"]), "get:message", "get:name"];
    if ("throwError" in scenario) expected.push("get:name");
    else if ("disabled" in scenario) expected.push("get:name", "console");
    else if ("callback" in scenario) expected.push("callback", "get:name", "console");
    else {
      expected.push("has:message", "get:message");
      if (!("failure" in scenario && scenario.failure === "message")) {
        const keyword = "database" in scenario ? scenario.message.slice("diagnostic: ".length) : undefined;
        const tests = keyword === undefined ? 5 : ["no column", "column", "relation", "table", "does not exist"].indexOf(keyword) + 1;
        expected.push(...Array(tests).fill("get:message"));
        if (keyword !== undefined) expected.push("get:message", "log", "get:name", "console");
        else {
          expected.push("get:name", "has:name");
          if (scenario.errorName !== undefined) expected.push("get:name");
          if (!("failure" in scenario)) expected.push("log", "get:name", "console");
        }
      }
    }
    expect(events).toStrictEqual(expected);
    expect(database).toStrictEqual(emptyDatabase());
  });
}

for (const callable of [true, false]) {
  test(`HTTP error logging re-reads the message includes method: ${callable ? "native-method" : "non-callable"}`, async () => {
    const events: string[] = [];
    const logs: [string, unknown, unknown[]][] = [];
    const outer: unknown[][] = [];
    const payload = { message: "native logger message" };
    const receiver = { includes: callable ? function (this: unknown, needle: string) {
      expect(this).toBe(receiver);
      events.push(`includes:${needle}`);
      return { matched: true };
    } : 42 };
    let reads = 0;
    let logging = false;
    let loggerReads = 0;
    const cause = new Proxy({ name: "RuntimeFailure", get message() {
      events.push(`message:${++reads}`);
      if (!logging) return "ordinary failure";
      return ++loggerReads === 1 ? "ordinary failure" : loggerReads === 2 ? receiver : payload;
    } }, { has(value, property) {
      if (property === "message") logging = true;
      return Reflect.has(value, property);
    } });
    const database = emptyDatabase();
    const auth = betterAuth({
      baseURL: origin, secret: "http-error-logging-secret-at-least-32-characters",
      database: memoryAdapter(database), telemetry: { enabled: false }, rateLimit: { enabled: false },
      logger: { log(level, message, ...args) { events.push("log"); logs.push([level, message, args]); } },
      plugins: [{ id: "http-error-message-method", middlewares: [{ path: "/logging-failure",
        middleware: Object.assign(async () => { throw cause; }, { options: {} }),
      }], endpoints: { loggingFailure: createAuthEndpoint("/logging-failure", { method: "GET" }, async () => ({ unreachable: true })) } }],
    });
    await auth.$context;
    logs.length = 0;
    const originalConsole = console.error;
    console.error = (...args: unknown[]) => { events.push("console"); outer.push(args); };
    let response: Response | undefined;
    let caught: unknown;
    try { response = await auth.handler(new Request(`${origin}/api/auth/logging-failure`)); }
    catch (error) { caught = error; }
    finally { console.error = originalConsole; }
    const http = response ? { status: response.status, headers: [...response.headers], body: await response.text() } : null;
    process.stdout.write(`${JSON.stringify({ case: "http-error-message-method", callable, events,
      logs: logs.map(([level, message, args]) => [level, message === payload ? "payload" : message,
        args.map(argument => argument === cause ? "original" : "replacement")]),
      outer: outer.map(args => [args[0], args[1] === cause ? "original" : "replacement"]),
      response: http,
      error: caught instanceof Error ? { name: caught.name, message: caught.message } : null })}\n`);
    if (callable) {
      expect(caught).toBeUndefined();
      expect(http).toStrictEqual({ status: 500, headers: [], body: "" });
      expect(logs).toStrictEqual([["error", payload, []]]);
      expect(logs[0]![1]).toBe(payload);
      expect(outer).toStrictEqual([["# SERVER_ERROR: ", cause]]);
      expect(events).toStrictEqual(["message:1", "message:2", "message:3", "includes:no column", "message:4", "log", "console"]);
    } else {
      expect(caught).toBeInstanceOf(TypeError);
      expect(response).toBeUndefined();
      expect(logs).toStrictEqual([]);
      expect(outer).toStrictEqual([]);
      expect(events).toStrictEqual(["message:1", "message:2", "message:3"]);
    }
    expect(database).toStrictEqual(emptyDatabase());
  });
}
