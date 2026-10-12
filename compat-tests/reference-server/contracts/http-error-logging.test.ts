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
    let selectedName = false;
    const target: Record<string, unknown> = { message: scenario.message };
    if (scenario.errorName !== undefined) target.name = scenario.errorName;
    const cause = new Proxy(target, {
      has(value, property) {
        if (property === "name" || property === "message") events.push(`has:${property}`);
        if (property === "name") selectedName = true;
        return Reflect.has(value, property);
      },
      get(value, property, receiver) {
        if (property === "name" || property === "message") events.push(`get:${property}`);
        if ("failure" in scenario && (scenario.failure === "message" && property === "message"
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
    if ("failure" in scenario || "throwError" in scenario) {
      expect(caught).toBe("failure" in scenario ? replacement : cause);
      expect(response).toBeUndefined();
      expect(logs).toStrictEqual([]);
      expect(outer).toStrictEqual([]);
    } else {
      expect(caught).toBeUndefined();
      expect(response!.status).toBe(500);
      expect([...response!.headers]).toStrictEqual([]);
      expect(await response!.text()).toBe("");
      expect(outer).toStrictEqual([["# SERVER_ERROR: ", cause]]);
      if ("disabled" in scenario || "callback" in scenario) {
        expect(logs).toStrictEqual([]);
        expect(events.filter(event => event.startsWith("has:") || event === "get:message")).toStrictEqual([]);
      } else if ("database" in scenario) {
        expect(logs).toStrictEqual([["error", scenario.message, []]]);
      } else {
        expect(logs).toStrictEqual([["error", scenario.errorName === undefined ? "" : scenario.errorName, [cause]]]);
        expect(logs[0]![2][0]).toBe(cause);
        if (scenario.name === "native-name") expect(logs[0]![1]).toBe(scenario.errorName);
      }
    }
    expect(database).toStrictEqual(emptyDatabase());
    process.stdout.write(`${JSON.stringify({ case: "http-error-logging", name: scenario.name, events,
      logs: logs.map(([level, message, args]) => [level, message, args.map(argument => argument === cause ? "original" : "replacement")]),
      outer: outer.map(args => [args[0], args[1] === cause ? "original" : "replacement"]),
      outcome: caught === replacement ? "replacement" : caught === cause ? "original" : "500" })}\n`);
  });
}
