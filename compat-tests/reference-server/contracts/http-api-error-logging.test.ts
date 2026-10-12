import { expect, test } from "bun:test";
import { tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { getColorDepth } from "@better-auth/core/env";
import { betterAuth } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";

const originA = "https://http-api-error-a.test";
const originB = "https://http-api-error-b.test";
const secret = "http-api-error-logging-secret-at-least-thirty-two-characters";
const now = 2_000_000_000_123;
const timestamp = new Date(now).toISOString();
const defaultColors = getColorDepth() !== 1;
const emptyDatabase = () => ({ user: [], session: [], account: [], verification: [] });
const levels = [undefined, "error", "warn", "debug", "info"] as const;
type Log = [string, unknown, unknown[]];

function defaultMessage(message: string) {
  return defaultColors
    ? `\x1b[2m${timestamp}\x1b[0m \x1b[31mERROR\x1b[0m \x1b[1m[Better Auth]:\x1b[0m ${message}`
    : `${timestamp} ERROR [Better Auth]: ${message}`;
}

async function responseSnapshot(response: Response) {
  return {
    status: response.status,
    statusText: response.statusText,
    headers: [...response.headers],
    cookies: response.headers.getSetCookie(),
    body: await response.text(),
  };
}

for (const nested of [false, true]) {
  for (const status of ["FORBIDDEN", "INTERNAL_SERVER_ERROR"] as const) {
    for (const level of levels) {
      for (const disabled of [false, true]) {
        test(`HTTP APIError logger scope nested=${nested} status=${status} level=${level ?? "omitted"} disabled=${disabled}`, async () => {
          const events: unknown[][] = [];
          const logsA: Log[] = [];
          const logsB: Log[] = [];
          const defaults: unknown[][] = [];
          const scopes: { phase: string; context: unknown }[] = [];
          const databaseA = emptyDatabase();
          const databaseB = emptyDatabase();
          const body = {
            message: "Scoped API failure",
            code: "SCOPED_FAILURE",
            details: { retry: false, owner: "B" },
          };
          const errorHeaders = { "x-api-error": "B" };
          const cause = new APIError(status, body, errorHeaders);
          const originalError = Object.getOwnPropertyDescriptors(cause);
          let parentContext: unknown;
          let innerResponse: Awaited<ReturnType<typeof responseSnapshot>> | undefined;
          const observeScope = (phase: string) => {
            const context = tryGetCurrentAuthEndpointContext()?.context;
            scopes.push({ phase, context });
            return context === undefined ? "none" : context === parentContext ? "A" : "unexpected";
          };
          const authB = betterAuth({
            baseURL: originB, secret,
            database: memoryAdapter(databaseB), telemetry: { enabled: false }, rateLimit: { enabled: false },
            logger: {
              ...(level === undefined ? {} : { level }), disabled, disableColors: true,
              log(logLevel, message, ...args) {
                logsB.push([logLevel, message, args]);
                events.push(["B:log", observeScope("B:log"), logLevel, message, args]);
              },
            },
            plugins: [{ id: "http-api-error-b", middlewares: [{
              path: "/failure",
              middleware: Object.assign(async () => {
                events.push(["B:middleware", observeScope("B:middleware")]);
                throw cause;
              }, { options: {} }),
            }], endpoints: {
              failure: createAuthEndpoint("/failure", { method: "GET" }, async () => {
                throw new Error("The failed middleware must prevent the B endpoint handler");
              }),
            } }],
          });
          const authA = betterAuth({
            baseURL: originA, secret,
            database: memoryAdapter(databaseA), telemetry: { enabled: false }, rateLimit: { enabled: false },
            logger: { level: "error", disableColors: true,
              log(logLevel, message, ...args) {
                logsA.push([logLevel, message, args]);
                events.push(["A:log", observeScope("A:log"), logLevel, message, args]);
              },
            },
            plugins: [{ id: "http-api-error-a", endpoints: {
              nested: createAuthEndpoint("/nested", { method: "GET" }, async ctx => {
                parentContext = ctx.context;
                events.push(["A:enter", observeScope("A:enter")]);
                const response = await authB.handler(new Request(`${originB}/api/auth/failure`));
                events.push(["A:restored", observeScope("A:restored")]);
                innerResponse = await responseSnapshot(response.clone());
                return response;
              }),
            } }],
          });
          const rootA = await authA.$context;
          const rootB = await authB.$context;
          const rootBefore = {
            A: { baseURL: rootA.baseURL, optionURL: rootA.options.baseURL },
            B: { baseURL: rootB.baseURL, optionURL: rootB.options.baseURL },
          };
          events.length = 0;
          logsA.length = 0;
          logsB.length = 0;
          scopes.length = 0;
          const originalConsole = console.error;
          let response: Response | undefined;
          let caught: unknown;
          try {
            console.error = (...args: unknown[]) => {
              defaults.push(args);
              events.push(["default", observeScope("default"), args]);
            };
            await withClock(async setClock => {
              setClock(now);
              response = nested
                ? await authA.handler(new Request(`${originA}/api/auth/nested`))
                : await authB.handler(new Request(`${originB}/api/auth/failure`));
            });
          } catch (error) {
            caught = error;
          } finally {
            console.error = originalConsole;
          }
          const http = response === undefined ? undefined : await responseSnapshot(response);
          events.push(["response", http]);
          const errorObservation = {
            name: cause.name, message: cause.message, status: cause.status,
            statusCode: cause.statusCode, body: cause.body, headers: cause.headers,
            keys: Object.keys(cause),
          };
          process.stdout.write(`${JSON.stringify({
            case: "http-api-error-logging", nested, status, level: level ?? "omitted", disabled,
            timestamp, defaultColors, error: errorObservation,
            events, logsA, logsB, defaults, response: http, innerResponse,
            originalArguments: logsB.map(([, , args]) => args.map(argument => argument === cause)),
            caught: caught === undefined ? null : { original: caught === cause, value: String(caught) },
            databaseA, databaseB,
          })}\n`);

          expect(caught).toBeUndefined();
          const expectedResponse = {
            status: status === "FORBIDDEN" ? 403 : 500,
            statusText: status,
            headers: [["content-type", "application/json"], ["x-api-error", "B"]],
            cookies: [],
            body: JSON.stringify(body),
          };
          expect(http).toStrictEqual(expectedResponse);
          expect(innerResponse).toStrictEqual(nested ? expectedResponse : undefined);
          const instanceLog = !disabled && status === "INTERNAL_SERVER_ERROR";
          const proxyLog = !disabled && (level === "error" || level === "warn" || level === "debug");
          expect(logsB).toStrictEqual(instanceLog ? [["error", status, [cause]]] : []);
          if (instanceLog) expect(logsB[0]![2][0]).toBe(cause);
          expect(logsA).toStrictEqual(nested && proxyLog ? [["error", body.message, []]] : []);
          expect(defaults).toStrictEqual(!nested && proxyLog ? [[defaultMessage(body.message)]] : []);
          const expectedEvents: unknown[][] = nested ? [["A:enter", "A"]] : [];
          expectedEvents.push(["B:middleware", nested ? "A" : "none"]);
          if (instanceLog) expectedEvents.push(["B:log", nested ? "A" : "none", "error", status, [cause]]);
          if (proxyLog) expectedEvents.push(nested
            ? ["A:log", "A", "error", body.message, []]
            : ["default", "none", [defaultMessage(body.message)]]);
          if (nested) expectedEvents.push(["A:restored", "A"]);
          expectedEvents.push(["response", expectedResponse]);
          expect(events).toStrictEqual(expectedEvents);
          for (const observation of scopes) expect(observation.context).toBe(nested ? parentContext : undefined);
          if (nested) expect(parentContext).not.toBe(rootA);
          expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
          expect(Object.getOwnPropertyDescriptors(cause)).toStrictEqual(originalError);
          expect(cause.body).toBe(body);
          expect(cause.headers).toBe(errorHeaders);
          expect({
            A: { baseURL: rootA.baseURL, optionURL: rootA.options.baseURL },
            B: { baseURL: rootB.baseURL, optionURL: rootB.options.baseURL },
          }).toStrictEqual(rootBefore);
          expect(databaseA).toStrictEqual(emptyDatabase());
          expect(databaseB).toStrictEqual(emptyDatabase());
        });
      }
    }
  }
}
