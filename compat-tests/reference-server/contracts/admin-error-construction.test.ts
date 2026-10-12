import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { APIError } from "@better-auth/core/error";
import { APIError as CallError, serializeSignedCookie, toResponse } from "better-call";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { admin } from "better-auth/plugins";
import cases from "../../../tests/fixtures/admin-error-construction-cases.json";

const origin = "http://admin-errors.test";
const secret = "admin-error-construction-contract-secret-at-least-32";
const createdAt = new Date("2025-01-01T00:00:00.000Z");

for (const backend of ["memory", "sqlite"] as const) for (const scenario of cases) {
  test(`Admin ${scenario.name} preserves native provenance and storage on ${backend}`, async () => {
    const sql = backend === "sqlite" ? new Database(":memory:") : undefined;
    const memory = { user: [], session: [], account: [], verification: [] };
    const auth = betterAuth({
      baseURL: origin, secret, database: sql ?? memoryAdapter(memory),
      logger: { disabled: true }, telemetry: { enabled: false },
      session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
      plugins: [admin()],
    });
    try {
      if (sql) await (await getMigrations(auth.options)).runMigrations();
      const { adapter } = await auth.$context;
      const cookies: Record<string, string> = {};
      for (const [id, role] of [["actor", "admin"], ["target", "user"]]) {
        await adapter.create({ model: "user", forceAllowId: true, data: {
          id, name: id, email: `${id}@admin-errors.test`, role, emailVerified: true,
          banned: false, createdAt, updatedAt: createdAt,
        } });
        await adapter.create({ model: "session", forceAllowId: true, data: {
          id: `${id}-session`, token: `${id}-token`, userId: id,
          expiresAt: new Date("2099-01-01T00:00:00.000Z"), createdAt, updatedAt: createdAt,
        } });
        cookies[id] = (await serializeSignedCookie("better-auth.session_token", `${id}-token`, secret)).split(";")[0];
      }
      const snapshot = async () => sql
        ? Object.fromEntries(["user", "session", "account", "verification"].map(model => [model, sql.query(`SELECT * FROM "${model}" ORDER BY id`).all()]))
        : structuredClone(memory);
      const stored = await snapshot();
      const headers = scenario.actor === "server" ? undefined : new Headers(
        scenario.actor === "anonymous" ? {} : { cookie: cookies[scenario.actor] },
      );
      let thrown: unknown;
      try {
        await Reflect.apply(auth.api[scenario.operation as keyof typeof auth.api], undefined, [{
          ...(headers === undefined ? {} : { headers }),
          ...("body" in scenario ? { body: scenario.body } : {}),
          ...("query" in scenario ? { query: scenario.query } : {}),
        }]);
      } catch (error) { thrown = error; }
      expect(thrown, scenario.name).toBeInstanceOf(CallError);
      expect(thrown instanceof APIError, scenario.name).toBe(scenario.brand === "BetterAuth");
      const error = thrown as CallError;
      const body = "expectedBody" in scenario ? scenario.expectedBody : undefined;
      expect(error.status, scenario.name).toBe(scenario.status);
      expect(error.statusCode, scenario.name).toBe(scenario.httpStatus);
      expect(error.body, scenario.name).toStrictEqual(body);
      expect(Object.keys(error.body ?? {}), scenario.name).toStrictEqual(Object.keys(body ?? {}));
      const response = toResponse(error);
      expect(response.status, scenario.name).toBe(scenario.httpStatus);
      expect(await response.text(), scenario.name).toBe(body === undefined ? "" : JSON.stringify(body));
      expect(await snapshot(), scenario.name).toStrictEqual(stored);
    } finally { sql?.close(); }
  });
}
