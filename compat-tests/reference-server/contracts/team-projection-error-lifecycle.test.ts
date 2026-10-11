import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { getCurrentAuthEndpointContext, runWithEndpointContext, tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
const models = ["user", "session", "account", "verification", "organization", "member", "invitation", "team", "teamMember"] as const;
const date = () => new Date("2030-01-01T00:00:00.000Z");
type Fields = Record<string, unknown>;
type Outcome = { value: unknown } | { error: unknown };

for (const backend of ["memory", "sqlite"] as const) {
  for (const joins of [false, true]) {
    test(`${backend} ${joins ? "native" : "fallback"} Team parent error retains its peer through Team projection`, async () => {
      const memory: Record<string, Fields[]> = Object.fromEntries(models.map(model => [model, []]));
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      const options: BetterAuthOptions = {
        database: database ?? memoryAdapter(memory), baseURL: "http://team-projection-lifetime.test",
        secret: "team-projection-lifetime-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        advanced: { database: { joins } }, plugins: [organization({ teams: { enabled: true } })],
      };
      const snapshot = () => Object.fromEntries(models.map(model => [model, structuredClone(database
        ? database.query(`SELECT * FROM "${model}" ORDER BY id`).all()
        : memory[model]!.toSorted((left, right) => String(left.id).localeCompare(String(right.id))))])) as Record<string, Fields[]>;
      const phases = new Map(["teamId:A", "teamId:B", "userId:user", "name:B", "memberCount:1", "memberCount:7"].map(key => [key, {
        started: Promise.withResolvers<void>(), result: Promise.withResolvers<unknown>(),
        finished: Promise.withResolvers<Outcome>(), entered: false,
      }]));
      const phase = (key: string) => {
        const value = phases.get(key);
        if (!value) throw new Error(`Missing Team projection phase ${key}`);
        return value;
      };
      const events: string[] = [];
      const headers = new Headers({ "x-contract": "team-projection-lifetime" });
      const request = new Request("http://team-projection-lifetime.test/team-projection-lifetime", { headers });
      const body = { identity: "retained-team-body" };
      let writer: DBAdapter;
      let pending: Promise<Outcome> | undefined;
      const assertContext = () => {
        const current = getCurrentAuthEndpointContext();
        expect(current.path).toBe("/team-projection-lifetime");
        expect(current.headers?.get("x-contract")).toBe("team-projection-lifetime");
        expect(current.request).toBe(request);
        expect(current.body).toBe(body);
      };
      const field = (name: string) => ({ type: "string" as const, transform: {
        async output(value: unknown) {
          assertContext();
          const key = `${name}:${value}`;
          const gate = phase(key);
          gate.entered = true;
          events.push(`${key}:start`);
          gate.started.resolve();
          try {
            const result = await gate.result.promise;
            assertContext();
            if (name === "name" && value === "B") {
              await writer.update({ model: "team", where: [{ field: "id", value: "B" }],
                update: { memberCount: 7, updatedAt: date() } });
              assertContext();
            }
            events.push(`${key}:resolved`);
            gate.finished.resolve({ value: result });
            return result;
          } catch (error) {
            assertContext();
            events.push(`${key}:rejected`);
            gate.finished.resolve({ error });
            throw error;
          }
        },
      } });
      try {
        if (database) await (await getMigrations(options)).runMigrations();
        const initial = await betterAuth(options).$context;
        writer = initial.adapter;
        await seed(writer, getOrgAdapter(initial, {}));
        const before = snapshot();
        const context = await betterAuth({ ...options, plugins: [organization({ teams: { enabled: true } }), {
          id: "team-projection-lifecycle", schema: {
            teamMember: { fields: {
              teamId: { ...field("teamId"), references: { model: "team", field: "id" } },
              userId: { ...field("userId"), references: { model: "user", field: "id" } },
            } },
            team: { fields: { name: field("name"), memberCount: { ...field("memberCount"), type: "number" } } },
          },
        }] }).$context;
        pending = runWithEndpointContext({ context, path: "/team-projection-lifetime", headers, request, body }, () =>
          getOrgAdapter(context, {}).listTeamsByUser({ userId: "user" }),
        ).then(value => ({ value }), error => ({ error }));
        await Promise.all([phase("teamId:A").started.promise, phase("teamId:B").started.promise]);
        expect(new Set(events)).toStrictEqual(new Set(["teamId:A:start", "teamId:B:start"]));
        expect(events).toHaveLength(2);
        const started = events.slice();
        const original = new Error("original-team-parent-error");
        phase("teamId:A").result.reject(original);
        const outcome = await pending;
        expect("error" in outcome ? outcome.error : undefined).toBe(original);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(snapshot()).toStrictEqual(before);
        expect(events).toStrictEqual([...started, "teamId:A:rejected"]);
        // Release the parent peer only after the caller receives the original error.
        phase("teamId:B").result.resolve("B");
        await phase("userId:user").started.promise;
        phase("userId:user").result.resolve("user");
        await phase("name:B").started.promise;
        phase("name:B").result.resolve("B-visible");
        const count = backend === "memory" ? "memberCount:7" : "memberCount:1";
        await phase(count).started.promise;
        const late = new Error("late-team-peer-error");
        phase(count).result.reject(late);
        const completed = await phase(count).finished.promise;
        expect("error" in completed ? completed.error : undefined).toBe(late);
        expect("error" in outcome ? outcome.error : undefined).toBe(original);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(events).toStrictEqual([
          ...started, "teamId:A:rejected", "teamId:B:resolved", "userId:user:start", "userId:user:resolved",
          "name:B:start", "name:B:resolved", `${count}:start`, `${count}:rejected`,
        ]);
        const expected = structuredClone(before);
        const row = expected.team!.find(row => row.id === "B");
        if (!row) throw new Error("Missing expected Team peer storage");
        row.memberCount = 7;
        expect(snapshot()).toStrictEqual(expected);
      } finally {
        for (const gate of phases.values()) gate.result.resolve("cleanup");
        if (pending) await pending;
        for (const gate of phases.values()) if (gate.entered) await gate.finished.promise;
        database?.close();
      }
    }, 10_000);
  }
}

async function seed(adapter: DBAdapter, org: { findOrCreateTeamMember(data: Fields): Promise<unknown> }) {
  await adapter.create({ model: "user", forceAllowId: true, data: {
    id: "user", name: "User", email: "user@team-temporal.test", emailVerified: false,
    image: null, createdAt: date(), updatedAt: date(),
  } });
  await adapter.create({ model: "organization", forceAllowId: true, data: {
    id: "organization", name: "Organization", slug: "organization", logo: null, metadata: null, createdAt: date(),
  } });
  for (const name of ["A", "B"]) {
    await adapter.create({ model: "team", forceAllowId: true, data: {
      id: name, name, memberCount: 0, organizationId: "organization", createdAt: date(), updatedAt: date(),
    } });
    await org.findOrCreateTeamMember({ teamId: name, userId: "user" });
    await adapter.update({ model: "team", where: [{ field: "id", value: name }], update: { updatedAt: date() } });
  }
}
