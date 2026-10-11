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
type Case = "user" | "organization";
type Fields = Record<string, unknown>;
type Outcome = { value: unknown } | { error: unknown };

for (const backend of ["memory", "sqlite"] as const) {
  for (const kind of ["user", "organization"] as const) {
    test(`${backend} ${kind} returns the original error before a retained projection peer settles`, async () => {
      const memory: Record<string, Fields[]> = Object.fromEntries(models.map(model => [model, []]));
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      const options: BetterAuthOptions = {
        database: database ?? memoryAdapter(memory), baseURL: "http://projection-lifetime.test",
        secret: "projection-lifetime-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        advanced: { database: { joins: false } }, plugins: [organization({ teams: { enabled: true } })],
      };
      const snapshot = () => Object.fromEntries(models.map(model => [model, structuredClone(database
        ? database.query(`SELECT * FROM "${model}" ORDER BY id`).all()
        : memory[model]!.toSorted((left, right) => String(left.id).localeCompare(String(right.id))))])) as Record<string, Fields[]>;
      const phases = new Map([
        "parent:A-parent", "parent:B-parent", "name:A", "name:B", "image:A.png", "image:B.png", "image:after-release",
      ].map(key => [key, {
        started: Promise.withResolvers<void>(), result: Promise.withResolvers<unknown>(),
        finished: Promise.withResolvers<Outcome>(),
      }]));
      const phase = (key: string) => {
        const value = phases.get(key);
        if (!value) throw new Error(`Missing projection phase ${key}`);
        return value;
      };
      const events: string[] = [];
      const headers = new Headers({ "x-contract": "projection-lifetime" });
      const request = new Request("http://projection-lifetime.test/projection-lifetime", { headers });
      const body = { identity: "retained-body" };
      let writer: DBAdapter;
      let pending: Promise<Outcome> | undefined;
      const assertContext = () => {
        const current = getCurrentAuthEndpointContext();
        expect(current.path).toBe("/projection-lifetime");
        expect(current.headers?.get("x-contract")).toBe("projection-lifetime");
        expect(current.request).toBe(request);
        expect(current.body).toBe(body);
      };
      const field = (name: string) => ({ type: "string" as const, transform: {
        async output(value: unknown) {
          assertContext();
          const key = `${name}:${value}`;
          const gate = phase(key);
          events.push(`${key}:start`);
          gate.started.resolve();
          try {
            const result = await gate.result.promise;
            assertContext();
            if (name === "name" && value === "B") {
              await writer.update({ model: kind, where: [{ field: "id", value: "B" }],
                update: kind === "user" ? { image: "after-release", updatedAt: date() } : { logo: "after-release" } });
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
        writer = (await betterAuth(options).$context).adapter;
        await seed(writer, kind);
        const before = snapshot();
        const context = await betterAuth({
          ...options,
          ...(kind === "user" ? { user: { additionalFields: { name: field("name"), image: field("image") } } } : {}),
          plugins: [organization({ teams: { enabled: true }, ...(kind === "organization" ? { schema: {
            member: { additionalFields: { role: field("parent") } },
            organization: { additionalFields: { name: field("name"), logo: field("image") } },
          } } : {}) })],
        }).$context;
        pending = runWithEndpointContext({ context, path: "/projection-lifetime", headers, request, body }, () =>
          kind === "user"
            ? context.adapter.findMany({ model: "user", sortBy: { field: "email", direction: "asc" } })
            : getOrgAdapter(context, {}).listOrganizations("A"),
        ).then(value => ({ value }), error => ({ error }));
        const initialKeys = kind === "user" ? ["name:A", "name:B"] : ["parent:A-parent", "parent:B-parent"];
        await Promise.all(initialKeys.map(key => phase(key).started.promise));
        expect(new Set(events)).toStrictEqual(new Set(initialKeys.map(key => `${key}:start`)));
        expect(events).toHaveLength(2);
        const initial = events.slice();
        if (kind === "organization") {
          phase("parent:A-parent").result.resolve("A-parent");
          await phase("name:A").started.promise;
        }
        const original = new Error("original-projection-error");
        phase("name:A").result.reject(original);
        const outcome = await pending;
        expect("error" in outcome ? outcome.error : undefined).toBe(original);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(snapshot()).toStrictEqual(before);
        expect(events).toStrictEqual([
          ...initial,
          ...(kind === "organization" ? ["parent:A-parent:resolved", "name:A:start"] : []),
          "name:A:rejected",
        ]);
        // The peer remains blocked until the caller has received the original error.
        if (kind === "organization") {
          phase("parent:B-parent").result.resolve("B-parent");
          await phase("name:B").started.promise;
        }
        phase("name:B").result.resolve("B-visible");
        const image = backend === "memory" ? "image:after-release" : "image:B.png";
        await phase(image).started.promise;
        const late = new Error("late-peer-error");
        if (kind === "organization") phase(image).result.reject(late);
        else phase(image).result.resolve("B-image-visible");
        const completed = await phase(image).finished.promise;
        if (kind === "organization") expect("error" in completed ? completed.error : undefined).toBe(late);
        else expect(completed).toStrictEqual({ value: "B-image-visible" });
        expect("error" in outcome ? outcome.error : undefined).toBe(original);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(events).toStrictEqual([
          ...initial,
          ...(kind === "organization" ? ["parent:A-parent:resolved", "name:A:start"] : []),
          "name:A:rejected",
          ...(kind === "organization" ? ["parent:B-parent:resolved", "name:B:start"] : []),
          "name:B:resolved", `${image}:start`, `${image}:${kind === "organization" ? "rejected" : "resolved"}`,
        ]);
        const expected = structuredClone(before);
        const row = expected[kind]!.find(row => row.id === "B");
        if (!row) throw new Error("Missing expected peer storage");
        row[kind === "user" ? "image" : "logo"] = "after-release";
        expect(snapshot()).toStrictEqual(expected);
      } finally {
        for (const gate of phases.values()) gate.result.resolve("cleanup");
        if (pending) await pending;
        database?.close();
      }
    }, 10_000);
  }
}

async function seed(adapter: DBAdapter, kind: Case) {
  for (const name of ["A", "B"]) {
    await adapter.create({ model: "user", forceAllowId: true, data: {
      id: name, name, email: `${name}@temporal.test`, emailVerified: false,
      image: `${name}.png`, createdAt: date(), updatedAt: date(),
    } });
    if (kind === "organization") {
      await adapter.create({ model: "organization", forceAllowId: true, data: {
        id: name, name, slug: name, logo: `${name}.png`, metadata: null, createdAt: date(),
      } });
      await adapter.create({ model: "member", forceAllowId: true, data: {
        id: name, organizationId: name, userId: "A", role: `${name}-parent`, createdAt: date(),
      } });
    }
  }
}
