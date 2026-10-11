import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import { Database } from "bun:sqlite";
import { getCurrentAuthEndpointContext, runWithEndpointContext, tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

test("Session/User references fail before queries and preserve complete controls", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/session-user-join-reference-1.7.6.json", import.meta.url)).json();
  const capture = fileURLToPath(new URL("session-user-join-reference-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);

for (const backend of ["memory", "sqlite"] as const) {
  for (const mode of ["fallback", "native", "delete"] as const) {
    const joins = mode === "native", deleting = mode === "delete";
    test(`${backend} Session ${mode} retains a blocked parent after the original error`, async () => {
      type Row = Record<string, unknown>;
      type Outcome = { value: unknown } | { error: unknown };
      const tables = ["user", "session", "account", "verification"] as const;
      const memory: Record<string, Row[]> = Object.fromEntries(tables.map(table => [table, []]));
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      const token = "session-user-join-existing-token";
      const tokens = [token, `${token}-b`];
      const date = () => new Date("2030-01-02T03:04:05.000Z");
      const options: BetterAuthOptions = {
        database: database ?? memoryAdapter(memory), baseURL: "http://retained-session.test",
        secret: "session-user-join-reference-contract-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        advanced: { database: { joins } },
        session: { additionalFields: { ownerRef: { type: "string", required: false } } },
      };
      const snapshot = () => Object.fromEntries(tables.map(table => [table, structuredClone(database
        ? database.query(`SELECT * FROM "${table}" ORDER BY id`).all()
        : memory[table]!.toSorted((left, right) => String(left.id).localeCompare(String(right.id))))])) as Record<string, Row[]>;
      const phases = new Map([
        ...tokens.map(value => `token:${value}`), "userAgent:session-user-join-reference",
        "name:User a", "name:User b", "image:image-a", "image:image-b", "image:after-release",
      ].map(key => [key, {
        started: Promise.withResolvers<void>(), result: Promise.withResolvers<unknown>(),
        finished: Promise.withResolvers<Outcome>(),
      }]));
      const phase = (key: string) => {
        const value = phases.get(key);
        if (!value) throw new Error(`Missing retained Session phase ${key}`);
        return value;
      };
      const parents = Promise.withResolvers<void>();
      const deleted = Promise.withResolvers<Outcome>();
      const resume = Promise.withResolvers<void>();
      const events: string[] = [];
      const hooks: string[] = [];
      const headers = new Headers({ "x-contract": "retained-session" });
      const request = new Request("http://retained-session.test/retained-session", { headers });
      const body = { identity: "retained-session-body" };
      let writer: DBAdapter;
      let pending: Promise<Outcome> | undefined;
      const assertContext = () => {
        const current = getCurrentAuthEndpointContext();
        expect(current.path).toBe("/retained-session");
        expect(current.headers?.get("x-contract")).toBe("retained-session");
        expect(current.request).toBe(request);
        expect(current.request?.headers.get("x-contract")).toBe("retained-session");
        expect(current.body).toBe(body);
      };
      const field = (name: string) => ({ type: "string" as const, transform: {
        async output(value: unknown) {
          assertContext();
          const key = `${name}:${value}`, gate = phase(key);
          events.push(`${key}:start`);
          gate.started.resolve();
          if (name === "token" && events.length === 2) parents.resolve();
          try {
            const result = await gate.result.promise;
            assertContext();
            if (name === "name") {
              if (typeof value !== "string" || !value.startsWith("User ")) throw new Error("Expected seeded Session User name");
              await writer.update({ model: "user", where: [{ field: "id", value: `user-${value.slice(5)}` }],
                update: { image: "after-release", updatedAt: date() } });
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
        for (const suffix of ["a", "b", "c"]) {
          await writer.create({ model: "user", forceAllowId: true, data: {
            id: `user-${suffix}`, name: `User ${suffix}`, email: `${suffix}@session-user-join-reference.test`,
            emailVerified: true, image: `image-${suffix}`, createdAt: date(), updatedAt: date(),
          } });
        }
        for (const suffix of ["a", "b"]) {
          await writer.create({ model: "session", forceAllowId: true, data: {
            id: `session-${suffix}`, token: suffix === "a" ? token : `${token}-b`, userId: `user-${suffix}`,
            expiresAt: new Date("2100-01-02T03:04:05.000Z"), createdAt: date(), updatedAt: date(),
            ipAddress: "203.0.113.8", userAgent: "session-user-join-reference", ownerRef: suffix === "a" ? "user-b" : "user-a",
          } });
        }
        const before = snapshot();
        const afterDelete = structuredClone(before);
        expect(afterDelete.session).toHaveLength(2);
        afterDelete.session = [];
        const context = await betterAuth({ ...options,
          session: { additionalFields: { ...options.session?.additionalFields,
            token: { ...field("token"), required: true, unique: true }, userAgent: field("userAgent"),
          } },
          user: { additionalFields: { name: { ...field("name"), required: true }, image: field("image") } },
          databaseHooks: { session: { delete: {
            before: async () => { hooks.push("before"); },
            after: async () => { hooks.push("after"); },
          } } },
        }).$context;
        pending = runWithEndpointContext({ context, path: "/retained-session", headers, request, body },
          async () => {
            if (!deleting) return context.internalAdapter.findSessions(tokens);
            const result = await context.internalAdapter.deleteSessions(tokens)
              .then(value => ({ value }), error => ({ error }));
            deleted.resolve(result);
            if ("error" in result) throw result.error;
            await resume.promise;
            assertContext();
            expect(await context.internalAdapter.findSessions(tokens)).toStrictEqual([]);
            return result.value;
          },
        ).then(value => ({ value }), error => ({ error }));
        await parents.promise;
        expect(events).toHaveLength(2);
        // Session queries have no ORDER BY. Derive the selected peers from the observed gates.
        const selected = events.map(event => {
          if (!event.startsWith("token:") || !event.endsWith(":start")) throw new Error(`Unexpected Session event ${event}`);
          return event.slice("token:".length, -":start".length);
        });
        expect(new Set(selected)).toStrictEqual(new Set(tokens));
        const [rejected, peer] = selected as [string, string];
        const initial = events.slice();
        const original = new Error(deleting ? "original-session-delete-error" : "original-session-parent-error");
        phase(`token:${rejected}`).result.reject(original);
        const outcome = await (deleting ? deleted.promise : pending);
        if (deleting) expect(outcome).toStrictEqual({ value: undefined });
        else expect("error" in outcome ? outcome.error : undefined).toBe(original);
        const rejectedCompletion = await phase(`token:${rejected}`).finished.promise;
        expect("error" in rejectedCompletion ? rejectedCompletion.error : undefined).toBe(original);
        expect(events).toStrictEqual([...initial, `token:${rejected}:rejected`]);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(hooks).toStrictEqual([]);
        expect(snapshot()).toStrictEqual(deleting ? afterDelete : before);
        phase(`token:${peer}`).result.resolve(peer);
        await phase("userAgent:session-user-join-reference").started.promise;
        if (deleting) {
          const late = new Error("late-session-delete-error");
          phase("userAgent:session-user-join-reference").result.reject(late);
          const completed = await phase("userAgent:session-user-join-reference").finished.promise;
          expect("error" in completed ? completed.error : undefined).toBe(late);
          resume.resolve();
          expect(await pending).toStrictEqual({ value: undefined });
          expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
          expect(events).toStrictEqual([
            ...initial, `token:${rejected}:rejected`, `token:${peer}:resolved`,
            "userAgent:session-user-join-reference:start", "userAgent:session-user-join-reference:rejected",
          ]);
          expect(hooks).toStrictEqual([]);
          expect(snapshot()).toStrictEqual(afterDelete);
          return;
        }
        phase("userAgent:session-user-join-reference").result.resolve("session-user-join-reference");
        const suffix = peer === token ? "a" : "b";
        await phase(`name:User ${suffix}`).started.promise;
        phase(`name:User ${suffix}`).result.resolve(`User ${suffix}`);
        const image = backend === "memory" ? "after-release" : `image-${suffix}`;
        await phase(`image:${image}`).started.promise;
        phase(`image:${image}`).result.resolve(image);
        expect(await phase(`image:${image}`).finished.promise).toStrictEqual({ value: image });
        expect("error" in outcome ? outcome.error : undefined).toBe(original);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(events).toStrictEqual([
          ...initial, `token:${rejected}:rejected`, `token:${peer}:resolved`,
          "userAgent:session-user-join-reference:start", "userAgent:session-user-join-reference:resolved",
          `name:User ${suffix}:start`, `name:User ${suffix}:resolved`, `image:${image}:start`, `image:${image}:resolved`,
        ]);
        const expected = structuredClone(before);
        const user = expected.user!.find(row => row.id === `user-${suffix}`);
        if (!user) throw new Error("Expected retained Session User in complete storage");
        user.image = "after-release";
        expect(snapshot()).toStrictEqual(expected);
      } finally {
        for (const gate of phases.values()) gate.result.resolve("cleanup");
        resume.resolve();
        if (pending) await pending;
        database?.close();
      }
    }, 10_000);
  }
}
