import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { getCurrentAuthEndpointContext, runWithEndpointContext, tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

for (const backend of ["memory", "sqlite"] as const) {
  for (const asynchronous of [false, true]) {
    for (const reject of [false, true]) {
      test(`${backend} ordinary account join: async=${asynchronous}, reject=${reject}`, async () => {
        let armed = false;
        const events: string[] = [];
        const ownerB = Promise.withResolvers<void>();
        const phases = new Map(
          ["access:A", "access:B", "refresh:A", "refresh:B"].map(key => [key, {
            started: Promise.withResolvers<void>(),
            result: Promise.withResolvers<unknown>(),
          }]),
        );
        const phase = (key: string) => {
          const value = phases.get(key);
          if (!value) throw new Error(`Missing ordinary field phase ${key}`);
          return value;
        };
        const original = new Error("ordinary token output failed");
        const output = (name: string) => (value: unknown) => {
          if (!armed) return value;
          const key = `${name}:${value}`;
          events.push(key);
          if (asynchronous) {
            phase(key).started.resolve();
            return phase(key).result.promise;
          }
          if (reject && key === "access:A") throw original;
          return `${value}:${name}`;
        };
        const database = backend === "sqlite" ? new Database(":memory:") : undefined;
        const options = {
          database: database ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
          baseURL: "http://account-owner-batch.test",
          secret: "ordinary-account-field-fixture-secret-32-characters",
          logger: { disabled: true },
          user: { additionalFields: { name: { type: "string" as const, transform: {
            output(value: unknown) {
              if (armed) {
                events.push(`user:${value}`);
                if (value === "B") ownerB.resolve();
              }
              return value;
            },
          } } } },
          account: { additionalFields: {
            accessToken: { type: "string" as const, transform: { output: output("access") } },
            refreshToken: { type: "string" as const, transform: { output: output("refresh") } },
          } },
        };
        try {
          if (database) await (await getMigrations(options)).runMigrations();
          const { adapter } = await betterAuth(options).$context;
          for (const name of ["A", "B"]) {
            const user = await adapter.create({ model: "user", data: {
              name, email: `${name.toLowerCase()}@account-owner-batch.test`, emailVerified: true,
              createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
            } });
            await adapter.create({ model: "account", data: {
              userId: user.id, providerId: "ordinary", accountId: `ordinary-${name}`,
              accessToken: name, refreshToken: name,
              createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
            } });
          }
          armed = true;
          // Distinct accounts exercise the shared join projection without an identity collision.
          const pending = adapter.findMany({
            model: "account", sortBy: { field: "accountId", direction: "asc" }, join: { user: true },
          }).then(rows => ({ rows }), error => ({ error }));
          if (asynchronous) {
            await Promise.all([phase("access:A").started.promise, phase("access:B").started.promise]);
            if (reject) phase("access:A").result.reject(original);
            phase("access:B").result.resolve("B:access");
            await phase("refresh:B").started.promise;
            phase("refresh:B").result.resolve("B:refresh");
            await ownerB.promise;
            expect(events).toStrictEqual(["access:A", "access:B", "refresh:B", "user:B"]);
            if (!reject) {
              phase("access:A").result.resolve("A:access");
              await phase("refresh:A").started.promise;
              phase("refresh:A").result.resolve("A:refresh");
            }
          }
          const outcome = await pending;
          // Promise.all may reject before a successful peer finishes its owner projection.
          await ownerB.promise;
          if (reject) {
            expect("error" in outcome && outcome.error).toBe(original);
            expect(events).toStrictEqual(["access:A", "access:B", "refresh:B", "user:B"]);
          } else {
            if (!("rows" in outcome)) throw outcome.error;
            expect(outcome.rows.map((row: any) => ({
              access: row.accessToken, refresh: row.refreshToken, owner: row.user.name,
            }))).toStrictEqual([
              { access: "A:access", refresh: "A:refresh", owner: "A" },
              { access: "B:access", refresh: "B:refresh", owner: "B" },
            ]);
            expect(events).toStrictEqual(asynchronous
              ? ["access:A", "access:B", "refresh:B", "user:B", "refresh:A", "user:A"]
              : ["access:A", "access:B", "refresh:A", "refresh:B", "user:A", "user:B"]);
          }
        } finally {
          database?.close();
        }
      });
    }
  }
}

test("Memory Account owner number selectors match ordinary reads with native joins", async () => {
  const date = new Date("2030-01-01T00:00:00.000Z");
  const user = {
    id: "selector-owner", name: "Selector owner", email: "selector-owner@example.test",
    emailVerified: true, image: null, createdAt: date, updatedAt: date,
  };
  const account = {
    id: "numeric-provider", accountId: "shared-subject", providerId: 1, userId: user.id,
    accessToken: null, refreshToken: null, idToken: null, accessTokenExpiresAt: null,
    refreshTokenExpiresAt: null, scope: null, password: null, createdAt: date, updatedAt: date,
  };
  const data = {
    user: [user], session: [], verification: [],
    account: [account, { ...account, id: "string-decoy", providerId: "01" }],
  };
  const before = structuredClone(data);
  for (const joins of [false, true]) {
    const events: unknown[] = [];
    const context = await betterAuth({
      database: memoryAdapter(data),
      baseURL: "http://account-owner-selector.test",
      secret: "ordinary-account-selector-secret-32-characters",
      logger: { disabled: true },
      advanced: { database: { joins } },
      account: { additionalFields: { providerId: {
        type: "number", transform: { input(value) { events.push(["provider-input", value]); return value; } },
      } } },
    }).$context;
    const selector = { providerId: "01", accountId: "shared-subject" };
    expect(await context.internalAdapter.findAccountByKey(selector)).toStrictEqual(account);
    expect(await context.internalAdapter.findAccountOwnerByKey(selector)).toStrictEqual({
      kind: "owned", user, account,
    });
    expect(events).toStrictEqual([]);
    expect(data).toStrictEqual(before);
  }
});

for (const backend of ["memory", "sqlite"] as const) {
  for (const joins of [false, true]) {
    test(`${backend} Account owner joins=${joins} retains a blocked parent after the original error`, async () => {
      type Row = Record<string, unknown>;
      type Outcome = { value: unknown } | { error: unknown };
      const models = ["user", "account", "session", "verification"] as const;
      const memory: Record<string, Row[]> = Object.fromEntries(models.map(model => [model, []]));
      const database = backend === "sqlite" ? new Database(":memory:") : undefined;
      const date = () => new Date("2030-01-01T00:00:00.000Z");
      const providerId = "retained-provider", accountId = "duplicate-subject";
      const options: BetterAuthOptions = {
        database: database ?? memoryAdapter(memory), baseURL: "http://retained-owner.test",
        secret: "retained-account-owner-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        advanced: { database: { joins, defaultFindManyLimit: 1 } },
      };
      const snapshot = () => Object.fromEntries(models.map(model => [model, structuredClone(database
        ? database.query(`SELECT * FROM "${model}" ORDER BY id`).all()
        : memory[model]!.toSorted((left, right) => String(left.id).localeCompare(String(right.id))))])) as Record<string, Row[]>;
      const phases = new Map([
        ...["accessToken", "refreshToken", "name"].flatMap(name => ["A", "B", "C"].map(label => `${name}:${label}`)),
        ...["A.png", "B.png", "C.png", "after-release"].map(image => `image:${image}`),
      ].map(key => [key, {
        started: Promise.withResolvers<void>(), result: Promise.withResolvers<unknown>(),
        finished: Promise.withResolvers<Outcome>(),
      }]));
      const phase = (key: string) => {
        const value = phases.get(key);
        if (!value) throw new Error(`Missing Account owner phase ${key}`);
        return value;
      };
      const parents = Promise.withResolvers<void>();
      const events: string[] = [];
      const headers = new Headers({ "x-contract": "retained-account-owner" });
      const request = new Request("http://retained-owner.test/retained-account-owner", { headers });
      const body = { identity: "retained-owner-body" };
      let writer: DBAdapter;
      let pending: Promise<Outcome> | undefined;
      const assertContext = () => {
        const current = getCurrentAuthEndpointContext();
        expect(current.path).toBe("/retained-account-owner");
        expect(current.headers?.get("x-contract")).toBe("retained-account-owner");
        expect(current.request).toBe(request);
        expect(current.request?.headers.get("x-contract")).toBe("retained-account-owner");
        expect(current.body).toBe(body);
      };
      const field = (name: string) => ({ type: "string" as const, transform: {
        async output(value: unknown) {
          assertContext();
          const key = `${name}:${value}`, gate = phase(key);
          events.push(`${key}:start`);
          gate.started.resolve();
          if (name === "accessToken" && events.length === 2) parents.resolve();
          try {
            const result = await gate.result.promise;
            assertContext();
            if (name === "name") {
              await writer.update({ model: "user", where: [{ field: "id", value: `user-${value}` }],
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
        const writerContext = await betterAuth(options).$context;
        writer = writerContext.adapter;
        for (const label of ["A", "B", "C"]) {
          await writer.create({ model: "user", forceAllowId: true, data: {
            id: `user-${label}`, name: label, email: `${label}@retained-owner.test`, emailVerified: false,
            image: `${label}.png`, createdAt: date(), updatedAt: date(),
          } });
          await writer.create({ model: "account", forceAllowId: true, data: {
            id: `account-${label}`, providerId, accountId, userId: `user-${label}`,
            accessToken: label, refreshToken: label, createdAt: date(), updatedAt: date(),
          } });
        }
        const before = snapshot();
        const context = await betterAuth({ ...options,
          account: { additionalFields: { accessToken: field("accessToken"), refreshToken: field("refreshToken") } },
          user: { additionalFields: { name: field("name"), image: field("image") } },
        }).$context;
        pending = runWithEndpointContext({ context, path: "/retained-account-owner", headers, request, body },
          () => context.internalAdapter.findAccountOwnerByKey({ providerId, accountId }),
        ).then(value => ({ value }), error => ({ error }));
        await parents.promise;
        expect(events).toHaveLength(2);
        // The owner query has no ORDER BY. Select gates from the two observed parents.
        const labels = events.map(event => {
          const match = /^accessToken:([ABC]):start$/.exec(event);
          if (!match) throw new Error(`Unexpected initial Account owner event ${event}`);
          return match[1]!;
        });
        expect(new Set(labels).size).toBe(2);
        const [rejected, peer] = labels as [string, string];
        const initial = events.slice();
        const original = new Error("original-account-owner-error");
        phase(`accessToken:${rejected}`).result.reject(original);
        const outcome = await pending;
        expect("error" in outcome ? outcome.error : undefined).toBe(original);
        expect(events).toStrictEqual([...initial, `accessToken:${rejected}:rejected`]);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(snapshot()).toStrictEqual(before);
        phase(`accessToken:${peer}`).result.resolve(`${peer}:out`);
        await phase(`refreshToken:${peer}`).started.promise;
        phase(`refreshToken:${peer}`).result.resolve(`${peer}:out`);
        await phase(`name:${peer}`).started.promise;
        phase(`name:${peer}`).result.resolve(`${peer}:out`);
        const image = backend === "memory" ? "after-release" : `${peer}.png`;
        await phase(`image:${image}`).started.promise;
        phase(`image:${image}`).result.resolve(`${image}:out`);
        expect(await phase(`image:${image}`).finished.promise).toStrictEqual({ value: `${image}:out` });
        expect("error" in outcome ? outcome.error : undefined).toBe(original);
        expect(tryGetCurrentAuthEndpointContext()).toBeUndefined();
        expect(events).toStrictEqual([
          ...initial, `accessToken:${rejected}:rejected`, `accessToken:${peer}:resolved`,
          `refreshToken:${peer}:start`, `refreshToken:${peer}:resolved`,
          `name:${peer}:start`, `name:${peer}:resolved`, `image:${image}:start`, `image:${image}:resolved`,
        ]);
        const expected = structuredClone(before);
        const user = expected.user!.find(row => row.id === `user-${peer}`);
        if (!user) throw new Error("Expected retained Account owner's User row");
        user.image = "after-release";
        expect(snapshot()).toStrictEqual(expected);
        const control = await writerContext.internalAdapter.findAccountOwnerByKey({ providerId, accountId })
          .then(value => ({ value }), error => ({ error }));
        if (!("error" in control)) throw new Error("Successful parents must reject duplicate identities");
        expect(control.error).toBeInstanceOf(Error);
        expect((control.error as Error).message).toBe(
          'Multiple accounts match the same accountId for provider "retained-provider". Resolve duplicate account identities before continuing.',
        );
        expect(snapshot()).toStrictEqual(expected);
      } finally {
        for (const gate of phases.values()) gate.result.resolve("cleanup");
        if (pending) await pending;
        database?.close();
      }
    }, 10_000);
  }
}
