import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { secondaryStorageInvocation } from "./secondary-storage-invocation.mjs";

for (const synchronous of [false, true]) {
  test(`Session deletion stops at synchronous invocation failure and retains started peers: ${synchronous}`, async () => {
    const original = { kind: "storage", ownUndefined: undefined };
    const release = Promise.withResolvers<void>();
    const completed = Promise.withResolvers<void>();
    const invoked: string[] = [];
    const deleted: string[] = [];
    const database = { user: [], session: [], account: [], verification: [] };
    const auth = betterAuth({
      database: memoryAdapter(database), baseURL: "http://secondary-invocation.test",
      secret: "secondary-invocation-secret-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      secondaryStorage: secondaryStorageInvocation({
        get() { throw new Error("Token deletion must not read storage"); },
        set() { throw new Error("Token deletion must not write storage"); },
        delete(key: string) {
          invoked.push(key);
          if (key === "failure") throw original;
          const remove = () => { deleted.push(key); };
          if (key === "pending") return release.promise.then(() => { remove(); completed.resolve(); });
          remove();
        },
      }, synchronous),
    });
    const context = await auth.$context;
    let error: unknown;
    try { await context.internalAdapter.deleteSessions(["pending", "failure", "later"]); }
    catch (caught) { error = caught; }
    expect(error).toBe(original);
    expect(invoked).toStrictEqual(synchronous ? ["pending", "failure"] : ["pending", "failure", "later"]);
    expect(deleted).toStrictEqual(synchronous ? [] : ["later"]);
    release.resolve();
    await completed.promise;
    expect(deleted).toStrictEqual(synchronous ? ["pending"] : ["later", "pending"]);
    expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  });
}

test("User refresh catches a synchronous read failure while the started sibling completes after return", async () => {
  const original = { kind: "storage", ownUndefined: undefined };
  const release = Promise.withResolvers<void>();
  const completed = Promise.withResolvers<void>();
  const starts: string[] = [];
  const logs: unknown[][] = [];
  const date = new Date("2030-01-01T00:00:00.000Z");
  const expiresAt = new Date("2100-01-01T00:00:00.000Z");
  const owner = { id: "owner", name: "Original", email: "owner@refresh.test", emailVerified: true,
    image: null, createdAt: date, updatedAt: date };
  const session = { id: "pending", token: "pending", userId: "owner", expiresAt,
    createdAt: date, updatedAt: date, ipAddress: null, userAgent: null };
  const database = { user: [structuredClone(owner)], session: [], account: [], verification: [] };
  const index = JSON.stringify(["failure", "pending"].map(token => ({ token, expiresAt: expiresAt.getTime() })));
  const cached = new Map([["active-sessions-owner", index], ["pending", JSON.stringify({ session, user: owner })]]);
  const auth = betterAuth({
    database: memoryAdapter(database), baseURL: "http://secondary-invocation.test",
    secret: "secondary-invocation-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, logger: { level: "error", log(...args) { logs.push(args); } },
    secondaryStorage: {
      get(key) {
        starts.push(key);
        if (key === "failure") throw original;
        if (key === "pending") return release.promise.then(() => cached.get(key) ?? null);
        return cached.get(key) ?? null;
      },
      set(key, value) { cached.set(key, value); completed.resolve(); },
      delete() { throw new Error("User refresh must not delete cache entries"); },
    },
  });
  const context = await auth.$context;
  const returned = await context.internalAdapter.updateUser("owner", { name: "Updated" });
  expect(starts).toStrictEqual(["active-sessions-owner", "failure", "pending"]);
  expect(logs).toStrictEqual([["error", "Failed to refresh committed user sessions in secondary storage", original]]);
  expect(returned).toStrictEqual(database.user[0]);
  expect(returned?.name).toBe("Updated");
  expect(JSON.parse(cached.get("pending")!).user).toStrictEqual(JSON.parse(JSON.stringify(owner)));
  release.resolve();
  await completed.promise;
  expect(cached.get("active-sessions-owner")).toBe(index);
  expect(JSON.parse(cached.get("pending")!)).toStrictEqual(JSON.parse(JSON.stringify({ session, user: returned })));
  expect(logs[0]?.[2]).toBe(original);
});
