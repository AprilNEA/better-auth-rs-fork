import { expect, test } from "bun:test";
import { runWithAdapter, runWithTransaction } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";

const secret = "secondary-logger-scope-secret-at-least-thirty-two-characters";
const date = new Date("2030-01-01T00:00:00.000Z");
const expiry = new Date("2100-01-01T00:00:00.000Z");
const user = { id: "owner", name: "Owner", email: "owner@scope.test", emailVerified: true, image: null, createdAt: date, updatedAt: date };
const session = { id: "session", token: "token", userId: user.id, expiresAt: expiry, createdAt: date, updatedAt: date, ipAddress: "", userAgent: "" };
const messages = {
  "missing-session": "Session not found in secondary storage",
  "missing-list": "Active sessions list not found in secondary storage",
  "mirror-failure": "Failed to mirror committed session to secondary storage",
  "delete-failure": "Failed to delete committed user sessions from secondary storage",
};

for (const mode of Object.keys(messages) as (keyof typeof messages)[]) {
  for (const nested of [false, true]) {
    test(`Secondary logger keeps instance ownership ${mode} nested=${nested}`, async () => {
      const events: unknown[][] = [];
      const logs: [string, string, unknown, unknown[]][] = [];
      const cause = new Error("cache failure");
      const causeBefore = Object.getOwnPropertyDescriptors(cause);
      const database = { user: [{ ...user }], session: mode === "mirror-failure" ? [] : [{ ...session }], account: [], verification: [] };
      const databaseA = { user: [], session: [], account: [], verification: [] };
      const cache = new Map<string, string>();
      if (mode === "missing-session") cache.set("token", "{}");
      if (mode === "missing-list") cache.set("token", JSON.stringify({ session }));
      if (mode === "delete-failure") {
        cache.set("active-sessions-owner", JSON.stringify([{ token: "token", expiresAt: expiry.getTime() }]));
        cache.set("token", JSON.stringify({ session, user }));
      }
      const beforeCache = [...cache];
      const log = (owner: string) => (level: string, message: unknown, ...args: unknown[]) => {
        logs.push([owner, level, message, args]);
        events.push(["log", owner, level, message, args.map(value => ({ original: value === cause }))]);
      };
      const authB = betterAuth({
        baseURL: "https://secondary-b.test", secret, database: memoryAdapter(database),
        session: { storeSessionInDatabase: true }, telemetry: { enabled: false },
        advanced: { database: { generateId: ({ model }) => `${model}-created` } },
        logger: { disableColors: true, log: log("B") },
        secondaryStorage: {
          async get(key) {
            events.push(["get", key]);
            if (mode === "mirror-failure") throw cause;
            return cache.get(key) ?? null;
          },
          async set(key, value, ttl) {
            events.push(["set", key, value, ttl]);
            cache.set(key, value);
          },
          async delete(key) {
            events.push(["delete", key]);
            if (mode === "delete-failure") throw cause;
            cache.delete(key);
          },
        },
      });
      const contextB = await authB.$context;
      let created: unknown;
      const operation = async () => {
        if (mode === "mirror-failure" || mode === "delete-failure") {
          await runWithTransaction(contextB.adapter, async () => {
            if (mode === "mirror-failure") {
              created = await contextB.internalAdapter.createSession(user.id, false, { ...session, id: undefined }, true, { deferSecondaryStorageWrites: true });
            } else {
              await contextB.internalAdapter.deleteUser(user.id);
            }
          });
        } else {
          await runWithAdapter(contextB.adapter, () => contextB.internalAdapter.deleteSession("token"));
        }
        return { complete: true };
      };
      const authA = betterAuth({
        baseURL: "https://secondary-a.test", secret, database: memoryAdapter(databaseA), telemetry: { enabled: false },
        logger: { disableColors: true, log: log("A") },
        plugins: [{ id: "secondary-logger-scope", endpoints: {
          callStore: createAuthEndpoint("/call-store", { method: "GET" }, operation),
        } }],
      });
      await authA.$context;
      events.length = 0;
      logs.length = 0;
      const result = nested ? await authA.api.callStore() : await operation();
      const expectedLog = ["log", "B", "error", messages[mode], mode.endsWith("failure") ? [{ original: true }] : []];
      const expectedEvents = mode === "missing-session"
        ? [["get", "token"], expectedLog]
        : mode === "missing-list"
          ? [["get", "token"], ["get", "active-sessions-owner"], expectedLog, ["delete", "token"]]
          : mode === "mirror-failure"
            ? [["get", "active-sessions-owner"], expectedLog]
            : [["get", "active-sessions-owner"], ["delete", "token"], expectedLog];
      process.stdout.write(`${JSON.stringify({ case: "secondary-logger-scope", mode, nested, events, result, created, database, databaseA, cache: [...cache] })}\n`);
      expect(events).toStrictEqual(expectedEvents);
      expect(logs).toStrictEqual([["B", "error", messages[mode], mode.endsWith("failure") ? [cause] : []]]);
      if (mode.endsWith("failure")) expect(logs[0][3][0]).toBe(cause);
      expect(Object.getOwnPropertyDescriptors(cause)).toStrictEqual(causeBefore);
      expect(result).toStrictEqual({ complete: true });
      expect(databaseA).toStrictEqual({ user: [], session: [], account: [], verification: [] });
      expect(database).toStrictEqual({
        user: mode === "delete-failure" ? [] : [user],
        session: mode === "mirror-failure" ? [{ ...session, id: "session-created" }] : mode === "missing-session" ? [session] : [],
        account: [], verification: [],
      });
      expect(created).toStrictEqual(mode === "mirror-failure" ? { ...session, id: "session-created" } : undefined);
      expect([...cache]).toStrictEqual(mode === "missing-list" ? [] : beforeCache);
    });
  }
}
