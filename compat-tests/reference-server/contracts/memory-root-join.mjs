import assert from "node:assert/strict";
import { expect, test } from "bun:test";
import { runWithEndpointContext } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { date } from "./memory-graph-clone.mjs";

const session = () => ({
  id: "session", token: "token", userId: "owner", expiresAt: date(),
  createdAt: date(), updatedAt: date(), ipAddress: null, userAgent: null,
});

for (const hit of [false, true]) {
  for (const disabled of [false, true]) {
    test(`Memory missing native join hit=${hit} disabled=${disabled}`, async () => {
      const row = session();
      const table = [row];
      const memory = { session: table };
      const logs = [];
      const context = await betterAuth({
        database: memoryAdapter(memory), baseURL: "http://memory-root-join.test",
        secret: "memory-root-join-contract-at-least-thirty-two-characters",
        logger: { disabled, log(level, message, ...args) { logs.push([level, message, args]); } },
        telemetry: { enabled: false }, advanced: { database: { joins: true } },
      }).$context;
      let result;
      let failure;
      try {
        result = await runWithEndpointContext({ context }, () => context.adapter.findOne({
          model: "session", where: [{ field: "token", value: hit ? "token" : "missing" }],
          join: { user: true },
        }));
      } catch (error) { failure = error; }
      if (hit) {
        expect(result).toBeUndefined();
        expect({ name: failure.name, message: failure.message }).toStrictEqual({
          name: "Error", message: "JoinOption model user not found",
        });
      } else {
        expect(failure).toBeUndefined();
        expect(result).toBeNull();
      }
      expect(logs).toStrictEqual(hit && !disabled ? [[
        "error", "[MemoryAdapter] JoinOption model user not found in the DB", [["session"]],
      ]] : []);
      assert.deepStrictEqual(memory, { session: [session()] });
      expect(Object.keys(memory)).toStrictEqual(["session"]);
      expect(memory.session).toBe(table);
      expect(table[0]).toBe(row);
    });
  }
}
