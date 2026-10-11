import assert from "node:assert/strict";
import { expect, spyOn, test } from "bun:test";
import { apiKey } from "@better-auth/api-key";
import { logger } from "@better-auth/core/env";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { key } from "./memory-graph-clone.mjs";

async function outcome(action) {
  try { return { value: await action() }; }
  catch (error) { return { error: { name: error.name, message: error.message } }; }
}

// Compare the complete native error across JavaScript engines, including the failing expression.
function missingLength(create) {
  const activeDb = {};
  const model = "apikey";
  const props = { model };
  try {
    if (create) return activeDb[props.model].length;
    return activeDb[model].length;
  } catch (error) { return { error: { name: error.name, message: error.message } }; }
}

for (const explicit of [false, true]) {
  for (const alias of [false, true]) {
    for (const serial of [false, true]) {
      test(`Memory root initialization explicit=${explicit} alias=${alias} serial=${serial}`, async () => {
        const memory = {};
        const events = [];
        const logs = [];
        const physical = alias ? "credential_store" : "apikey";
        const prebuilt = !explicit && !alias;
        const spy = spyOn(logger, "error").mockImplementation((...args) => { logs.push(args); });
        const observed = field => ({ type: "string", transform: {
          input(value) { events.push(`input:${field}`); return value; },
          output(value) { events.push(`output:${field}`); return value; },
        } });
        let initialized;
        try {
          const { adapter } = await betterAuth({
            ...(explicit ? { database: memoryAdapter(memory) } : {}),
            baseURL: "http://memory-root.test",
            secret: "memory-root-contract-at-least-thirty-two-characters",
            logger: { disabled: true }, telemetry: { enabled: false },
            advanced: { database: { generateId: serial ? "serial" : false } },
            plugins: [apiKey(), {
              id: "memory-root-observer",
              schema: { apikey: { modelName: physical, fields: {
                name: observed("name"), before: observed("before"),
                id: { type: "string" }, after: observed("after"),
              } } },
              async init(context) {
                events.push("init");
                initialized = {
                  find: await outcome(() => context.adapter.findMany({ model: "apikey" })),
                  count: await outcome(() => context.adapter.count({ model: "apikey" })),
                  filteredCount: await outcome(() => context.adapter.count({ model: "apikey", where: [] })),
                };
              },
            }],
          }).$context;
          const missing = { error: { name: "Error", message: `Model ${physical} not found` } };
          assert.deepStrictEqual(initialized, prebuilt
            ? { find: { value: [] }, count: { value: 0 }, filteredCount: { value: 0 } }
            : { find: missing, count: missingLength(false), filteredCount: missing });
          const initialKeys = explicit ? [] : ["user", "session", "account", "verification", "apikey"];
          assert.deepStrictEqual(logs, prebuilt ? [] : [
            [`[MemoryAdapter] Model ${physical} not found in the DB`, initialKeys],
            [`[MemoryAdapter] Model ${physical} not found in the DB`, initialKeys],
          ]);
          expect(events).toStrictEqual(["init"]);
          assert.deepStrictEqual(memory, {});

          const input = { ...key("target", 5), before: "before", after: "after" };
          const result = await outcome(() => adapter.create({ model: "apikey", data: input, forceAllowId: true }));
          if (serial && !prebuilt) {
            assert.deepStrictEqual(result, missingLength(true));
            expect(events).toStrictEqual(["init", "input:name", "input:before"]);
            assert.deepStrictEqual(memory, {});
          } else {
            const value = { ...input, id: serial ? "1" : "target" };
            assert.deepStrictEqual(result, { value });
            expect(events).toStrictEqual([
              "init", "input:name", "input:before", "input:after",
              "output:name", "output:before", "output:after",
            ]);
            if (explicit) {
              assert.deepStrictEqual(memory, { [physical]: [{ ...input, metadata: "null" }] });
              expect(Object.keys(memory)).toStrictEqual([physical]);
              expect(memory[physical][0].createdAt).toBe(input.createdAt);
            }
            const readback = await adapter.findMany({ model: "apikey", where: [] });
            assert.deepStrictEqual(readback, [value]);
            expect(readback[0]).not.toBe(result.value);
            expect(readback[0].createdAt).toBe(result.value.createdAt);
            expect(events).toStrictEqual([
              "init", "input:name", "input:before", "input:after",
              "output:name", "output:before", "output:after",
              "output:name", "output:before", "output:after",
            ]);
          }
          expect(logs).toHaveLength(prebuilt ? 0 : 2);
        } finally { spy.mockRestore(); }
      });
    }
  }
}
