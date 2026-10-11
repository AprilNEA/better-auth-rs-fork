import assert from "node:assert/strict";
import { expect, test } from "bun:test";
import { API_KEY_ERROR_CODES, apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";

const date = () => new Date(1_893_456_000_000);
const apiErrorBody = () => ({
  code: "VALIDATOR_REJECTED", message: "Validator rejected the key",
  details: { retry: false, reason: ["policy", "owner"] },
});

function key(name) {
  return {
    id: "key-id", name, start: null, prefix: null, key: "validator-secret",
    referenceId: "owner", configId: "default", refillInterval: null,
    refillAmount: null, lastRefillAt: null, enabled: true, rateLimitEnabled: true,
    rateLimitTimeWindow: 60_000, rateLimitMax: 3, requestCount: 0, remaining: 5,
    lastRequest: null, expiresAt: null, createdAt: date(), updatedAt: date(),
    permissions: null, metadata: null,
  };
}

const storedKey = name => ({ ...key(name), metadata: "null" });

function failure(kind) {
  switch (kind) {
    case "ordinary": return new Error("Validator operation failed");
    case "cyclic-json": {
      const value = {};
      value.self = value;
      try { JSON.stringify(value); } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        return error;
      }
      throw new Error("Cyclic JSON must throw a TypeError");
    }
    case "range": return new RangeError("Invalid array length");
    case "data-clone": {
      try { structuredClone(() => {}); } catch (error) {
        expect(error.name).toBe("DataCloneError");
        return error;
      }
      throw new Error("A function must fail structured clone");
    }
    case "api-forbidden": return new APIError("FORBIDDEN", apiErrorBody());
    case "api-internal": return new APIError("INTERNAL_SERVER_ERROR", apiErrorBody());
    default: throw new Error(`Unknown validator failure ${kind}`);
  }
}

for (const kind of ["ordinary", "cyclic-json", "range", "data-clone", "api-forbidden", "api-internal"]) {
  for (const scoped of [false, true]) {
    test(`API Key validator ${kind}, scoped=${scoped}, retains catch scope and committed callback write`, async () => {
      const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
      const events = [];
      let original;
      const auth = betterAuth({
        database: memoryAdapter(memory), baseURL: "http://validator-errors.test",
        secret: "validator-error-contract-at-least-32-characters", telemetry: { enabled: false },
        logger: { level: "error", log(level, message, ...args) {
          expect(level).toBe("error");
          expect(args).toHaveLength(1);
          expect(args[0]).toBe(original);
          events.push(["log", level, message, args[0] === original]);
        } },
        plugins: [apiKey({ disableKeyHashing: true, deferUpdates: false,
          async customAPIKeyValidator({ ctx, key: presented }) {
            events.push(["validator:enter", presented, ctx.body]);
            const updated = await ctx.context.adapter.update({
              model: "apikey", where: [{ field: "id", value: "key-id" }],
              update: { name: "After", updatedAt: date() },
            });
            assert.deepStrictEqual(updated, key("After"));
            events.push(["validator:persisted"]);
            original = failure(kind);
            throw original;
          },
        })],
      });
      const { adapter } = await auth.$context;
      assert.deepStrictEqual(
        await adapter.create({ model: "apikey", forceAllowId: true, data: key("Before") }),
        key("Before"),
      );
      assert.deepStrictEqual(memory, {
        user: [], session: [], account: [], verification: [], apikey: [storedKey("Before")],
      });
      const body = scoped ? { key: "validator-secret", configId: "default" } : { key: "validator-secret" };
      let result;
      let error;
      try {
        result = await auth.api.verifyApiKey({ body });
        events.push(["consumer:returned"]);
      } catch (caught) {
        error = caught;
        events.push(["consumer:threw"]);
      }
      if (scoped) {
        expect(result).toBeUndefined();
        expect(error).toBe(original);
        if (kind.startsWith("api-")) {
          expect(error.statusCode).toBe(kind === "api-forbidden" ? 403 : 500);
          expect(error.body).toStrictEqual(apiErrorBody());
        }
      } else {
        expect(error).toBeUndefined();
        expect(result).toStrictEqual({
          valid: false, key: null,
          error: kind.startsWith("api-") ? apiErrorBody() : {
            code: "INVALID_API_KEY", message: API_KEY_ERROR_CODES.INVALID_API_KEY,
          },
        });
        if (!kind.startsWith("api-")) {
          expect(result.error.message).toBe(API_KEY_ERROR_CODES.INVALID_API_KEY);
          expect(Object.keys(result.error.message)).toStrictEqual(["code", "message", "toString"]);
          expect(result.error.message.toString()).toBe("INVALID_API_KEY");
        }
        assert.deepStrictEqual(JSON.parse(JSON.stringify(result)), {
          valid: false, key: null,
          error: kind.startsWith("api-") ? apiErrorBody() : {
            code: "INVALID_API_KEY", message: { code: "INVALID_API_KEY", message: "Invalid API key." },
          },
        });
      }
      assert.deepStrictEqual(memory, {
        user: [], session: [], account: [], verification: [], apikey: [storedKey("After")],
      });
      expect(events).toStrictEqual([
        ["validator:enter", "validator-secret", body], ["validator:persisted"],
        ...(scoped ? [] : [["log", "error", "Failed to validate API key:", true]]),
        [scoped ? "consumer:threw" : "consumer:returned"],
      ]);
    });
  }
}
