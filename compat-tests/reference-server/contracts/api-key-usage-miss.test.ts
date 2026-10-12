import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";
import { apiKey } from "@better-auth/api-key";
import { APIError } from "@better-auth/core/error";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const HASH = "api-key:usage-secret";
function seed() {
  return {
    id: "usage-key", name: "Before eviction", start: null, prefix: null,
    key: "usage-secret", referenceId: "owner", configId: "default",
    refillInterval: null, refillAmount: null, lastRefillAt: null,
    enabled: true, rateLimitEnabled: false, rateLimitTimeWindow: 60_000,
    rateLimitMax: 3, requestCount: 0, remaining: 5, lastRequest: null,
    expiresAt: null, createdAt: "2030-01-02T03:04:05.000Z",
    updatedAt: "2030-01-02T03:04:05.000Z", permissions: null, metadata: null,
  };
}

for (const deferred of [false, true]) for (const pending of [false, true]) {
  test(`secondary usage reread miss preserves result, Logger and storage ownership (deferred=${deferred}, pending=${pending})`, async () => {
    for (const name of ["better-auth", "@better-auth/api-key", "@better-auth/core"]) {
      const packageJson = JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8"));
      expect(packageJson.version).toBe("1.7.6");
    }
    const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
    const values = new Map([
      [HASH, JSON.stringify(seed())],
      ["api-key:by-id:usage-key", JSON.stringify(seed())],
      ["api-key:by-ref:owner", '["usage-key"]'],
    ]);
    const before = new Map(values);
    const reads: string[] = [];
    const writes: unknown[] = [];
    const logs: { level: string; message: unknown; arguments: unknown[] }[] = [];
    const tasks: Promise<unknown>[] = [];
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const customStorage = {
      async get(key: string) {
        expect(key).toBe(HASH);
        reads.push(key);
        if (reads.length === 2) {
          values.delete(HASH);
          started.resolve();
          if (pending) await release.promise;
        }
        return values.get(key) ?? null;
      },
      async set(key: string, value: string, ttl?: number) {
        writes.push(["set", key, value, ttl]);
        values.set(key, value);
      },
      async delete(key: string) {
        writes.push(["delete", key]);
        values.delete(key);
      },
    };
    const auth = betterAuth({
      database: memoryAdapter(memory), baseURL: "http://api-key-usage-miss.test",
      secret: "api-key-usage-miss-contract-at-least-thirty-two-characters",
      telemetry: { enabled: false },
      logger: { level: "error", log(level, message, ...args) {
        logs.push({ level, message, arguments: args });
      } },
      advanced: { backgroundTasks: { handler(task) { tasks.push(task); } } },
      plugins: [apiKey({ storage: "secondary-storage", customStorage, disableKeyHashing: true, deferUpdates: deferred })],
    });
    await auth.$context;
    const earliest = Date.now();
    const verification = auth.api.verifyApiKey({ body: { key: "usage-secret" } });
    await started.promise;
    if (pending) expect(logs).toStrictEqual([]);
    if (!deferred) release.resolve();
    const result = await verification;
    const latest = Date.now();
    release.resolve();
    expect(tasks).toHaveLength(deferred ? 2 : 0);
    const taskResults = await Promise.all(tasks);
    if (deferred) {
      assert.ok(result.key);
      expect(result.valid).toBe(true);
      expect(result.error).toBeNull();
      for (const timestamp of [result.key.lastRequest, result.key.updatedAt]) {
        assert.ok(timestamp instanceof Date);
        expect(timestamp.getTime()).toBeGreaterThanOrEqual(earliest);
        expect(timestamp.getTime()).toBeLessThanOrEqual(latest);
      }
      const { key: _hash, ...expected } = seed();
      expect(result).toStrictEqual({ valid: true, error: null, key: {
        ...expected, remaining: 4, createdAt: new Date(expected.createdAt),
        lastRequest: result.key.lastRequest, updatedAt: result.key.updatedAt,
      } });
      expect(taskResults).toStrictEqual([null, undefined]);
      expect(logs).toStrictEqual([]);
    } else {
      const body = { message: "Failed to update API key", code: "FAILED_TO_UPDATE_API_KEY" };
      expect(result).toStrictEqual({ valid: false, key: null, error: body });
      expect(logs).toHaveLength(1);
      const [log] = logs;
      assert.ok(log);
      expect(log.level).toBe("error");
      expect(log.message).toBe("Failed to validate API key:");
      expect(log.arguments).toHaveLength(1);
      const [error] = log.arguments;
      assert.ok(error instanceof APIError);
      expect(error.status).toBe("INTERNAL_SERVER_ERROR");
      expect(error.statusCode).toBe(500);
      expect(error.body).toStrictEqual(body);
      expect([...new Headers(error.headers).entries()]).toStrictEqual([]);
      expect(taskResults).toStrictEqual([]);
    }
    before.delete(HASH);
    expect(values).toStrictEqual(before);
    expect(reads).toStrictEqual([HASH, HASH]);
    expect(writes).toStrictEqual([]);
    expect(memory).toStrictEqual({ user: [], session: [], account: [], verification: [], apikey: [] });
  }, 15_000);
}
