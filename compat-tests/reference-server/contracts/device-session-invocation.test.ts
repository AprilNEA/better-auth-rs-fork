import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import { deviceAuthorization } from "better-auth/plugins/device-authorization";
import { secondaryStorageInvocation } from "./secondary-storage-invocation.mjs";

for (const synchronous of [false, true]) {
  test(`Device storage failure retains the consumed code, created session, and published snapshot: ${synchronous}`, async () => {
    const database: Record<string, any[]> = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    const cache = new Map<string, string>();
    const original = new Error("device secondary write rejected");
    let endpointContext: any;
    const writes: { key: string; value: string; ttl: number; published: any }[] = [];
    const auth = betterAuth({
      database: memoryAdapter(database), baseURL: "http://device-invocation.test",
      secret: "device-invocation-secret-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
      session: { storeSessionInDatabase: true },
      plugins: [deviceAuthorization()],
      hooks: { before: createAuthMiddleware(ctx => { endpointContext = ctx.context; }) },
      secondaryStorage: secondaryStorageInvocation({
        get(key: string) { return cache.get(key) ?? null; },
        set(key: string, value: string, ttl: number) {
          const published = endpointContext?.newSession ?? null;
          writes.push({ key, value, ttl, published });
          if (published) throw original;
          cache.set(key, value);
        },
        delete(key: string) { cache.delete(key); },
      }, synchronous),
    });
    const context = await auth.$context;
    const date = new Date("2030-01-01T00:00:00.000Z");
    const user = await context.adapter.create<any>({ model: "user", forceAllowId: true, data: {
      id: "owner", name: "Selected User", email: "owner@device-invocation.test", emailVerified: true,
      image: null, createdAt: date, updatedAt: date,
    } });
    await context.adapter.create({ model: "deviceCode", forceAllowId: true, data: {
      id: "device", deviceCode: "device-code", userCode: "ABCD2345", userId: user.id,
      expiresAt: new Date("2100-01-01T00:00:00.000Z"), status: "approved",
      clientId: "client", scope: "read",
    } });
    const userBefore = structuredClone(database.user);
    let error: unknown;
    try {
      await auth.api.deviceToken({ body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "device-code", client_id: "client",
      } });
    } catch (caught) { error = caught; }
    expect(error).toBe(original);
    expect(database.deviceCode).toStrictEqual([]);
    expect(database.user).toStrictEqual(userBefore);
    expect(database.account).toStrictEqual([]);
    expect(database.verification).toStrictEqual([]);
    expect(database.session).toHaveLength(1);
    expect(writes).toHaveLength(3);
    const published = endpointContext.newSession;
    expect(published.user).toStrictEqual(user);
    expect(published.session).toStrictEqual(database.session![0]);
    expect(writes.map(write => write.published)).toStrictEqual([null, null, published]);
    expect(writes[2]!.key).toBe(published.session.token);
    expect(JSON.parse(writes[2]!.value)).toStrictEqual(JSON.parse(JSON.stringify(published)));
    expect(cache.get(published.session.token)).toBe(writes[1]!.value);
    expect(cache.size).toBe(2);
  });
}
