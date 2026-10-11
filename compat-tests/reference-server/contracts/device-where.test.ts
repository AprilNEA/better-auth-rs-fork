import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { deviceAuthorization } from "better-auth/plugins";
import { captureDeviceWhere } from "./device-where-capture.mjs";

for (const backend of ["memory", "sqlite"]) {
  test(`Device Where preserves complete ${backend} query results, errors, callbacks and raw storage`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-where-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureDeviceWhere(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.groups.flatMap(group => group.cases)).toHaveLength(90);
    expect(observed).toStrictEqual(fixture);
  });
}

for (const values of [[], ["Alpha"]]) {
  for (const [operator, shared, consumes] of [["eq", true, true], ["eq", false, false], ["ne", true, false], ["ne", false, true]] as const) {
    test(`Memory Device insensitive ${operator} preserves ${shared ? "shared" : "distinct"} ${values.length ? "string" : "empty"} array identity`, async () => {
      const memory: Record<string, Record<string, unknown>[]> = {
        user: [], session: [], account: [], verification: [], deviceCode: [],
      };
      const events: string[] = [];
      const { adapter } = await betterAuth({
        baseURL: "http://device-bindings.test",
        secret: "device-consumption-bindings-secret-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false }, database: memoryAdapter(memory),
        plugins: [deviceAuthorization(), {
          id: "device-insensitive-array-identity", schema: { deviceCode: { fields: {
            scope: { type: "string", required: false, fieldName: "stored_scope", transform: {
              output(value) { events.push("output"); return value; },
            } },
          } } },
        }],
      }).$context;
      const original = [...values];
      const operand = shared ? original : [...values];
      const input = (label: string, scope: unknown) => ({
        id: label, deviceCode: `binding-device-${label}`, userCode: `binding-user-${label}`,
        userId: "binding-owner", expiresAt: new Date(4_102_444_800_000), status: "approved",
        lastPolledAt: null, pollingInterval: 5000, clientId: "binding-client", scope,
      });
      const target = await adapter.create({ model: "deviceCode", forceAllowId: true, data: input("target", original) });
      await adapter.create({ model: "deviceCode", forceAllowId: true, data: input("decoy", "unchanged") });
      const before = structuredClone(memory);
      const targetSource = memory.deviceCode.find(row => row.id === target.id);
      const decoySource = memory.deviceCode.find(row => row.id === "decoy");
      expect(target.scope).toBe(original);
      expect(targetSource?.stored_scope).toBe(original);
      expect(operand === original).toBe(shared);
      expect(events).toStrictEqual(["output", "output"]);
      events.length = 0;
      const result = await Reflect.apply(adapter.consumeOne, adapter, [{ model: "deviceCode", where: [
        { field: "id", value: target.id },
        { field: "scope", operator, value: operand, mode: "insensitive" },
        { field: "deviceCode", value: target.deviceCode },
        { field: "clientId", value: target.clientId },
        { field: "userId", value: target.userId },
        { field: "status", value: "approved" },
      ] }]);
      if (consumes) {
        expect(result).toStrictEqual(target);
        expect(result.scope).toBe(original);
      } else {
        expect(result).toBeNull();
        expect(memory.deviceCode.find(row => row.id === target.id)).toBe(targetSource);
        expect(targetSource?.stored_scope).toBe(original);
      }
      expect(events).toStrictEqual(consumes ? ["output"] : []);
      expect(memory).toStrictEqual({
        ...before, deviceCode: before.deviceCode.filter(row => !consumes || row.id !== target.id),
      });
      expect(memory.deviceCode.find(row => row.id === "decoy")).toBe(decoySource);
    });
  }
}
