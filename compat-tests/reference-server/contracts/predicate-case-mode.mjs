import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins";

for (const operator of ["eq", "ne", "in", "not_in", "contains", "starts_with", "ends_with"]) {
  for (const array of [false, true]) {
    test(`SQLite Device insensitive ${operator} retains ${array ? "array" : "scalar"} operand semantics`, async () => {
      const database = new Database(":memory:");
      try {
        // SQLite's default LIKE hides whether the adapter selected an insensitive expression.
        database.exec(`PRAGMA case_sensitive_like = ON;
          CREATE TABLE deviceCode (id TEXT PRIMARY KEY NOT NULL, deviceCode TEXT NOT NULL, userCode TEXT NOT NULL, userId TEXT, expiresAt TEXT NOT NULL, status TEXT NOT NULL, lastPolledAt TEXT, pollingInterval INTEGER, clientId TEXT, scope TEXT);
          INSERT INTO deviceCode VALUES ('target', 'target-device', 'ABCD2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', NULL, NULL, 'client', 'upper'),
            ('retained', 'retained-device', 'EFGH2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', NULL, NULL, 'client', 'upper');`);
        const raw = () => database.query("SELECT * FROM deviceCode ORDER BY id").all();
        const before = raw();
        expect(before).toHaveLength(2);
        const { adapter } = await betterAuth({
          database,
          baseURL: "http://predicate-case-mode.test",
          secret: "predicate-case-mode-contract-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          plugins: [deviceAuthorization()],
        }).$context;
        const consume = () => adapter.consumeOne({
          model: "deviceCode", where: [
            { field: "id", value: "target" },
            { field: "scope", operator, value: array ? ["UPPER"] : "UPPER", mode: "insensitive" },
            { field: "status", value: "approved" },
          ],
        });
        if (operator === "in" && !array) {
          let failure;
          try { await consume(); } catch (error) { failure = error; }
          expect({ name: failure?.name, message: failure?.message }).toStrictEqual({
            name: "BetterAuthError", message: "Value must be an array",
          });
          expect(raw()).toStrictEqual(before);
          return;
        }
        const result = await consume();
        const consumes = operator === "in" || operator !== "not_in" && (operator === "ne" ? array : !array);
        expect(result).toStrictEqual(consumes ? {
          id: "target", deviceCode: "target-device", userCode: "ABCD2345", userId: "owner",
          expiresAt: new Date("2030-01-01T00:00:00.000Z"), status: "approved",
          lastPolledAt: null, pollingInterval: null, clientId: "client", scope: "upper",
        } : null);
        expect(raw()).toStrictEqual(before.filter(row => !consumes || row.id !== "target"));
      } finally { database.close(); }
    });
  }
}
