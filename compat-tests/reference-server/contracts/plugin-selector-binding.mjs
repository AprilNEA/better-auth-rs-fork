import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { walletPlugin } from "./wallet-additional-fields";

for (const model of ["walletAddress", "twoFactor"]) {
  for (const array of [false, true]) {
    test(`SQLite ${model} parses all ${array ? "array" : "scalar"} selectors before driver values`, async () => {
      const database = new Database(":memory:");
      try {
        database.exec(`
          CREATE TABLE walletAddress (id TEXT PRIMARY KEY, userId TEXT, address TEXT, chainId INTEGER, isPrimary INTEGER, createdAt TEXT);
          INSERT INTO walletAddress VALUES ('wallet', 'owner', 'target-address', 1, 0, '2030-01-01T00:00:00.000Z');
          CREATE TABLE twoFactor (id TEXT PRIMARY KEY, secret TEXT, backupCodes TEXT, userId TEXT, verified INTEGER, failedVerificationCount INTEGER, lockedUntil TEXT);
          INSERT INTO twoFactor VALUES ('factor', 'stored-secret', 'stored-codes', 'owner', 0, 0, NULL);
        `);
        const raw = () => ({
          wallet: database.query("SELECT * FROM walletAddress").all(),
          factor: database.query("SELECT * FROM twoFactor").all(),
        });
        const before = raw();
        const events = [];
        const original = new Error("plugin-selector-second");
        const failure = () => { events.push("second"); throw original; };
        const later = () => { events.push("later"); throw new Error("plugin-selector-later"); };
        const invalid = { "driver-invalid": true };
        const first = array ? [invalid] : invalid;
        const second = array ? [failure, later] : failure;
        const { adapter } = await betterAuth({
          database,
          baseURL: "http://plugin-selector-binding.test",
          secret: "plugin-selector-binding-contract-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          plugins: [walletPlugin(), twoFactor()],
        }).$context;
        const where = model === "walletAddress"
          ? [{ field: "address", value: first }, { field: "chainId", value: second }]
          : [{ field: "id", value: first }, { field: "backupCodes", value: second }];
        let rejected;
        try {
          if (model === "walletAddress") await adapter.findOne({ model, where });
          else await adapter.incrementOne({ model, where, increment: {}, set: { backupCodes: "must-not-persist" } });
        } catch (error) {
          rejected = error;
        }
        expect(rejected).toBe(original);
        expect(events).toStrictEqual(["second"]);
        expect(raw()).toStrictEqual(before);
      } finally {
        database.close();
      }
    });
  }
}

test("SQLite User ID IN parses all items before driver values", async () => {
  const database = new Database(":memory:");
  try {
    database.exec(`
      CREATE TABLE user (id TEXT PRIMARY KEY, name TEXT, email TEXT, emailVerified INTEGER, image TEXT, createdAt TEXT, updatedAt TEXT);
      INSERT INTO user VALUES
        ('target', 'Target', 'target@plugin-selector.test', 1, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'),
        ('retained', 'Retained', 'retained@plugin-selector.test', 0, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z');
    `);
    const raw = () => database.query("SELECT * FROM user ORDER BY id").all();
    const before = raw();
    expect(before).toHaveLength(2);
    const events = [];
    const original = new Error("plugin-selector-second");
    const failure = () => { events.push("second"); throw original; };
    const later = () => { events.push("later"); throw new Error("plugin-selector-later"); };
    const { adapter } = await betterAuth({
      database,
      baseURL: "http://plugin-selector-binding.test",
      secret: "plugin-selector-binding-contract-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
    }).$context;
    let actual;
    let rejected;
    try {
      actual = await adapter.findMany({
        model: "user",
        where: [{ field: "id", operator: "in", value: [{ "driver-invalid": true }, failure, later] }],
        limit: 10,
      });
    } catch (error) {
      rejected = error;
    }
    expect(rejected).toBe(original);
    expect(actual).toBeUndefined();
    expect(events).toStrictEqual(["second"]);
    expect(raw()).toStrictEqual(before);
  } finally {
    database.close();
  }
});
