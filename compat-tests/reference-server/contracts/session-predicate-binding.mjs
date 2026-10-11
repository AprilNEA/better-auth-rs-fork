import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";

function database() {
  const database = new Database(":memory:");
  database.exec(`CREATE TABLE session (id TEXT PRIMARY KEY NOT NULL, token TEXT NOT NULL, userId TEXT NOT NULL, expiresAt TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL, ipAddress TEXT, userAgent TEXT);
    INSERT INTO session VALUES ('selected', 'selected-token', 'owner', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', 'seed-ip', 'seed-agent'),
      ('expired', 'expired-token', 'owner', '2000-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', 'expired-ip', 'expired-agent'),
      ('retained', 'other-token', 'other', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', 'other-ip', 'other-agent');`);
  return database;
}

function context(database, events, preserve, expiryAlias) {
  return betterAuth({
    database,
    baseURL: "http://session-predicate-binding.test",
    secret: "session-predicate-binding-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    session: {
      storeSessionInDatabase: true,
      preserveSessionInDatabase: preserve,
      additionalFields: {
        expiresAt: expiryAlias ? { type: "date", fieldName: expiryAlias } : {
          type: "date", transform: { input() {
            events.push("expiry-input");
            return new Date("2000-01-02T00:00:00.000Z");
          } },
        },
        updatedAt: {
          type: "date",
          onUpdate() { events.push("updated-on-update"); return new Date("2030-01-01T00:00:01.000Z"); },
          transform: { input(value) { events.push("updated-input"); return value; } },
        },
        ipAddress: { type: "string", transform: {
          output(value) { events.push("ip-output"); return value; },
        } },
      },
    },
    secondaryStorage: preserve ? {
      async get() { return null; }, async set() {}, async delete() {}, async getAndDelete() { return null; },
    } : undefined,
  }).$context;
}

for (const array of [false, true]) {
  test(`SQLite Session active reads retain ${array ? "array" : "scalar"} callback errors through declared aliases`, async () => {
    const db = database();
    try {
      const raw = () => db.query("SELECT * FROM session ORDER BY id").all();
      const before = raw();
      const events = [];
      const { internalAdapter } = await context(db, events, false, "updatedAt");
      const failure = new Error("session-predicate-error");
      const callback = () => { events.push("query"); throw failure; };
      let actual;
      let caught;
      try { actual = await internalAdapter.listSessions(array ? [callback] : callback, { onlyActiveSessions: true }); }
      catch (error) { caught = error; }
      expect(caught).toBe(failure);
      expect(actual).toBeUndefined();
      expect(events).toStrictEqual(["query"]);
      expect(raw()).toStrictEqual(before);
    } finally { db.close(); }
  });

  test(`SQLite Session queries reject unknown names before ${array ? "array" : "scalar"} callbacks`, async () => {
    const db = database();
    try {
      const raw = () => db.query("SELECT * FROM session ORDER BY id").all();
      const before = raw();
      const events = [];
      const { adapter } = await context(db, events, false);
      const callback = () => { events.push("query"); throw new Error("session-predicate-error"); };
      let actual;
      let caught;
      try {
        actual = await adapter.findMany({ model: "session", where: [
          { field: "userId", value: array ? [callback] : callback },
          { field: "unknownExpiry", value: new Date(), operator: "gt" },
        ] });
      } catch (error) { caught = error; }
      expect(caught?.message).toBe("Field unknownExpiry not found in model session");
      expect(actual).toBeUndefined();
      expect(events).toStrictEqual([]);
      expect(raw()).toStrictEqual(before);
    } finally { db.close(); }
  });
}

for (const byToken of [false, true]) {
  for (const array of [false, true]) {
    test(`SQLite Session preservation repeats ${byToken ? "token" : "userId"} ${array ? "array" : "scalar"} parsing after its caught snapshot`, async () => {
      const db = database();
      try {
        const raw = () => db.query("SELECT * FROM session ORDER BY id").all();
        const before = raw();
        const events = [];
        const { internalAdapter } = await context(db, events, true);
        const failure = new Error("session-predicate-error");
        const callback = () => { events.push("query"); throw failure; };
        const value = array ? [{ "driver-invalid": true }, callback] : callback;
        let actual;
        let caught;
        try {
          actual = byToken
            ? await internalAdapter.deleteSession(value)
            : await internalAdapter.deleteUserSessions(value);
        } catch (error) { caught = error; }
        expect(caught).toBe(failure);
        expect(actual).toBeUndefined();
        expect(events).toStrictEqual(["query", "expiry-input", "updated-on-update", "updated-input", "query"]);
        expect(raw()).toStrictEqual(before);
      } finally { db.close(); }
    });
  }
}

test("SQLite Session singleton equality retains full output and preserves only live matches", async () => {
  const db = database();
  try {
    const raw = () => db.query("SELECT * FROM session ORDER BY id").all();
    const before = raw();
    expect(before).toHaveLength(3);
    const events = [];
    const reader = await context(db, events, false);
    const writer = await context(db, events, true);
    const owner = ["owner"];
    expect(await reader.internalAdapter.listSessions(owner, { onlyActiveSessions: true })).toStrictEqual([{
      id: "selected", token: "selected-token", userId: "owner",
      expiresAt: new Date("2030-01-01T00:00:00.000Z"), createdAt: new Date("2030-01-01T00:00:00.000Z"),
      updatedAt: new Date("2030-01-01T00:00:00.000Z"), ipAddress: "seed-ip", userAgent: "seed-agent",
    }]);
    expect(events.splice(0)).toStrictEqual(["ip-output"]);
    expect(raw()).toStrictEqual(before);
    expect(await writer.internalAdapter.deleteUserSessions(owner)).toBeUndefined();
    expect(events.splice(0)).toStrictEqual(["ip-output", "expiry-input", "updated-on-update", "updated-input"]);
    expect(raw()).toStrictEqual(before.map(row => row.id === "selected" ? {
      ...row, expiresAt: "2000-01-02T00:00:00.000Z", updatedAt: "2030-01-01T00:00:01.000Z",
    } : row));
    expect(await reader.internalAdapter.listSessions(owner, { onlyActiveSessions: true })).toStrictEqual([]);
    expect(events).toStrictEqual([]);
  } finally { db.close(); }
});
