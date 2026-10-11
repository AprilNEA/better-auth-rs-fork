import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";

function database(model) {
  const database = new Database(":memory:");
  const seed = {
    apikey: `CREATE TABLE apikey (id TEXT PRIMARY KEY NOT NULL, name TEXT, start TEXT, prefix TEXT, key TEXT NOT NULL, referenceId TEXT NOT NULL, configId TEXT NOT NULL, refillInterval REAL, refillAmount REAL, lastRefillAt TEXT, enabled INTEGER NOT NULL, rateLimitEnabled INTEGER NOT NULL, rateLimitTimeWindow REAL, rateLimitMax REAL, requestCount REAL, remaining REAL, lastRequest TEXT, expiresAt TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL, permissions TEXT, metadata TEXT);
      INSERT INTO apikey (id, name, key, referenceId, configId, enabled, rateLimitEnabled, createdAt, updatedAt) VALUES
        ('target', 'Before', 'target-key', 'owner', 'default', 1, 0, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'),
        ('retained', 'Retained', 'other-key', 'other', 'default', 1, 0, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z');`,
    passkey: `CREATE TABLE passkey (id TEXT PRIMARY KEY NOT NULL, name TEXT, publicKey TEXT NOT NULL, userId TEXT NOT NULL, credentialID TEXT NOT NULL, counter INTEGER NOT NULL, deviceType TEXT NOT NULL, backedUp INTEGER NOT NULL, transports TEXT, credential TEXT NOT NULL, aaguid TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL);
      INSERT INTO passkey (id, name, publicKey, userId, credentialID, counter, deviceType, backedUp, credential, createdAt, updatedAt) VALUES
        ('target', 'Before', 'public-key', 'owner', 'credential', 0, 'singleDevice', 0, 'opaque-credential', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'),
        ('retained', 'Retained', 'other-public-key', 'other', 'other-credential', 7, 'singleDevice', 1, 'other-opaque-credential', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z');`,
    user: `CREATE TABLE user (id TEXT PRIMARY KEY NOT NULL, name TEXT, email TEXT NOT NULL, emailVerified INTEGER NOT NULL, image TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL);
      INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt) VALUES
        ('target', 'Before', 'target@update-phases.test', 1, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'),
        ('retained', 'Retained', 'other@update-phases.test', 0, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z');`,
  };
  database.exec(seed[model]);
  return database;
}

async function adapter(database, model, invalidName, events) {
  const fields = {
    name: { type: "string", transform: {
      input(value) { events.push("name-input"); return value; },
      output(value) { events.push("name-output"); return value; },
    } },
    ...(invalidName ? { id: { type: "string", fieldName: "old_id" } } : {}),
  };
  return (await betterAuth({
    database,
    baseURL: "http://update-binding-phases.test",
    secret: "update-binding-phases-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    user: model === "user" ? { additionalFields: fields } : undefined,
    plugins: model === "user" ? [] : [
      model === "apikey" ? apiKey() : passkey(),
      { id: "ordinary-update-phases", schema: { [model]: { fields } } },
    ],
  }).$context).adapter;
}

for (const model of ["apikey", "passkey", "user"]) {
  for (const scenario of ["where-name", "set-before-where", "where-before-driver", "set-before-driver", "missing-row"]) {
    test(`SQLite ${model} ordinary UPDATE preserves ${scenario} phase order`, async () => {
      const db = database(model);
      try {
        const raw = () => db.query(`SELECT * FROM ${model} ORDER BY id`).all();
        const before = raw();
        expect(before).toHaveLength(2);
        const events = [];
        const update = await adapter(db, model, scenario === "where-name", events);
        const setError = new Error("update-set-error");
        const whereError = new Error("update-where-error");
        const setCallback = () => { events.push("set"); throw setError; };
        const whereCallback = () => { events.push("where"); throw whereError; };
        const invalid = { "driver-invalid": true };
        let set = setCallback;
        let selector = whereCallback;
        if (scenario === "where-before-driver") set = invalid;
        else if (scenario === "set-before-driver") selector = invalid;
        else if (scenario === "missing-row") selector = "missing";
        let actual;
        let caught;
        try {
          actual = await update.update({ model, where: [{ field: "id", value: selector }], update: { name: set } });
        } catch (error) { caught = error; }
        if (scenario === "where-name") {
          expect(caught?.message).toBe(`Field old_id not found in model ${model}`);
          expect(events).toStrictEqual(["name-input"]);
        } else {
          const phase = scenario === "where-before-driver" ? "where" : "set";
          expect(caught).toBe(phase === "where" ? whereError : setError);
          expect(events).toStrictEqual(["name-input", phase]);
        }
        expect(actual).toBeUndefined();
        expect(raw()).toStrictEqual(before);
      } finally { db.close(); }
    });
  }
}
