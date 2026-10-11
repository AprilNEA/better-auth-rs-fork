import { expect, test } from "bun:test";
import { capturePasskeySharedDisplay } from "./passkey-shared-display-capture.mjs";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const fixture = await Bun.file(new URL("../../../tests/fixtures/passkey-shared-display-1.7.6.json", import.meta.url)).json();

test("Passkey shared display columns preserve both declaration orders and HTTP updates", async () => {
  expect(await capturePasskeySharedDisplay()).toStrictEqual(fixture);
}, 60_000);

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} complete Passkey declarations control typed-equivalent input and raw CRUD`, async () => {
    const id = "typed-declaration-passkey";
    const table = "ordinary_passkey_fields";
    const memory: Record<string, Record<string, unknown>[]> = { user: [], session: [], account: [], verification: [], [table]: [] };
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const object = { source: "output" };
    const events: [string, string, unknown][] = [];
    const inputError = new Error("passkey-input-stop");
    const outputError = new Error("passkey-output-stop");
    const callback = (phase: "input" | "output", field: string) => (value: unknown) => {
      events.push([phase, field, value]);
      if (field === "name") {
        if (value === (phase === "input" ? "reject-input" : "stored:reject-output")) throw phase === "input" ? inputError : outputError;
        if (value === null || value === undefined) return value;
        if (phase === "output") {
          if (value === "stored:omit-output") return undefined;
          if (value === "stored:object-output") return object;
        }
        return `${phase === "input" ? "stored" : "visible"}:${value}`;
      }
      return phase === "input" ? value : `count:${value}`;
    };
    const options: BetterAuthOptions = {
      database: database ?? memoryAdapter(memory),
      baseURL: "http://typed-passkey-declarations.test",
      secret: "typed-passkey-declarations-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      plugins: [{ id: "typed-passkey-declarations", schema: { passkey: { modelName: table, fields: {
        name: { type: "string", required: false, fieldName: "stored_label", transform: { input: callback("input", "name"), output: callback("output", "name") } },
        counter: { type: "number", required: false, fieldName: "stored_counter", transform: { input: callback("input", "counter"), output: callback("output", "counter") } },
      } } } }],
    };
    try {
      database?.exec(`CREATE TABLE ${table} (id TEXT PRIMARY KEY NOT NULL, stored_label TEXT, stored_counter INTEGER)`);
      const { adapter } = await betterAuth(options).$context;
      const snapshot = (): Record<string, unknown>[] => database
        ? database.query(`SELECT * FROM ${table} ORDER BY id`).all() as Record<string, unknown>[]
        : structuredClone(memory[table]);
      const columns = () => database?.query(`PRAGMA table_info(${table})`).all().map((column: any) => column.name);
      if (database) expect(columns()).toStrictEqual(["id", "stored_label", "stored_counter"]);
      const where = [{ field: "id", value: id }];
      for (const [stage, label, counter] of [
        ["create", "Desk", 1], ["read", "Desk", 1], ["update", "Next", 2], ["auth", "Next", 3],
        ["null", null, 4], ["undefined-output", "omit-output", 5], ["object-output", "object-output", 6],
        ["output-error", "reject-output", 7], ["read-error", "reject-output", 7],
        ["recover", "Restored", 8], ["input-error", "Restored", 8], ["delete", null, 0], ["missing", null, 0],
      ] as const) {
        const before = snapshot();
        const supplied = stage === "input-error" ? "reject-input" : label;
        const create = stage === "create";
        const remove = stage === "delete";
        const read = stage === "read" || stage === "read-error" || stage === "missing";
        const write = !remove && !read;
        const present = !remove && stage !== "missing";
        const rejected = stage === "input-error" || stage === "output-error" || stage === "read-error";
        const execute = () => create
          ? adapter.create({ model: "passkey", forceAllowId: true, data: {
            id, name: supplied, counter, userId: "must-not-return-owner", credentialID: "must-not-return-id",
            publicKey: "must-not-return-key", deviceType: "singleDevice", backedUp: false, transports: "internal",
            aaguid: "must-not-return-aaguid", mustNotReturn: "extension",
          } })
          : remove ? adapter.delete({ model: "passkey", where })
            : read ? adapter.findOne({ model: "passkey", where })
              : adapter.update({ model: "passkey", where, update: {
                ...(stage === "auth" ? {} : { name: supplied }), counter: stage === "input-error" ? 9 : counter,
              } });
        if (rejected) await expect(execute()).rejects.toBe(stage === "input-error" ? inputError : outputError);
        else {
          const actual = await execute();
          const name = label === null ? null : label === "omit-output" ? undefined : label === "object-output" ? object : `visible:stored:${label}`;
          const expected = { name, counter: `count:${counter}`, id };
          expect(actual).toStrictEqual(remove ? undefined : present ? expected : null);
          if (present) {
            expect(Object.keys(actual!)).toStrictEqual(["name", "counter", "id"]);
            expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
            if (label === "object-output") expect((actual as { name: unknown }).name).toBe(object);
          }
        }
        const storedName = label === null ? null : `stored:${label}`;
        const callbacks: [string, string, unknown][] = [];
        if (write) {
          if (stage !== "auth") callbacks.push(["input", "name", supplied]);
          if (stage !== "input-error") callbacks.push(["input", "counter", counter]);
        }
        if (present && stage !== "input-error") {
          callbacks.push(["output", "name", storedName]);
          if (!rejected) callbacks.push(["output", "counter", counter]);
        }
        expect(events.splice(0)).toStrictEqual(callbacks);
        const expected = database
          ? { id, stored_label: storedName, stored_counter: counter }
          : { stored_label: storedName, stored_counter: counter, id };
        const rows = snapshot();
        expect(rows).toStrictEqual(present ? [expected] : []);
        for (const row of rows) expect(Object.keys(row)).toStrictEqual(Object.keys(expected));
        if (read || stage === "input-error") expect(rows).toStrictEqual(before);
        if (database) expect(columns()).toStrictEqual(["id", "stored_label", "stored_counter"]);
      }
    } finally { database?.close(); }
  });
}
