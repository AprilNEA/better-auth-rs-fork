import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { admin } from "better-auth/plugins";

test("registered User fields retain slots around native plugin declarations and callback failures", async () => {
  for (const customFirst of [true, false]) {
    for (const fail of [false, true]) {
      const trace: string[] = [];
      const markerError = new Error("marker output failed");
      const field = (name: string) => ({
        type: "string" as const,
        fieldName: `stored_${name}`,
        transform: { output(value: any) {
          trace.push(name);
          if (fail && name === "marker") throw markerError;
          return value;
        } },
      });
      const marker = { id: "ordered-marker", schema: { user: { fields: { marker: field("marker") } } } };
      const role = { id: "ordered-role", schema: { user: { fields: { role: field("role") } } } };
      const row = {
        id: "user-id", name: "Owner", email: "order@fields.test", emailVerified: false,
        image: null, createdAt: new Date(0), updatedAt: new Date(0),
        stored_marker: "marker-value", stored_role: "role-value", banned: false,
        banReason: null, banExpires: null,
      };
      const memory = { user: [row], session: [], account: [], verification: [] };
      const before = structuredClone(memory);
      const { adapter, tables } = await betterAuth({
        database: memoryAdapter(memory), baseURL: "http://fields.test",
        secret: "ordinary-model-fields-secret-at-least-32-characters",
        logger: { disabled: true },
        plugins: customFirst ? [marker, admin(), role] : [admin(), marker, role],
      }).$context;
      const names = ["name", "email", "emailVerified", "image", "createdAt", "updatedAt"];
      if (customFirst) names.push("marker");
      names.push("role", "banned", "banReason", "banExpires");
      if (!customFirst) names.push("marker");
      expect(Object.keys(tables.user.fields)).toStrictEqual(names);
      const result = adapter.findOne({ model: "user", where: [{ field: "id", value: "user-id" }] });
      if (fail) {
        await expect(result).rejects.toBe(markerError);
      } else {
        const output = await result;
        names.push("id");
        const expected = Object.fromEntries(names.map(name => [name,
          name === "marker" ? row.stored_marker : name === "role" ? row.stored_role : row[name as keyof typeof row],
        ]));
        expect(output).toStrictEqual(expected);
        expect(Object.keys(output!)).toStrictEqual(names);
      }
      expect(trace).toStrictEqual(customFirst ? (fail ? ["marker"] : ["marker", "role"]) : ["role", "marker"]);
      expect(memory).toStrictEqual(before);
      expect(memory.user[0]).toBe(row);
    }
  }
});

test("plugin-declared ordinary passkey names transform once around Memory and SQLite writes", async () => {
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = [];
    const inputError = new Error("ordinary input error");
    const outputError = new Error("ordinary output error");
    const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], passkey: [] };
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = {
      database: database ?? memoryAdapter(memory),
      baseURL: "http://fields.test", secret: "ordinary-model-fields-secret-at-least-32-characters",
      logger: { disabled: true },
      plugins: [passkey(), { id: "ordinary-model-fields", schema: { passkey: { fields: {
        name: { type: "string" as const, onUpdate: () => "Renewed", transform: {
          input(value: any) {
            trace.push(`input:${JSON.stringify(value)}`);
            if (value === "input-error") throw inputError;
            return value.trim();
          },
          output(value: any) {
            trace.push(`output:${JSON.stringify(value)}`);
            if (value === "output-error") throw outputError;
            return `${value}:out`;
          },
        } },
      } } } }],
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    const user: any = await adapter.create({ model: "user", data: {
      name: "Owner", email: "ordinary@fields.test", emailVerified: false,
      createdAt: new Date(), updatedAt: new Date(),
    } });
    const create = (name: string) => adapter.create<any>({ model: "passkey", data: {
      name, userId: user.id, credentialID: `credential:${name}`, publicKey: "ordinary-public-key",
      counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: new Date(),
    } });
    const rawNames = () => (database
      ? database.query<{ name: string }, []>('SELECT name FROM "passkey"').all()
      : memory.passkey).map(row => row.name).sort();
    const created = await create("  Desk  ");
    expect(created.name).toBe("Desk:out");
    expect(trace).toStrictEqual(['input:"  Desk  "', 'output:"Desk"']);
    expect(rawNames()).toStrictEqual(["Desk"]);
    const where = [{ field: "id", value: created.id }];
    const updated: any = await adapter.update({ model: "passkey", where, update: { name: "  Mobile  " } });
    expect(updated.name).toBe("Mobile:out");
    expect((await adapter.findOne<any>({ model: "passkey", where }))?.name).toBe("Mobile:out");
    const renewed: any = await adapter.update({ model: "passkey", where, update: { counter: 0 } });
    expect(renewed.name).toBe("Renewed:out");
    await create(" Travel ");
    trace.length = 0;
    const listed: any[] = await adapter.findMany({ model: "passkey" });
    expect(trace).toStrictEqual(listed.map(row => `output:${JSON.stringify(row.name.slice(0, -4))}`));
    expect(listed.map(row => row.name).sort()).toStrictEqual(["Renewed:out", "Travel:out"]);
    expect(rawNames()).toStrictEqual(["Renewed", "Travel"]);
    await expect(create("input-error")).rejects.toBe(inputError);
    expect(rawNames()).toStrictEqual(["Renewed", "Travel"]);
    await expect(create("output-error")).rejects.toBe(outputError);
    expect(rawNames()).toStrictEqual(["Renewed", "Travel", "output-error"]);
    database?.close();
  }
});


test("Session input preserves declared native plugin slots and whole replacement policies", async () => {
  for (const name of ["impersonatedBy", "activeOrganizationId", "activeTeamId"]) {
    for (const markerFirst of [true, false]) {
      for (const create of [true, false]) {
        for (const fail of [false, true]) {
          const trace: string[] = [];
          const markerError = new Error("marker input failed");
          const field = (label: string, type: "string" | "boolean") => ({
            type, required: true, input: true, fieldName: `stored_${label}`,
            transform: { input(value: any) {
              trace.push(label);
              if (fail && label === "marker") throw markerError;
              return value;
            } },
          });
          const declarations = markerFirst ? ["marker", name] : [name, "marker"];
          const fields = Object.fromEntries(declarations.map(label => [label, field(label, label === "marker" ? "string" : "boolean")]));
          const input = {
            expiresAt: new Date(0), token: "session-token", createdAt: new Date(0),
            updatedAt: new Date(0), ipAddress: null, userAgent: null, userId: "owner-id",
            marker: "marker-value", [name]: true,
          };
          const names = ["expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId", ...declarations];
          const stored = Object.fromEntries(names.map(label => [
            label === "marker" || label === name ? `stored_${label}` : label,
            input[label as keyof typeof input],
          ]));
          stored.id = "session-id";
          const memory = { user: [], session: create ? [] : [structuredClone(stored)], account: [], verification: [] };
          const before = structuredClone(memory);
          const { adapter, tables } = await betterAuth({
            database: memoryAdapter(memory), baseURL: "http://fields.test",
            secret: "ordinary-model-fields-secret-at-least-32-characters",
            logger: { disabled: true },
            plugins: [{ id: "session-slot-contract", schema: { session: { fields } } }],
          }).$context;
          expect(Object.keys(tables.session.fields)).toStrictEqual(names);
          expect(tables.session.fields[name]).toStrictEqual(fields[name]);
          const result = create
            ? adapter.create({ model: "session", data: { ...input, id: "session-id" }, forceAllowId: true })
            : adapter.update({ model: "session", where: [{ field: "id", value: "session-id" }], update: input });
          if (fail) {
            await expect(result).rejects.toBe(markerError);
            expect(memory).toStrictEqual(before);
          } else {
            const output = await result;
            expect(output).toStrictEqual({ ...input, id: "session-id" });
            expect(Object.keys(output!)).toStrictEqual([...names, "id"]);
            expect(memory.session).toStrictEqual([stored]);
          }
          expect(trace).toStrictEqual(markerFirst && fail ? ["marker"] : declarations);
        }
      }
    }
  }
});
