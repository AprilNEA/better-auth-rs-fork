import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const models = [
  { model: "apikey", table: "api_keys", target: "enabled", column: "enabled", marker: "remaining", type: "boolean", first: true, next: false, selector: undefined },
  { model: "twoFactor", table: "ordinary_two_factor_fields", target: "verified", column: "verified", marker: "backup_codes", type: "boolean", first: true, next: false, selector: ["userId", "user_id", "owner"] },
  { model: "jwks", table: "jwks", target: "alg", column: "alg", marker: "crv", type: "string", first: "first-alg", next: "next-alg", selector: undefined },
  { model: "walletAddress", table: "wallet_address", target: "chainId", column: "chain_id", marker: "created_at", type: "number", first: 1, next: 2, selector: ["address", "address", "wallet"] },
] as const;

for (const backend of ["memory", "sqlite"] as const) for (const model of models) {
  test(`${backend} sparse ${model.model} fields retain complete typed-equivalent operations`, async () => {
    const id = "typed-metadata-record";
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const memory: Record<string, Record<string, unknown>[]> = { user: [], session: [], account: [], verification: [], [model.table]: [] };
    const events: [string, string, unknown][] = [];
    const object = { source: "output" };
    let output: unknown;
    let reject: "input" | "output" | undefined;
    const errors = { input: new Error("typed-metadata-input-stop"), output: new Error("typed-metadata-output-stop") };
    const callback = (phase: "input" | "output", name: string) => (value: unknown) => {
      events.push([phase, name, value]);
      if (name === model.target) {
        if (phase === reject) throw errors[phase];
        if (phase === "output") return output;
      }
      return value;
    };
    const fields: Record<string, DBFieldAttribute> = {
      marker: { type: "string", required: false, fieldName: model.marker, transform: { input: callback("input", "marker"), output: callback("output", "marker") } },
      [model.target]: { type: model.type, required: false, fieldName: model.column, transform: { input: callback("input", model.target), output: callback("output", model.target) } },
    };
    if (model.selector) fields[model.selector[0]] = { type: "string", required: false, fieldName: model.selector[1] };
    const options: BetterAuthOptions = {
      database: database ?? memoryAdapter(memory), baseURL: "http://typed-metadata.test",
      secret: "typed-metadata-contract-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      plugins: [{ id: "typed-metadata-fields", schema: { [model.model]: { modelName: model.table, fields } } }],
    };
    try {
      const kind = model.type === "boolean" ? "BOOLEAN" : model.type === "number" ? "INTEGER" : "TEXT";
      const selectorColumn = model.selector ? `, ${model.selector[1]} TEXT` : "";
      database?.exec(`CREATE TABLE ${model.table} (id TEXT PRIMARY KEY, ${model.marker} TEXT, ${model.column} ${kind}${selectorColumn})`);
      const { adapter } = await betterAuth(options).$context;
      const snapshot = () => {
        const rows = database ? database.query(`SELECT * FROM ${model.table} ORDER BY id`).all() : structuredClone(memory[model.table]);
        return rows.map((row) => ({ row, keys: Object.keys(row as Record<string, unknown>) }));
      };
      const physicalValue = (value: unknown) => backend === "sqlite" && typeof value === "boolean" ? Number(value) : value;
      const storedRecord = (marker: string, target: unknown) => {
        const row: Record<string, unknown> = {};
        if (backend === "sqlite") row.id = id;
        row[model.marker] = marker;
        row[model.column] = physicalValue(target);
        if (model.selector) row[model.selector[1]] = model.selector[2];
        if (backend === "memory") row.id = id;
        return [{ row, keys: Object.keys(row) }];
      };
      const record = (marker: string, value: unknown) => ({ marker, [model.target]: value,
        ...(model.selector ? { [model.selector[0]]: model.selector[2] } : {}), id });
      let storedMarker = "created";
      let storedTarget: unknown = model.first;
      for (const stage of ["create", "object", "undefined", "null", "update", "output-error", "recover", "input-error"] as const) {
        expect(events).toStrictEqual([]);
        output = stage === "object" || stage === "update" ? object : stage === "undefined" ? undefined : stage === "null" ? null : "visible-output";
        reject = stage === "input-error" ? "input" : stage === "output-error" ? "output" : undefined;
        const write = stage === "create" || stage === "update" || stage === "output-error" || stage === "input-error";
        const marker = stage === "update" ? "updated" : stage === "output-error" ? "persisted" : stage === "input-error" ? "rejected" : storedMarker;
        const before = snapshot();
        const where = [{ field: "id", value: id }];
        const result = stage === "create"
          ? adapter.create({ model: model.model, forceAllowId: true, data: { undeclared: true, ...record(marker, model.first) } })
          : write ? adapter.update({ model: model.model, where, update: { marker, [model.target]: model.next, undeclared: true } })
          : adapter.findOne({ model: model.model, where });
        if (reject) await expect(result).rejects.toBe(errors[reject]);
        else {
          const actual = await result as Record<string, unknown>;
          const expected = record(marker, output);
          expect(actual).toStrictEqual(expected);
          expect(Object.keys(actual)).toStrictEqual(Object.keys(expected));
          expect(actual[model.target]).toBe(output);
          expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
        }
        if (!write || stage === "input-error") expect(snapshot()).toStrictEqual(before);
        if (write && stage !== "input-error") { storedMarker = marker; storedTarget = stage === "create" ? model.first : model.next; }
        expect(snapshot()).toStrictEqual(storedRecord(storedMarker, storedTarget));
        const expectedEvents: [string, string, unknown][] = [];
        if (write) expectedEvents.push(["input", "marker", marker], ["input", model.target, stage === "create" ? model.first : model.next]);
        if (stage !== "input-error") expectedEvents.push(["output", "marker", storedMarker], ["output", model.target, physicalValue(storedTarget)]);
        expect(events.splice(0)).toStrictEqual(expectedEvents);
      }
    } finally { database?.close(); }
  });
}
