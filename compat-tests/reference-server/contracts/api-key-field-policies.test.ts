import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { APIError } from "@better-auth/core/error";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

function fieldPlugin(trace: string[], inputError = new Error("ordinary input error"), outputError = new Error("ordinary output error"), fieldName?: string) {
  return { id: "ordinary-key-name", schema: { apikey: { fields: { name: {
    type: "string" as const, required: true, defaultValue: "Fallback", onUpdate: () => "Renewed",
    ...(fieldName === undefined ? {} : { fieldName }),
    transform: {
      input(value: any) { trace.push(`input:${JSON.stringify(value)}`); if (value === "input-error") throw inputError; return value.trim(); },
      output(value: any) { trace.push(`output:${JSON.stringify(value)}`); if (value === "output-error") throw outputError; return `${value}:out`; },
    },
  } } } } };
}

async function fixture(backend: "memory" | "sqlite", mode: "database" | "secondary" | "fallback", trace: string[], plugin: any = fieldPlugin(trace), fieldName?: string) {
  const memory: Record<string, any[]> = {user: [], session: [], account: [], verification: [], apikey: []};
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const cache = new Map<string, string>();
  const customStorage = {
    get: async (key: string) => cache.get(key) ?? null,
    set: async (key: string, value: string) => { cache.set(key, value); },
    delete: async (key: string) => { cache.delete(key); },
  };
  const options = {
    database: database ?? memoryAdapter(memory), baseURL: "http://key-fields.test",
    secret: "ordinary-api-key-fields-contract-at-least-32-characters", logger: { disabled: true },
    emailAndPassword: { enabled: true },
    plugins: [apiKey({ storage: mode === "database" ? "database" : "secondary-storage", fallbackToDatabase: mode === "fallback", customStorage, deferUpdates: false }), plugin],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const column = fieldName || "name";
  const raw = (id: string) => database ? database.query<any, [string]>(`SELECT "${column}" FROM apikey WHERE id=?`).get(id) : memory.apikey.find(row => row.id === id);
  const snapshot = (id: string) => structuredClone(database ? database.query<any, [string]>("SELECT * FROM apikey WHERE id=?").get(id) : memory.apikey.find(row => row.id === id));
  return { auth, adapter: context.adapter, raw, snapshot, cache, close: () => database?.close() };
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const phase of ["input", "output"] as const) for (const kind of ["ordinary", "api"] as const) {
    test(`API Key update wraps ${kind} ${phase} errors after the ${backend} write boundary`, async () => {
      const trace: string[] = [];
      const message = `${kind} ${phase} storage failure`;
      const failure = kind === "api"
        ? new APIError("CONFLICT", { message: "original body message", code: "ORIGINAL" }, { "x-original": "discarded" })
        : new Error(message);
      failure.message = message;
      const f = await fixture(backend, "database", trace, fieldPlugin(trace, failure, failure));
      try {
        const created = await f.auth.api.createApiKey({ body: { userId: "ordinary-owner", name: "Desk" } });
        const before = f.snapshot(created.id);
        trace.length = 0;
        let caught: any;
        try { await f.auth.api.updateApiKey({ body: { userId: "ordinary-owner", keyId: created.id, name: `${phase}-error` } }); }
        catch (error) { caught = error; }
        expect(caught).toBeInstanceOf(APIError);
        expect(caught).not.toBe(failure);
        expect(caught.status).toBe("INTERNAL_SERVER_ERROR");
        expect(caught.statusCode).toBe(500);
        expect(caught.body).toStrictEqual({ message });
        expect(Object.keys(caught.body)).toStrictEqual(["message"]);
        expect([...new Headers(caught.headers).entries()]).toStrictEqual([]);
        expect(f.snapshot(created.id)).toStrictEqual(phase === "input" ? before : { ...before, name: "output-error" });
        expect(trace).toStrictEqual(phase === "input"
          ? ['output:"Desk"', 'input:"input-error"']
          : ['output:"Desk"', 'input:"output-error"', 'output:"output-error"']);
      } finally { f.close(); }
    });
  }

  test(`API Key update retains message getter failures at the ${backend} catch boundary`, async () => {
    const trace: string[] = [];
    const sentinel = new APIError("CONFLICT", { message: "message getter failure" });
    const failure = new Error("unread message");
    Object.defineProperty(failure, "message", { get() { throw sentinel; } });
    const f = await fixture(backend, "database", trace, fieldPlugin(trace, failure));
    try {
      const created = await f.auth.api.createApiKey({ body: { userId: "ordinary-owner", name: "Desk" } });
      const before = f.snapshot(created.id);
      trace.length = 0;
      await expect(f.auth.api.updateApiKey({ body: { userId: "ordinary-owner", keyId: created.id, name: "input-error" } })).rejects.toBe(sentinel);
      expect(f.snapshot(created.id)).toStrictEqual(before);
      expect(trace).toStrictEqual(['output:"Desk"', 'input:"input-error"']);
    } finally { f.close(); }
  });

  test(`API Key update leaves ${backend} lookup failures outside the write catch`, async () => {
    const trace: string[] = [];
    const failure = new APIError("CONFLICT", { message: "lookup failure", code: "ORIGINAL" });
    const f = await fixture(backend, "database", trace, fieldPlugin(trace, failure, failure));
    try {
      const created = await f.auth.api.createApiKey({ body: { userId: "ordinary-owner", name: "Desk" } });
      await expect(f.adapter.update({ model: "apikey", where: [{ field: "id", value: created.id }], update: { name: "output-error" } })).rejects.toBe(failure);
      const before = f.snapshot(created.id);
      trace.length = 0;
      await expect(f.auth.api.updateApiKey({ body: { userId: "ordinary-owner", keyId: created.id, name: "Mobile" } })).rejects.toBe(failure);
      expect(f.snapshot(created.id)).toStrictEqual(before);
      expect(trace).toStrictEqual(['output:"output-error"']);
    } finally { f.close(); }
  });
}

test("ordinary API Key names preserve adapter write phases and legal counter expressions", async () => {
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = []; const inputError = new Error("ordinary input error"); const outputError = new Error("ordinary output error");
    const f = await fixture(backend, "database", trace, fieldPlugin(trace, inputError, outputError));
    const create = (name: string | null, key: string) => f.adapter.create<any>({model: "apikey", data: {
      name, key, configId: "default", referenceId: "ordinary-owner", enabled: true, remaining: 10,
      rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3, requestCount: 0,
      lastRefillAt: null, lastRequest: null, createdAt: new Date(), updatedAt: new Date(),
    }});
    const created = await create("  Desk  ", "ordinary-first");
    expect(created.name).toBe("Desk:out"); expect(f.raw(created.id).name).toBe("Desk");
    expect(trace).toStrictEqual(['input:"  Desk  "', 'output:"Desk"']);
    expect((await create(null, "ordinary-default")).name).toBe("Fallback:out");
    const where = [{field: "id", value: created.id}];
    const updated: any = await f.adapter.update({model: "apikey", where, update: {name: "  Mobile  "}});
    expect(updated.name).toBe("Mobile:out");
    trace.length = 0;
    const list: any[] = await f.adapter.findMany({model: "apikey", sortBy: {field: "name", direction: "asc"}});
    expect(list.map(row => row.name)).toStrictEqual(["Fallback:out", "Mobile:out"]);
    expect(trace).toStrictEqual(['output:"Fallback"', 'output:"Mobile"']);
    const now = new Date();
    const writes = [
      {increment: {remaining: -1}},
      {increment: {}, set: {requestCount: 1, lastRequest: now}},
      {increment: {requestCount: 1}, set: {lastRequest: now}},
      {update: {lastRequest: now}}, {update: {updatedAt: now}},
      {increment: {}, set: {remaining: 8, lastRefillAt: now}},
    ];
    for (const [index, write] of writes.entries()) {
      trace.length = 0;
      const row: any = "update" in write
        ? await f.adapter.update({model: "apikey", where, update: write.update!})
        : await f.adapter.incrementOne({model: "apikey", where, increment: write.increment!, ...("set" in write ? {set: write.set} : {})});
      expect(row.remaining).toBe(index === 5 ? 8 : 9);
      expect(row.requestCount).toBe(index === 0 ? 0 : index === 1 ? 1 : 2);
      expect(row.name).toBe(index === 0 ? "Mobile:out" : "Renewed:out");
      expect(trace).toStrictEqual(index === 0 ? ['output:"Mobile"'] : ['input:"Renewed"', 'output:"Renewed"']);
      expect(f.raw(created.id).name).toBe(index === 0 ? "Mobile" : "Renewed");
    }
    await expect(create("input-error", "ordinary-input-error")).rejects.toBe(inputError);
    await expect(create("output-error", "ordinary-output-error")).rejects.toBe(outputError);
    f.close();
  }
});

test("ordinary and mapped API Key cache-only and fallback hits bypass adapter name policies", async () => {
  for (const fieldName of [undefined, "", "stored_name"]) for (const backend of ["memory", "sqlite"] as const) for (const mode of ["database", "secondary", "fallback"] as const) {
    const trace: string[] = []; const f = await fixture(backend, mode, trace, fieldPlugin(trace, undefined, undefined, fieldName), fieldName);
    const cachedName = (id: string, expected: string) => {
      const cached = JSON.parse(f.cache.get(`api-key:by-id:${id}`)!);
      expect(cached.name).toBe(expected);
      expect(Object.hasOwn(cached, "stored_name")).toBe(false);
      expect(cached.id).toBe(id);
    };
    const signup = await f.auth.api.signUpEmail({body: {name: "Owner", email: "owner@key-fields.test", password: "ordinary-fixture-password"}, returnHeaders: true});
    const headers = new Headers({cookie: signup.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ")});
    const created: any = await f.auth.api.createApiKey({headers, body: {name: "  Desk  "}});
    const expected = mode === "secondary" ? "  Desk  " : "Desk:out";
    expect(created.name).toBe(expected);
    expect(trace).toStrictEqual(mode === "secondary" ? [] : ['input:"  Desk  "', 'output:"Desk"']);
    expect(f.raw(created.id)?.[fieldName || "name"] ?? null).toBe(mode === "secondary" ? null : "Desk");
    if (fieldName !== undefined && mode !== "database") cachedName(created.id, expected);
    trace.length = 0;
    expect((await f.auth.api.getApiKey({headers, query: {id: created.id}})).name).toBe(expected);
    expect(trace).toStrictEqual(mode === "database" ? ['output:"Desk"'] : []);
    for (let turn = 0; turn < 2; turn++) {
      trace.length = 0;
      expect((await f.auth.api.listApiKeys({headers})).apiKeys[0].name).toBe(expected);
      expect(trace).toStrictEqual(mode === "database" || mode === "fallback" && turn === 0 ? ['output:"Desk"'] : []);
    }
    trace.length = 0;
    const updated: any = await f.auth.api.updateApiKey({headers, body: {keyId: created.id, name: "  Mobile  "}});
    expect(updated.name).toBe(mode === "secondary" ? "  Mobile  " : "Mobile:out");
    if (fieldName !== undefined && mode !== "database") cachedName(created.id, mode === "secondary" ? "  Mobile  " : "Mobile:out");
    expect(trace).toStrictEqual(mode === "secondary" ? [] : [...(mode === "database" ? ['output:"Desk"'] : []), 'input:"  Mobile  "', 'output:"Mobile"']);
    if (mode === "fallback") {
      f.cache.delete(`api-key:by-id:${created.id}`);
      for (let turn = 0; turn < 2; turn++) {
        trace.length = 0;
        expect((await f.auth.api.getApiKey({headers, query: {id: created.id}})).name).toBe("Mobile:out");
        expect(trace).toStrictEqual(turn === 0 ? ['output:"Mobile"'] : []);
        if (fieldName !== undefined) cachedName(created.id, "Mobile:out");
      }
    }
    f.close();
  }
});

const timestamps = {
  old: "2000-01-02T03:04:05.000Z", generated: "2001-01-02T03:04:05.000Z",
  stored: "2002-01-02T03:04:05.000Z", projected: "2003-01-02T03:04:05.000Z",
  supplied: "2004-01-02T03:04:05.000Z", usage: "2005-01-02T03:04:05.000Z",
};
const timestampEvent = (phase: string, value: string) => `${phase}:${JSON.stringify(value)}`;
const jsonRecord = (value: any) => JSON.parse(JSON.stringify(value));
function publicRecord(row: any) {
  const { key, ...view } = row;
  return jsonRecord({ ...view, metadata: row.metadata ?? null, permissions: row.permissions ? JSON.parse(row.permissions) : null });
}
function timestampInput(key: string, metadata: any = null) {
  return { name: "Desk", key, configId: "default", referenceId: "ordinary-owner", start: null, prefix: null,
    enabled: true, remaining: 10, rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3,
    requestCount: 0, refillInterval: null, refillAmount: null, lastRefillAt: null, lastRequest: null,
    expiresAt: null, createdAt: new Date(timestamps.old), updatedAt: new Date(timestamps.old), permissions: null, metadata };
}
function timestampFields(trace: string[], declaration: string) {
  const state = { enabled: false, failure: "" };
  const errors = Object.fromEntries(["onUpdate", "input", "output"].map(phase => [phase, new Error(`ordinary updatedAt ${phase} error`)]));
  const emit = (phase: string, value?: any) => {
    trace.push(phase === "onUpdate" ? phase : `${phase}:${JSON.stringify(value)}`);
    if (state.failure === phase) throw errors[phase];
  };
  const updatedAt = { type: "date" as const, required: false,
    ...(declaration === "on-update" ? { onUpdate() { emit("onUpdate"); return new Date(timestamps.generated); } } : {}),
    transform: {
      input(value: any) { if (!state.enabled) return value; emit("input", value); return new Date(timestamps.stored); },
      output(value: any) { if (!state.enabled) return value; emit("output", value); return new Date(timestamps.projected); },
    },
  };
  return { state, errors, plugin: { id: "ordinary-key-timestamps", schema: { apikey: { fields: declaration === "native" ? {} : { updatedAt } } } } };
}

test("API Key updates preserve omitted dates, supplied dates, and timestamp callback phases", async () => {
  for (const backend of ["memory", "sqlite"] as const) for (const declaration of ["native", "replacement", "on-update"]) {
    const trace: string[] = [];
    const { state, errors, plugin } = timestampFields(trace, declaration);
    const f = await fixture(backend, "database", trace, plugin);
    try {
      const key: any = await f.adapter.create({ model: "apikey", data: timestampInput(`timestamp-${declaration}`) });
      let expectedStored = f.snapshot(key.id);
      const where = [{ field: "id", value: key.id }];
      const replacement = declaration !== "native";
      const onUpdate = declaration === "on-update";
      const physicalDate = (value: string) => backend === "memory" ? new Date(value) : value;
      state.enabled = true;
      const updated = await f.auth.api.updateApiKey({ body: { userId: "ordinary-owner", keyId: key.id, name: "Mobile" } });
      expect(jsonRecord(updated)).toStrictEqual({ ...publicRecord(key), name: "Mobile", updatedAt: replacement ? timestamps.projected : timestamps.old });
      expectedStored = { ...expectedStored, name: "Mobile", updatedAt: physicalDate(onUpdate ? timestamps.stored : timestamps.old) };
      expect(f.snapshot(key.id)).toStrictEqual(expectedStored);
      expect(trace.splice(0)).toStrictEqual(onUpdate
        ? [timestampEvent("output", timestamps.old), "onUpdate", timestampEvent("input", timestamps.generated), timestampEvent("output", timestamps.stored)]
        : replacement ? [timestampEvent("output", timestamps.old), timestampEvent("output", timestamps.old)] : []);

      const supplied: any = await f.adapter.update({ model: "apikey", where, update: { name: "Typed", updatedAt: new Date(timestamps.supplied) } });
      expect(jsonRecord(supplied)).toStrictEqual({ ...jsonRecord(key), name: "Typed", updatedAt: replacement ? timestamps.projected : timestamps.supplied });
      expectedStored = { ...expectedStored, name: "Typed", updatedAt: physicalDate(replacement ? timestamps.stored : timestamps.supplied) };
      expect(f.snapshot(key.id)).toStrictEqual(expectedStored);
      expect(trace.splice(0)).toStrictEqual(replacement ? [timestampEvent("input", timestamps.supplied), timestampEvent("output", timestamps.stored)] : []);

      const usage: any = await f.adapter.update({ model: "apikey", where, update: { updatedAt: new Date(timestamps.usage) } });
      expect(jsonRecord(usage)).toStrictEqual({ ...jsonRecord(key), name: "Typed", updatedAt: replacement ? timestamps.projected : timestamps.usage });
      expectedStored = { ...expectedStored, updatedAt: physicalDate(replacement ? timestamps.stored : timestamps.usage) };
      expect(f.snapshot(key.id)).toStrictEqual(expectedStored);
      expect(trace.splice(0)).toStrictEqual(replacement ? [timestampEvent("input", timestamps.usage), timestampEvent("output", timestamps.stored)] : []);

      if (onUpdate) for (const [index, phase] of ["onUpdate", "input", "output"].entries()) {
        state.failure = phase;
        await expect(f.adapter.update({ model: "apikey", where, update: { name: "Rejected" } })).rejects.toBe(errors[phase]);
        if (phase === "output") expectedStored = { ...expectedStored, name: "Rejected" };
        expect(f.snapshot(key.id)).toStrictEqual(expectedStored);
        expect(trace.splice(0)).toStrictEqual(["onUpdate", timestampEvent("input", timestamps.generated), timestampEvent("output", timestamps.stored)].slice(0, index + 1));
      }
    } finally { f.close(); }
  }
});

test("secondary-only API Key updates own the timestamp and bypass adapter policies", async () => {
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = [];
    const { state, plugin } = timestampFields(trace, "on-update");
    const f = await fixture(backend, "secondary", trace, plugin);
    try {
      const key: any = await f.adapter.create({ model: "apikey", data: timestampInput("secondary-timestamp") });
      const before = f.snapshot(key.id);
      f.cache.set(`api-key:by-id:${key.id}`, JSON.stringify(key));
      state.enabled = true;
      state.failure = "onUpdate";
      const earliest = Date.now();
      const updated = await f.auth.api.updateApiKey({ body: { userId: "ordinary-owner", keyId: key.id, name: "Cached" } });
      const latest = Date.now();
      expect(new Date(updated.updatedAt).getTime()).toBeGreaterThanOrEqual(earliest);
      expect(new Date(updated.updatedAt).getTime()).toBeLessThanOrEqual(latest);
      expect(new Date(updated.updatedAt).toISOString()).not.toBe(timestamps.old);
      expect(jsonRecord(updated)).toStrictEqual({ ...publicRecord(key), name: "Cached", updatedAt: new Date(updated.updatedAt).toISOString() });
      expect(JSON.parse(f.cache.get(`api-key:by-id:${key.id}`)!)).toStrictEqual({ ...jsonRecord(key), name: "Cached", updatedAt: new Date(updated.updatedAt).toISOString() });
      expect(f.snapshot(key.id)).toStrictEqual(before);
      expect(trace).toStrictEqual([]);
    } finally { f.close(); }
  }
});

test("API Key legacy metadata repair preserves the timestamp and the remaining record", async () => {
  for (const backend of ["memory", "sqlite"] as const) {
    const { plugin } = timestampFields([], "native");
    const f = await fixture(backend, "database", [], plugin);
    try {
      const metadata = { legacy: "value" };
      const key: any = await f.adapter.create({ model: "apikey", data: timestampInput("legacy-timestamp", JSON.stringify(metadata)) });
      const before = f.snapshot(key.id);
      const updated = await f.auth.api.updateApiKey({ body: { userId: "ordinary-owner", keyId: key.id, name: "Mobile" } });
      expect(jsonRecord(updated)).toStrictEqual({ ...publicRecord(key), name: "Mobile", metadata });
      expect(f.snapshot(key.id)).toStrictEqual({ ...before, name: "Mobile", metadata: JSON.stringify(metadata) });
    } finally { f.close(); }
  }
});
