import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";

const date = new Date("2030-01-02T03:04:05.000Z");
export const coreQueryIdSortOperations = ["sort-only", "sort-after-email", "sort-after-id-in"];

function options(memory, serial, fields) {
  return {
    database: memoryAdapter(memory), baseURL: "http://core-query-id-sort.test",
    secret: "ordinary-core-query-id-sort-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: serial ? "serial" : ({ model }) => `${model}-query-id` } },
    user: { additionalFields: fields },
  };
}

function request(operation) {
  const where = operation === "sort-only" ? [] : operation === "sort-after-email"
    ? [{ field: "email", operator: "contains", value: "@core-query-id-sort.test" }]
    : [{ field: "id", operator: "in", value: ["1", "2"] }];
  return {
    findMany: { model: "user", where, sortBy: { field: "id", direction: "asc" }, limit: 10, offset: 0 },
    count: { model: "user", where },
  };
}

async function captureCase(operation, serial) {
  const memory = { user: [], session: [], account: [], verification: [] };
  const writer = (await betterAuth(options(memory, serial, {
    selectionId: { type: serial ? "number" : "string", fieldName: "old_id" },
    label: { type: "string" },
  })).$context).adapter;
  const setup = [];
  for (const [id, alias, label] of [["1", "2", "first"], ["2", "1", "second"]]) {
    const input = { model: "user", forceAllowId: true, data: {
      id, name: `Core sort ${label}`, email: `${label}@core-query-id-sort.test`, emailVerified: false,
      image: null, createdAt: date, updatedAt: date,
      selectionId: serial ? Number(alias) : alias, label,
    } };
    const before = observeValue(memory);
    const result = await writer.create(input);
    setup.push({ input: observeValue(input), before, result: observeValue(result), after: observeValue(memory) });
  }
  const events = [];
  const reader = await betterAuth(options(memory, serial, {
    id: { type: "string", fieldName: "old_id" },
    label: { type: "string", transform: {
      input(value) { events.push(["input", "label", observeValue(value)]); return value; },
      output(value) { events.push(["output", "label", observeValue(value)]); return value; },
    } },
  })).$context;
  const steps = [];
  for (const attempt of [1, 2]) {
    const input = request(operation);
    const before = observeValue(memory);
    const result = {
      users: await reader.internalAdapter.listUsers(input.findMany.limit, input.findMany.offset, input.findMany.sortBy, input.findMany.where),
      total: await reader.internalAdapter.countTotalUsers(input.count.where),
    };
    steps.push({ attempt, method: "listUsers+countTotalUsers", input: observeValue(input), before,
      result: observeValue(result), events: events.splice(0), after: observeValue(memory) });
  }
  return { model: "user", operation, serial, idFieldName: "old_id", setup, steps };
}

export async function captureCoreQueryIdSort() {
  const cases = [];
  for (const operation of coreQueryIdSortOperations) {
    for (const serial of [false, true]) cases.push(await captureCase(operation, serial));
  }
  return { version: "1.7.6", backend: "memory", cases };
}
