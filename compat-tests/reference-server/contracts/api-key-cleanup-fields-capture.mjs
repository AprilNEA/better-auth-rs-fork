import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";
import { nativeInput, nativePlugin } from "./native-plugin-replacements-capture.mjs";

export const apiKeyCleanupCurrent = new Date("2031-01-02T03:04:05.000Z");
export const apiKeyCleanupScenarios = [
  { name: "mapped-date", type: "date", serial: false, reference: false },
  { name: "mapped-json", type: "json", serial: false, reference: false },
  { name: "mapped-serial-reference", type: "date", serial: true, reference: true },
];

export function apiKeyCleanupConfiguration(scenario, events) {
  const declaration = {
    type: scenario.type, required: false, fieldName: "stored_expiry",
    ...(scenario.reference ? { references: { model: "user", field: "id" } } : {}),
    transform: {
      input(value) { events.push(["input", "expiresAt", observeValue(value)]); return value; },
      output(value) { events.push(["output", "expiresAt", observeValue(value)]); return value; },
    },
  };
  return {
    baseURL: "http://cleanup-fields.test",
    secret: "ordinary-cleanup-fields-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: scenario.serial ? "serial" : ({ model }) => `${model}-query-id` } },
    plugins: [nativePlugin("apikey"), { id: "cleanup-fields", schema: { apikey: { fields: { expiresAt: declaration } } } }],
  };
}

async function captureCase(scenario) {
  const memory = { user: [], session: [], account: [], verification: [], apikey: [] };
  const events = [];
  const context = await betterAuth({
    database: memoryAdapter(memory), ...apiKeyCleanupConfiguration(scenario, events),
  }).$context;
  const setup = [];
  for (const [index, expiresAt] of [new Date("2030-01-02T03:04:05.000Z"), new Date("2032-01-02T03:04:05.000Z"), null].entries()) {
    const input = { model: "apikey", forceAllowId: true, data: {
      ...nativeInput("apikey"), id: String(index + 1), expiresAt,
    } };
    const before = observeValue(memory);
    const result = await context.adapter.create(input);
    setup.push({ input: observeValue(input), before, result: observeValue(result), events: events.splice(0), after: observeValue(memory) });
  }
  const steps = [];
  for (const attempt of [1, 2]) {
    const input = { model: "apikey", where: [
      { field: "expiresAt", operator: "lt", value: apiKeyCleanupCurrent },
      { field: "expiresAt", operator: "ne", value: null },
    ] };
    const before = observeValue(memory);
    const result = await context.adapter.deleteMany(input);
    steps.push({ attempt, method: "deleteMany", input: observeValue(input), before, result: observeValue(result), events: events.splice(0), after: observeValue(memory) });
  }
  assert.deepEqual(steps.map(step => step.events), [[], []]);
  return { scenario, setup, steps };
}

export async function captureApiKeyCleanupFields() {
  const cases = [];
  for (const scenario of apiKeyCleanupScenarios) cases.push(await captureCase(scenario));
  return { version: "1.7.6", backend: "memory", current: observeValue(apiKeyCleanupCurrent), cases };
}
