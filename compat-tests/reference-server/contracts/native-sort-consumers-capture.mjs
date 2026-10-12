import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getJwksAdapter } from "../node_modules/better-auth/dist/plugins/jwt/adapter.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, withSecondarySourceExports } from "./secondary-native-shared.mjs";
import { createNativeSortHarness, nativeSortScenarios, jwkSortScenarios } from "./native-sort-consumers-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const version = "1.7.6";
assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/api-key", "@better-auth/memory-adapter"]);

function source(path) {
  return { path, sha256: createHash("sha256").update(readFileSync(new URL(path, import.meta.url))).digest("hex") };
}

async function captureMemory(scenario, direction) {
  const harness = createNativeSortHarness("memory", scenario);
  const memory = { user: harness.rows, session: [], account: [], verification: [] };
  const { adapter } = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://native-sort-consumers.test",
    secret: "native-sort-consumers-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    user: { additionalFields: { name: { type: "string", required: false, transform: { output(value) {
      harness.record("output", { value: value !== null && typeof value === "object" ? "native-object" : harness.observe(value) });
      return value;
    } } } },
  }).$context;
  assert.deepEqual(harness.events, [], "Context initialization must not consume sorting fields");
  const captured = await harness.capture(() => adapter.findMany({
    model: "user", sortBy: { field: "name", direction }, limit: 1000,
  }));
  assert.deepEqual([memory.session, memory.account, memory.verification], [[], [], []]);
  assert.equal(memory.user, harness.rows);
  return { consumer: "memory", scenario: scenario.name, direction, ...captured };
}

async function captureApiKey(module, scenario, direction) {
  const harness = createNativeSortHarness("api-key", scenario);
  const captured = await harness.capture(() => module.applySortingAndPagination(harness.rows, "name", direction));
  return { consumer: "api-key", scenario: scenario.name, direction, ...captured };
}

async function captureJwk(scenario, lane, algorithm) {
  const harness = createNativeSortHarness("jwk", scenario);
  const ctx = { marker: "sort-context" };
  const baseAdapter = { async findMany(...args) {
    harness.record("adapter-read", { arguments: harness.observe(args), sameReceiver: this === baseAdapter });
    return harness.rows;
  } };
  const customAdapter = { async getJwks(...args) {
    harness.record("keyring-read", { arguments: harness.observe(args), sameReceiver: this === customAdapter });
    return harness.rows;
  } };
  const adapter = getJwksAdapter(baseAdapter, {
    jwks: { keyPairConfig: { alg: "EdDSA" } }, ...(lane === "custom" ? { adapter: customAdapter } : {}),
  });
  const captured = await harness.capture(() => algorithm
    ? adapter.getLatestKeyByAlg(ctx, algorithm) : adapter.getLatestKey(ctx));
  return { consumer: "jwk", scenario: scenario.name, lane, algorithm: algorithm ?? null, ...captured };
}

export async function captureNativeSortConsumers(observed) {
  return await withClock(async setClock => {
    setClock(2_000_000_000_000);
    await withSecondarySourceExports("@better-auth/api-key", ["applySortingAndPagination"], async (module, provenance) => {
      observed.sources.apiKey = provenance;
      for (const scenario of nativeSortScenarios) {
        for (const direction of ["asc", "desc"]) {
          observed.cases.push(await captureMemory(scenario, direction));
          observed.cases.push(await captureApiKey(module, scenario, direction));
        }
        observed.cases.push(await captureJwk(scenario, "custom"));
      }
      for (const scenario of [...jwkSortScenarios, nativeSortScenarios[5]]) {
        for (const lane of ["default", "custom"]) {
          for (const algorithm of [undefined, "EdDSA"]) observed.cases.push(await captureJwk(scenario, lane, algorithm));
        }
      }
    });
    return observed;
  });
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the native sort consumers capture output path");
  const observed = {
    version,
    runtime: { bun: Bun.version, versions: { ...process.versions }, collator: new Intl.Collator().resolvedOptions() },
    sources: {
      memory: source("../node_modules/@better-auth/memory-adapter/dist/index.mjs"),
      jwk: source("../node_modules/better-auth/dist/plugins/jwt/adapter.mjs"),
    },
    scenarios: [...nativeSortScenarios, ...jwkSortScenarios].map(scenario => ({
      ...scenario, values: scenario.values.map(value => ({
        ...value,
        ...(Object.hasOwn(value, "value") ? { value: value.value === undefined ? { type: "undefined" }
          : typeof value.value === "number" && !Number.isFinite(value.value) ? { type: "number", value: String(value.value) } : value.value } : {}),
      })),
    })),
    cases: [],
  };
  try {
    await captureNativeSortConsumers(observed);
    assert.equal(observed.cases.length, nativeSortScenarios.length * 5 + (jwkSortScenarios.length + 1) * 4);
    writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
  } finally {
    const serialized = `${JSON.stringify(observed, null, 2)}\n`;
    writeFileSync(`${output}.raw.json`, serialized);
    await writeObservation(serialized);
  }
}
