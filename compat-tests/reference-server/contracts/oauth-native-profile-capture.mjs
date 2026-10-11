import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createState, errorValue, observeComplete, replaceGenerated, timestamp } from "./oauth-native-profile-values.mjs";
import { invoke, observeHeaders, setup, withProviderFetch } from "./oauth-native-profile-harness.mjs";

const version = "1.7.6";
export const nativeProfileScenarios = [
  { name: "generic-helper-dynamic", provider: "generic", operation: "helper", shape: "dynamic" },
  { name: "generic-helper-missing", provider: "generic", operation: "helper", shape: "missing" },
  { name: "generic-helper-null", provider: "generic", operation: "helper", shape: "null" },
  { name: "generic-helper-scalar-profile", provider: "generic", operation: "helper", shape: "scalar" },
  { name: "generic-helper-getters", provider: "generic", operation: "helper", shape: "getters" },
  { name: "generic-helper-mapper-error", provider: "generic", operation: "helper", shape: "mapper-error" },
  { name: "generic-helper-raw-getter-error", provider: "generic", operation: "helper", shape: "raw-getter-error" },
  { name: "generic-callback-identity", provider: "generic", operation: "callback", shape: "identity" },
  { name: "generic-callback-native-business", provider: "generic", operation: "callback", shape: "native-business" },
  { name: "generic-callback-empty-email", provider: "generic", operation: "callback", shape: "empty-email" },
  { name: "generic-callback-mapper-error", provider: "generic", operation: "callback", shape: "mapper-error" },
  { name: "social-callback-empty-email", provider: "social", operation: "callback", shape: "empty-email" },
  { name: "social-direct-empty-email", provider: "social", operation: "direct", shape: "empty-email" },
  { name: "social-callback-subject-error", provider: "social", operation: "callback", shape: "subject-error" },
  { name: "social-direct-subject-error", provider: "social", operation: "direct", shape: "subject-error" },
  { name: "social-direct-dynamic-email", provider: "social", operation: "direct", shape: "dynamic-email" },
  { name: "social-direct-falsy-defaults", provider: "social", operation: "direct", shape: "falsy-defaults" },
  { name: "generic-account-info-dynamic", provider: "generic", operation: "account-info", shape: "dynamic" },
  { name: "social-account-info-response-spread", provider: "social", operation: "account-info", shape: "response-spread" },
  { name: "social-account-info-spread-error", provider: "social", operation: "account-info", shape: "response-spread-error" },
];

function assertExecution(scenario, state, sample, outcome, events, value) {
  const subjects = events.filter(event => event.kind === "subject");
  assert.ok(events.some(event => event.kind === "get-user-info"), scenario.name);
  assert.equal(events.some(event => event.kind === "unexpected-social-mapper"), false);
  for (const event of events.filter(event => ["subject", "mapper"].includes(event.kind))) {
    assert.equal(event.sameProfile, true, `${scenario.name}: ${event.kind} must receive the original profile`);
  }
  if (scenario.operation === "account-info") {
    assert.equal(subjects.length, 0);
    assert.equal(state.admissions.length, 0);
    assert.equal(events.some(event => event.kind === "hook"), false);
    if (scenario.shape === "response-spread-error") {
      assert.equal(outcome.returned, false);
      assert.equal(outcome.originalError, true);
    } else {
      assert.equal(outcome.returned, true);
      assert.deepEqual(value.account, { id: "stored-account", providerId: sample.providerId, accountId: "stored-provider-id" });
      if (scenario.provider === "social") {
        assert.deepEqual(Object.keys(value), ["providerMeta", "user", "account", "data", "ownUndefined", "tail"]);
        assert.equal(value.providerMeta, state.marker);
        assert.equal(value.data, state.raw);
        assert.equal(Object.hasOwn(value, "hidden"), false);
      }
    }
  }
  if (scenario.shape === "empty-email") {
    assert.equal(subjects.length, scenario.operation === "callback" ? 1 : 0);
    assert.equal(state.admissions.length, 0);
    assert.deepEqual(sample.memory.user, []);
    assert.deepEqual(sample.memory.account, []);
    assert.deepEqual(sample.memory.session, []);
  }
  if (scenario.shape === "subject-error") {
    assert.equal(subjects.length, 1);
    assert.equal(state.admissions.length, 0);
    assert.deepEqual(sample.memory.user, []);
    assert.deepEqual(sample.memory.account, []);
    assert.deepEqual(sample.memory.session, []);
  }
  if (scenario.shape === "identity") {
    assert.equal(outcome.returned, true);
    assert.equal(outcome.status, 302);
    assert.equal(state.admissions.length, 1);
    assert.equal(sample.memory.account.length, 1);
    assert.equal(sample.memory.account[0].accountId, "23");
    assert.notEqual(sample.memory.account[0].accountId, state.mapped.id);
    assert.equal(state.raw.admissionMarker, state.marker);
  }
  if (["native-business", "falsy-defaults"].includes(scenario.shape)) {
    assert.equal(outcome.returned, true);
    for (const model of ["user", "account", "session"]) assert.equal(sample.memory[model].length, 1);
    assert.equal(sample.memory.account[0].accountId, "raw-account");
    if (scenario.shape === "falsy-defaults") {
      assert.equal(sample.memory.user[0].name, "");
      assert.equal(sample.memory.user[0].emailVerified, false);
      assert.equal(sample.memory.user[0].image, false);
    }
  }
  if (scenario.shape === "dynamic-email") {
    assert.equal(subjects.length, 1);
    assert.equal(outcome.returned, false);
    assert.equal(outcome.error.name, "TypeError");
    assert.equal(state.admissions.length, 0);
    for (const model of ["user", "account", "session"]) assert.deepEqual(sample.memory[model], []);
  }
  if (scenario.operation === "helper") {
    if (["mapper-error", "raw-getter-error"].includes(scenario.shape)) {
      assert.equal(outcome.returned, false);
      assert.equal(outcome.originalError, true);
      assert.equal(subjects.length, 0);
      assert.equal(events.some(event => event.kind === "own-keys" && event.object === "mapped"), false);
    } else if (scenario.shape === "scalar") {
      assert.equal(outcome.returned, false);
      assert.equal(outcome.error.message, "OAUTH_ACCOUNT_SUBJECT_INVALID");
      assert.equal(subjects.length, 1);
      assert.equal(state.info.data, 7);
      assert.deepEqual(state.info.user, { email: undefined, emailVerified: undefined, image: undefined, name: undefined });
    } else {
      assert.equal(outcome.returned, true);
      assert.equal(subjects.length, 1);
      assert.equal(value.info.data, state.raw);
      assert.equal(value.accountKey.accountId, "raw-account");
      if (["null", "missing", "getters"].includes(scenario.shape)) {
        assert.equal(Object.hasOwn(value.info.user, "image"), true);
        assert.equal(value.info.user.image, undefined);
      }
      if (scenario.shape === "dynamic") {
        assert.deepEqual(value.info.user.name, { label: "Mapped" });
        assert.equal(value.info.user.email, 9);
        assert.equal(value.info.user.emailVerified, "verified");
        assert.equal(value.info.user.image, 13);
      }
    }
  }
}

async function captureCase(scenario) {
  const state = createState(scenario);
  const sample = await setup(state);
  const before = {
    raw: observeComplete(state.raw, state, "before.raw"),
    mapped: observeComplete(state.mapped, state, "before.mapped"),
    storage: observeComplete(sample.memory, state, "before.storage"),
  };
  const beforeObservationEvents = state.events.splice(0);
  state.phase = "execute";
  let outcome;
  let value;
  let headers;
  try {
    const result = await withProviderFetch(state, () => invoke(sample, state));
    value = result.value;
    headers = result.headers;
    outcome = result.kind === "http"
      ? { returned: true, kind: "http", status: result.status, body: result.text }
      : { returned: true, kind: "native" };
  } catch (error) {
    outcome = { returned: false, ...errorValue(error, state) };
    headers = error.headers ? new Headers(error.headers) : undefined;
  }
  const executionEvents = state.events.splice(0);
  state.phase = "assertion";
  assertExecution(scenario, state, sample, outcome, executionEvents, value);
  const assertionEvents = state.events.splice(0);
  const observedHeaders = observeHeaders(headers, state);
  const after = {
    raw: observeComplete(state.raw, state, "after.raw"),
    mapped: observeComplete(state.mapped, state, "after.mapped"),
    providerResponse: observeComplete(state.info, state, "after.provider-response"),
    result: outcome.kind === "native" ? observeComplete(value, state, "after.result") : null,
    admissions: observeComplete(state.admissions, state, "after.admissions"),
    storage: observeComplete(sample.memory, state, "after.storage"),
  };
  if (scenario.operation === "account-info") assert.deepEqual(after.storage, before.storage);
  state.phase = "identity-observation";
  const identities = {
    providerDataIsRaw: state.info === undefined ? null : state.info.data === state.raw,
    customResponseIsOriginal: scenario.provider === "social" && state.info !== undefined ? state.info === state.socialResponse : null,
    mapperIsRaw: state.mapperInput === undefined ? null : state.mapperInput === state.raw,
    subjectIsRaw: state.subjectInput === undefined ? null : state.subjectInput === state.raw,
    admissionProfilesAreRaw: state.admissions.map(data => data.source.oauth.profile === state.raw),
  };
  return replaceGenerated({
    ...scenario, backend: "memory", before, outcome: { ...outcome, headers: observedHeaders },
    executionEvents, assertionEvents, after,
    observationEvents: { before: beforeObservationEvents, after: state.events.splice(0) },
    identities,
  }, state.replacements);
}

export async function captureOAuthNativeProfile() {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  const OriginalDate = globalThis.Date;
  class FixedDate extends OriginalDate {
    constructor(...args) { super(...(args.length ? args : [timestamp])); }
    static now() { return timestamp; }
    static [Symbol.hasInstance](value) { return value instanceof OriginalDate; }
  }
  globalThis.Date = FixedDate;
  try {
    const cases = [];
    for (const scenario of nativeProfileScenarios) cases.push(await captureCase(scenario));
    assert.equal(cases.length, 20);
    return { version, scenarios: nativeProfileScenarios, cases };
  } finally { globalThis.Date = OriginalDate; }
}

if (import.meta.main) {
  const output = `${JSON.stringify(await captureOAuthNativeProfile(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], output);
  else process.stdout.write(output);
}
