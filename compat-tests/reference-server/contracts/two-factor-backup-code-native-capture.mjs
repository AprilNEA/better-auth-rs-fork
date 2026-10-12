import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { serializeSignedCookie } from "better-call";
import { twoFactor } from "better-auth/plugins/two-factor";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, secondaryNativeNow as now, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { createConsumerHarness, consumerSecret, consumerUser } from "./verification-consumer-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

export const twoFactorBackupCodeNativeCases = [
  { name: "includes-false-still-filters", status: "false" },
  { name: "includes-truthy-object", status: "object" },
  { name: "includes-getter-original-error", fail: "includes:get" },
  { name: "includes-call-original-error", fail: "includes:call" },
  { name: "includes-false-filter-getter-original-error", status: "false", fail: "filter:get" },
  { name: "includes-false-filter-call-original-error", status: "false", fail: "filter:call" },
  ...["undefined", "null", "false", "zero", "nan", "empty"].map(updated => ({ name: `filter-${updated}`, updated })),
  { name: "filter-native-object", updated: "object" },
  { name: "filter-native-string", updated: "string" },
  { name: "filter-to-json-original-error", updated: "object", fail: "toJSON:call" },
  { name: "filter-cas-conflict", replace: true },
].map(scenario => ({ consumer: "two-factor-backup-code", value: "owner", status: "true", updated: "array", ...scenario }));

export async function captureTwoFactorBackupCodeNativeCase(scenario) {
  const identifier = "2fa-backup-native";
  const harness = createConsumerHarness(scenario, identifier);
  const { runtime, native } = harness;
  const attemptsIdentifier = `2fa-attempts-${identifier}`;
  const attemptsKey = `verification:${attemptsIdentifier}`;
  harness.cache.set(attemptsKey, JSON.stringify({
    id: "attempts-row", identifier: attemptsIdentifier, value: "0",
    expiresAt: new Date(now + 60_000), createdAt: new Date(now), updatedAt: new Date(now),
  }));
  const factor = { id: "factor-row", secret: "native-factor-secret", backupCodes: "native-backup-ciphertext",
    userId: "owner", verified: true, failedVerificationCount: 2, lockedUntil: null };
  harness.database.twoFactor = [factor];
  const visits = [];
  const codes = Object.assign(new Date(now), { marker: "native-codes", visits });
  const status = scenario.status === "false" ? false : scenario.status === "object" ? { marker: "native-status" } : true;
  const updated = scenario.updated === "undefined" ? undefined : scenario.updated === "null" ? null
    : scenario.updated === "false" ? false : scenario.updated === "zero" ? 0 : scenario.updated === "nan" ? NaN
    : scenario.updated === "empty" ? "" : scenario.updated === "string" ? "kept"
    : scenario.updated === "function" ? function backupUpdated() {}
    : scenario.updated.startsWith("object") ? { marker: "native-filter-result", ownUndefined: undefined } : ["keep", 7];
  const method = (object, name, body) => Object.defineProperty(object, name, {
    configurable: true, get() {
      visits.push(`${name}:get`);
      harness.event(`get:${name}`, { sameReceiver: this === object });
      if (scenario.fail === `${name}:get`) harness.fail(`throw:${name}:get`);
      return function backupMethod(...args) {
        visits.push(`${name}:call`);
        harness.event(`call:${name}`, { sameReceiver: this === object, arguments: runtime.value(args) },
          { sameReceiver: this === object, arguments: native.snapshot(args) });
        assert.equal(this, object);
        assert.equal(args.length, 1);
        if (scenario.fail === `${name}:call`) harness.fail(`throw:${name}:call`);
        return body(args);
      };
    },
  });
  method(codes, "includes", ([code]) => {
    assert.equal(code, "used");
    return status;
  });
  method(codes, "filter", ([predicate]) => {
    assert.equal(typeof predicate, "function");
    const results = [predicate.call("ignored receiver", "used", 9, codes), predicate.call(codes, ["used"]), predicate()];
    assert.deepEqual(results, [false, true, true]);
    harness.event("filter:predicate", { results });
    return updated;
  });
  if (scenario.updated.startsWith("object")) method(updated, "toJSON", ([key]) => {
    assert.equal(key, "");
    if (scenario.updated === "object-undefined") return undefined;
    return { codes: ["kept"], tag: "native" };
  });
  const codeState = () => ({ root: codes, visits: [...visits], status, updated });
  const codesBefore = native.snapshot(codeState());
  const runtimeCodesBefore = runtime.value(codeState());
  let context;
  const cipher = {
    async decrypt(ciphertext) {
      harness.event("cipher:decrypt", { sameCiphertext: ciphertext === "native-backup-ciphertext", value: runtime.value(ciphertext) });
      assert.equal(ciphertext, "native-backup-ciphertext");
      if (scenario.replace) {
        const replacement = await context.adapter.update({ model: "twoFactor", where: [{ field: "id", value: factor.id }],
          update: { backupCodes: "concurrent-backup-ciphertext" } });
        harness.event("cipher:replace", { result: runtime.value(replacement) }, { result: native.snapshot(replacement) });
      }
      return codes;
    },
    async encrypt(serialized) {
      harness.event("cipher:encrypt", { value: runtime.value(serialized) });
      if (scenario.fail === "cipher:encrypt") harness.fail("throw:cipher:encrypt");
      if (scenario.encrypted === "string") return "encoded-native-backup-codes";
      return serialized;
    },
  };
  const plugin = twoFactor({ backupCodeOptions: { storeBackupCodes: cipher } });
  const captured = await harness.capture([plugin], async (auth, authContext) => {
    context = authContext;
    const cookie = (await serializeSignedCookie(context.createAuthCookie("two_factor").name, identifier, consumerSecret)).split(";", 1)[0];
    return auth.api.verifyBackupCode({ body: { code: "used", disableSession: true }, headers: new Headers({ cookie }) });
  });
  const { events, after } = captured.observation.runtime;
  const methodPhases = events.filter(event => /^(get|call):(includes|filter|toJSON)$/.test(event.phase)).map(event => event.phase);
  const expectedMethods = ["get:includes", "call:includes", "get:filter", "call:filter"];
  if (scenario.fail === "includes:get") expectedMethods.splice(1);
  else if (scenario.fail === "includes:call") expectedMethods.splice(2);
  else if (scenario.fail === "filter:get") expectedMethods.splice(3);
  if (scenario.updated.startsWith("object")) expectedMethods.push("get:toJSON", "call:toJSON");
  assert.deepEqual(methodPhases, expectedMethods);
  const consumedAt = events.findIndex(event => event.phase === "storage.getAndDelete" && event.key === attemptsKey);
  const includesAt = events.findIndex(event => event.phase === "get:includes");
  assert.ok(consumedAt >= 0 && consumedAt < includesAt);
  assert.equal(after.targetSameRoot, true);
  assert.equal(after.targetPresent, true);
  const remaining = harness.cache.has(attemptsKey) ? JSON.parse(harness.cache.get(attemptsKey)) : undefined;
  const invalid = !scenario.fail && (scenario.status === "false" || ["undefined", "null", "false", "zero", "nan", "empty"].includes(scenario.updated));
  const restored = scenario.fail && scenario.fail !== "toJSON:call" && scenario.fail !== "cipher:encrypt";
  if (scenario.fail) {
    assert.equal(captured.caught, harness.original);
    assert.equal(captured.observation.runtime.outcome.sameOriginal, true);
  } else if (invalid) {
    assert.equal(captured.caught.statusCode, 401);
    assert.deepEqual(captured.caught.body, { code: "INVALID_BACKUP_CODE", message: "Invalid backup code" });
  } else if (scenario.replace) {
    assert.equal(captured.caught.statusCode, 409);
    assert.deepEqual(captured.caught.body, { message: "Failed to verify backup code. Please try again." });
  } else {
    assert.equal(captured.caught, undefined);
    assert.deepEqual(captured.result, { token: undefined, user: consumerUser() });
  }
  assert.equal(remaining?.value, invalid ? "1" : restored ? "0" : undefined);
  if (remaining) assert.equal(remaining.expiresAt, new Date(now + 60_000).toISOString());
  const success = !scenario.fail && !invalid && !scenario.replace;
  const encoded = scenario.encrypted === "string" ? "encoded-native-backup-codes" : scenario.updated === "object" ? '{"codes":["kept"],"tag":"native"}' : scenario.updated === "string" ? '"kept"' : '["keep",7]';
  assert.deepEqual(harness.database.twoFactor, [{ ...factor,
    backupCodes: scenario.replace ? "concurrent-backup-ciphertext" : success ? encoded : "native-backup-ciphertext",
    failedVerificationCount: success ? 0 : invalid ? 3 : 2,
  }]);
  assert.equal(events.filter(event => event.phase === "cipher:encrypt").length, success || scenario.replace || scenario.fail === "cipher:encrypt" ? 1 : 0);
  if (scenario.updated === "function" || scenario.updated === "object-undefined") {
    assert.deepEqual(events.find(event => event.phase === "cipher:encrypt").value, { type: "undefined" });
  }
  return { ...captured.observation, codes: { before: codesBefore, after: native.snapshot(codeState()) },
    runtime: { ...captured.observation.runtime, codes: { before: runtimeCodesBefore, after: runtime.value(codeState()) } } };
}

export async function captureTwoFactorBackupCodeNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["plugins/two-factor/backup-codes/index.mjs", "plugins/two-factor/verify-two-factor.mjs", "db/internal-adapter.mjs"].map(path => ({
    path: `better-auth/dist/${path}`, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/better-auth/dist/${path}`, import.meta.url))).digest("hex"),
  }));
  provenance.push({ path: "@better-auth/core/dist/utils/json.mjs", sha256: createHash("sha256")
    .update(readFileSync(new URL("../node_modules/@better-auth/core/dist/utils/json.mjs", import.meta.url))).digest("hex") });
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of twoFactorBackupCodeNativeCases) cases.push(await captureTwoFactorBackupCodeNativeCase(scenario));
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Real TwoFactor verifyBackupCode endpoint with disableSession=true, Memory adapter and secondary storage. A configured decrypt callback returns a native Date object, which safeJSONParse preserves. Complete includes/filter getter and method order, receiver identity, callback failures, attempts, factor rows and storage are observed. JSON encoding occurs through the real custom encrypt path. Concurrent replacement uses the real adapter update before the endpoint compare-and-swap. No consumer algorithm is copied into the harness.", cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "two-factor-backup-code-native", ...await captureTwoFactorBackupCodeNative() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
