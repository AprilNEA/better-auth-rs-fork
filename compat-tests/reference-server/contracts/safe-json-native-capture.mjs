import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { runWithEndpointContext } from "@better-auth/core/context";
import { safeJSONParse } from "@better-auth/core/utils/json";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const iso = "2030-01-02T03:04:05.000Z";
export const safeJsonNativeCases = [
  "array-own-map-function-result", "array-own-map-object-result", "array-map-getter-error",
  "array-map-method-error", "array-map-noncallable", "array-holes-and-undefined",
  "object-key-snapshot-and-late-getters", "object-getter-error", "logger-original-error",
  "date-root-skips-properties", "function-root-skips-properties", "object-native-children",
];

async function captureCase(name) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver();
  const events = [];
  const logs = [];
  const original = { failure: name, ownUndefined: undefined };
  const loggerFailure = { loggerFailure: name, original };
  const preservedDate = new Date(iso);
  const preservedFunction = function preservedFunction() {};
  let input;
  let result;
  let customResult;
  const event = (phase, fields = {}) => { native.record(phase, fields); events.push({ phase, ...fields }); };
  const getter = (root, key, read, enumerable = true) => Object.defineProperty(root, key, {
    enumerable, configurable: true, get() { event(`get:${key}`, { sameReceiver: this === root }); return read(); },
  });
  if (name.startsWith("array-") && name !== "array-holes-and-undefined") {
    input = [iso, , "ordinary"];
    customResult = name === "array-own-map-function-result" ? function mapResult() {} : {};
    Object.assign(customResult, { untouched: iso, preservedDate, preservedFunction });
    getter(input, "map", () => {
      if (name === "array-map-getter-error") throw original;
      if (name === "array-map-noncallable") return undefined;
      return function map(...args) {
        event("call:map", { sameReceiver: this === input, arguments: runtime.value(args) });
        assert.equal(args.length, 1);
        assert.equal(typeof args[0], "function");
        if (name === "array-map-method-error") throw original;
        const parsed = args[0].call("ignored receiver", iso, 9, input);
        const date = args[0].call(undefined, preservedDate);
        const fn = args[0].call(null, preservedFunction);
        const missing = args[0]();
        event("map:reviver-results", { parsed: runtime.value(parsed), date: runtime.value(date),
          fn: runtime.value(fn), missing: runtime.value(missing), sameDate: date === preservedDate, sameFunction: fn === preservedFunction });
        assert.equal(parsed.toISOString(), iso);
        assert.equal(date, preservedDate);
        assert.equal(fn, preservedFunction);
        assert.equal(missing, undefined);
        return customResult;
      };
    }, false);
  } else if (name === "array-holes-and-undefined") {
    input = [iso, , undefined, preservedDate, preservedFunction];
    input.ignoredNamedField = iso;
  } else if (name === "object-key-snapshot-and-late-getters") {
    input = {};
    let late = "before";
    const child = {};
    getter(child, "date", () => iso);
    getter(input, "first", () => {
      delete input.removed;
      late = iso;
      getter(input, "added", () => { throw new Error("A newly added key must not enter the captured key list"); });
      return child;
    });
    getter(input, "removed", () => { throw new Error("A removed key getter must not run"); });
    getter(input, "later", () => late);
    getter(input, "hidden", () => { throw new Error("A non-enumerable getter must not run"); }, false);
  } else if (name === "object-getter-error" || name === "logger-original-error") {
    input = {};
    getter(input, "first", () => {
      input.mutation = "retained-before-error";
      throw original;
    });
    getter(input, "later", () => { throw new Error("A getter after the first failure must not run"); });
  } else if (name === "date-root-skips-properties" || name === "function-root-skips-properties") {
    input = name.startsWith("date-") ? preservedDate : preservedFunction;
    input.iso = iso;
    getter(input, "unread", () => { throw new Error("Native roots must not enumerate their properties"); });
    if (input instanceof Date) getter(input, "getTime", () => { throw new Error("Revival must not read Date.getTime"); }, false);
  } else {
    assert.equal(name, "object-native-children");
    input = { date: preservedDate, fn: preservedFunction, iso, nested: { date: preservedDate, fn: preservedFunction } };
  }
  const before = native.snapshot(input);
  const logger = { error(message, ...args) {
    const error = args[0]?.error;
    logs.push({ message, arguments: native.snapshot(args), sameOriginal: error === original });
    event("logger:error", { message, argumentCount: args.length, argumentKeys: Object.keys(args[0]), sameOriginal: error === original,
      error: error instanceof Error ? { name: error.name, message: error.message, properties: runtime.ownValues(error) } : runtime.value(error) });
    if (name === "logger-original-error") throw loggerFailure;
  } };
  const outcome = await native.outcome(() => runtime.capture(async () => {
    result = await runWithEndpointContext({ context: { logger } }, () => safeJSONParse(input));
    return result;
  }, loggerFailure), loggerFailure);
  const identities = { sameInput: result === input, sameCustomResult: customResult !== undefined && result === customResult,
    sameDateChild: result?.date === preservedDate, sameFunctionChild: result?.fn === preservedFunction };
  const after = native.snapshot(input);
  const failure = ["array-map-getter-error", "array-map-method-error", "array-map-noncallable", "object-getter-error", "logger-original-error"].includes(name);
  assert.equal(logs.length, failure ? 1 : 0);
  assert.equal(outcome.returned, name !== "logger-original-error");
  if (failure) {
    assert.equal(logs[0].message, "Error parsing JSON");
    assert.equal(logs[0].sameOriginal, name !== "array-map-noncallable");
    if (name === "logger-original-error") assert.equal(outcome.sameOriginal, true);
    else assert.equal(result, null);
  } else if (name.startsWith("array-own-map-")) {
    assert.equal(result, customResult);
    assert.equal(result.untouched, iso);
  } else if (name === "array-holes-and-undefined") {
    assert.equal(result.length, input.length);
    assert.equal(Object.hasOwn(result, "1"), false);
    assert.equal(Object.hasOwn(result, "2"), true);
    assert.equal(result[2], undefined);
    assert.equal(result[3], preservedDate);
    assert.equal(result[4], preservedFunction);
    assert.equal(Object.hasOwn(result, "ignoredNamedField"), false);
  } else if (name === "object-key-snapshot-and-late-getters") {
    assert.deepEqual(Object.keys(result), ["first", "removed", "later"]);
    assert.equal(Object.hasOwn(result, "removed"), true);
    assert.equal(result.removed, undefined);
    assert.equal(result.first.date.toISOString(), iso);
    assert.equal(result.later.toISOString(), iso);
    assert.deepEqual(events.map(entry => entry.phase), ["get:first", "get:date", "get:later"]);
  } else if (name.endsWith("root-skips-properties")) {
    assert.equal(result, input);
    assert.equal(result.iso, iso);
    assert.deepEqual(events, []);
  } else {
    assert.notEqual(result, input);
    assert.equal(result.date, preservedDate);
    assert.equal(result.fn, preservedFunction);
    assert.equal(result.nested.date, preservedDate);
    assert.equal(result.nested.fn, preservedFunction);
    assert.equal(result.iso.toISOString(), iso);
  }
  return { name, before, outcome, events: native.events, logs, after, functions: native.functions,
    runtime: { outcome: runtime.outcome, events, identities,
      resultData: customResult && result === customResult ? runtime.ownValues(result) : undefined,
      inputKeysAfter: Object.keys(input), mutation: runtime.value(input.mutation), functionIds: runtime.functionIds } };
}

export async function captureSafeJsonNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const path = "@better-auth/core/dist/utils/json.mjs";
  const provenance = { path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex") };
  const cases = [];
  for (const name of safeJsonNativeCases) cases.push(await captureCase(name));
  return { version: secondaryNativeVersion, boundary: "safeJSONParse with the real endpoint-scoped logger; descriptor reflection and Error host metadata remain in the source audit.", provenance, cases };
}

if (import.meta.main) {
  const observation = await captureSafeJsonNative();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify({ contract: "safe-json-native", ...observation })}\n`);
}
