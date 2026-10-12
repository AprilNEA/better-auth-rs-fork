import assert from "node:assert/strict";
import { secondaryNativeNow as now } from "./secondary-native-shared.mjs";

export const verificationConsumeNativeCases = [
  "native-object-identity", "native-object-expiry-before-spread", "native-expiry-date-skips-own-methods",
  "native-expiry-getter-error", "native-date-conversion-getter-error", "native-date-conversion-method-error",
  "native-spread-getter-error", "native-second-expiry-getter-error", "native-invalid-expiry-skips-spread",
  "native-expired-object", "native-null-expiry", "native-array-root", "native-date-root", "native-function-root",
  "native-true", "native-number", "native-infinity", "native-false", "native-null", "native-undefined",
  "string-object-revival", "string-true", "string-number", "string-text", "string-array", "string-null", "string-malformed",
];

export function verificationConsumeInput(name, event, runtime, targetPresent) {
  const iso = "2030-01-02T03:04:05.000Z";
  const original = { failure: name, ownUndefined: undefined };
  const childDate = new Date(now - 3000);
  const childFunction = function preservedChild() {};
  const nested = { iso, childDate, childFunction, ownUndefined: undefined };
  const expiryDate = new Date(now + 60_000);
  let input;
  let expiryReads = 0;
  let conversionCalls = 0;

  const effect = (phase, fields = {}) => {
    assert.equal(targetPresent(), false, "Atomic consumption must precede hydration callbacks");
    event(phase, { ...fields, targetPresent: targetPresent() });
  };
  const getter = (root, key, read, enumerable = true) => Object.defineProperty(root, key, {
    enumerable, configurable: true, get() {
      effect(`get:${key}`, { sameReceiver: this === root });
      return read();
    },
  });
  const fail = phase => {
    input.mutation = `retained:${phase}`;
    effect("throw", { stage: phase, error: runtime.value(original) });
    throw original;
  };
  const record = () => ({ id: "native-row", identifier: "subject", value: iso, expiresAt: expiryDate,
    createdAt: iso, updatedAt: iso, nested, ownUndefined: undefined, childFunction });

  if (name === "native-object-identity" || name === "native-expiry-date-skips-own-methods") {
    input = record();
    if (name === "native-expiry-date-skips-own-methods") {
      for (const key of ["getTime", "valueOf", "toString"]) {
        getter(expiryDate, key, () => { throw new assert.AssertionError({ message: `Date construction must not read ${key}` }); }, false);
      }
    }
  } else if (name === "native-object-expiry-before-spread" || name.endsWith("-error") || name === "native-invalid-expiry-skips-spread") {
    input = { id: "native-row", identifier: "subject" };
    const converted = {};
    getter(converted, "valueOf", () => {
      if (name === "native-date-conversion-getter-error") return fail("valueOf-getter");
      return function valueOf(...args) {
        conversionCalls += 1;
        effect("call:valueOf", { sameReceiver: this === converted, arguments: runtime.value(args), conversionCalls });
        assert.deepEqual(args, []);
        if (name === "native-date-conversion-method-error") return fail("valueOf-method");
        return now + 60_000;
      };
    }, false);
    getter(input, "payload", () => {
      if (name === "native-spread-getter-error") return fail("payload-getter");
      effect("payload:read", { expiryReads, conversionCalls });
      assert.equal(expiryReads, 1);
      assert.equal(conversionCalls, 1);
      return nested;
    });
    getter(input, "expiresAt", () => {
      expiryReads += 1;
      effect("expiry:read", { expiryReads });
      if (name === "native-expiry-getter-error") return fail("expiry-getter");
      if (name === "native-second-expiry-getter-error" && expiryReads === 2) return fail("second-expiry-getter");
      if (name === "native-invalid-expiry-skips-spread") return undefined;
      return expiryReads === 1 ? converted : "ignored-spread-expiry";
    });
    input.value = iso;
  } else if (name === "native-expired-object" || name === "native-null-expiry") {
    input = record();
    input.expiresAt = name === "native-null-expiry" ? null : new Date(now - 1);
    getter(input, "spreadWitness", () => {
      effect("spread:witness");
      return "read-before-expiration-gate";
    });
  } else if (name === "native-array-root" || name === "native-date-root") {
    input = name === "native-array-root" ? ["array-value", , undefined] : new Date(now - 4000);
    Object.assign(input, { id: "native-row", identifier: "subject", value: iso, expiresAt: expiryDate, nested });
    getter(input, name === "native-array-root" ? "map" : "getTime", () => {
      throw new assert.AssertionError({ message: "Native roots must bypass safeJSONParse revival" });
    }, false);
  } else if (name === "native-function-root") {
    input = function rejectedFunctionRoot() {};
    getter(input, "expiresAt", () => {
      throw new assert.AssertionError({ message: "Function roots must be rejected before reading properties" });
    });
  } else if (name.startsWith("native-")) {
    const values = { "native-true": true, "native-number": 42, "native-infinity": Infinity,
      "native-false": false, "native-null": null, "native-undefined": undefined };
    assert.ok(Object.hasOwn(values, name));
    input = values[name];
  } else if (name === "string-object-revival") {
    input = JSON.stringify(record());
  } else {
    const values = { "string-true": "true", "string-number": "42", "string-text": '"text"',
      "string-array": "[]", "string-null": "null", "string-malformed": "{" };
    assert.ok(Object.hasOwn(values, name));
    input = values[name];
  }

  function identities(result) {
    return {
      sameInput: result === input,
      sameNested: result?.nested === nested,
      samePayload: result?.payload === nested,
      sameChildDate: result?.nested?.childDate === childDate,
      sameChildFunction: result?.nested?.childFunction === childFunction,
      sameTopFunction: result?.childFunction === childFunction,
      sameExpiryDate: result?.expiresAt === expiryDate,
    };
  }

  function verify(outcome, result) {
    const failed = name.endsWith("-error");
    assert.equal(outcome.returned, !failed);
    if (failed) {
      assert.equal(outcome.sameOriginal, true);
      assert.equal(typeof input.mutation, "string");
      return;
    }
    const returnsRecord = ["native-object-identity", "native-object-expiry-before-spread", "native-expiry-date-skips-own-methods",
      "native-array-root", "native-date-root", "string-object-revival"].includes(name);
    if (!returnsRecord) {
      assert.equal(result, null);
      return;
    }
    assert.notEqual(result, input);
    assert.equal(Date.prototype.getTime.call(result.expiresAt), now + 60_000);
    assert.notEqual(result.expiresAt, expiryDate);
    if (name === "native-object-expiry-before-spread") {
      assert.equal(result.payload, nested);
      assert.equal(expiryReads, 2);
      assert.equal(conversionCalls, 1);
      assert.deepEqual(Object.keys(result), ["id", "identifier", "payload", "expiresAt", "value"]);
    } else if (name === "string-object-revival") {
      assert.equal(Date.prototype.toISOString.call(result.value), iso);
      assert.equal(Date.prototype.toISOString.call(result.nested.iso), iso);
      assert.notEqual(result.nested, nested);
      assert.equal(Object.hasOwn(result, "ownUndefined"), false);
    } else {
      assert.equal(result.value, iso);
      assert.equal(result.nested, nested);
      assert.equal(result.nested.iso, iso);
      assert.equal(result.nested.childDate, childDate);
      assert.equal(result.nested.childFunction, childFunction);
      if (name === "native-array-root") {
        assert.equal(Array.isArray(result), false);
        assert.deepEqual(Object.keys(result), ["0", "2", "id", "identifier", "value", "expiresAt", "nested"]);
        assert.equal(Object.hasOwn(result, "1"), false);
        assert.equal(Object.hasOwn(result, "2"), true);
        assert.equal(result[2], undefined);
      }
      if (name === "native-date-root") assert.equal(result instanceof Date, false);
    }
  }

  return { input, original, identities, verify, state: () => ({ expiryReads, conversionCalls,
    mutation: runtime.value(input !== null && (typeof input === "object" || typeof input === "function") ? input.mutation : undefined) }) };
}
