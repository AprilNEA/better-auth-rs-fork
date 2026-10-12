import assert from "node:assert/strict";

export function createSecondaryRuntimeObserver(native) {
  const functions = new WeakMap();
  const functionIds = [];
  const capturedValues = new WeakMap();
  const events = [];
  let outcome;
  function value(input) {
    if (input === undefined) return { type: "undefined" };
    if (typeof input === "function") {
      if (!functions.has(input)) {
        const identity = `function-${functionIds.length + 1}`;
        functions.set(input, identity);
        functionIds.push(identity);
      }
      return { type: "function", identity: functions.get(input) };
    }
    if (input instanceof Date) return { type: "date", value: Number.isNaN(Date.prototype.getTime.call(input))
      ? "Invalid Date" : Date.prototype.toISOString.call(input) };
    if (typeof input === "number" && !Number.isFinite(input)) return { type: "number", value: String(input) };
    if (typeof input === "number" && Object.is(input, -0)) return { type: "number", value: "-0" };
    if (Array.isArray(input)) return Array.from({ length: input.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
      if (!descriptor) return { type: "hole" };
      assert.ok("value" in descriptor, "Capture indexed accessor evaluation as a separate runtime event");
      return value(descriptor.value);
    });
    if (input !== null && typeof input === "object") return ownValues(input);
    return input;
  }
  function ownValues(input) {
    return Object.fromEntries(Object.keys(input).map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      assert.ok("value" in descriptor, "Capture enumerable accessor evaluation as a separate runtime event");
      return [key, value(descriptor.value)];
    }));
  }
  const snapshot = native.snapshot;
  native.snapshot = input => {
    const observation = snapshot(input);
    if (observation !== null && typeof observation === "object") capturedValues.set(observation, value(input));
    return observation;
  };
  const record = native.record;
  native.record = (phase, fields = {}) => {
    record(phase, fields);
    events.push({ phase, ...Object.fromEntries(Object.entries(fields).map(([key, field]) => [
      key, field !== null && typeof field === "object" && capturedValues.has(field) ? capturedValues.get(field) : field,
    ])) });
  };
  const call = native.call;
  native.call = (phase, receiver, expected, args) => {
    call(phase, receiver, expected, args);
    events.push({ phase, sameReceiver: receiver === expected, arguments: value(args) });
  };
  async function capture(operation, original) {
    try {
      const result = await operation();
      outcome = { returned: true, result: value(result) };
      return result;
    } catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      outcome = { returned: false, sameOriginal: error === original, error: value(error) };
      throw error;
    }
  }
  return { value, ownValues, capture, events, functionIds, get outcome() { return outcome; } };
}
