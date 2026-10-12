import assert from "node:assert/strict";

export const observationPointer = path => `/${path.map(part => String(part).replaceAll("~", "~0").replaceAll("/", "~1")).join("/")}`;
export const observationValueType = value => value === null ? "null" : Array.isArray(value) ? "array" : typeof value;

export function assertObservationReplay(actual, expected, label, hostPaths = new Set()) {
  function compare(actual, expected, path) {
    const location = `${label}${observationPointer(path)}`;
    assert.equal(observationValueType(actual), observationValueType(expected), `${location}: value type`);
    if (hostPaths.has(observationPointer(path))) return;
    if (expected !== null && typeof expected === "object") {
      if (Array.isArray(expected)) assert.equal(actual.length, expected.length, `${location}: array length`);
      assert.deepEqual(Object.keys(actual), Object.keys(expected), `${location}: own key order`);
      for (const name of Object.keys(expected)) compare(actual[name], expected[name], [...path, name]);
    } else {
      assert.equal(actual, expected, location);
    }
  }

  compare(actual, expected, []);
}
