import assert from "node:assert/strict";

export const observationPointer = path => `/${path.map(part => String(part).replaceAll("~", "~0").replaceAll("/", "~1")).join("/")}`;
export const observationValueType = value => value === null ? "null" : Array.isArray(value) ? "array" : typeof value;

export function assertObservationReplay(actual, expected, label, hostPaths = new Set()) {
  const pending = [{ actual, expected, path: "" }];
  while (pending.length) {
    const { actual, expected, path } = pending.pop();
    const pointer = path || "/";
    const location = `${label}${pointer}`;
    assert.equal(observationValueType(actual), observationValueType(expected), `${location}: value type`);
    if (hostPaths.has(pointer)) continue;
    if (expected !== null && typeof expected === "object") {
      if (Array.isArray(expected)) assert.equal(actual.length, expected.length, `${location}: array length`);
      assert.deepEqual(Object.keys(actual), Object.keys(expected), `${location}: own key order`);
      const names = Object.keys(expected);
      for (let index = names.length - 1; index >= 0; index -= 1) {
        const name = names[index];
        pending.push({ actual: actual[name], expected: expected[name], path: `${path}${observationPointer([name])}` });
      }
    } else {
      assert.equal(actual, expected, location);
    }
  }
}
