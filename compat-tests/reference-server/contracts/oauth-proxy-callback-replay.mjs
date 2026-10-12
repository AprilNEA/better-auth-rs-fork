import assert from "node:assert/strict";

const hostFields = ["stack", "originalLine", "originalColumn", "line", "column", "sourceURL"];
const pointer = path => `/${path.map(part => String(part).replaceAll("~", "~0").replaceAll("/", "~1")).join("/")}`;
const valueType = value => value === null ? "null" : Array.isArray(value) ? "array" : typeof value;

function errorPaths(scenario) {
  const paths = [["originalError"]];
  if (scenario.expected.kind !== "returned") paths.push(["outcome", "error"]);
  for (const [index, log] of scenario.expected.logs.entries()) {
    if (["error", "original-error", "issues"].includes(log.argument)) {
      paths.push(["logs", index, "arguments", 0]);
    }
  }
  if (scenario.invalidUser) paths.push(["globalLogs", 0, "arguments", 1, "error"]);
  return paths;
}

function readPath(record, path) {
  return path.reduce((value, name) => value?.[name], record);
}

export function callbackHostObservations(record, scenario) {
  return errorPaths(scenario).map(path => {
    const error = readPath(record, path);
    return {
      path: pointer(path),
      fields: hostFields.map(name => {
        const container = name === "stack" ? error : error?.properties;
        const keys = container === undefined ? [] : Object.keys(container);
        const present = container !== undefined && Object.hasOwn(container, name);
        return {
          name, present, position: keys.indexOf(name),
          ownKeyPosition: error?.ownKeys?.findIndex(key => key === name) ?? -1,
          type: valueType(present ? container[name] : undefined),
          value: present ? container[name] : { type: "undefined" },
        };
      }),
    };
  });
}

export function assertCallbackReplay(actual, expected, scenario) {
  const hostPaths = new Set(errorPaths(scenario).flatMap(path => hostFields.map(name =>
    pointer(name === "stack" ? [...path, name] : [...path, "properties", name]))));

  function compare(actual, expected, path) {
    const location = `${scenario.name}${pointer(path)}`;
    assert.equal(valueType(actual), valueType(expected), `${location}: value type`);
    if (hostPaths.has(pointer(path))) return;
    if (expected !== null && typeof expected === "object") {
      if (Array.isArray(expected)) assert.equal(actual.length, expected.length, `${location}: array length`);
      assert.deepEqual(Object.keys(actual), Object.keys(expected), `${location}: own key order`);
      for (const name of Object.keys(expected)) compare(actual[name], expected[name], [...path, name]);
    } else {
      assert.equal(actual, expected, location);
    }
  }

  compare(actual, expected, []);
  const hostShape = observations => observations.map(({ path, fields }) => ({
    path,
    fields: fields.map(({ value, ...shape }) => shape),
  }));
  assert.deepEqual(hostShape(callbackHostObservations(actual, scenario)),
    hostShape(callbackHostObservations(expected, scenario)), `${scenario.name}: Error host field shape`);
}
