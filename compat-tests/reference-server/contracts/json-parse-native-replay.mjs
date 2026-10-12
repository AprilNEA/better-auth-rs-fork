import assert from "node:assert/strict";
import { assertObservationReplay, observationPointer } from "./observation-replay.mjs";

function* jsonParserErrors(document) {
  const pending = [{ node: document, path: "" }];
  while (pending.length) {
    const { node, path } = pending.pop();
    if (node === null || typeof node !== "object") continue;
    if (node.type === "object" && Array.isArray(node.ownKeys) && Array.isArray(node.properties)
      && node.ownKeys.includes("sourceURL") && node.ownKeys.includes("message")) {
      yield { node, path };
    }
    const entries = Object.entries(node);
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const [name, value] = entries[index];
      pending.push({ node: value, path: `${path}${observationPointer([name])}` });
    }
  }
}

export function jsonParserHostStackPaths(document) {
  const paths = new Set();
  for (const { node, path } of jsonParserErrors(document)) {
    for (const [index, [name, descriptor]] of node.properties.entries()) {
      if (name !== "stack" || !Object.hasOwn(descriptor, "value")) continue;
      const valuePath = `${path}${observationPointer(["properties", index, 1, "value"])}`;
      if (typeof descriptor.value === "string") {
        paths.add(valuePath);
      } else if (descriptor.value?.type === "utf16" && Array.isArray(descriptor.value.value)
        && descriptor.value.value.every(unit => Number.isInteger(unit) && unit >= 0 && unit <= 65535)) {
        paths.add(`${valuePath}/value`);
      }
    }
  }
  return paths;
}

const sourceErrorKeys = ["message", "originalLine", "originalColumn", "line", "column", "sourceURL", "stack"];
const originKey = name => name === "originalLine" || name === "originalColumn";
const descriptor = (node, name) => node.properties.find(([key]) => key === name)?.[1];

function verifyGcSyntaxErrors(actual, expected) {
  const observed = new Map([...jsonParserErrors(actual)].map(({ node, path }) => [path, node]));
  const variants = [];
  const caseShapes = new Map();
  for (const { node, path } of jsonParserErrors(expected)) {
    const location = path.match(/^(\/cases\/(\d+))?(\/outcome\/error|\/error)$/);
    if (!location) continue;
    const source = location[2] === undefined ? expected : expected.cases[location[2]];
    if (source.runtime?.error?.name !== "SyntaxError" || source.outcome?.sameOriginal !== false) continue;
    const stack = descriptor(node, "stack")?.value;
    if (typeof stack !== "string") continue;
    const frames = stack.split("\n");
    if (!stack.startsWith("SyntaxError: JSON Parse error:") || frames[1] !== "    at <parse> (:0)"
      || frames[2] !== "    at parse (unknown)" || !frames[3]) continue;
    const current = observed.get(path);
    assert.ok(current, `${path}: source SyntaxError snapshot is absent`);
    const gc = !originKeyPresence(current, "originalLine") || !originKeyPresence(current, "originalColumn");
    const identity = `${location[1] ?? ""}/${node.identity}`;
    const shape = { gc, stack: gc ? descriptor(current, "stack")?.value : undefined };
    if (caseShapes.has(identity)) {
      assert.deepEqual(shape, caseShapes.get(identity), `${path}: repeated SyntaxError snapshots must retain one host shape and stack`);
    }
    caseShapes.set(identity, shape);
    if (!gc) continue;
    assert.deepEqual(node.ownKeys, sourceErrorKeys, `${path}: source SyntaxError keys`);
    assert.deepEqual(node.properties.map(([key]) => key), sourceErrorKeys, `${path}: source SyntaxError descriptors`);
    const gcStack = descriptor(current, "stack")?.value;
    assert.equal(typeof gcStack, "string", `${path}: GC stack must be a native string`);
    assert.ok(gcStack.startsWith(["Error", ...frames.slice(2, 4), ""].join("\n")),
      `${path}: GC stack must retain the native parse and source frames`);
    assert.ok(!gcStack.includes("\n    at <parse> "), `${path}: GC stack must omit the parser pseudo-frame`);
    const projected = { ...node,
      ownKeys: node.ownKeys.filter(key => !originKey(key)),
      properties: node.properties.filter(([key]) => !originKey(key))
        .map(([key, value]) => key === "stack" ? [key, { ...value, value: gcStack }] : [key, value]),
    };
    assertObservationReplay(current, projected, `json-parse-native${path}`);
    variants.push(path);
  }
  return variants;
}

function originKeyPresence(node, name) {
  return node.ownKeys.includes(name) && node.properties.some(([key]) => key === name);
}

export function assertJsonParseNativeReplay(actual, expected) {
  const gcSyntaxErrorPaths = verifyGcSyntaxErrors(actual, expected);
  const verified = path => gcSyntaxErrorPaths.some(node => path.startsWith(`${node}/`));
  const paths = jsonParserHostStackPaths(expected);
  assert.deepEqual([...jsonParserHostStackPaths(actual)].filter(path => !verified(path)),
    [...paths].filter(path => !verified(path)), "JSON parser host stack value paths");
  // Each excluded Error node has already passed a complete descriptor comparison above.
  assertObservationReplay(actual, expected, "json-parse-native", new Set([...paths, ...gcSyntaxErrorPaths]));
  return { gcSyntaxErrorPaths };
}
