import assert from "node:assert/strict";
import { assertObservationReplay, observationPointer } from "./observation-replay.mjs";

export function jsonParserHostStackPaths(document) {
  const paths = new Set();
  const pending = [{ node: document, path: "" }];
  while (pending.length) {
    const { node, path } = pending.pop();
    if (node === null || typeof node !== "object") continue;
    if (node.type === "object" && Array.isArray(node.ownKeys) && Array.isArray(node.properties)
      && node.ownKeys.includes("sourceURL") && node.ownKeys.includes("message")) {
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
    const entries = Object.entries(node);
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const [name, value] = entries[index];
      pending.push({ node: value, path: `${path}${observationPointer([name])}` });
    }
  }
  return paths;
}

export function assertJsonParseNativeReplay(actual, expected) {
  const paths = jsonParserHostStackPaths(expected);
  assert.deepEqual([...jsonParserHostStackPaths(actual)], [...paths], "JSON parser host stack value paths");
  assertObservationReplay(actual, expected, "json-parse-native", paths);
}
