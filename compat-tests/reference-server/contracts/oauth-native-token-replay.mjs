import assert from "node:assert/strict";
import { assertObservationReplay, observationPointer as pointer, observationValueType as valueType } from "./observation-replay.mjs";

const hostFields = ["stack", "originalLine", "originalColumn", "line", "column", "sourceURL"];
const errorPaths = record => [["originalError"], ...(record.outcome.kind === "thrown" ? [["outcome", "error"]] : [])];
const readPath = (record, path) => path.reduce((value, name) => value?.[name], record);

export function tokenHostObservations(record) {
  return errorPaths(record).map(path => {
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

export function assertTokenReplay(actual, expected) {
  const paths = new Set(errorPaths(expected).flatMap(path => hostFields.map(name =>
    pointer(name === "stack" ? [...path, name] : [...path, "properties", name]))));
  assertObservationReplay(actual, expected, expected.name, paths);
  const shape = record => tokenHostObservations(record).map(({ path, fields }) => ({
    path, fields: fields.map(({ value, ...shape }) => shape),
  }));
  assert.deepEqual(shape(actual), shape(expected), `${expected.name}: Error host field shape`);
}
