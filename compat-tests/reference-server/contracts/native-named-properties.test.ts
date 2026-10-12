import { expect, test } from "bun:test";
import { writeObservation } from "./write-observation.mjs";

test("native named properties retain identity across spread, JSON, and structured clone", async () => {
  const records = [];
  for (const kind of ["array", "date", "function"]) {
    const events: string[] = [];
    const child = { ownUndefined: undefined };
    const value: any = kind === "array" ? ["first", , "last"]
      : kind === "date" ? new Date(0) : function nativeFunction() {};
    value.alias = child;
    value.ownUndefined = undefined;
    Object.defineProperty(value, "selected", { enumerable: true, get() {
      events.push(`get:${this === value}`);
      return child;
    } });
    Object.defineProperty(value, "hidden", { enumerable: false, get() {
      throw new Error("Hidden getter must not run");
    } });
    const spread = { ...value };
    const spreadEvents = events.splice(0);
    const json = JSON.stringify(value);
    const jsonEvents = events.splice(0);
    let copy: any;
    let error: any;
    try { copy = structuredClone(value); } catch (caught) { error = caught; }
    const cloneEvents = events.splice(0);
    const record = {
      kind, keys: Object.keys(value), spreadKeys: Object.keys(spread),
      spreadAlias: spread.alias === child, spreadSelected: spread.selected === child,
      spreadEvents, json, jsonEvents, cloneEvents,
      clone: error ? { name: error.name, message: error.message }
        : { keys: Object.keys(copy), ownUndefined: Object.hasOwn(copy, "ownUndefined"),
          aliasRetained: copy.alias === copy.selected, aliasFresh: copy.alias !== child,
          arrayLength: Array.isArray(copy) ? copy.length : undefined,
          date: copy instanceof Date ? copy.toISOString() : undefined },
    };
    records.push(record);
    await writeObservation(`${JSON.stringify({ contract: "native-named-properties", ...record })}\n`);
    expect(spread.alias).toBe(child);
    expect(spread.selected).toBe(child);
    expect(spreadEvents).toStrictEqual(["get:true"]);
    expect(jsonEvents).toStrictEqual([]);
    expect(cloneEvents).toStrictEqual(kind === "array" ? ["get:true"] : []);
    if (kind === "array") {
      expect(json).toBe('["first",null,"last"]');
      expect(Object.keys(copy)).toStrictEqual(["0", "2", "alias", "ownUndefined", "selected"]);
      expect(copy.length).toBe(3);
      expect(copy.alias).not.toBe(child);
      expect(copy.alias).toBe(copy.selected);
      expect(Object.hasOwn(copy, "ownUndefined")).toBe(true);
    } else if (kind === "date") {
      expect(json).toBe('"1970-01-01T00:00:00.000Z"');
      expect(Object.keys(copy)).toStrictEqual([]);
      expect(copy.getTime()).toBe(0);
      expect(copy).not.toBe(value);
    } else {
      expect(json).toBeUndefined();
      expect(error.name).toBe("DataCloneError");
    }
    let receiver: any;
    let arguments_: any;
    value.toJSON = function (...args: any[]) { receiver = this; arguments_ = args; return "custom"; };
    const custom = JSON.stringify({ value });
    const customRecord = { kind, custom, receiver: receiver === value, arguments: arguments_, events };
    await writeObservation(`${JSON.stringify({ contract: "native-named-properties-to-json", ...customRecord })}\n`);
    expect(custom).toBe('{"value":"custom"}');
    expect(receiver).toBe(value);
    expect(arguments_).toStrictEqual(["value"]);
    expect(events).toStrictEqual([]);
  }
  expect(records).toHaveLength(3);
});
