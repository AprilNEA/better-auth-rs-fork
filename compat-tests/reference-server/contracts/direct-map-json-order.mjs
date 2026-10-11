import { expect, test } from "bun:test";

const insertion = ["tail", "10", "2", "01", "4294967295", "1"];
const order = ["1", "2", "10", "tail", "01", "4294967295"];
const expected = '{"1":{"value":"1"},"2":{"value":"2"},"10":{"value":"10"},"tail":{"value":"tail"},"01":{"value":"01"},"4294967295":{"value":"4294967295"}}';

for (const clone of [false, true]) {
  for (const fail of [false, true]) {
    test(`direct map ${clone ? "clone" : "JSON"} observes numeric getter order${fail ? " before rejection" : ""}`, () => {
      const events = [];
      const failure = new Error("numeric map getter original error");
      const entries = insertion.map(name => [name, { get value() {
        events.push(name);
        if (fail && name === "2") throw failure;
        return name;
      } }]);
      const input = Object.fromEntries(entries);
      let actual;
      let caught;
      try {
        if (clone) {
          const copy = structuredClone(input);
          expect(Object.keys(copy)).toStrictEqual(order);
          actual = JSON.stringify(copy);
        } else actual = JSON.stringify(input);
      } catch (error) { caught = error; }
      expect(entries.map(([name]) => name)).toStrictEqual(insertion);
      expect(Object.keys(input)).toStrictEqual(order);
      if (fail) {
        expect(caught).toBe(failure);
        expect(actual).toBeUndefined();
        expect(events).toStrictEqual(["1", "2"]);
      } else {
        expect(caught).toBeUndefined();
        expect(actual).toBe(expected);
        expect(events).toStrictEqual(order);
      }
    });
  }
}
