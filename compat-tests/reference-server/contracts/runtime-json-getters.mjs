import { expect, test } from "bun:test";

for (const reject of [false, true]) {
  test(`JSON getter traversal ${reject ? "retains the original child error" : "reads later properties after the child"}`, () => {
    const events = [];
    const failure = new Error("JSON getter original error");
    const state = { tail: "before", drop: true };
    const child = { get value() {
      events.push("child.value");
      if (reject) throw failure;
      state.tail = "after";
      delete outer.drop;
      outer.added = true;
      return 1;
    } };
    const outer = {
      get child() { events.push("outer.child"); return child; },
      get tail() { events.push("outer.tail"); return state.tail; },
      get drop() { events.push("outer.drop"); return state.drop; },
    };
    let actual;
    let caught;
    try { actual = JSON.stringify(outer); } catch (error) { caught = error; }
    if (reject) {
      expect(caught).toBe(failure);
      expect(actual).toBeUndefined();
      expect(events).toStrictEqual(["outer.child", "child.value"]);
      expect(Object.keys(outer)).toStrictEqual(["child", "tail", "drop"]);
      expect(state).toStrictEqual({ tail: "before", drop: true });
    } else {
      expect(caught).toBeUndefined();
      expect(actual).toBe('{"child":{"value":1},"tail":"after"}');
      expect(events).toStrictEqual(["outer.child", "child.value", "outer.tail"]);
      expect(Object.keys(outer)).toStrictEqual(["child", "tail", "added"]);
      expect(state).toStrictEqual({ tail: "after", drop: true });
      expect(outer.added).toBe(true);
    }
  });
}
