import { expect, test } from "bun:test";
import { toResponse } from "better-call";

test("raw JSON wrappers encode one body and keep strict cycles", async () => {
  for (const [body, bytes] of [
    [undefined, undefined], [null, "null"], [false, "false"], [0, "0"],
    ["", '""'], ["text", '"text"'],
    [{ _flag: "json", body: "nested" }, '{"_flag":"json","body":"nested"}'],
  ] as const) {
    const value = { _flag: "json", body };
    const response = toResponse(value);
    expect(response.status).toBe(200);
    expect([...response.headers]).toStrictEqual([["content-type", "application/json"]]);
    expect(response.body === null).toBe(bytes === undefined);
    expect(await response.text()).toBe(bytes ?? "");
  }
  const body: any = {}; body.self = body;
  expect(() => toResponse({ _flag: "json", body })).toThrow(TypeError);
});

test("wrapper headers merge in order and strip only endpoint headers", async () => {
  const response = toResponse({
    _flag: "json", body: "body", status: 202,
    routerResponse: { status: 203, headers: {
      "x-router": "router", "x-shared": "router", "set-cookie": "router=1", authorization: "router-credential",
    } },
    headers: [["x-data", "data"], ["x-shared", "data"], ["set-cookie", "data=1"],
      ["cookie", "a=1"], ["Cookie", "b=2"], ["x-repeat", " a "], ["X-Repeat", "b"]],
  }, { status: 201, headers: {
    "x-init": "init", "x-shared": "init", authorization: "removed", "content-type": "overridden", "set-cookie": "init=1",
  } });
  expect(response.status).toBe(202);
  expect(await response.text()).toBe('"body"');
  expect([...response.headers].filter(([name]) => name !== "set-cookie")).toStrictEqual([
    ["authorization", "router-credential"], ["content-type", "application/json"], ["cookie", "a=1; b=2"],
    ["x-data", "data"], ["x-init", "init"], ["x-repeat", "a, b"], ["x-router", "router"], ["x-shared", "init"],
  ]);
  expect(response.headers.getSetCookie()).toStrictEqual(["router=1", "data=1", "init=1"]);
});

test("wrapper status keeps nullish precedence and Bun numeric conversion", () => {
  for (const [data, init, router, status, failed] of [
    [undefined, undefined, undefined, 200, false], [undefined, undefined, 203, 203, false],
    [null, 201, 203, 201, false], [202, 201, 203, 202, false], ["202.9", 201, 203, 202, false],
    ["4294967497", undefined, undefined, 201, false], [4294967497, undefined, undefined, 4294967497, true],
    [false, 201, 203, 0, true], [undefined, undefined, null, 0, true], [199.9, undefined, undefined, 199, true],
  ] as const) {
    const materialize = () => toResponse({ _flag: "json", body: true, status: data, routerResponse: { status: router } }, { status: init });
    if (failed) {
      expect(materialize).toThrow(RangeError);
      expect(materialize).toThrow(`The status provided (${status}) must be 101 or in the range of [200, 599]`);
    } else expect(materialize().status).toBe(status);
  }
});

test("wrapper getters keep JSON before spread and ResponseInit conversion", async () => {
  const expected = [
    "data._flag", "data.body", "data.routerResponse", "router.headers", "data.headers", "body.toJSON",
    "router.headers", "router.status", "router.extra", "router.statusText", "router.method",
    "data.status", "router.status", "router.statusText", "status.valueOf", "statusText.toString", "method.toString",
  ];
  for (const failure of [undefined, ...expected]) {
    const events: string[] = [];
    const error = new Error(`original ${failure} error`);
    const record = (event: string) => { events.push(event); if (event === failure) throw error; };
    const getters = (label: string, values: Record<string, unknown>) => Object.defineProperties({},
      Object.fromEntries(Object.entries(values).map(([name, value]) => [name, {
        enumerable: true, get() { record(`${label}.${name}`); return value; },
      }])));
    const body = { toJSON(key: string) { expect(this).toBe(body); expect(key).toBe(""); record("body.toJSON"); return { kept: 1 }; } };
    const router = getters("router", {
      headers: {}, status: { valueOf() { record("status.valueOf"); return 202; } }, extra: true,
      statusText: { toString() { record("statusText.toString"); return "Custom\r\n中"; } },
      method: { toString() { record("method.toString"); return "GET"; } },
    });
    const value = getters("data", { _flag: "json", body, routerResponse: router, headers: {}, status: undefined });
    expect(events).toStrictEqual([]);
    if (failure) {
      let caught: unknown;
      try { toResponse(value); } catch (actual) { caught = actual; }
      expect(caught).toBe(error);
      expect(events).toStrictEqual(expected.slice(0, expected.indexOf(failure) + 1));
    } else {
      const response = toResponse(value);
      expect(response.status).toBe(202);
      expect(response.statusText).toBe("Custom\r\n中");
      expect(await response.text()).toBe('{"kept":1}');
      expect(events).toStrictEqual(expected);
    }
  }
});

test("HeadersInit converts all DOMStrings before validating headers", () => {
  for (const sequence of [false, true]) {
    for (const failed of [false, true]) {
      const events: string[] = [];
      const failure = new Error("original later.toString error");
      const first = { toString() { events.push("first.toString"); return "value"; } };
      const later = { toString() { events.push("later.toString"); if (failed) throw failure; return "value"; } };
      const headers = sequence ? [["bad name", first], ["later", later]] : { "bad name": first, later };
      let caught: unknown;
      try { toResponse({ _flag: "json", body: true, headers }); } catch (error) { caught = error; }
      if (failed) expect(caught).toBe(failure);
      else {
        expect(caught).toBeInstanceOf(TypeError);
        expect((caught as Error).message).toBe("Invalid header name: 'bad name'");
      }
      expect(events).toStrictEqual(["first.toString", "later.toString"]);
    }
  }
  for (const value of ["one\ntwo", "中"]) {
    expect(() => toResponse({ _flag: "json", body: true, headers: { "x-bad": value } }))
      .toThrow(`Header 'x-bad' has invalid value: '${value}'`);
  }
});

test("HeadersInit record rechecks deleted fields and keeps explicit undefined", () => {
  const headers: Record<string, unknown> = {
    first: { toString() { delete headers.removed; return "first"; } },
    removed: "never copied",
    explicit: undefined,
  };
  const response = toResponse({ _flag: "json", body: true, headers });
  expect([...response.headers]).toStrictEqual([
    ["content-type", "application/json"], ["explicit", "undefined"], ["first", "first"],
  ]);
});

test("init headers validate before stripping on each HTTP path", () => {
  for (const [name, value, message] of [
    ["bad name", "value", "Invalid header name: 'bad name'"],
    ["x-invalid", "one\ntwo", "Header 'x-invalid' has invalid value: 'one\ntwo'"],
    ["authorization", "one\ntwo", "Header 'Authorization' has invalid value: 'one\ntwo'"],
    ["AUTHORIZATION", "one\ntwo", "Header 'Authorization' has invalid value: 'one\ntwo'"],
    ["eTaG", "one\ntwo", "Header 'ETag' has invalid value: 'one\ntwo'"],
    ["X-Unknown", "one\ntwo", "Header 'X-Unknown' has invalid value: 'one\ntwo'"],
  ] as const) {
    for (const data of [true, { _flag: "json", body: true }, new Response("explicit", { status: 207, headers: { "x-owned": "kept" } })]) {
      let caught: unknown;
      try { toResponse(data, { headers: { [name]: value } }); } catch (error) { caught = error; }
      expect(caught).toBeInstanceOf(TypeError);
      expect((caught as Error).message).toBe(message);
    }
  }
});

test("init header validation follows wrapper header conversion and precedes body JSON", () => {
  for (const stage of ["header", "init", "body"]) {
    const events: string[] = [];
    const headerError = new Error("original header.toString error");
    const bodyError = new Error("original body.toJSON error");
    const body = { toJSON() { events.push("body.toJSON"); throw bodyError; } };
    const header = { toString() { events.push("header.toString"); if (stage === "header") throw headerError; return "value"; } };
    let caught: unknown;
    try {
      toResponse({ _flag: "json", body, headers: { "x-data": header } }, stage === "body" ? undefined : { headers: { "bad name": "invalid init" } });
    } catch (error) { caught = error; }
    if (stage === "header") expect(caught).toBe(headerError);
    else if (stage === "body") expect(caught).toBe(bodyError);
    else {
      expect(caught).toBeInstanceOf(TypeError);
      expect((caught as Error).message).toBe("Invalid header name: 'bad name'");
    }
    expect(events).toStrictEqual(stage === "body" ? ["header.toString", "body.toJSON"] : ["header.toString"]);
  }
});

test("HeadersInit sequences observe live inner and outer lengths", () => {
  for (const mode of ["inner-grow", "inner-shrink", "outer-grow", "outer-shrink"]) {
    const array: unknown[] = [];
    const events: string[] = [];
    const name = { toString() {
      events.push("name.toString");
      if (mode === "inner-grow") array.push("third");
      else if (mode === "outer-grow") array.push(["x-added", "added"]);
      else array.length = 1;
      return "x-first";
    } };
    let headers;
    if (mode.startsWith("inner")) { array.push(name, "first"); headers = [array]; }
    else {
      array.push([name, "first"]);
      if (mode === "outer-shrink") array.push(["x-removed", "never copied"]);
      headers = array;
    }
    if (mode.startsWith("inner")) {
      let caught: unknown;
      try { toResponse({ _flag: "json", body: true, headers }); } catch (error) { caught = error; }
      expect(caught).toBeInstanceOf(TypeError);
      expect((caught as Error).message).toBe("Header sub-sequence must contain exactly two items");
    } else {
      const response = toResponse({ _flag: "json", body: true, headers });
      expect([...response.headers]).toStrictEqual([
        ["content-type", "application/json"],
        ...(mode === "outer-grow" ? [["x-added", "added"]] : []),
        ["x-first", "first"],
      ]);
    }
    expect(events).toStrictEqual(["name.toString"]);
  }
});
