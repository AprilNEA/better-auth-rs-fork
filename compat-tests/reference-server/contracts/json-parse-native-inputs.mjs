import assert from "node:assert/strict";

const cases = (category, valid, entries) => entries.map(([name, text]) => ({ name, category, valid, text }));
export const jsonParseNativeTextCases = [
  ...cases("value", true, [
    ["null", "null"], ["true", "true"], ["false", "false"], ["empty-object", "{}"], ["empty-array", "[]"],
    ["empty-string", '""'], ["nested-values", '{"a":[true,false,null,{"v":"text"}]}'],
    ["duplicate-properties", '{"before":0,"same":1,"after":2,"same":3}'],
    ["integer-property-order", '{"10":"ten","2":"two","tail":true}'],
    ["proto-own-property", '{"__proto__":{"polluted":true},"constructor":"own","__proto__":7}'],
    ["date-string", '"2030-01-02T03:04:05.000Z"'],
  ]),
  ...cases("number", true, [
    ["zero", "0"], ["negative-zero", "-0"], ["negative-decimal-zero", "-0.0"], ["negative-exponent-zero", "-0e9"],
    ["fraction", "-12.345"], ["positive-exponent", "1.25e+3"], ["negative-exponent", "1.25E-3"],
    ["max-finite", "1.7976931348623157e308"], ["overflow", "1e309"], ["negative-overflow", "-1e309"],
    ["underflow", "1e-324"], ["negative-underflow", "-1e-324"], ["minimum-subnormal", "5e-324"],
    ["rounded-integer", "9007199254740993"], ["large-integer", "123456789012345678901234567890"],
  ]),
  ...cases("whitespace", true, [
    ["space-prefix", " 0"], ["tab-prefix", "\ttrue"], ["lf-prefix", "\nfalse"], ["cr-prefix", "\rnull"],
    ["space-suffix", "0 "], ["tab-suffix", "true\t"], ["lf-suffix", "false\n"], ["cr-suffix", "null\r"],
    ["all-json-whitespace", " \t\r\n { \n\"x\" \t: [ 1 , 2 ] } \t\r\n"],
  ]),
  ...cases("whitespace", false, [
    ["empty-input", ""], ["whitespace-only", " \t\r\n"],
    ...[["bom", "\ufeff"], ["nbsp", "\u00a0"], ["vertical-tab", "\v"], ["form-feed", "\f"],
      ["line-separator", "\u2028"], ["paragraph-separator", "\u2029"]]
      .flatMap(([name, value]) => [[`${name}-prefix`, `${value}0`], [`${name}-suffix`, `0${value}`]]),
  ]),
  ...cases("value-token", false, [
    ...["]", "}", ":", "(", ")", ",", ".", "=", ";", "+", "/", "@"].map((token, index) => [`punctuation-${index}`, token]),
    ["single-quoted-string", "'text'"], ["undefined-token", "undefined"], ["nan-token", "NaN"], ["infinity-token", "Infinity"],
    ["short-true", "tru"], ["short-false", "fals"], ["short-null", "nul"], ["capital-true", "True"],
    ["identifier-underscore-dollar", "_name$42"], ["identifier-200", "a".repeat(200)], ["identifier-201", "a".repeat(201)],
    ["identifier-joiner", "a\u200cb"], ["non-latin-token", "中"], ["literal-with-tail", "truefalse"],
  ]),
  ...cases("object", false, [
    ["object-unclosed", "{"], ["object-key-unclosed", '{"a"'], ["object-value-missing", '{"a":'],
    ["object-after-value-unclosed", '{"a":1'], ["object-colon-missing", '{"a" 1}'],
    ["object-comma-missing", '{"a":1 "b":2}'], ["object-key-unquoted", "{a:1}"], ["object-initial-comma", "{,}"],
    ["object-trailing-comma", '{"a":1,}'], ["object-repeated-comma", '{"a":1,,}'],
    ["object-after-comma-key-unquoted", '{"a":1,b:2}'], ["object-closing-array-value", '{"a":]}'],
    ["object-wrong-closing-token", '{"a":1]'], ["object-single-quoted-value", '{"a":\'x\'}'],
    ["object-colon-lexer-error", '{"a" @}'], ["object-tail-lexer-error", '{"a":1 @}'],
  ]),
  ...cases("array", false, [
    ["array-unclosed", "["], ["array-after-value-unclosed", "[1"], ["array-comma-missing", "[1 2]"],
    ["array-trailing-comma", "[1,]"], ["array-leading-comma", "[,1]"], ["array-repeated-comma", "[1,,2]"],
    ["array-colon", "[1:2]"], ["array-wrong-closing-token", "[1}"], ["array-semicolon", "[true;]"],
    ["array-tail-lexer-error", "[1 @]"], ["array-element-lexer-error", "[1,@]"],
  ]),
  ...cases("number", false, [
    ["minus-only", "-"], ["minus-dot", "-.1"], ["double-minus", "--1"], ["plus-number", "+1"],
    ["leading-zero", "01"], ["negative-leading-zero", "-01"], ["double-zero", "00"], ["hex-number", "0x10"],
    ["decimal-no-digits", "1."], ["decimal-exponent-no-digits", "1.e2"], ["exponent-no-digits", "1e"],
    ["exponent-plus-no-digits", "1e+"], ["exponent-minus-no-digits", "1e-"], ["exponent-letter", "1e+x"],
    ["second-decimal", "1e2.3"], ["number-separator", "1_000"],
  ]),
  ...cases("string", true, [
    ["all-escapes", '"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041"'], ["unicode-pair-escaped", '"\\ud83d\\ude00"'],
    ["high-surrogate-escaped", '"\\ud800"'], ["low-surrogate-escaped", '"\\udfff"'],
    ["high-surrogate-raw", '"\ud800"'], ["low-surrogate-raw", '"\udfff"'],
    ["raw-line-separators", '"\u2028\u2029"'], ["non-latin-string", '"中😀"'],
    ["surrogate-object-key", '{"\\ud800":"value","after":1}'],
  ]),
  ...cases("string", false, [
    ["string-quote-only", '"'], ["string-unclosed", '"text'], ["string-escape-unclosed", '"text\\'],
    ["unicode-escape-short-0", '"\\u"'], ["unicode-escape-short-1", '"\\u0"'], ["unicode-escape-short-2", '"\\u00"'],
    ["unicode-escape-short-3", '"\\u000"'], ["unicode-escape-invalid-hex", '"\\u00g0"'], ["unicode-escape-braces", '"\\u{41}"'],
    ["escape-x", '"\\x41"'], ["escape-v", '"\\v"'], ["escape-zero", '"\\0"'], ["escape-single-quote", '"\\\'"'],
    ["raw-control-null", '"\0"'], ["raw-control-tab", '"\t"'], ["raw-control-lf", '"\n"'], ["raw-control-cr", '"\r"'],
    ["escaped-raw-surrogate", '"\\\ud800"'], ["unicode-escape-raw-surrogate", '"\\u\ud800"'],
    ["surrogate-token", "\ud800"], ["string-after-surrogate", '"\ud800""'],
  ]),
  ...cases("trailing", false, [
    ["two-numbers", "1 2"], ["object-literal-tail", "{}true"], ["object-lexer-tail", "{}@"],
    ["number-literal-tail", "42 true"], ["number-lexer-tail", "42@"], ["string-identifier-tail", '"ok"x'],
    ["array-object-tail", "[]{}"], ["comment-prefix", "// comment\n0"], ["comment-suffix", "0/* comment */"],
  ]),
  ...[127, 129, 256].map(depth => ({ name: `nested-array-${depth}`, category: "depth", valid: true, text: `${"[".repeat(depth)}0${"]".repeat(depth)}` })),
  { name: "nested-array-129-unclosed", category: "depth", valid: false, text: `${"[".repeat(129)}0${"]".repeat(128)}` },
];

export const jsonParseNativeCoercionCases = [
  "native-null", "native-undefined", "native-true", "native-number", "native-nan", "native-infinity", "native-bigint", "native-symbol",
  "native-empty-array", "native-single-array", "native-many-array", "native-date",
  "to-string-success", "to-string-invalid-json", "to-string-getter-error", "to-string-method-error",
  "value-of-fallback", "noncallable-to-string", "value-of-getter-error", "value-of-method-error", "both-methods-return-objects",
  "symbol-method-success", "symbol-method-error", "symbol-getter-error", "symbol-method-object", "date-own-to-string",
];

export function nativeCoercionInput(name, event, runtime) {
  const original = { failure: name, ownUndefined: undefined };
  const values = { "native-null": null, "native-undefined": undefined, "native-true": true, "native-number": 17,
    "native-nan": NaN, "native-infinity": Infinity, "native-bigint": 9007199254740993n, "native-symbol": Symbol("json-input"),
    "native-empty-array": [], "native-single-array": ["null"], "native-many-array": [1, 2], "native-date": new Date(0) };
  if (Object.hasOwn(values, name)) return { input: values[name], original };
  let input = name === "date-own-to-string" ? new Date(0) : { label: name };
  const failure = stage => {
    input.mutation = stage;
    event("throw", { stage, error: runtime.value(original) });
    throw original;
  };
  const method = (key, read, label = key) => Object.defineProperty(input, key, {
    configurable: true, get() {
      event(`get:${label}`, { sameReceiver: this === input });
      return read();
    },
  });
  if (name.startsWith("symbol-")) {
    method(Symbol.toPrimitive, () => {
      if (name === "symbol-getter-error") return failure("symbol-getter");
      return function toPrimitive(...args) {
        event("call:@@toPrimitive", { sameReceiver: this === input, arguments: runtime.value(args) });
        assert.deepEqual(args, ["string"]);
        if (name === "symbol-method-error") return failure("symbol-method");
        return name === "symbol-method-object" ? {} : '{"converted":true}';
      };
    }, "@@toPrimitive");
  } else {
    method("toString", () => {
      if (name === "to-string-getter-error") return failure("toString-getter");
      if (name === "noncallable-to-string") return 7;
      return function toString(...args) {
        event("call:toString", { sameReceiver: this === input, arguments: runtime.value(args) });
        assert.deepEqual(args, []);
        if (name === "to-string-method-error") return failure("toString-method");
        if (name === "to-string-invalid-json") return "{";
        if (name === "to-string-success" || name === "date-own-to-string") return '{"converted":true}';
        return {};
      };
    });
    method("valueOf", () => {
      if (name === "value-of-getter-error") return failure("valueOf-getter");
      return function valueOf(...args) {
        event("call:valueOf", { sameReceiver: this === input, arguments: runtime.value(args) });
        assert.deepEqual(args, []);
        if (name === "value-of-method-error") return failure("valueOf-method");
        return name === "both-methods-return-objects" ? {} : '{"converted":true}';
      };
    });
  }
  return { input, original };
}

// A JSON fixture must preserve code units that JSON text allows but Rust UTF-8 strings cannot store.
export function observeDocument(value) {
  if (typeof value === "string" && !value.isWellFormed()) {
    return { type: "utf16", value: Array.from({ length: value.length }, (_, index) => value.charCodeAt(index)) };
  }
  if (typeof value === "bigint" || typeof value === "symbol") return { type: typeof value, value: String(value) };
  if (Array.isArray(value)) return value.map(observeDocument);
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.some(([key]) => !key.isWellFormed())) {
      return { type: "utf16-keyed-object", entries: entries.map(([key, item]) => [observeDocument(key), observeDocument(item)]) };
    }
    return Object.fromEntries(entries.map(([key, item]) => [key, observeDocument(item)]));
  }
  return value;
}
