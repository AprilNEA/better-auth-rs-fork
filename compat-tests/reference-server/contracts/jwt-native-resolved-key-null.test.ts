import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { signJWT } from "better-auth/plugins/jwt";

expect(JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version).toBe("1.7.6");

for (const mode of ["function", "object"]) {
  test(`a sign getter that becomes truthy returns a null resolved key before adapter access: ${mode}`, async () => {
    const events: string[] = [];
    let reads = 0;
    const options = {
      jwt: {
        get sign() {
          reads += 1;
          events.push(`sign.get:${reads}`);
          if (reads === 1) return false;
          return mode === "function" ? () => {
            events.push("sign.call");
            throw new Error("Resolving a delegated signing key must not call the signer");
          } : { delegated: true };
        },
      },
      get jwks() {
        events.push("jwks.get");
        throw new Error("Null key resolution must not read key options");
      },
      get adapter() {
        events.push("adapter.get");
        throw new Error("Null key resolution must not access the adapter");
      },
    };
    let failure: unknown;
    try {
      await signJWT({ context: { options: { baseURL: "http://jwt-native-null-key.test" } } } as any, {
        payload: { iat: 10, exp: 70 }, options,
      } as any);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(TypeError);
    const error = failure as TypeError;
    expect(Object.getPrototypeOf(error)).toBe(TypeError.prototype);
    expect(error.name).toBe("TypeError");
    expect(error.message).toBe("Cannot destructure property 'alg' from null or undefined value");
    expect(typeof error.stack).toBe("string");
    expect(events).toStrictEqual(["sign.get:1", "sign.get:2"]);
    const properties = Reflect.ownKeys(error).map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(error, key)!;
      return {
        key: String(key), enumerable: descriptor.enumerable, configurable: descriptor.configurable,
        writable: descriptor.writable, getter: typeof descriptor.get, setter: typeof descriptor.set,
        value: key === "stack" ? { type: typeof descriptor.value, firstLine: error.stack?.split("\n", 1)[0] } : descriptor.value,
      };
    });
    const values = [
      ["message", "Cannot destructure property 'alg' from null or undefined value"],
      ["originalLine", 78], ["originalColumn", 81], ["line", 103], ["column", 63],
      ["sourceURL", fileURLToPath(new URL("../node_modules/better-auth/dist/plugins/jwt/sign.mjs", import.meta.url))],
      ["stack", { type: "string", firstLine: "TypeError: Cannot destructure property 'alg' from null or undefined value" }],
    ];
    expect({ constructor: error.constructor.name, properties }).toStrictEqual({
      constructor: "TypeError",
      properties: values.map(([key, value]) => ({
        key, enumerable: false, configurable: true, writable: true,
        getter: "undefined", setter: "undefined", value,
      })),
    });
  });
}
