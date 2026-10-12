import { expect, test } from "bun:test";
import { assertSecondaryNativeVersions, withSecondarySourceExports } from "./secondary-native-shared.mjs";

test("API Key TTL samples Date.now before expiration conversion and preserves the original failure", async () => {
  assertSecondaryNativeVersions(["@better-auth/api-key"]);
  await withSecondarySourceExports("@better-auth/api-key", ["calculateTTL"], async source => {
    const originalNow = Date.now;
    try {
      for (const fails of [false, true]) {
        const events: string[] = [];
        let clock = 2_000_000_000_000;
        Date.now = () => { events.push("Date.now"); return clock; };
        const original = { cause: "expiry conversion" };
        const expiresAt = {
          valueOf(...args: unknown[]) {
            expect(this).toBe(expiresAt);
            expect(args).toStrictEqual([]);
            events.push("valueOf");
            clock = 2_000_000_060_000;
            if (fails) throw original;
            return 2_000_000_060_000;
          },
        };
        const key = { expiresAt };
        if (fails) {
          let caught: unknown;
          try { source.calculateTTL(key); } catch (error) { caught = error; }
          expect(caught).toBe(original);
        } else expect(source.calculateTTL(key)).toBe(60);
        expect(events).toStrictEqual(["Date.now", "valueOf"]);
        expect(key.expiresAt).toBe(expiresAt);
      }
    } finally { Date.now = originalNow; }
  });
});
