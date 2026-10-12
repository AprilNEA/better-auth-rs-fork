import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`User plugin declarations and the complete ${backend} catalog retain registration order and replacements`, async () => {
    const capture = new URL("./user-plugin-catalog-capture.mjs", import.meta.url);
    const fixture = new URL(`../../../tests/fixtures/user-plugin-catalog-${backend}-1.7.6.json`, import.meta.url);
    await expectStandaloneCapture(capture, fixture, [backend]);
    await expectStandaloneCapture(capture, fixture, [backend]);
  });
}
