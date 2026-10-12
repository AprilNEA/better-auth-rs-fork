import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("selected User property reads retain Array, Function and Date receivers through session replacement", async () => {
  await expectStandaloneCapture(
    new URL("./selected-user-property-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/selected-user-property-1.7.6.json", import.meta.url),
  );
}, 120_000);
