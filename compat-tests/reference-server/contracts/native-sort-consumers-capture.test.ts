import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("native sorting consumers preserve short comparison schedules and long mixed-run observations", async () => {
  const capture = new URL("./native-sort-consumers-capture.mjs", import.meta.url);
  const fixture = new URL("../../../tests/fixtures/native-sort-consumers-1.7.6.json.gz", import.meta.url);
  await expectStandaloneCapture(capture, fixture);
  await expectStandaloneCapture(capture, fixture);
}, 120_000);
