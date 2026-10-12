import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("data records retain native sorting callbacks, failures, returned identities and complete storage", async () => {
  const capture = new URL("./native-sort-data-capture.mjs", import.meta.url);
  const fixture = new URL("../../../tests/fixtures/native-sort-data-1.7.6.json.gz", import.meta.url);
  await expectStandaloneCapture(capture, fixture);
  await expectStandaloneCapture(capture, fixture);
}, 120_000);
