import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { assertObservationReplay } from "./observation-replay.mjs";
import { passkeyNativeErrorCases } from "./passkey-native-errors-capture.mjs";
import { readStandaloneFixture, runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("Passkey native errors preserve cookie consumption, verification order, original errors and committed storage", async () => {
  const capture = new URL("./passkey-native-errors-capture.mjs", import.meta.url);
  const fixture = new URL("../../../tests/fixtures/passkey-native-errors-1.7.6.json", import.meta.url);
  const observation = JSON.parse(readStandaloneFixture(fixture));
  expect(observation.contract).toBe("passkey-native-errors");
  expect(observation.version).toBe("1.7.6");
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(passkeyNativeErrorCases);
  const result = await runStandaloneCapture(capture, [fileURLToPath(fixture)]);
  await writeObservation(result.stdout);
  expect({ status: result.status, stderr: result.stderr }, `Replay evidence: ${result.directory}`).toEqual({ status: 0, stderr: "" });
  const replay = JSON.parse(readFileSync(result.output, "utf8"));
  expect(Object.keys(replay)).toStrictEqual(Object.keys(observation));
  for (const key of ["contract", "version", "backend", "provenance", "boundary"]) {
    assertObservationReplay(replay[key], observation[key], `passkey-native-errors/${key}`);
  }
  expect(replay.cases).toHaveLength(observation.cases.length);
  for (const [index, entry] of observation.cases.entries()) {
    expect(Object.keys(replay.cases[index])).toStrictEqual(Object.keys(entry));
    for (const key of ["name", "scenario", "input", "runtime"]) {
      assertObservationReplay(replay.cases[index][key], entry[key], `passkey-native-errors/${entry.name}/${key}`);
    }
  }
}, 120_000);
