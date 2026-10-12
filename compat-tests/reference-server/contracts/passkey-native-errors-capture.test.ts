import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { passkeyNativeErrorCases } from "./passkey-native-errors-capture.mjs";
import { runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("Passkey native errors preserve cookie consumption, verification order, original errors and committed storage", async () => {
  const capture = new URL("./passkey-native-errors-capture.mjs", import.meta.url);
  const first = await runStandaloneCapture(capture);
  await writeObservation(first.stdout);
  expect({ status: first.status, stderr: first.stderr }, `Capture evidence: ${first.directory}`).toEqual({ status: 0, stderr: "" });
  const observation = JSON.parse(readFileSync(first.output, "utf8"));
  expect(observation.contract).toBe("passkey-native-errors");
  expect(observation.version).toBe("1.7.6");
  expect(observation.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(passkeyNativeErrorCases);
  const second = await runStandaloneCapture(capture, [first.output]);
  await writeObservation(second.stdout);
  expect({ status: second.status, stderr: second.stderr }, `Replay evidence: ${second.directory}`).toEqual({ status: 0, stderr: "" });
  const replay = JSON.parse(readFileSync(second.output, "utf8"));
  assertObservationReplay(replay.provenance, observation.provenance, "passkey-native-errors/provenance");
  for (const [index, entry] of observation.cases.entries()) {
    assertObservationReplay(replay.cases[index].input, entry.input, `passkey-native-errors/${entry.name}/input`);
    assertObservationReplay(replay.cases[index].runtime, entry.runtime, `passkey-native-errors/${entry.name}/runtime`);
  }
}, 120_000);
