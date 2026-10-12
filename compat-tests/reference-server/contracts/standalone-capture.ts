import { expect } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

async function runStandaloneCapture(
  capture: URL,
  args: readonly string[] = [],
) {
  const script = fileURLToPath(capture);
  const directory = mkdtempSync(join(tmpdir(), `better-auth-${basename(script, ".mjs")}-`));
  const output = join(directory, "capture.json");
  // Bun's test runner exposes different Error properties from standalone captures.
  const env = { ...process.env };
  // The standalone capture has no test-mode IP fallback.
  delete env.NODE_ENV;
  delete env.TEST;
  const child = Bun.spawn([process.execPath, "--no-install", script, ...args, output], {
    stdout: "pipe", stderr: "pipe", env,
  });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  writeFileSync(join(directory, "stdout.log"), stdout);
  writeFileSync(join(directory, "stderr.log"), stderr);
  return { directory, output, stdout, stderr, status };
}

export async function expectStandaloneCapture(
  capture: URL,
  fixture: URL,
  args: readonly string[] = [],
): Promise<void> {
  const expected = readFileSync(fixture, "utf8");
  const { directory, output, stderr, status } = await runStandaloneCapture(capture, args);
  expect({ status, stderr }, `Capture evidence: ${directory}`).toEqual({ status: 0, stderr: "" });
  expect(readFileSync(output, "utf8"), `Capture evidence: ${directory}`).toBe(expected);
  rmSync(directory, { recursive: true });
}

export async function expectStandaloneObservation(
  capture: URL,
  fixture: URL,
  label: string,
  hostPaths = new Set<string>(),
): Promise<void> {
  const { directory, output, stdout, stderr, status } = await runStandaloneCapture(capture);
  try {
    await Promise.all([
      writeObservation(stdout),
      new Promise<void>((resolve, reject) => {
        process.stderr.write(stderr, error => {
          if (error) reject(error);
          else resolve();
        });
      }),
    ]);
    expect(status, `Capture evidence: ${directory}`).toBe(0);
    assertObservationReplay(
      JSON.parse(readFileSync(output, "utf8")),
      JSON.parse(readFileSync(fixture, "utf8")),
      label,
      hostPaths,
    );
  } catch (error) {
    console.error(`Capture evidence: ${directory}`);
    throw error;
  }
  rmSync(directory, { recursive: true });
}
