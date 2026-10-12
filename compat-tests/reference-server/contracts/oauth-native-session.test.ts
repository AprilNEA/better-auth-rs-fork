import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

test("OAuth native sessions preserve all 172 pinned HTTP, cache, state, and storage cases", async () => {
  const fixture = readFileSync(new URL("../../../tests/fixtures/oauth-native-session-1.7.6.json", import.meta.url), "utf8");
  const capture = fileURLToPath(new URL("oauth-native-session-capture.mjs", import.meta.url));
  const directory = mkdtempSync(join(tmpdir(), "better-auth-oauth-native-session-"));
  try {
    const output = join(directory, "observed.json");
    const child = Bun.spawn([process.execPath, "--no-install", capture, output], {
      // The standalone capture has no test-mode IP fallback; Bun test must not change that input.
      env: { ...process.env, NODE_ENV: "", TEST: "" },
      stdout: "pipe", stderr: "pipe",
    });
    const [stdout, stderr, status] = await Promise.all([
      new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
    ]);
    process.stderr.write(stderr);
    expect({ status, stdout }).toEqual({ status: 0, stdout: "" });
    expect(readFileSync(output, "utf8")).toBe(fixture);
  } finally {
    rmSync(directory, { recursive: true });
  }
}, 60_000);
