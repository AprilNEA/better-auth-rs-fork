import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("OAuth native profiles preserve the complete pinned callback contract", async () => {
  const fixture = readFileSync(new URL("../../../tests/fixtures/oauth-native-profile-1.7.6.json", import.meta.url), "utf8");
  const capture = fileURLToPath(new URL("oauth-native-profile-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(stdout).toBe(fixture);
}, 60_000);
