import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("Full Organization SQL fallback preserves the complete pinned public and storage contract", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/organization-full-fallback-1.7.6.json", import.meta.url), "utf8"));
  const capture = fileURLToPath(new URL("organization-full-fallback-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  if (status !== 0) throw new Error(`Full Organization capture exited with ${status}: ${stderr}`);
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);
