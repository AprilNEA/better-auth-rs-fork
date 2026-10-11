import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("OAuth sign-in preserves complete callback order, cookies, and durable writes", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/account-user-auth-order-1.7.6.json", import.meta.url)).json();
  const capture = fileURLToPath(new URL("account-user-auth-order-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);
