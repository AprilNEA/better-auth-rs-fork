import { test } from "bun:test";
import { checkIncrementBindingPhases } from "../contracts/increment-binding-phases.mjs";

for (const backend of ["postgres", "mysql"] as const) {
  test(`${backend} atomic updates preserve phase order, guard misses, rollback and complete storage`, async () => {
    await checkIncrementBindingPhases(backend);
  });
}
