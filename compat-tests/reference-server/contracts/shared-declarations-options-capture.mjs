import { writeFileSync } from "node:fs";
import { captureSharedDeclarations } from "./shared-declarations-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

const observation = await captureSharedDeclarations("options");
if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
await writeObservation(`${JSON.stringify(observation)}\n`);
