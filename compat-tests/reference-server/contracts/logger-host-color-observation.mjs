import { getColorDepth } from "@better-auth/core/env";

process.stdout.write(`${JSON.stringify({ colors: getColorDepth() !== 1 })}\n`);
