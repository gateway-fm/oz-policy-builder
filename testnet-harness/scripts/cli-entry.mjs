import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Node normally resolves module symlinks but leaves the invoked path in argv[1].
// Imports (including eval/embedded callers without a real entry file) must stay inert.
export function isMainModule(moduleUrl) {
  if (!process.argv[1]) return false;
  try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(moduleUrl)); }
  catch { return false; }
}
