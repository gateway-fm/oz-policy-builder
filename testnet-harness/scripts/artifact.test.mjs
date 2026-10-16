import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// A separate process enables VM module isolation for the real installer, without enabling
// experimental modules for the other suites. Only RPC and key access are replaced.
const fixture = fileURLToPath(new URL('./fixtures/install-artifact-check.mjs', import.meta.url));
for (const mode of ['matching', 'canonical-order', 'missing', 'malformed', 'unrelated', 'amount',
  'call-cap', 'invalid-spec', 'cli-failure', 'authority-matching', 'authority-amount']) {
  test(`installer artifact identity: ${mode}`, () => {
    execFileSync(process.execPath, ['--experimental-vm-modules', fixture, mode], {
      stdio: 'pipe', env: process.env,
    });
  });
}
