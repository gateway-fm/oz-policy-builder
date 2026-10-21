import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('./fixtures/install-deployment-check.mjs', import.meta.url));
for (const mode of ['refused', 'declined', 'approved', 'default', 'subscription-approved', 'subscription-approved-reverse', 'subscription-incomplete-approval']) {
  test(`installer preserves deployment evidence: ${mode}`, () => {
    execFileSync(process.execPath, ['--experimental-vm-modules', fixture, mode], { stdio: 'pipe' });
  });
}

for (const mode of ['approved', 'default']) {
  for (const failure of ['is_installed', 'remaining_calls', 'not_installed']) {
    test(`installer preserves confirmed installation after ${failure}: ${mode}`, () => {
      execFileSync(process.execPath, ['--experimental-vm-modules', fixture, mode, failure], { stdio: 'pipe' });
    });
  }
}
