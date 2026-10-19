import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

for (const mode of ['matching', 'submitted hash differs', 'confirmed hash differs', 'failed result', 'read ledgers', 'missing read ledger',
  'other entry key', 'other data contract', 'other data key', 'other durability', 'expired instance', 'future modified', 'missing modified', 'missing TTL', 'explicit auth modes']) {
  test(`RPC receipt and read identity: ${mode}`, () => {
    execFileSync(process.execPath, ['--experimental-vm-modules',
      fileURLToPath(new URL('./fixtures/submission-receipt.mjs', import.meta.url)), mode], { stdio: 'pipe' });
  });
}
