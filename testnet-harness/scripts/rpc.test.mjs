import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

for (const mode of ['matching', 'submitted hash differs', 'confirmed hash differs', 'failed result', 'read ledgers', 'missing read ledger',
  'other entry key', 'other data contract', 'other data key', 'other durability', 'expired instance', 'future modified', 'missing modified', 'missing TTL',
  'fee ceiling', 'resource fee', 'fee zero', 'fee above ceiling', 'negative resource fee', 'resource fee exceeds total', 'replacement operation',
  'replacement source', 'replacement sequence', 'replacement network', 'replacement timeout', 'replacement memo',
  'replacement signatures', 'extra operation', 'extra auth', 'wrong fetched source', 'submit enforce mode',
  'source auth', 'create source auth', 'upload no auth', 'existing auth', 'wrong create source',
  'upload fee ceiling', 'upload fee above ceiling', 'upload bytes replaced', 'replacement upload bypass', 'explicit auth modes', 'submission checkpoint', 'checkpoint failure', 'send backpressure', 'unknown send status',
  'named fee ceiling', 'named fee above ceiling', 'named ceiling out of range']) {
  test(`RPC receipt and read identity: ${mode}`, () => {
    execFileSync(process.execPath, ['--experimental-vm-modules',
      fileURLToPath(new URL('./fixtures/submission-receipt.mjs', import.meta.url)), mode], { stdio: 'pipe' });
  });
}
