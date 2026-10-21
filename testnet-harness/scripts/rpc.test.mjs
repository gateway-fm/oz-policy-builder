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
  'named fee ceiling', 'named fee above ceiling', 'named ceiling out of range',
  'poll transient error', 'submission max time', 'readback error ledger']) {
  test(`RPC receipt and read identity: ${mode}`, () => {
    execFileSync(process.execPath, ['--experimental-vm-modules',
      fileURLToPath(new URL('./fixtures/submission-receipt.mjs', import.meta.url)), mode], { stdio: 'pipe' });
  });
}

test('secrets of this run are redacted from cleanup diagnostics; addresses and hashes are kept', async (t) => {
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { redactSecrets } = await import('./rpc.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-redact-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const seed = 'S' + 'B'.repeat(55), credential = 'pk-' + 'x'.repeat(40);
  writeFileSync(join(dir, 'keys.json'), JSON.stringify({ payer: seed, passkey: { credential } }));
  const previous = process.env.OZPB_HARNESS_SECRETS;
  process.env.OZPB_HARNESS_SECRETS = join(dir, 'keys.json');
  t.after(() => { if (previous === undefined) delete process.env.OZPB_HARNESS_SECRETS; else process.env.OZPB_HARNESS_SECRETS = previous; });
  const address = 'C' + 'A'.repeat(55), tx = 'ab'.repeat(32), other = 'S' + 'C'.repeat(55);
  const text = redactSecrets(`failed ${seed} ${credential} ${other} ${address} ${tx}`);
  for (const secret of [seed, credential, other]) assert.ok(!text.includes(secret));
  assert.ok(text.includes(address) && text.includes(tx));
});

test('a readback is accepted only at or after the confirmed ledger, and retried below it within a bound', async () => {
  const { observeAtOrAfter, SimulationError } = await import('./rpc.mjs');
  const ledgers = [99, 100, 101];
  let reads = 0;
  const read = async () => ({ value: 'v', ledger: ledgers[reads++] });
  assert.deepEqual(await observeAtOrAfter(101, read, { delay: async () => {}, attempts: 3 }), { value: 'v', ledger: 101 });
  reads = 0;
  await assert.rejects(observeAtOrAfter(102, read, { delay: async () => {}, attempts: 3 }), /confirmed ledger/);
  const absent = Object.assign(new SimulationError('get', 'Error(Contract, #3000)'), { ledger: 120 });
  await assert.rejects(observeAtOrAfter(101, async () => { throw absent; }, { delay: async () => {} }), (e) => e === absent);
  let transport = 0;
  await assert.rejects(observeAtOrAfter(101, async () => { transport++; throw new Error('fetch failed'); },
    { delay: async () => {}, attempts: 2 }), /confirmed ledger/);
  assert.equal(transport, 2);
});
