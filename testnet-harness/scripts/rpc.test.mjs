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

// transactionOutcome itself, against a stubbed endpoint: only ledger close times decide that an
// unseen transaction can no longer land; the local clock only bounds how long it polls.
async function outcomeWith(responses, { maxTime, nowSeconds = [], budgetMs } = {}) {
  const rpcModule = await import('./rpc.mjs');
  const original = rpcModule.server.getTransaction;
  let reads = 0, clock = 0;
  rpcModule.server.getTransaction = async () => {
    const r = responses[Math.min(reads++, responses.length - 1)];
    if (r instanceof Error) throw r;
    return r;
  };
  try {
    const result = await rpcModule.transactionOutcome('ab'.repeat(32), maxTime, {
      now: () => (nowSeconds.length ? nowSeconds[Math.min(clock++, nowSeconds.length - 1)] : 0) * 1000,
      delay: async () => {}, ...(budgetMs === undefined ? {} : { budgetMs }) });
    return { result, reads };
  } finally { rpcModule.server.getTransaction = original; }
}
const missing = (latest, oldest) => ({ status: 'NOT_FOUND', latestLedgerCloseTime: String(latest), oldestLedgerCloseTime: String(oldest) });
const WINDOW_END = 2_000_000_000, WINDOW_START = WINDOW_END - 120;
test('transactionOutcome returns a final status at once', async () => {
  for (const status of ['SUCCESS', 'FAILED']) {
    const { result, reads } = await outcomeWith([{ status, ledger: 9 }], { maxTime: WINDOW_END });
    assert.equal(result.status, status);
    assert.equal(reads, 1);
  }
});
test('without a known window one read is made and not-found proves nothing', async () => {
  const { result, reads } = await outcomeWith([missing(WINDOW_END + 999, 1)], { maxTime: null });
  assert.deepEqual([result.status, result.after_window, reads], ['NOT_FOUND', false, 1]);
});
test('not-found counts as unseen only once a ledger closed after the window and the endpoint retains its start', async () => {
  const inside = await outcomeWith([missing(WINDOW_END - 5, 1), missing(WINDOW_END, 1), missing(WINDOW_END + 1, WINDOW_START)],
    { maxTime: WINDOW_END });
  assert.deepEqual([inside.result.status, inside.result.after_window, inside.reads], ['NOT_FOUND', true, 3]);
  const lands = await outcomeWith([missing(WINDOW_END - 5, 1), { status: 'SUCCESS', ledger: 7 }], { maxTime: WINDOW_END });
  assert.equal(lands.result.status, 'SUCCESS');
});
test('an endpoint that no longer retains the window start cannot call a transaction unseen', async () => {
  const { result } = await outcomeWith([missing(WINDOW_END + 600_000, WINDOW_START + 1)], { maxTime: WINDOW_END });
  assert.deepEqual([result.status, result.after_window], ['NOT_FOUND', false]);
});
test('a fast local clock never makes a lagging endpoint\'s not-found unseen', async () => {
  const { result, reads } = await outcomeWith([missing(WINDOW_END - 60, 1)], { maxTime: WINDOW_END,
    nowSeconds: [WINDOW_END + 10_000, WINDOW_END + 20_000, WINDOW_END + 30_000], budgetMs: 1000 });
  assert.deepEqual([result.status, result.after_window], ['NOT_FOUND', false]);
  assert.ok(reads >= 1);
});
test('transport errors are retried within the polling budget, then reported as unknown', async () => {
  const retried = await outcomeWith([new Error('fetch failed'), { status: 'SUCCESS', ledger: 3 }], { maxTime: WINDOW_END });
  assert.equal(retried.result.status, 'SUCCESS');
  assert.equal(retried.reads, 2);
  const down = await outcomeWith([new Error('fetch failed')], { maxTime: WINDOW_END, nowSeconds: [0, 0, 10, 10], budgetMs: 5000 });
  assert.deepEqual([down.result.status, down.result.after_window], ['UNKNOWN', false]);
});

test('run journals are replaced atomically through a synced temporary file in the same directory', async (t) => {
  const { mkdtempSync, readdirSync, readFileSync: rf, rmSync, writeFileSync: wf } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { writeJson } = await import('./rpc.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-atomic-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'run.json');
  wf(path, '{"old":true}\n');
  writeJson(path, { value: 1 });
  assert.deepEqual(JSON.parse(rf(path, 'utf8')), { value: 1 });
  assert.deepEqual(readdirSync(dir), ['run.json'], 'no temporary file is left behind');
});
