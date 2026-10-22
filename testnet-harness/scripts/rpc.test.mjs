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
async function outcomeWith(responses, { maxTime, nowSeconds = [], budgetMs, minLedger } = {}) {
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
      delay: async () => {}, ...(budgetMs === undefined ? {} : { budgetMs }), ...(minLedger === undefined ? {} : { minLedger }) });
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

const unseen = (overrides = {}) => ({ status: 'NOT_FOUND', latestLedger: 500, latestLedgerCloseTime: String(WINDOW_END + 1),
  oldestLedger: 100, oldestLedgerCloseTime: String(WINDOW_START), ...overrides });
for (const field of ['latestLedgerCloseTime', 'oldestLedgerCloseTime']) {
  for (const bad of [null, '', ' ', false, '0', 0, '-5', -5, '12a', 1.5, '1e3', undefined]) {
    test(`a malformed ${field} (${JSON.stringify(bad)}) never makes a removal unseen`, async () => {
      const { result } = await outcomeWith([unseen({ [field]: bad })], { maxTime: WINDOW_END, nowSeconds: [0, 10], budgetMs: 5000 });
      assert.equal(result.after_window, false);
    });
  }
}
test('close times out of order never make a removal unseen', async () => {
  const { result } = await outcomeWith([unseen({ oldestLedgerCloseTime: String(WINDOW_END + 2) })],
    { maxTime: WINDOW_END, nowSeconds: [0, 10], budgetMs: 5000 });
  assert.equal(result.after_window, false);
});
test('with the prepare-time ledger known, the endpoint must still retain it', async () => {
  assert.equal((await outcomeWith([unseen({ oldestLedger: 100 })], { maxTime: WINDOW_END, minLedger: 100 })).result.after_window, true);
  for (const oldestLedger of [101, 0, '100', null]) {
    const { result } = await outcomeWith([unseen({ oldestLedger })], { maxTime: WINDOW_END, minLedger: 100, nowSeconds: [0, 10], budgetMs: 5000 });
    assert.equal(result.after_window, false, `oldestLedger ${JSON.stringify(oldestLedger)}`);
  }
});

function recordingIo(fs, overrides = {}) {
  const calls = [];
  const io = {};
  for (const name of ['openSync', 'writeSync', 'fsyncSync', 'closeSync', 'renameSync', 'rmSync']) {
    io[name] = (...args) => { calls.push([name, ...args.filter((a) => typeof a === 'string')]); return (overrides[name] ?? fs[name])(...args); };
  }
  return { io, calls };
}
test('writeJson writes a new temporary file, syncs it, then renames it over the journal', async (t) => {
  const fs = await import('node:fs');
  const { join, dirname } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { writeJson } = await import('./rpc.mjs');
  const dir = fs.mkdtempSync(join(tmpdir(), 'ozpb-atomic-io-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'run.json');
  const { io, calls } = recordingIo(fs);
  writeJson(path, { value: 2 }, io);
  const names = calls.map(([name]) => name);
  assert.equal(names[0], 'openSync');
  const temporary = calls[0][1];
  assert.notEqual(temporary, path);
  assert.equal(dirname(temporary), dir);
  assert.equal(calls[0][2], 'wx');
  assert.ok(names.indexOf('fsyncSync') < names.indexOf('renameSync'));
  assert.deepEqual(calls.find(([name]) => name === 'renameSync').slice(1), [temporary, path]);
  assert.deepEqual(JSON.parse(fs.readFileSync(path, 'utf8')), { value: 2 });
});
test('writeJson completes short writes and refuses a write that makes no progress', async (t) => {
  const fs = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { writeJson } = await import('./rpc.mjs');
  const dir = fs.mkdtempSync(join(tmpdir(), 'ozpb-short-write-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'run.json');
  const short = recordingIo(fs, { writeSync: (fd, buffer, offset, length, position) => fs.writeSync(fd, buffer, offset, Math.min(length, 7), position) });
  writeJson(path, { value: 'a fairly long journal value that needs several short writes' }, short.io);
  assert.equal(JSON.parse(fs.readFileSync(path, 'utf8')).value, 'a fairly long journal value that needs several short writes');
  assert.ok(short.calls.filter(([name]) => name === 'writeSync').length > 3);
  const stuck = recordingIo(fs, { writeSync: () => 0 });
  assert.throws(() => writeJson(path, { value: 'replacement' }, stuck.io), /no progress/);
  assert.equal(JSON.parse(fs.readFileSync(path, 'utf8')).value, 'a fairly long journal value that needs several short writes');
  assert.deepEqual(fs.readdirSync(dir), ['run.json'], 'the partial temporary file is removed and never renamed');
});
