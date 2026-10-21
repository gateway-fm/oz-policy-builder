import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { createWalletServer } from '../server/http.mjs';
import { CAPTURE_LEDGER, reviewed } from './native-actions-fixture.mjs';
import { captureFixture, transferCall } from './captured-execution-fixture.mjs';

const status = (result) => Object.fromEntries(result.verification.layers.map((layer) => [layer.layer, layer.status]));
const check = (f) => f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
const capturedRuns = (f) => f.runs.filter((run) => run.captured);

test('check-account adds a captured_target layer only for a capture and report matching the review', async () => {
  const f = await reviewed();
  const result = await check(f);
  assert.deepEqual(status(result), { reference: 'passed', account_wasm: 'passed', captured_target: 'passed', live_enforcement: 'unavailable' });
  const layer = result.verification.layers[2];
  assert.equal(layer.evidence.observedLedger, CAPTURE_LEDGER);
  assert.equal(layer.evidence.captureHash, f.captured.prepared.capture_hash);
  assert.equal(layer.evidence.runHash, result.verification.layers[1].evidence.runHash, 'one preparation, one run');
  assert.equal(layer.evidence.complete, false);
  assert.equal(result.verification.complete, false);
  // The worker's captured job is the CLI request with the capture's own ledger, plus the capture verbatim.
  const [prepare, run] = capturedRuns(f);
  assert.equal(prepare.prepareOnly, true);
  assert.equal(prepare.jobText, run.jobText);
  const job = JSON.parse(prepare.jobText);
  assert.deepEqual(job.capture, f.capture);
  assert.equal(job.native.ledger.sequence, CAPTURE_LEDGER);
  assert.equal(job.native.request.run_nonce, JSON.parse(f.runs[0].jobText).request.run_nonce);
  assert.equal((await f.actions.status({})).capabilities.install, false);
  await assert.rejects(() => f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
});

test('the check-account report never contains the capture envelope or delegate key material', async () => {
  const f = await reviewed();
  const result = await check(f);
  assert.equal(f.envelopes.length, 1);
  const text = JSON.stringify(result);
  for (const secret of [f.envelopes[0], f.delegate.capabilityId]) {
    assert.ok(!text.includes(secret));
    assert.ok(!f.runs.some((run) => run.jobText.includes(secret)), 'nor does any worker job');
  }
  assert.ok(!/"S[A-Z2-7]{55}"/.test(text), 'no secret seed');
  const again = await f.actions.review({ deploymentId: f.deployed.deploymentId, wallet: f.f.wallet });
  assert.equal(again.verification.layers[2].status, 'unavailable', 'a fresh review starts without captured evidence');
});

const swapCall = (call) => (capture) => { capture.invocation_xdr = call.toXDR('base64'); };
for (const [name, options] of [
  ['another amount', { captureChange: (c, { account }) => swapCall(transferCall({ account, amount: 1000001n }))(c) }],
  ['another recipient', { captureChange: (c, { account }) => swapCall(transferCall({ account, recipient: Keypair.random().publicKey() }))(c) }],
  ['another account', { captureChange: (c) => { Object.assign(c, captureFixture({ account: 'CAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCRUA6',
    observedLedger: CAPTURE_LEDGER })); } }],
  ['another network', { captureChange: (c) => { c.network_id = '1'.repeat(64); } }],
  ['another account code', { captureChange: (c) => { c.account_code_hash = '2'.repeat(64); } }],
]) {
  test(`a foreign capture (${name}) fails the captured layer before the worker runs`, async () => {
    const f = await reviewed(options);
    const result = await check(f);
    assert.equal(status(result).captured_target, 'failed');
    assert.equal(status(result).account_wasm, 'passed');
    assert.equal(result.verification.layers[2].evidence, undefined);
    assert.equal(capturedRuns(f).length, 0);
  });
}

for (const [name, notBefore] of [['older than the check', CAPTURE_LEDGER + 1], ['beyond the freshness window', CAPTURE_LEDGER - 13]]) {
  test(`a stale capture (${name}) is unavailable: no current evidence, and the worker never runs`, async () => {
    const f = await reviewed({ notBefore });
    const result = await check(f);
    assert.equal(status(result).captured_target, 'unavailable');
    assert.match(result.verification.layers[2].detail, /ledger window/);
    assert.equal(capturedRuns(f).length, 0);
  });
}

for (const [name, options] of [
  ['a read outside the capture', { capturedChange: (r) => { r.cases[0].undeclared_reads = [r.cases[0].created_keys[0]]; } }],
  ['a target refusal of the original', { capturedChange: (r) => { Object.assign(r.cases[0], { permitted: false,
    host_error: 'HostError: Error(Contract, #10)', sender_delta: '0', recipient_delta: '0', counter_after: 0,
    state_after_hash: r.cases[0].state_before_hash, created_keys: [], written_keys: [], ttl_extended_keys: [] }); } }],
  ['a denial the target refused instead of the policy', { capturedChange: (r) => { r.cases[1].refusal_contract = null; r.cases[1].refusal_code = null; } }],
  ['a worker that exits without a passing report', { capturedRunFails: true }],
  ['a preparation for another capture', { capturedPreparedChange: (p) => { p.capture_hash = '7'.repeat(64); } }],
]) {
  test(`${name} fails the captured layer and accepts no evidence`, async () => {
    const f = await reviewed(options);
    const result = await check(f);
    assert.equal(status(result).captured_target, 'failed');
    assert.equal(result.verification.layers[2].evidence, undefined);
  });
}

for (const failure of ['envelopeFails', 'captureFails']) {
  test(`an infrastructure error before the captured worker (${failure}) is unavailable, not a failed candidate`, async () => {
    const f = await reviewed({ [failure]: true });
    const result = await check(f);
    assert.equal(status(result).captured_target, 'unavailable');
    assert.match(result.verification.layers[2].detail, /did not run/);
    assert.equal(status(result).account_wasm, 'passed');
    assert.equal(capturedRuns(f).length, 0);
  });
}

test('a grant that expired before the captured ledger is unavailable, not a failed candidate', async () => {
  const f = await reviewed();
  f.artifact.spec.rules[0].valid_until = { ledger: CAPTURE_LEDGER, approx_time: null };
  const result = await check(f);
  assert.equal(status(result).captured_target, 'unavailable');
  assert.match(result.verification.layers[2].detail, /expires/);
  assert.equal(capturedRuns(f).length, 0);
  f.artifact.spec.rules[0].valid_until = { ledger: CAPTURE_LEDGER + 1, approx_time: null };
  assert.equal(status(await check(f)).captured_target, 'passed', 'a rule still valid at the next ledger runs');
});

const outOfScope = [{ fn: 'transfer', args: [{ i: 0, c: { eq_address: { value: 'SELF' } } },
  { i: 2, c: { range_i128: { min: '1', max: '1000000' } } }] }];
test('a grant outside the captured scope is unsupported and nothing is captured', async () => {
  const f = await reviewed({ allowedCalls: outOfScope });
  const result = await check(f);
  assert.equal(status(result).captured_target, 'unsupported');
  assert.equal(f.envelopes.length + f.captures.length + capturedRuns(f).length, 0);
});

for (const failure of [{ prepareFails: true }, { intentChange: (evidence) => { delete evidence.enumeration_evidence; } }]) {
  test(`an unsupported shape stays unsupported when the check also cannot run (${Object.keys(failure)[0]})`, async () => {
    const f = await reviewed({ allowedCalls: outOfScope, ...failure });
    const result = await check(f);
    assert.equal(status(result).captured_target, 'unsupported');
    assert.equal(status(result).account_wasm, 'unavailable');
  });
}

// Called directly with a signal, as the HTTP server passes it: an abort at any stage rejects the
// check, so no layer is recorded, and the signal reaches whatever child process is running.
const pending = (signal) => new Promise((_resolve, reject) => signal.addEventListener('abort',
  () => reject(new Error('native process refused; no execution evidence accepted')), { once: true }));
for (const stage of ['capture-target', 'captured worker', 'account worker']) {
  test(`an aborted check-account rejects at the ${stage} and records no evidence`, async () => {
    const controller = new AbortController();
    const f = await reviewed();
    let held = false;
    const seen = [];
    const reached = new Promise((resolve) => {
      if (stage === 'capture-target') {
        const capture = f.toolchain.captureTarget;
        f.toolchain.captureTarget = async (envelope, options) => {
          if (held) return capture(envelope, options);
          held = true; seen.push(options?.signal); resolve(); return pending(options.signal);
        };
      } else {
        const run = f.native.run;
        f.native.run = async (executable, jobText, options) => {
          if (held || (stage === 'captured worker') !== (options.captured === true)) return run(executable, jobText, options);
          held = true; seen.push(options.signal); resolve(); return pending(options.signal);
        };
      }
    });
    const checking = f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId },
      { signal: controller.signal });
    await reached;
    controller.abort();
    await assert.rejects(checking, /refused/);
    assert.deepEqual(seen, [controller.signal], 'the signal reaches the running child process');
    // The check lock is free again: the next check runs both layers to completion.
    const next = await check(f);
    assert.equal(status(next).account_wasm, 'passed');
    assert.equal(status(next).captured_target, 'passed');
  });
}

// A real process tree: the worker records its PID and a descendant's, then hangs until killed.
function hungWorker(t) {
  const dir = mkdtempSync(join(tmpdir(), 'wallet-hung-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const marker = join(dir, 'started');
  writeFileSync(join(dir, 'worker.mjs'), `import {existsSync, writeFileSync} from 'node:fs';import {spawn} from 'node:child_process';`
    + `if (existsSync(${JSON.stringify(marker)})) process.exit(1);`
    + `const d=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});`
    + `writeFileSync(${JSON.stringify(marker)}, JSON.stringify([process.pid, d.pid]));setInterval(()=>{},1000);`, { mode: 0o600 });
  const executable = join(dir, 'worker');
  writeFileSync(executable, `#!/bin/sh\nexec '${process.execPath}' '${join(dir, 'worker.mjs')}' "$@"\n`, { mode: 0o700 });
  return { executable, marker };
}
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; } };
const until = async (predicate, ms) => {
  for (const end = performance.now() + ms; performance.now() < end;) { if (predicate()) return true; await new Promise((r) => setTimeout(r, 20)); }
  return predicate();
};

test('check-account aborts worker and releases busy lock on disconnect', async (t) => {
  const worker = hungWorker(t);
  const f = await reviewed({ native: { executable: worker.executable } });
  const server = createWalletServer({ session: f.session, actions: f.actions });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  let pids = [];
  t.after(() => { for (const pid of pids) if (alive(pid)) try { process.kill(pid, 'SIGKILL'); } catch { /* gone */ } });
  const body = JSON.stringify({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const open = (path, text, onResponse = () => {}) => request({ hostname: '127.0.0.1', port: server.address().port, method: 'POST',
    path: `/api/policy-builder/${path}`, headers: { host: '127.0.0.1:3000', origin: 'http://127.0.0.1:3000',
      authorization: `Bearer ${'ab'.repeat(32)}`, 'content-type': 'application/json' } }, onResponse);
  const send = (path, text) => new Promise((resolve, reject) => {
    const req = open(path, text, (res) => { const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() })); });
    req.on('error', reject); req.end(text);
  });
  const hanging = open('check-account', body);
  hanging.on('error', () => {});
  hanging.end(body);
  assert.ok(await until(() => existsSync(worker.marker), 20000), 'the worker started');
  pids = JSON.parse(readFileSync(worker.marker, 'utf8'));
  assert.equal((await send('status', '{}')).status, 409, 'the backend is busy while the worker runs');
  hanging.destroy();
  assert.ok(await until(() => pids.every((pid) => !alive(pid)), 10000), 'the worker and its descendant were killed');
  let freed;
  for (const end = performance.now() + 10000; performance.now() < end;) {
    freed = await send('status', '{}');
    if (freed.status === 200) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(freed.status, 200, 'the busy lock was released');
  // The account-check lock is released too: the next check runs (the worker now exits at once).
  const next = await send('check-account', body);
  assert.equal(next.status, 200);
  assert.equal(JSON.parse(next.body).verification.layers[1].status, 'failed');
  assert.ok(!next.body.includes(f.delegate.capabilityId));
});
