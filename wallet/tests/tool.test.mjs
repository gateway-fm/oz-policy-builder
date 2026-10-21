import assert from 'node:assert/strict';
import test from 'node:test';
import { runTool } from '../server/tool.mjs';

test('wallet CLI runner bounds output without returning confidential diagnostics', async () => {
  await assert.rejects(runTool(process.execPath, ['-e', "process.stdout.write('SOURCE-CANARY'.repeat(1000))"],
    { maxOutput: 100 }), (error) => /tool failed/.test(error.message) && !error.message.includes('SOURCE-CANARY'));
});

test('wallet CLI runner refuses nonzero exit and discards stderr', async () => {
  await assert.rejects(runTool(process.execPath, ['-e', "process.stderr.write('SIGNATURE-CANARY');process.exit(1)"]),
    (error) => /tool failed/.test(error.message) && !error.message.includes('SIGNATURE-CANARY'));
});

test('wallet CLI runner has a finite process deadline', async () => {
  const before = performance.now();
  await assert.rejects(runTool(process.execPath, ['-e', 'setTimeout(()=>{},1000)'], { timeoutMs: 50 }), /tool failed/);
  assert.ok(performance.now() - before < 900);
});

test('wallet CLI runner drops inherited credentials and accepts only operator build variables', async () => {
  process.env.OZPB_WALLET_CANARY = 'CONFIDENTIAL';
  try {
    const output = await runTool(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(process.env))'],
      { env: { CARGO_NET_OFFLINE: 'true', OZPB_HTTP_BEARER_TOKEN: 'must-not-pass' } });
    const observed = JSON.parse(output);
    assert.equal(observed.OZPB_WALLET_CANARY, undefined);
    assert.equal(observed.OZPB_HTTP_BEARER_TOKEN, undefined);
    assert.equal(observed.CARGO_NET_OFFLINE, 'true');
  } finally { delete process.env.OZPB_WALLET_CANARY; }
});

test('wallet CLI runner stops its process group as soon as the caller aborts', async () => {
  const controller = new AbortController();
  const before = performance.now();
  const run = runTool(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], { signal: controller.signal });
  setTimeout(() => controller.abort(), 50);
  await assert.rejects(run, /tool failed/);
  assert.ok(performance.now() - before < 5000);
  await assert.rejects(runTool(process.execPath, ['-e', ''], { signal: AbortSignal.abort() }), /tool failed/,
    'an already aborted caller starts nothing');
});
