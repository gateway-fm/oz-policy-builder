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

test('wallet CLI runner surfaces only an allowlisted refusal code from the CLI, never its text', async () => {
  const refusing = (text, code = 1) => ['-e', `process.stderr.write(${JSON.stringify(text)});process.exit(${code})`];
  await assert.rejects(runTool(process.execPath, refusing('Error: E_TARGET_REFUSED: endpoint quoted SECRET-CANARY\n'),
    { codes: ['E_TARGET_REFUSED', 'E_TARGET_ARCHIVED'] }),
  (error) => error.code === 'E_TARGET_REFUSED' && /tool failed/.test(error.message) && !error.message.includes('SECRET'));
  for (const [text, codes] of [
    ['Error: E_RPC: SECRET\n', ['E_TARGET_REFUSED']],
    ['Error: E_TARGET_REFUSED: x', []],
    ['warning\nError: E_TARGET_REFUSED: x', ['E_TARGET_REFUSED']],
    ['Error: E_TARGET_REFUSED_LATER: x', ['E_TARGET_REFUSED']],
  ]) {
    await assert.rejects(runTool(process.execPath, refusing(text), { codes }),
      (error) => error.code === undefined && !error.message.includes('SECRET'), text);
  }
  const flood = ['-e', "process.stderr.write('x'.repeat(1<<20));process.stderr.write('Error: E_TARGET_REFUSED: x');process.exit(1)"];
  await assert.rejects(runTool(process.execPath, flood, { codes: ['E_TARGET_REFUSED'] }), (error) => error.code === undefined);
  await assert.rejects(runTool(process.execPath, ['-e', 'setTimeout(()=>{},1000)'], { codes: ['E_TARGET_REFUSED'], timeoutMs: 50 }),
    (error) => error.code === undefined, 'a killed process carries no code');
  await assert.rejects(runTool(process.execPath, refusing('Error: E_TARGET_REFUSED: x'), { codes: ['not a code'] }), /tool failed/);
});

test('a refusal code counts only from a process that exited by itself, within the stderr prefix bound', async () => {
  // Killed by a signal after writing a well-formed refusal: no exit status, so no code.
  await assert.rejects(runTool(process.execPath, ['-e',
    "process.stderr.write('Error: E_TARGET_REFUSED: x\\n', () => process.kill(process.pid, 'SIGKILL'))"],
  { codes: ['E_TARGET_REFUSED'] }), (error) => error.code === undefined);
  // The same refusal with an ordinary failing exit does carry it (control).
  await assert.rejects(runTool(process.execPath, ['-e',
    "process.stderr.write('Error: E_TARGET_REFUSED: x\\n', () => process.exit(2))"], { codes: ['E_TARGET_REFUSED'] }),
  (error) => error.code === 'E_TARGET_REFUSED');
  // Only the first 256 bytes are read: an allowlisted code ending beyond them is not surfaced.
  const long = `E_${'A'.repeat(300)}`;
  await assert.rejects(runTool(process.execPath, ['-e', `process.stderr.write('Error: ${long}: x');process.exit(1)`],
    { codes: [long] }), (error) => error.code === undefined);
  const short = `E_${'A'.repeat(200)}`;
  await assert.rejects(runTool(process.execPath, ['-e', `process.stderr.write('Error: ${short}: x');process.exit(1)`],
    { codes: [short] }), (error) => error.code === short, 'a code within the bound is read (control)');
});
