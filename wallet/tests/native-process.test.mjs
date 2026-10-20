import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runNative } from '../server/native-process.mjs';
const quote = (text) => `'${text.replaceAll("'", "'\\''")}'`;
const realKill = process.kill;
/** Signal 0 through the real `process.kill`, so a test stub never decides liveness. */
const alive = (pid) => { try { realKill.call(process, pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; } };
// Kill only a process confirmed alive: a reaped pid may already belong to something else.
const reap = (pid) => { if (pid && alive(pid)) try { realKill.call(process, pid, 'SIGKILL'); } catch {} };
function worker(t, source) {
  const dir = mkdtempSync(join(tmpdir(), 'wallet-native-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'worker.mjs'), source, { mode: 0o600 });
  const executable = join(dir, 'worker');
  writeFileSync(executable, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(join(dir, 'worker.mjs'))} "$@"\n`, { mode: 0o700 });
  return { executable, dir };
}
const emit = `const emit = (frame) => process.stdout.write(JSON.stringify(frame)+'\\n');`;
const input = `import {createInterface} from 'node:readline'; const lines=createInterface({input:process.stdin});`;
const prepared = { type: 'prepared', id: 'retained' };
const result = { type: 'result', passed: true, complete: false };
const hooks = () => ({ validatePrepared: (frame) => { assert.deepEqual(frame, prepared); },
  sign: (frame) => { assert.equal(frame.type, 'sign_request'); return { type: 'signature', request_id: frame.request_id }; },
  validateResult: (frame) => { assert.deepEqual(frame, result); return frame; } });

test('fixed preparation accepts exactly one frame and closes job input', async (t) => {
  const w = worker(t, `${input}${emit}let count=0;for await(const line of lines){count++;JSON.parse(line);}if(process.argv[2]!=='--prepare'||count!==1)process.exit(1);emit(${JSON.stringify(prepared)});`);
  assert.deepEqual(await runNative(w.executable, '{"integer":9223372036854775807}', { prepareOnly: true, ...hooks() }), prepared);
});
test('interactive protocol sends a job and one response, waits for zero exit and drops inherited secrets', async (t) => {
  const w = worker(t, `${input}${emit}let count=0;for await(const line of lines){const f=JSON.parse(line);if(count++===0){if(process.argv.length!==2||Object.hasOwn(process.env,'OZPB_TEST_PRIVATE_TOKEN'))process.exit(3);emit(${JSON.stringify(prepared)});emit({type:'sign_request',request_id:'1'});}else{if(f.type!=='signature')process.exit(4);emit(${JSON.stringify(result)});lines.close();break;}}`);
  process.env.OZPB_TEST_PRIVATE_TOKEN = 'test-only-never-passed';
  try { assert.deepEqual(await runNative(w.executable, '{"schema":1}', hooks()), result); }
  finally { delete process.env.OZPB_TEST_PRIVATE_TOKEN; }
});
for (const scenario of ['missing newline', 'invalid UTF8', 'nonzero after result',
  'extra after result', 'missing result', 'unknown frame']) {
  test(`native process rejects ${scenario} without returning usable evidence`, async (t) => {
    let source;
    if (scenario === 'missing newline') source = `process.stdout.write(JSON.stringify(${JSON.stringify(prepared)}));`;
    if (scenario === 'invalid UTF8') source = 'process.stdout.write(Buffer.from([0xff,10]));';
    if (scenario === 'nonzero after result') source = `emit(${JSON.stringify(prepared)});emit(${JSON.stringify(result)});process.exitCode=2;`;
    if (scenario === 'extra after result') source = `emit(${JSON.stringify(prepared)});emit(${JSON.stringify(result)});emit(${JSON.stringify(result)});`;
    if (scenario === 'missing result') source = `emit(${JSON.stringify(prepared)});`;
    if (scenario === 'unknown frame') source = `emit(${JSON.stringify(prepared)});emit({type:'execute'});`;
    const w = worker(t, `${emit}${source}`);
    await assert.rejects(() => runNative(w.executable, '{}', { ...hooks(), timeoutMs: 2000 }), /native process refused/);
  });
}
// Each worker reads its job and completes an otherwise valid prepared/result exchange, so only
// the named guard can refuse it; the control run shows the same worker passes without the violation.
const lenient = () => ({ ...hooks(), validatePrepared: (frame) => { assert.equal(frame.type, 'prepared'); } });
const violations = {
  'trailing partial line': [`emit(PREPARED);emit(RESULT);process.stdout.write('{"type"');`, `emit(PREPARED);emit(RESULT);`],
  'oversized frame': [`emit({...PREPARED,pad:'x'.repeat(256*1024)});emit(RESULT);`, `emit({...PREPARED,pad:'x'.repeat(1024)});emit(RESULT);`],
  'stderr flood': [`process.stderr.write('x'.repeat(65537));emit(PREPARED);emit(RESULT);`, `process.stderr.write('x'.repeat(65536));emit(PREPARED);emit(RESULT);`],
  'unsafe number': [`process.stdout.write('{"type":"prepared","id":"retained","big":9007199254740993}\\n');emit(RESULT);`,
    `process.stdout.write('{"type":"prepared","id":"retained","big":9007199254740991}\\n');emit(RESULT);`],
  'two outstanding signatures': [
    `process.stdout.write(JSON.stringify(PREPARED)+'\\n'+JSON.stringify({type:'sign_request',request_id:'1'})+'\\n'+JSON.stringify({type:'sign_request',request_id:'2'})+'\\n');await it.next();await it.next();emit(RESULT);`,
    `emit(PREPARED);emit({type:'sign_request',request_id:'1'});await it.next();emit(RESULT);`],
};
for (const [scenario, [violation, control]] of Object.entries(violations)) {
  for (const [kind, body] of [['rejects', violation], ['accepts control for', control]]) {
    test(`native process ${kind} ${scenario}`, async (t) => {
      const w = worker(t, `${input}${emit}const PREPARED=${JSON.stringify(prepared)},RESULT=${JSON.stringify(result)};`
        + `const it=lines[Symbol.asyncIterator]();await it.next();${body}`);
      // Generous: only a hang reaches it, and a control must not lose a race with slow start-up.
      const run = runNative(w.executable, '{}', { ...lenient(), timeoutMs: 20000 });
      if (kind === 'rejects') await assert.rejects(() => run, /native process refused/);
      else assert.deepEqual(await run, result);
    });
  }
}
test('native deadline kills its entire process group and waits for termination', async (t) => {
  const w = worker(t, '');
  const pidFile = join(w.dir, 'pid');
  writeFileSync(join(w.dir, 'worker.mjs'), `import {writeFileSync} from 'node:fs';import{spawn}from'node:child_process';const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});writeFileSync(${JSON.stringify(pidFile)},String(child.pid));setInterval(()=>{},1000);`);
  // The deadline must exceed process start-up: first execution of a fresh script can take seconds
  // on a loaded host, and a deadline that fires first proves nothing about the process group.
  await assert.rejects(() => runNative(w.executable, '{}', { ...hooks(), timeoutMs: 5000 }), /native process refused/);
  assert.ok(existsSync(pidFile), 'the real child started');
  const pid = Number(readFileSync(pidFile, 'utf8'));
  // The OS may retain a dead orphan briefly; it must not remain a live running process.
  const { execFileSync } = await import('node:child_process');
  let state = '';
  // `ps` exits 1 for an absent process; any other failure must not pass this check vacuously.
  try { state = execFileSync('ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8' }).trim(); }
  catch (error) { if (error.status !== 1) throw error; }
  assert.ok(!state || state.startsWith('Z'), `grandchild remains live: ${state}`);
});
test('a refused process-group signal still terminates the worker itself', async (t) => {
  const w = worker(t, '');
  const pidFile = join(w.dir, 'self');
  writeFileSync(join(w.dir, 'worker.mjs'), `import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setInterval(()=>{},1000);`);
  const original = process.kill;
  // Simulate a group that cannot be signalled (not yet formed, or refused): only that call fails.
  process.kill = (pid, signal) => {
    if (pid < 0) throw Object.assign(new Error('kill ESRCH'), { code: 'ESRCH' });
    return original.call(process, pid, signal);
  };
  let selfPid;
  // Uses the pid read during the test, not the file, which worker()'s cleanup may already have removed.
  t.after(() => { process.kill = original; reap(selfPid); });
  const started = performance.now();
  await assert.rejects(() => runNative(w.executable, '{}', { ...hooks(), timeoutMs: 5000 }), /native process refused/);
  process.kill = original;
  assert.ok(existsSync(pidFile), 'the worker started before its deadline');
  selfPid = Number(readFileSync(pidFile, 'utf8'));
  assert.equal(alive(selfPid), false, 'the worker survived its deadline');
  assert.ok(performance.now() - started < 9000, 'termination was observed, not assumed after the grace period');
});
// The worker leaves a descendant in its own process group, with ignored stdio so that `close`
// does not wait for it, and then ends as `body` says. `kill` may stub `process.kill` for the run.
async function descendantRun(t, body, { descendant: spawnDescendant = true, kill } = {}) {
  const w = worker(t, '');
  const pidFile = join(w.dir, 'descendant');
  writeFileSync(join(w.dir, 'worker.mjs'), `import {writeFileSync} from 'node:fs';import {spawn} from 'node:child_process';`
    + `${input}${emit}const PREPARED=${JSON.stringify(prepared)},RESULT=${JSON.stringify(result)};`
    + `const it=lines[Symbol.asyncIterator]();await it.next();`
    + (spawnDescendant ? `const d=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});d.unref();`
      + `writeFileSync(${JSON.stringify(pidFile)},String(d.pid));` : '') + body);
  let descendant;
  // Uses the pid read during the test, and kills it only if still alive, whatever the assertions do.
  t.after(() => { process.kill = realKill; reap(descendant); });
  if (kill) process.kill = kill;
  const run = runNative(w.executable, '{}', { ...hooks(), timeoutMs: 20000 });
  await run.catch(() => {});
  process.kill = realKill;
  if (spawnDescendant) {
    descendant = existsSync(pidFile) ? Number(readFileSync(pidFile, 'utf8')) : undefined;
    assert.ok(descendant, 'the worker started its descendant');
  }
  await assert.rejects(() => run, /native process refused/);
  for (let i = 0; i < 50 && descendant && alive(descendant); i++) await new Promise((resolve) => setTimeout(resolve, 20));
  return descendant;
}
const exits = {
  'a nonzero exit': `process.exit(3);`,
  'an incomplete protocol': `process.stdout.write(JSON.stringify(PREPARED)+'\\n',()=>process.exit(0));`,
  'a clean report': `emit(PREPARED);emit(RESULT);`,
};
for (const [ending, body] of Object.entries(exits)) {
  test(`${ending} with a surviving descendant is refused and the descendant is terminated`, async (t) => {
    assert.equal(alive(await descendantRun(t, body)), false, 'the descendant survived the refused run');
  });
}
test('a group member that escapes one group signal is signalled again before the run settles', async (t) => {
  let dropped = false;
  // The first group SIGKILL is lost, as for a member forking while the kernel snapshots the group.
  const kill = (pid, signal) => {
    if (pid < 0 && signal === 'SIGKILL' && !dropped) { dropped = true; return true; }
    return realKill.call(process, pid, signal);
  };
  const descendant = await descendantRun(t, exits['a nonzero exit'], { kill });
  assert.equal(dropped, true);
  assert.equal(alive(descendant), false, 'a single lost group signal left the descendant running');
});
test('a group already empty at close is probed but never signalled', async (t) => {
  const groupSignals = [];
  const kill = (pid, signal) => { if (pid < 0) groupSignals.push(signal); return realKill.call(process, pid, signal); };
  await descendantRun(t, exits['a nonzero exit'], { descendant: false, kill });
  assert.deepEqual(groupSignals, [0], 'an empty group ID may be reused, so it must not be signalled');
});
test('aborted execution and malformed initial job never start a worker', async (t) => {
  const w = worker(t, 'process.exit(0)');
  const signal = AbortSignal.abort();
  await assert.rejects(() => runNative(w.executable, '{}', { ...hooks(), signal }), /native process refused/);
  for (const text of ['{}\n{}', 'x', 'x'.repeat(16*1024*1024+1)]) {
    await assert.rejects(() => runNative(w.executable, text, hooks()), /native process refused/);
  }
});
