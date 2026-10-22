import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// The cleanup children's stderr is kept in cleanup-child.log. A failure prints one redacted line:
// no stack trace, and no value from the run's secrets file, even when the error message quotes it.
for (const [script, args, prefix] of [
  ['bundle-command.mjs', ['cleanup'], 'bundle cleanup failed'],
  ['lifecycle.mjs', [], 'lifecycle removal failed'],
]) {
  test(`${script} reports a cleanup failure as one redacted line`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), 'ozpb-cli-redaction-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    // The run directory's name doubles as a "secret", so the ENOENT message quotes it.
    const secret = 'secretvalue' + 'x'.repeat(24);
    const runDir = join(dir, secret);
    mkdirSync(runDir);
    writeFileSync(join(dir, 'keys.json'), JSON.stringify({ payer: secret }));
    const result = spawnSync(process.execPath, [fileURLToPath(new URL(`./${script}`, import.meta.url)), ...args, '--run-dir', runDir],
      { encoding: 'utf8', env: { ...process.env, OZPB_HARNESS_SECRETS: join(dir, 'keys.json') }, timeout: 20000 });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, new RegExp(prefix));
    assert.match(result.stderr, /<redacted>/);
    assert.ok(!result.stderr.includes(secret), result.stderr);
    assert.doesNotMatch(result.stderr, /^\s+at /m, 'no stack trace');
  });
}
