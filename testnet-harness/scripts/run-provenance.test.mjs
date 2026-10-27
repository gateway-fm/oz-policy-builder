import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('a clean checkout starts provenance before npm dependencies are installed', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'ozpb-clean-start-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const scripts = join(root, 'testnet-harness', 'scripts');
  cpSync(fileURLToPath(new URL('.', import.meta.url)), scripts, {
    recursive: true, filter: (path) => !path.split(sep).includes('node_modules'),
  });
  execFileSync('git', ['init', '-q', root]);
  execFileSync('git', ['-C', root, '-c', 'user.name=Harness test', '-c', 'user.email=harness@example.invalid',
    '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '--allow-empty', '-qm', 'fixture']);
  const run = join(root, 'run');
  mkdirSync(run);
  const env = { ...process.env };
  delete env.OZPB_BIN;
  const result = spawnSync(process.execPath, [join(scripts, 'run-provenance.mjs'), 'start', run], { env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(join(run, 'provenance.json'), 'utf8')).cli.mode, 'cargo');
});
