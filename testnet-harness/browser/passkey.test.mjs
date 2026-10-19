// `passkey.mjs` exports a credential's private key through the DevTools Protocol, and Playwright's
// debug logs print DevTools traffic in full. The module must refuse to load when they could be on.
//
//   node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const load = (debug) => {
  const env = { ...process.env };
  delete env.DEBUG;
  if (debug !== undefined) env.DEBUG = debug;
  return spawnSync(process.execPath, ['--input-type=module', '-e', "await import('./passkey.mjs')"], {
    cwd: fileURLToPath(new URL('.', import.meta.url)), env, encoding: 'utf8',
  });
};

test('passkey.mjs refuses to load when DEBUG could print the private key', () => {
  for (const debug of ['pw:protocol', 'pw:channel', 'pw:*', '*', 'foo,pw:protocol']) {
    const run = load(debug);
    assert.notEqual(run.status, 0, `DEBUG=${debug} loaded`);
    assert.match(run.stderr, /private key/);
  }
});

test('passkey.mjs loads without DEBUG, and loading launches nothing', () => {
  const run = load(undefined);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout, '');
});
