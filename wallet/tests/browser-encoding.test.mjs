import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import test from 'node:test';

test('canonical credential and challenge encodings work with the actual browser Buffer package', async () => {
  const require = createRequire(import.meta.url);
  const browserBuffer = pathToFileURL(require.resolve('buffer/')).href;
  const source = readFileSync(new URL('../shared/base64url.mjs', import.meta.url), 'utf8')
    .replace("from 'buffer'", `from '${browserBuffer}'`);
  const { encodeBase64Url, decodeBase64Url } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  const { Buffer: BrowserBuffer } = require('buffer/');
  const bytes = BrowserBuffer.from([251, 255, 1, 2, 3]);
  assert.equal(encodeBase64Url(bytes), '-_8BAgM');
  assert.deepEqual(Array.from(decodeBase64Url('-_8BAgM')), Array.from(bytes));
  assert.equal(encodeBase64Url(decodeBase64Url('AQ')), 'AQ');
  for (const input of ['', 'A', 'AR', 'AQ==', '+/8=', 'x'.repeat(1367)]) assert.throws(() => decodeBase64Url(input));
});
