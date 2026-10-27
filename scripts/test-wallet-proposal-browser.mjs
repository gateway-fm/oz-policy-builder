// Exercise the real applied route with a synthetic backend. No RPC or signing is performed.
import assert from 'node:assert/strict';
import { chromium } from '../testnet-harness/browser/node_modules/playwright/index.mjs';
import { proposalFixture } from '../wallet/tests/proposal-fixture.mjs';
import { checkProposalArtifact, parseGrantProposal } from '../wallet/shared/proposal.mjs';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM } from '../wallet/shared/approval.mjs';

const origin = process.argv[2] ?? 'http://localhost:3000';
if (!/^http:\/\/localhost:[0-9]{1,5}$/.test(origin)) throw new Error('Expected a localhost UI origin');
const channel = process.env.OZPB_BROWSER_CHANNEL;
if (channel && !['chrome', 'chromium'].includes(channel)) throw new Error('Unsupported browser channel');
const f = proposalFixture(), calls = [];
let corrupt = false;
const browser = await chromium.launch({ headless: true, args: ['--host-resolver-rules=MAP localhost 127.0.0.1'],
  ...(channel ? { channel } : {}) });
try {
  const page = await browser.newPage();
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== origin) return route.abort();
    if (!url.pathname.startsWith('/api/policy-builder/')) return route.continue();
    const name = url.pathname.split('/').at(-1);
    calls.push(name);
    assert.equal(request.method(), 'POST');
    let body;
    if (name === 'status') body = { network: 'testnet', networkId: NETWORK_ID, accountWasm: ACCOUNT_WASM,
      verifierWasm: WEBAUTHN_WASM, capabilities: { importProposal: true, deploy: true } };
    else {
      assert.equal(name, 'import-proposal', 'import must not deploy, submit or request signing');
      const input = request.postDataJSON();
      assert.deepEqual(input.wallet, f.wallet);
      const proposal = parseGrantProposal(input.proposal, f.wallet.contractId);
      const artifact = structuredClone(f.artifact);
      const proposalReview = checkProposalArtifact(proposal, artifact);
      if (corrupt) artifact.spec.rules[0].allowed_calls[0].args[2].c.eq_i128.value = '2000000';
      body = { record: f.record, artifact, proposalReview };
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto(`${origin}/policy-builder#session=${'a'.repeat(64)}`);
  await page.getByRole('status').filter({ hasText: 'Connected' }).waitFor();
  await page.getByText('Attach an existing recognized wallet', { exact: true }).click();
  await page.locator('#wallet-locator').fill(JSON.stringify(f.wallet));
  await page.getByRole('button', { name: 'Use this wallet locator', exact: true }).click();
  await page.getByText('Import a grant proposal', { exact: true }).click();
  const paste = page.locator('#proposal-json'), submit = page.getByRole('button', { name: 'Import and verify proposal', exact: true });
  const deploy = page.getByRole('button', { name: 'Preview deployment', exact: true });

  await paste.fill('{}'); await submit.click();
  await page.getByRole('status').filter({ hasText: 'Action refused' }).waitFor();
  assert.deepEqual(calls, ['status']);
  await paste.fill(JSON.stringify(f.proposal)); await submit.click();
  await page.getByText('The regenerated permissions match the proposal. Review the grant below.', { exact: true }).waitFor();
  assert.equal(await deploy.isEnabled(), true);
  assert.equal(await page.getByText(f.proposal.spec_hash, { exact: true }).count(), 1);

  corrupt = true;
  await submit.click();
  await page.getByRole('status').filter({ hasText: 'Action refused' }).waitFor();
  assert.equal(await deploy.isDisabled(), true, 'a rejected retry clears the earlier artifact');
  assert.equal(await page.getByText('The regenerated permissions match the proposal. Review the grant below.', { exact: true }).count(), 0);

  corrupt = false;
  await page.locator('#proposal-file').setInputFiles({ name: 'proposal.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(f.proposal)) });
  await page.waitForFunction(text => document.querySelector('#proposal-json')?.value === text, JSON.stringify(f.proposal));
  await submit.click();
  await page.getByText('The regenerated permissions match the proposal. Review the grant below.', { exact: true }).waitFor();
  await page.locator('#proposal-file').setInputFiles({ name: 'large.json', mimeType: 'application/json', buffer: Buffer.alloc(16 * 1024 + 1) });
  await page.getByRole('status').filter({ hasText: 'exceeds 16 KiB' }).waitFor();
  assert.equal(await paste.inputValue(), '');
  assert.deepEqual(calls, ['status', 'import-proposal', 'import-proposal', 'import-proposal']);
  console.log('Proposal UI: paste/file imports, malformed input, changed grants, retry invalidation and size limits pass. Synthetic backend; no chain or signing claim.');
} finally { await browser.close(); }
