// The harness's install approval end to end, offline: a fake check runner stands in for
// `ozpb prepare-install-intent` / `ozpb check-policy-call-surface`, and the real CLI seam is
// driven against a fake `ozpb` executable. The fixture is hand-written from the check's output
// types and its contract document, not captured from the tool.
//
//   node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { approveInstall, signedRuleArgs } from './approve-install.mjs';
import { ToolError, cliCheckRunner } from './check-runner.mjs';
import { addContextRuleArgs } from './lib.mjs';
import { TRUST_OPERATOR, walletTrust } from './wallet-decision.mjs';

const FIXTURE_PATH = fileURLToPath(new URL('./fixtures/authority/intent-passkey-owner.json', import.meta.url));
const FIXTURE = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
const PASSKEY = FIXTURE.authority.verdict.authority_list[0].requirement.signers[0].public_key;
const EXPECT = {
  account: FIXTURE.account_contract,
  networkId: FIXTURE.authority.verdict.network_id,
  target: FIXTURE.context_contract,
  boundPolicies: [FIXTURE.policies[0].address],
  ruleIndex: 0,
};
const trust = walletTrust({ own: [{ scheme: 'webauthn_p256', public_key: PASSKEY }] });
const REQUEST = { account_address: EXPECT.account, rule_index: 0 };

/** A runner that answers from fixtures, and records what it was asked. */
function fakeRunner({ intent = structuredClone(FIXTURE), fresh = structuredClone(FIXTURE.authority), intentError, checkError } = {}) {
  const calls = [];
  return {
    calls,
    async prepareInstallIntent(request) {
      calls.push(['prepare-install-intent', request]);
      if (intentError) throw intentError;
      return intent;
    },
    async checkPolicyCallSurface(request) {
      calls.push(['check-policy-call-surface', request]);
      if (checkError) throw checkError;
      return fresh;
    },
  };
}
const quiet = () => {};
const yes = async () => true;

test('approves: intent, decision, confirmation, a fresh re-check with the same commitment', async () => {
  const runner = fakeRunner();
  const screens = [];
  const r = await approveInstall({ runner, request: REQUEST, trust, expect: EXPECT, confirm: async (s) => { screens.push(s); return true; }, log: quiet });
  assert.equal(r.approved, true, r.reasons?.join('; '));
  assert.deepEqual(runner.calls.map((c) => c[0]), ['prepare-install-intent', 'check-policy-call-surface']);
  // The same request both times: the re-check is the same question, asked again.
  assert.equal(runner.calls[0][1], REQUEST);
  assert.equal(runner.calls[1][1], REQUEST);
  assert.equal(screens.length, 1);
  assert.equal(r.commitment, FIXTURE.authority.verdict.authority_commitment);
  assert.deepEqual(r.args, {
    account: FIXTURE.account_contract, context: FIXTURE.context_contract, name: FIXTURE.rule_name,
    validUntil: FIXTURE.valid_until_ledger, signers: FIXTURE.delegate_signers, policies: FIXTURE.policies,
  });
  assert.equal(r.evidence.trust_basis, TRUST_OPERATOR);
});

test('a tool error is a refusal: its findings are shown, and nothing is asked or re-checked', async () => {
  for (const [code, message, details] of [
    ['E_DELEGATE_HAS_AUTHORITY', 'E_DELEGATE_HAS_AUTHORITY: the authority check did not clear this install; there is nothing to sign',
      ['E_DELEGATE_HAS_AUTHORITY (rule 2): the agent can manage the account Fix: remove it']],
    // Refused by the tool's own guards before any read, with no findings: a grant aimed at the
    // account itself, or at its own policy.
    ['E_UNSAFE_MANAGEMENT_SURFACE', 'E_UNSAFE_MANAGEMENT_SURFACE: the new rule targets the account itself, so it would let the agent call the account\'s management methods', []],
    ['E_UNSAFE_CALL_SURFACE', 'E_UNSAFE_CALL_SURFACE: the new rule targets a policy bound for this spec, so the agent could reset or uninstall it', []],
  ]) {
    const runner = fakeRunner({ intentError: new ToolError(code, message, details) });
    let asked = false;
    const shown = [];
    const r = await approveInstall({ runner, request: REQUEST, trust, expect: EXPECT, confirm: async () => { asked = true; return true; }, log: (s) => shown.push(s) });
    assert.equal(r.approved, false);
    assert.match(r.reasons.join('\n'), new RegExp(code));
    for (const line of [message, ...details]) assert.ok(shown.join('\n').includes(line), `shown: ${line}`);
    assert.equal(asked, false);
    assert.equal(runner.calls.length, 1);
  }
});

test('an intent whose arguments are not the checked grant is refused before anyone is asked', async () => {
  const intent = structuredClone(FIXTURE);
  intent.rule_name = 'something-else';
  let asked = false;
  const r = await approveInstall({ runner: fakeRunner({ intent }), request: REQUEST, trust, expect: EXPECT, confirm: async () => { asked = true; return true; }, log: quiet });
  assert.equal(r.approved, false);
  assert.match(r.reasons.join('\n'), /rule_name/);
  assert.equal(asked, false);
});

test('an untrusted owner is refused, and the screen is still shown', async () => {
  const intent = structuredClone(FIXTURE);
  intent.authority.verdict.authority_list[0].requirement.signers[0].public_key = `04${'ab'.repeat(64)}`;
  const screens = [];
  const r = await approveInstall({ runner: fakeRunner({ intent }), request: REQUEST, trust, expect: EXPECT, confirm: yes, log: (s) => screens.push(s) });
  assert.equal(r.approved, false);
  assert.ok(screens.some((s) => /REFUSED/.test(s)));
});

test('the operator declining stops it before the re-check', async () => {
  const runner = fakeRunner();
  const r = await approveInstall({ runner, request: REQUEST, trust, expect: EXPECT, confirm: async () => false, log: quiet });
  assert.equal(r.approved, false);
  assert.match(r.reasons.join('\n'), /declined/);
  assert.equal(runner.calls.length, 1);
});

test('a re-check that reads a different authority state means asking again', async () => {
  const fresh = structuredClone(FIXTURE.authority);
  fresh.verdict.authority_commitment = '99'.repeat(32);
  const r = await approveInstall({ runner: fakeRunner({ fresh }), request: REQUEST, trust, expect: EXPECT, confirm: yes, log: quiet });
  assert.equal(r.approved, false);
  assert.match(r.reasons.join('\n'), /ask again/i);
});

test('a re-check whose grant differs from the intent is refused, even under the same commitment', async () => {
  // The intent's first instruction: its arguments must equal the grant the wallet's own re-run
  // reports. The wallet cannot recompute the commitment, so it compares the grant itself.
  const fresh = structuredClone(FIXTURE.authority);
  fresh.verdict.grant.name = 'renamed';
  const r = await approveInstall({ runner: fakeRunner({ fresh }), request: REQUEST, trust, expect: EXPECT, confirm: yes, log: quiet });
  assert.equal(r.approved, false);
  assert.match(r.reasons.join('\n'), /rule_name/);
});

test('a re-check that reads an older ledger than the approval is refused', async () => {
  const fresh = structuredClone(FIXTURE.authority);
  fresh.verdict.observed_ledger -= 1;
  const r = await approveInstall({ runner: fakeRunner({ fresh }), request: REQUEST, trust, expect: EXPECT, confirm: yes, log: quiet });
  assert.equal(r.approved, false);
  assert.match(r.reasons.join('\n'), /older/);
});

test('a grant that has expired by the re-check is refused, though the commitment is unchanged', async () => {
  const fresh = structuredClone(FIXTURE.authority);
  fresh.verdict.observed_ledger = FIXTURE.valid_until_ledger;
  const r = await approveInstall({ runner: fakeRunner({ fresh }), request: REQUEST, trust, expect: EXPECT, confirm: yes, log: quiet });
  assert.equal(r.approved, false);
  assert.match(r.reasons.join('\n'), /expire/);
});

test('a re-check that cannot answer is a refusal', async () => {
  const r = await approveInstall({
    runner: fakeRunner({ checkError: new ToolError('E_RPC', 'E_RPC') }), request: REQUEST, trust, expect: EXPECT, confirm: yes, log: quiet,
  });
  assert.equal(r.approved, false);
  assert.match(r.reasons.join('\n'), /E_RPC/);
});

// --- the CLI seam ------------------------------------------------------------------------------

const FAKE_OZPB = fileURLToPath(new URL('./fixtures/authority/fake-ozpb.mjs', import.meta.url));
const cli = (mode, build) => cliCheckRunner({
  command: [process.execPath, FAKE_OZPB],
  registryRoots: '/roots.json', registryMinVersion: 3, rpcSources: '/sources.json', build,
  env: { FAKE_OZPB_MODE: mode, FAKE_OZPB_FIXTURE: FIXTURE_PATH },
});

test('the CLI runner passes the request by file with the operator\'s configuration, and parses the answer', async () => {
  const intent = await cli('ok').prepareInstallIntent(REQUEST);
  // The fake echoes the argv it got and the request it read into `next_steps`.
  const [argv, request] = intent.next_steps.map((s) => JSON.parse(s));
  assert.equal(argv[0], 'prepare-install-intent');
  assert.deepEqual(argv.slice(1).filter((a, i) => i % 2 === 0), ['--request', '--registry-roots', '--registry-min-version', '--rpc-sources']);
  assert.deepEqual([argv[4], argv[6], argv[8]], ['/roots.json', '3', '/sources.json']);
  assert.deepEqual(request, REQUEST);
  const checked = await cli('ok').checkPolicyCallSurface(REQUEST);
  assert.equal(checked.verdict.authority_commitment, FIXTURE.authority.verdict.authority_commitment);
});

test('the CLI runner passes the build settings the check needs to reproduce the policy', async () => {
  const build = { stellarBinary: '/opt/stellar', cacheDir: '/cache', jobs: 2, timeoutSecs: 900 };
  const [argv] = (await cli('ok', build).prepareInstallIntent(REQUEST)).next_steps.map((s) => JSON.parse(s));
  const flag = (name) => argv[argv.indexOf(name) + 1];
  assert.deepEqual([flag('--stellar-binary'), flag('--build-cache-dir'), flag('--build-jobs'), flag('--build-timeout-secs')],
    ['/opt/stellar', '/cache', '2', '900']);
  const [bare] = (await cli('ok').prepareInstallIntent(REQUEST)).next_steps.map((s) => JSON.parse(s));
  assert.ok(!bare.some((a) => a.startsWith('--build') || a === '--stellar-binary'), 'unset settings are not passed');
});

test('a non-zero exit becomes a ToolError carrying the E_ code, never an answer', async () => {
  await assert.rejects(cli('refuse').prepareInstallIntent(REQUEST), (e) => e instanceof ToolError
    && e.code === 'E_DELEGATE_HAS_AUTHORITY'
    && e.details.length === 2 && e.details[1].startsWith('E_UNSUPPORTED_AUTHORITY (rule 2) [classic_multisig]'));
  await assert.rejects(cli('unsafe').prepareInstallIntent(REQUEST), (e) => e instanceof ToolError
    && e.code === 'E_UNSAFE_MANAGEMENT_SURFACE' && e.details.length === 0 && /targets the account itself/.test(e.message));
  // Only the first line's leading code counts: an E_-looking word deeper in a parse error is not one.
  await assert.rejects(cli('parse').prepareInstallIntent(REQUEST), (e) => e instanceof ToolError && e.code === 'E_TOOL_FAILED');
  await assert.rejects(cli('usage').checkPolicyCallSurface(REQUEST), (e) => e instanceof ToolError && e.code === 'E_TOOL_FAILED');
  await assert.rejects(cli('crash').checkPolicyCallSurface(REQUEST), (e) => e instanceof ToolError && e.code === 'E_TOOL_FAILED');
  // Exit 0 with output that is not JSON is not an answer either.
  await assert.rejects(cli('garbage').checkPolicyCallSurface(REQUEST), (e) => e instanceof ToolError && e.code === 'E_TOOL_OUTPUT');
});

// --- what install.mjs signs ------------------------------------------------------------------------

const fromSpec = () => ({
  context: FIXTURE.context_contract, name: FIXTURE.rule_name, validUntil: FIXTURE.valid_until_ledger,
  signers: [{ kind: 'delegated', address: FIXTURE.delegate_signers[0].address }],
  policies: [{ address: FIXTURE.policies[0].address, install_params: { kind: 'generated' } }],
});

test('the signed arguments are the approved intent\'s, and only when they equal the spec\'s rule', async () => {
  const r = await approveInstall({ runner: fakeRunner(), request: REQUEST, trust, expect: EXPECT, confirm: yes, log: quiet });
  const args = signedRuleArgs({ approved: r.args, fromSpec: fromSpec(), account: EXPECT.account });
  const hexes = (a) => a.map((v) => Buffer.from(v.toXDR()).toString('hex'));
  assert.deepEqual(hexes(args), hexes(addContextRuleArgs(fromSpec())));
  for (const [field, change] of [
    ['name', (s) => { s.name = 'other'; }],
    ['expiry', (s) => { s.validUntil += 1; }],
    ['signer', (s) => { s.signers[0].address = 'GDS6LZPF4XS6LZPF4XS6LZPF4XS6LZPF4XS6LZPF4XS6LZPF4XS6LGS2'; }],
    ['policy', (s) => { s.policies[0].address = 'CCZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HODI'; }],
  ]) {
    const spec = fromSpec();
    change(spec);
    assert.throws(() => signedRuleArgs({ approved: r.args, fromSpec: spec, account: EXPECT.account }), /not the rule this spec/, field);
  }
  assert.throws(() => signedRuleArgs({ approved: r.args, fromSpec: fromSpec(), account: 'CCZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HM5TWOZ3HODI' }), /another account/);
});
