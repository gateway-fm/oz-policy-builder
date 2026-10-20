import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { accessSync, chmodSync, constants, existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

import { exportEvidence } from './evidence.mjs';
import { finishRun, startRun } from './run-provenance.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCRIPT = fileURLToPath(new URL('./evidence.mjs', import.meta.url));
const C = 'C' + 'A'.repeat(55);
const G = 'G' + 'B'.repeat(55);
const HASH = 'ab'.repeat(32);
const wasm = Buffer.from('test-only Wasm bytes');
const wasmHash = createHash('sha256').update(wasm).digest('hex');
const SENTINEL = 'confidential-value-must-never-appear';

function fixture() {
  return {
    network: 'Test SDF Network ; September 2015', protocol: 29,
    rpc: `https://user:${SENTINEL}@rpc.invalid/${SENTINEL}?key=${SENTINEL}`,
    account: C, account_code_hash: HASH, sac: C, owner: { kind: 'ed25519', address: G, secret: SENTINEL },
    delegate: G, recipient: G, amount: '10000000', policy: C, policy_wasm_hash: wasmHash, rule_id: 1,
    spec: `/local/${SENTINEL}/spec.json`, secret: SENTINEL,
    tx: { deploy_account: HASH, add_context_rule: HASH, [SENTINEL]: SENTINEL },
    invocations: [
      { signer: 'delegate', rule: 1, amount: '10000000', to: G, result: 'permit', hash: HASH, label: SENTINEL },
      { signer: 'delegate', rule: 1, amount: '10000001', to: G, result: 'deny', code: 6, enforcer: C, host: SENTINEL },
    ],
  };
}

function setup(t, record = fixture()) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-evidence-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  if (record !== null) writeFileSync(join(dir, 'run.json'), JSON.stringify(record));
  return dir;
}

test('selects public observations and labels transactions separately from simulation denials', (t) => {
  const dir = setup(t);
  mkdirSync(join(dir, 'policy'));
  writeFileSync(join(dir, 'policy', `${SENTINEL}.wasm`), wasm);
  writeFileSync(join(dir, 'spec.json'), '{"private_note":"' + SENTINEL + '"}');
  const report = exportEvidence(dir);
  assert.equal(report.provenance.status, 'unavailable');
  assert.equal(report.run.installation, 'recorded');
  assert.equal(report.run.invocations[0].observation, 'submitted_transaction');
  assert.equal(report.run.invocations[1].observation, 'enforcing_simulation');
  assert.equal(report.run.invocations[1].transaction, null);
  assert.equal(report.artifacts.policy_wasm.sha256, wasmHash);
  assert.equal(report.artifacts.spec.sha256, createHash('sha256').update(readFileSync(join(dir, 'spec.json'))).digest('hex'));
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
  assert.ok(!JSON.stringify(report).includes(dir));
});

test('exports unresolved removal and failure cleanup without claiming revocation', (t) => {
  const run = fixture();
  run.lifecycle = { removals: [], pending_removal: { rule_id: 1, transaction: HASH, status: 'prepared_for_submission', secret: SENTINEL } };
  run.failure_cleanup = { status: 'incomplete', reason: 'removal_already_recorded', network: run.network,
    account: C, account_code_hash: HASH, rule_id: 1, installation: HASH,
    policy: C, policy_wasm_hash: wasmHash, subscription: null, secret: SENTINEL };
  const report = exportEvidence(setup(t, run));
  assert.equal(report.lifecycle.pending_removal.transaction, HASH);
  assert.equal(report.failure_cleanup.status, 'incomplete');
  assert.equal(report.failure_cleanup.reason, 'removal_already_recorded');
  assert.equal(report.failure_cleanup.transaction, null);
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('exports a recorded synthesis and reproduction chain without upgrading its evidence trust', (t) => {
  const run = fixture();
  run.invocations.push({ signer: 'owner', rule: 0, result: 'permit', hash: HASH, amount: run.amount, to: run.recipient });
  const dir = setup(t, run);
  writeFileSync(join(dir, 'pipeline.json'), JSON.stringify({
    schema_version: 1, account: C, recorded_transaction: HASH, recording_hash: HASH,
    acquisition_trust: 'rpc_reported', synthesis_recording_hash: HASH, synthesis_trust: 'self_supplied',
    spec_hash: HASH, normalized_input_hash: HASH, reference_cases: 20,
    artifact_reproduction: 'matched', current_network_preflight: 'not_checked_here', private_note: SENTINEL,
  }));
  const report = exportEvidence(dir);
  assert.equal(report.pipeline.status, 'recorded');
  assert.equal(report.pipeline.synthesis_trust, 'self_supplied');
  assert.equal(report.pipeline.current_network_preflight, 'not_checked_here');
  assert.ok(report.artifacts.pipeline);
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('old runs do not acquire synthesized or verified status', (t) => {
  assert.deepEqual(exportEvidence(setup(t)).pipeline, { status: 'not_recorded' });
});

test('exports confirmed removal separately from installation and best-effort policy cleanup', (t) => {
  const run = fixture();
  run.lifecycle = { removals: [{ rule_id: 1, transaction: HASH, ledger: 20,
    event: 'verified', rule_readback: 'absent', policy_cleanup: 'still_installed', secret: SENTINEL }],
  configuration_checks: [{ configuration: 'matched', observation: 'non_atomic',
    read_ledgers: { account_code: 17, policy_code: 18, rule: 19 }, rule_id: 1,
    account_code_hash: HASH, policy_code_hash: wasmHash, private_note: SENTINEL }] };
  run.invocations.push({ signer: 'delegate', rule: 1, amount: run.amount, to: run.recipient,
    result: 'deny', code: 3000, enforcer: run.account, control: 'post_revocation' });
  const report = exportEvidence(setup(t, run));
  assert.equal(report.run.installation, 'recorded');
  assert.equal(report.lifecycle.removals[0].policy_cleanup, 'still_installed');
  assert.equal(report.lifecycle.removals[0].rule_readback, 'absent');
  assert.equal(report.run.invocations.at(-1).control, 'post_revocation');
  assert.equal(report.lifecycle.configuration_checks[0].configuration, 'matched');
  assert.deepEqual(report.lifecycle.configuration_checks[0].read_ledgers, { account_code: 17, policy_code: 18, rule: 19 });
  assert.equal(Object.hasOwn(report.lifecycle.configuration_checks[0], 'ledger'), false);
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
  run.lifecycle.configuration_checks[0].ledger = 19;
  assert.throws(() => exportEvidence(setup(t, run)), 'a synthetic common ledger is refused');
});

test('retains incomplete removal observations but rejects contradictory cleanup states', (t) => {
  const run = fixture();
  run.lifecycle = { removals: [{ rule_id: 1, transaction: HASH, ledger: 20,
    event: 'not_verified', rule_readback: 'not_checked', policy_cleanup: 'not_checked' }] };
  const dir = setup(t, run);
  assert.equal(exportEvidence(dir).lifecycle.removals[0].event, 'not_verified');
  run.lifecycle.removals[0].policy_cleanup = 'not_installed';
  writeFileSync(join(dir, 'run.json'), JSON.stringify(run));
  assert.throws(() => exportEvidence(dir));
});

test('subscription summary preserves known coverage gap, actual controls and separate reviewed cleanup', (t) => {
  const run = fixture(); run.payer = G;
  run.subscription = { schema_version: 1, mode: 'short_test_window', period_ledgers: 12,
    policy_address: C, policy_code_hash: HASH, other_token: C, installation_readback: 'matched',
    controls: { status: 'incomplete', steps: [{ name: 'early_repeat', result: 'inconclusive_window_elapsed',
      ledger: 112, before_ledger: 112, token: run.sac, to: run.recipient, amount: run.amount, signer: 'delegate',
      enforcer: C, code: 3221, private_note: SENTINEL }] } };
  run.lifecycle = { removals: [{ rule_id: 1, transaction: HASH, ledger: 120,
    event: 'verified', rule_readback: 'absent', policy_cleanup: 'not_installed', reviewed_policy_cleanup: 'still_installed' }] };
  run.invocations.push({ signer: 'owner', rule: 0, result: 'permit', hash: HASH, amount: run.amount, to: run.recipient });
  const dir = setup(t, run);
  const pipeline = { schema_version: 1, account: run.account, recorded_transaction: HASH,
    recording_hash: HASH, acquisition_trust: 'rpc_reported', synthesis_recording_hash: HASH,
    synthesis_trust: 'self_supplied', spec_hash: HASH, normalized_input_hash: HASH,
    reference_cases: 30, artifact_reproduction: 'matched', current_network_preflight: 'not_checked_here',
    models_all_policies: false, unmodeled_reviewed_policies: ['rule[0]: oz:spending_limit'] };
  writeFileSync(join(dir, 'pipeline.json'), JSON.stringify(pipeline));
  const report = exportEvidence(dir);
  assert.equal(report.pipeline.models_all_policies, false);
  assert.equal(report.run.subscription.controls.steps[0].result, 'inconclusive_window_elapsed');
  assert.equal(report.lifecycle.removals[0].reviewed_policy_cleanup, 'still_installed');
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
  pipeline.models_all_policies = true;
  writeFileSync(join(dir, 'pipeline.json'), JSON.stringify(pipeline));
  assert.throws(() => exportEvidence(dir), 'cannot upgrade the known missing model');
  pipeline.models_all_policies = false;
  writeFileSync(join(dir, 'pipeline.json'), JSON.stringify(pipeline));
  run.subscription.controls.steps[0].result = 'verified_denial';
  writeFileSync(join(dir, 'run.json'), JSON.stringify(run));
  assert.throws(() => exportEvidence(dir), 'late repeat cannot be a verified window denial');
});

test('refuses a pipeline claiming stronger synthesis trust or a different account', (t) => {
  const run = fixture();
  run.invocations.push({ signer: 'owner', rule: 0, result: 'permit', hash: HASH, amount: run.amount, to: run.recipient });
  const dir = setup(t, run);
  const path = join(dir, 'pipeline.json');
  const p = { schema_version: 1, account: C, recorded_transaction: HASH, recording_hash: HASH,
    acquisition_trust: 'rpc_reported', synthesis_recording_hash: HASH, synthesis_trust: 'rpc_reported',
    spec_hash: HASH, normalized_input_hash: HASH, reference_cases: 20,
    artifact_reproduction: 'matched', current_network_preflight: 'not_checked_here' };
  writeFileSync(path, JSON.stringify(p));
  assert.throws(() => exportEvidence(dir));
  p.synthesis_trust = 'self_supplied'; p.account = G;
  writeFileSync(path, JSON.stringify(p));
  assert.throws(() => exportEvidence(dir));
});

test('refuses a pipeline transaction absent from, or duplicated in, the owner transfer records', (t) => {
  const run = fixture();
  run.invocations.push({ signer: 'owner', rule: 0, result: 'permit', hash: HASH, amount: run.amount, to: run.recipient });
  const dir = setup(t, run);
  const p = { schema_version: 1, account: C, recorded_transaction: 'cd'.repeat(32), recording_hash: HASH,
    acquisition_trust: 'rpc_reported', synthesis_recording_hash: HASH, synthesis_trust: 'self_supplied',
    spec_hash: HASH, normalized_input_hash: HASH, reference_cases: 20,
    artifact_reproduction: 'matched', current_network_preflight: 'not_checked_here' };
  writeFileSync(join(dir, 'pipeline.json'), JSON.stringify(p));
  assert.throws(() => exportEvidence(dir));
  p.recorded_transaction = HASH;
  writeFileSync(join(dir, 'pipeline.json'), JSON.stringify(p));
  assert.equal(exportEvidence(dir).pipeline.status, 'recorded');
  run.invocations.push({ ...run.invocations.at(-1) });
  writeFileSync(join(dir, 'run.json'), JSON.stringify(run));
  assert.throws(() => exportEvidence(dir));
});

test('a refused run retains deployment evidence without claiming installation or exposing reasons', (t) => {
  const run = fixture();
  delete run.rule_id;
  delete run.tx.add_context_rule;
  run.tx.upload_policy = HASH;
  run.tx.create_policy = HASH;
  run.authority_check = { refused: [SENTINEL], operator_trust: { secret: SENTINEL } };
  const report = exportEvidence(setup(t, run));
  assert.equal(report.run.policy, C);
  assert.equal(report.run.transactions.create_policy, HASH);
  assert.equal(report.run.installation, 'not_recorded');
  assert.deepEqual(report.run.authority, { status: 'refused', reason_count: 1 });
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('passkey and accepted authority records omit credential data and operator trust', (t) => {
  const run = fixture();
  run.owner = { kind: 'passkey', verifier: C, verifier_code_hash: HASH, credential_id: SENTINEL, key_data: SENTINEL, public_key: SENTINEL };
  run.authority_check = { authority_commitment: HASH, checked_at_ledger: 1, rechecked_at_ledger: 2, accepted_entries: [SENTINEL] };
  const report = exportEvidence(setup(t, run));
  assert.equal(report.run.authority.status, 'rechecked');
  assert.equal(report.run.authority.rechecked_at_ledger, 2);
  assert.equal(report.run.owner.kind, 'passkey');
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

const invalid = {
  'another network': (r) => { r.network = 'Public Global Stellar Network ; September 2015'; },
  'seed in an address field': (r) => { r.delegate = 'S' + 'A'.repeat(55); },
  'free text in a transaction': (r) => { r.tx.add_context_rule = SENTINEL; },
  'free text in amount': (r) => { r.amount = SENTINEL; },
  'lossy rule number': (r) => { r.rule_id = 2 ** 53; },
  'i128 overflow': (r) => { r.amount = (1n << 127n).toString(); },
  'rule without install transaction': (r) => { delete r.tx.add_context_rule; },
  'transaction without rule': (r) => { delete r.rule_id; },
  'install without policy': (r) => { delete r.policy; delete r.policy_wasm_hash; },
  'simulation with a transaction hash': (r) => { r.invocations[1].hash = HASH; },
  'permit without a transaction hash': (r) => { delete r.invocations[0].hash; },
  'permit with a denial code': (r) => { r.invocations[0].code = 6; },
  'refusal with installed rule': (r) => { r.authority_check = { refused: ['refused'] }; },
  'older authority recheck': (r) => { r.authority_check = { authority_commitment: HASH, checked_at_ledger: 5, rechecked_at_ledger: 4 }; },
};
for (const [name, mutate] of Object.entries(invalid)) {
  test(`refuses ${name}`, (t) => {
    const run = fixture();
    mutate(run);
    assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
  });
}

test('does not turn an unrelated simulation error into a policy denial', (t) => {
  const run = fixture();
  run.invocations[1].code = null;
  run.invocations[1].enforcer = null;
  const report = exportEvidence(setup(t, run));
  assert.equal(report.run.invocations[1].code, null);
  assert.equal(report.run.invocations[1].enforcer, null);
});

test('artifact identity changes when bytes change and refuses a mismatched deployed Wasm', (t) => {
  const dir = setup(t);
  writeFileSync(join(dir, 'spec.json'), '{}');
  const original = exportEvidence(dir).artifacts.spec.sha256;
  writeFileSync(join(dir, 'spec.json'), '{ }');
  assert.notEqual(exportEvidence(dir).artifacts.spec.sha256, original);
  mkdirSync(join(dir, 'policy'));
  writeFileSync(join(dir, 'policy', 'policy.wasm'), 'different artifact');
  assert.throws(() => exportEvidence(dir), /invalid or inconsistent/);
});

test('refuses symlinks and ambiguous Wasm files instead of following outside artifacts', (t) => {
  const dir = setup(t);
  const outside = setup(t, null);
  writeFileSync(join(outside, 'secret'), SENTINEL);
  symlinkSync(join(outside, 'secret'), join(dir, 'spec.json'));
  assert.throws(() => exportEvidence(dir));
  rmSync(join(dir, 'spec.json'));
  symlinkSync(outside, join(dir, 'policy'));
  assert.throws(() => exportEvidence(dir));
  rmSync(join(dir, 'policy'));
  mkdirSync(join(dir, 'policy'));
  writeFileSync(join(dir, 'policy', 'one.wasm'), wasm);
  writeFileSync(join(dir, 'policy', 'two.wasm'), wasm);
  assert.throws(() => exportEvidence(dir));
});

test('CLI suppresses raw parse errors, file paths and partial output', (t) => {
  const dir = setup(t);
  writeFileSync(join(dir, 'run.json'), SENTINEL);
  const result = spawnSync(process.execPath, [SCRIPT, '--run-dir', dir], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.ok(!result.stderr.includes(SENTINEL));
  assert.ok(!result.stderr.includes(dir));
});

test('JSON null in an existing evidence file is malformed, not missing evidence', (t) => {
  for (const file of ['run.json', 'provenance.json']) {
    const dir = setup(t, null);
    startRun(dir, {});
    writeFileSync(join(dir, 'run.json'), JSON.stringify(fixture()));
    writeFileSync(join(dir, file), 'null');
    assert.throws(() => exportEvidence(dir), /invalid or inconsistent/);
  }
});

test('an explicit null invocation list is malformed', (t) => {
  const run = fixture();
  run.invocations = null;
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});

// Run the actual wrapper's EXIT handler without executing its live testnet steps.
function exitHandler(dir, code = 0, prelude = '', secrets = '') {
  const script = readFileSync(join(ROOT, 'testnet-harness/run.sh'), 'utf8');
  const start = script.indexOf('finish_run() {');
  const end = script.indexOf('trap finish_run EXIT', start) + 'trap finish_run EXIT'.length;
  assert.ok(start >= 0 && end > start);
  return spawnSync('bash', ['-c', `set -euo pipefail\n${prelude}\n${script.slice(start, end)}\nexit "$HARNESS_TEST_EXIT"\n`], {
    env: { ...process.env, RUN: dir, SCRIPTS: join(ROOT, 'testnet-harness/scripts'), SECRETS: secrets, HARNESS_TEST_EXIT: String(code) },
    encoding: 'utf8', timeout: 20000,
  });
}

for (const failure of ['invalid record', 'unwritable output']) {
  test(`actual exit handler records a reporting failure after successful steps: ${failure}`, (t) => {
    const dir = setup(t, null);
    startRun(dir, {});
    writeFileSync(join(dir, 'run.json'), failure === 'invalid record' ? 'invalid-json' : JSON.stringify(fixture()));
    if (failure === 'unwritable output') mkdirSync(join(dir, 'evidence.json'));
    const result = exitHandler(dir);
    assert.equal(result.status, 1, result.stderr);
    const record = JSON.parse(readFileSync(join(dir, 'provenance.json'), 'utf8'));
    assert.equal(record.exit_code, 1, 'provenance must not record a successful exit after reporting failed');
  });
}

test('actual exit handler keeps an original failure even when reporting also fails', (t) => {
  const dir = setup(t, null);
  startRun(dir, {});
  writeFileSync(join(dir, 'run.json'), 'invalid-json');
  assert.equal(exitHandler(dir, 42).status, 42);
  assert.equal(JSON.parse(readFileSync(join(dir, 'provenance.json'), 'utf8')).exit_code, 42);
});

test('actual exit handler publishes a matching finalized report without following output symlinks', (t) => {
  const dir = setup(t, null);
  const outside = setup(t, null);
  startRun(dir, {});
  writeFileSync(join(dir, 'run.json'), JSON.stringify(fixture()));
  const target = join(outside, 'keep');
  writeFileSync(target, SENTINEL);
  symlinkSync(target, join(dir, 'evidence.json'));
  const result = exitHandler(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(target, 'utf8'), SENTINEL);
  const report = JSON.parse(readFileSync(join(dir, 'evidence.json'), 'utf8'));
  assert.equal(report.provenance.status, 'exited_zero');
  const digest = createHash('sha256').update(readFileSync(join(dir, 'provenance.json'))).digest('hex');
  assert.equal(report.artifacts.provenance.sha256, digest);
});

test('provenance captures checkout and CLI bytes, then finishes a partial run', (t) => {
  const dir = setup(t, null);
  const binDir = setup(t, null);
  const bin = join(binDir, 'ozpb');
  writeFileSync(bin, '#!/bin/sh\nexit 0\n');
  chmodSync(bin, 0o755);
  const started = startRun(dir, { OZPB_BIN: 'ozpb', PATH: binDir });
  assert.equal(started.checkout_commit, execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim());
  assert.equal(started.cli.binary_sha256, createHash('sha256').update(readFileSync(bin)).digest('hex'));
  assert.equal(exportEvidence(dir).provenance.status, 'unfinished');
  finishRun(dir, 42);
  const report = exportEvidence(dir);
  assert.equal(report.run, null);
  assert.equal(report.provenance.status, 'exited_nonzero');
  assert.equal(report.provenance.exit_code, 42);
  assert.ok(!JSON.stringify(report).includes(binDir));
  assert.throws(() => finishRun(dir, 0));
});

test('zero exit is process bookkeeping, and absent CLI digest is explicit in Cargo mode', (t) => {
  const dir = setup(t, null);
  startRun(dir, {});
  finishRun(dir, 0);
  const report = exportEvidence(dir);
  assert.equal(report.provenance.status, 'exited_zero');
  assert.equal(report.provenance.cli.mode, 'cargo');
  assert.equal(report.provenance.cli.binary_sha256, null);
  assert.equal(report.run, null);
  assert.equal(report.evidence_kind, 'local_harness_record');
});

test('starting a run refuses old evidence and missing external CLI without replacing anything', (t) => {
  const dir = setup(t);
  assert.throws(() => startRun(dir, {}), /empty/);
  assert.ok(!existsSync(join(dir, 'provenance.json')));
  const empty = setup(t, null);
  assert.throws(() => startRun(empty, { OZPB_BIN: 'missing-cli', PATH: empty }), /not executable/);
  assert.ok(!existsSync(join(empty, 'provenance.json')));
});

test('provenance finalization refuses a replaced symlink without modifying its target', (t) => {
  const dir = setup(t, null);
  const outside = setup(t, null);
  startRun(dir, {});
  const original = readFileSync(join(dir, 'provenance.json'));
  const target = join(outside, 'provenance.json');
  writeFileSync(target, original);
  rmSync(join(dir, 'provenance.json'));
  symlinkSync(target, join(dir, 'provenance.json'));
  assert.throws(() => finishRun(dir, 0));
  assert.deepEqual(readFileSync(target), original);
});

test('an operator-selected CLI symlink hashes the executable it resolves to', (t) => {
  const dir = setup(t, null);
  const binDir = setup(t, null);
  const binary = join(binDir, 'binary');
  writeFileSync(binary, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  symlinkSync(binary, join(binDir, 'ozpb'));
  const record = startRun(dir, { OZPB_BIN: 'ozpb', PATH: binDir });
  assert.equal(record.cli.binary_sha256, createHash('sha256').update(readFileSync(binary)).digest('hex'));
});

test('a FIFO at an artifact path is refused promptly instead of blocking the exporter', (t) => {
  const dir = setup(t);
  execFileSync('mkfifo', [join(dir, 'spec.json')]);
  const result = spawnSync(process.execPath, [SCRIPT, '--run-dir', dir], { encoding: 'utf8', timeout: 3000 });
  assert.equal(result.status, 1, result.error?.message);
  assert.equal(result.stdout, '');
});

function wrapperEnvironment(t, runDir) {
  const binDir = setup(t, null);
  for (const [name, body] of [
    ['npm', ': > "$HARNESS_TEST_STEP"\nexit 42'], ['stellar', 'exit 0'], ['cargo', 'exit 0'],
  ]) {
    writeFileSync(join(binDir, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  }
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('OZPB_')));
  return {
    ...env, PATH: `${binDir}${delimiter}${process.env.PATH}`, OZPB_HARNESS_OUT: runDir,
    OZPB_HARNESS_OWNER: 'ed25519', HARNESS_TEST_STEP: join(binDir, 'npm-called'),
  };
}

for (const linkedCheckout of [false, true]) {
  for (const useSymlink of [false, true]) {
    test(`real run.sh exports partial evidence: checkout ${linkedCheckout ? 'symlink' : 'directory'}, output ${useSymlink ? 'symlink' : 'directory'}`, (t) => {
      const dir = setup(t, null);
      const parent = setup(t, null);
      const selected = useSymlink ? join(parent, 'selected-run') : dir;
      if (useSymlink) symlinkSync(dir, selected, 'dir');
      const checkout = linkedCheckout ? join(parent, 'checkout') : ROOT;
      if (linkedCheckout) symlinkSync(ROOT, checkout, 'dir');
      const env = wrapperEnvironment(t, selected);
      const result = spawnSync('bash', [join(checkout, 'testnet-harness/run.sh')], { env, encoding: 'utf8', timeout: 20000 });
      assert.equal(result.status, 42, result.stderr);
      assert.ok(existsSync(env.HARNESS_TEST_STEP));
      const report = JSON.parse(readFileSync(join(dir, 'evidence.json'), 'utf8'));
      assert.equal(report.provenance.exit_code, 42);
      assert.equal(report.run, null);
      assert.ok(!existsSync(join(dir, 'run.json')));
      assert.ok(!existsSync(join(dir, 'keys.json')));
    });
  }
}

test('a symlinked checkout refuses an occupied run before any steps', (t) => {
  const dir = setup(t);
  const original = readFileSync(join(dir, 'run.json'));
  const parent = setup(t, null);
  const checkout = join(parent, 'checkout');
  symlinkSync(ROOT, checkout, 'dir');
  const env = wrapperEnvironment(t, dir);
  const result = spawnSync('bash', [join(checkout, 'testnet-harness/run.sh')], { env, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.status, 1, result.stderr);
  assert.ok(!existsSync(env.HARNESS_TEST_STEP), 'startup must stop before npm or live operations');
  assert.deepEqual(readdirSync(dir), ['run.json']);
  assert.deepEqual(readFileSync(join(dir, 'run.json')), original);
});

for (const write of [false, true]) {
  test(`a symlinked evidence entry point runs ${write ? 'atomic publication' : 'stdout export'}`, (t) => {
    const dir = setup(t);
    const parent = setup(t, null);
    const entry = join(parent, 'evidence.mjs');
    symlinkSync(SCRIPT, entry);
    if (write) writeFileSync(join(dir, 'evidence.json'), SENTINEL);
    const result = spawnSync(process.execPath, [entry, '--run-dir', dir, ...(write ? ['--write'] : [])], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const report = write ? readFileSync(join(dir, 'evidence.json'), 'utf8') : result.stdout;
    assert.deepEqual(JSON.parse(report), exportEvidence(dir));
    if (write) assert.equal(result.stdout, '');
  });
}

test('a symlinked evidence entry point reports validation failure without exposing paths', (t) => {
  const dir = setup(t);
  const parent = setup(t, null);
  const entry = join(parent, `${SENTINEL}.mjs`);
  symlinkSync(SCRIPT, entry);
  writeFileSync(join(dir, 'run.json'), 'null');
  writeFileSync(join(dir, 'evidence.json'), SENTINEL);
  const result = spawnSync(process.execPath, [entry, '--run-dir', dir, '--write'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.ok(!result.stderr.includes(SENTINEL));
  assert.ok(!result.stderr.includes(dir));
  assert.equal(readFileSync(join(dir, 'evidence.json'), 'utf8'), SENTINEL);
});

for (const entry of ['absent', 'missing', 'other']) {
  test(`importing bookkeeping modules has no CLI effects with ${entry} argv[1]`, (t) => {
    const dir = setup(t, null);
    const other = join(dir, 'other.mjs');
    if (entry === 'other') writeFileSync(other, '');
    const argv = entry === 'absent' ? [] : [entry === 'other' ? other : join(dir, SENTINEL), 'start', dir];
    const source = `process.argv = [process.execPath, ...${JSON.stringify(argv)}];
      await import(${JSON.stringify(pathToFileURL(SCRIPT).href)});
      await import(${JSON.stringify(new URL('./run-provenance.mjs', import.meta.url).href)});
      console.log('imported');`;
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'imported\n');
    assert.equal(result.stderr, '');
    assert.deepEqual(readdirSync(dir), entry === 'other' ? ['other.mjs'] : []);
  });
}

for (const selection of ['PATH', 'explicit path']) {
  test(`CLI provenance respects current-user execute access: ${selection}`, (t) => {
    const dir = setup(t, null);
    const earlier = setup(t, null);
    const later = setup(t, null);
    const inaccessible = join(earlier, 'ozpb');
    const executable = join(later, 'ozpb');
    writeFileSync(inaccessible, '#!/bin/sh\nprintf wrong-cli\n');
    chmodSync(inaccessible, 0o641); // Others can execute, but this file's owner cannot.
    writeFileSync(executable, '#!/bin/sh\nprintf correct-cli\n', { mode: 0o755 });
    try {
      accessSync(inaccessible, constants.X_OK);
      t.skip('this user can execute mode 0641 (for example, root)');
      return;
    } catch (error) { assert.equal(error.code, 'EACCES'); }
    const env = { ...process.env, PATH: `${earlier}${delimiter}${later}` };
    for (const [command, args] of [[inaccessible, []], ['/bin/bash', ['-c', 'ozpb']], ['ozpb', []]]) {
      const actual = spawnSync(command, args, { env, encoding: 'utf8' });
      if (command === inaccessible) assert.equal(actual.error?.code, 'EACCES');
      else {
        assert.equal(actual.status, 0, actual.stderr);
        assert.equal(actual.stdout, 'correct-cli');
      }
    }
    if (selection === 'explicit path') {
      assert.throws(() => startRun(dir, { OZPB_BIN: inaccessible, PATH: env.PATH }), /not executable/);
      assert.ok(!existsSync(join(dir, 'provenance.json')));
    } else {
      const record = startRun(dir, { OZPB_BIN: 'ozpb', PATH: env.PATH });
      assert.equal(record.cli.binary_sha256, createHash('sha256').update(readFileSync(executable)).digest('hex'));
    }
  });
}

for (const selection of ['absolute path', 'relative path', 'absolute PATH', 'relative PATH', 'executable symlink']) {
  test(`CLI provenance hashes the executable Bash selects through symlink/..: ${selection}`, (t) => {
    const dir = setup(t, null);
    const parent = setup(t, null);
    const logical = join(parent, 'logical');
    const physical = join(parent, 'physical');
    mkdirSync(logical);
    mkdirSync(physical);
    mkdirSync(join(physical, 'nested'));
    symlinkSync(join(physical, 'nested'), join(logical, 'link'), 'dir');
    const expected = Buffer.from('#!/bin/sh\nprintf physical-cli\n');
    writeFileSync(join(physical, 'ozpb'), expected, { mode: 0o755 });
    writeFileSync(join(logical, 'ozpb'), '#!/bin/sh\nprintf logical-cli\n', { mode: 0o755 });

    // Keep the parent component literal: join/resolve would erase the behavior under test.
    const throughLink = `${logical}/link/..`;
    let command = `${throughLink}/ozpb`;
    let path = process.env.PATH;
    if (selection === 'relative path') command = 'logical/link/../ozpb';
    if (selection.endsWith('PATH')) {
      command = 'ozpb';
      path = `${selection === 'absolute PATH' ? throughLink : 'logical/link/..'}${delimiter}${path}`;
    }
    if (selection === 'executable symlink') {
      const alias = join(parent, 'selected-ozpb');
      symlinkSync(command, alias);
      command = alias;
    }
    const env = { ...process.env, OZPB_BIN: command, PATH: path };
    const actual = spawnSync('/bin/bash', ['-c', '"$1"', 'harness-cli-test', command], {
      cwd: parent, env, encoding: 'utf8', timeout: 3000,
    });
    assert.equal(actual.status, 0, actual.error?.message ?? actual.stderr);
    assert.equal(actual.stdout, 'physical-cli');

    const result = spawnSync(process.execPath, [join(ROOT, 'testnet-harness/scripts/run-provenance.mjs'), 'start', dir], {
      cwd: parent, env, encoding: 'utf8', timeout: 20000,
    });
    assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    const record = JSON.parse(readFileSync(join(dir, 'provenance.json'), 'utf8'));
    assert.equal(record.cli.binary_sha256, createHash('sha256').update(expected).digest('hex'));
  });
}

test('an empty PATH component selects an executable in the current directory', (t) => {
  const dir = setup(t, null);
  const parent = setup(t, null);
  const expected = Buffer.from('#!/bin/sh\nprintf current-directory-cli\n');
  writeFileSync(join(parent, 'ozpb'), expected, { mode: 0o755 });
  const env = { ...process.env, OZPB_BIN: 'ozpb', PATH: `${delimiter}${process.env.PATH}` };
  const actual = spawnSync('/bin/bash', ['-c', 'ozpb'], { cwd: parent, env, encoding: 'utf8', timeout: 3000 });
  assert.equal(actual.status, 0, actual.error?.message ?? actual.stderr);
  assert.equal(actual.stdout, 'current-directory-cli');
  const result = spawnSync(process.execPath, [join(ROOT, 'testnet-harness/scripts/run-provenance.mjs'), 'start', dir], {
    cwd: parent, env, encoding: 'utf8', timeout: 20000,
  });
  assert.equal(result.status, 0, result.error?.message ?? result.stderr);
  const record = JSON.parse(readFileSync(join(dir, 'provenance.json'), 'utf8'));
  assert.equal(record.cli.binary_sha256, createHash('sha256').update(expected).digest('hex'));
});

test('main detection follows the Node loader for a symlink target containing symlink/..', (t) => {
  const parent = setup(t, null);
  const logical = join(parent, 'logical');
  const physical = join(parent, 'physical');
  mkdirSync(logical);
  mkdirSync(physical);
  mkdirSync(join(physical, 'nested'));
  symlinkSync(join(physical, 'nested'), join(logical, 'link'), 'dir');
  const helper = new URL('./cli-entry.mjs', import.meta.url).href;
  for (const [directory, label] of [[logical, 'logical'], [physical, 'physical']]) {
    writeFileSync(join(directory, 'entry.mjs'), `import { isMainModule } from ${JSON.stringify(helper)};
      console.log(JSON.stringify({ label: ${JSON.stringify(label)}, main: isMainModule(import.meta.url) }));`);
  }
  const alias = join(parent, 'entry.mjs');
  symlinkSync(`${logical}/link/../entry.mjs`, alias);
  for (const flags of [[], ['--preserve-symlinks-main']]) {
    const result = spawnSync(process.execPath, [...flags, alias], { encoding: 'utf8', timeout: 3000 });
    assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { label: flags.length ? 'physical' : 'logical', main: true });
  }
});

test('CLI publishes evidence atomically and replaces output symlinks without touching their targets', (t) => {
  const dir = setup(t);
  const outside = setup(t, null);
  const target = join(outside, SENTINEL);
  writeFileSync(target, SENTINEL);
  symlinkSync(target, join(dir, 'evidence.json'));
  const result = spawnSync(process.execPath, [SCRIPT, '--run-dir', dir, '--write'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(readFileSync(target, 'utf8'), SENTINEL);
  assert.ok(lstatSync(join(dir, 'evidence.json')).isFile());
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'evidence.json'), 'utf8')), exportEvidence(dir));
  assert.ok(!readdirSync(dir).some((name) => name.startsWith('.evidence-')));
});

for (const useSymlink of [false, true]) {
  test(`CLI refuses invalid evidence without truncating ${useSymlink ? 'a symlink target' : 'the previous summary'}`, (t) => {
    const dir = setup(t, null);
    startRun(dir, {});
    const provenance = readFileSync(join(dir, 'provenance.json'));
    writeFileSync(join(dir, 'run.json'), 'null');
    const output = join(dir, 'evidence.json');
    if (useSymlink) symlinkSync(join(dir, 'provenance.json'), output);
    else writeFileSync(output, SENTINEL);
    const before = readFileSync(output);
    const result = spawnSync(process.execPath, [SCRIPT, '--run-dir', dir, '--write'], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes(dir));
    assert.ok(!result.stderr.includes(SENTINEL));
    assert.deepEqual(readFileSync(output), before);
    assert.deepEqual(readFileSync(join(dir, 'provenance.json')), provenance);
    assert.equal(lstatSync(output).isSymbolicLink(), useSymlink);
  });
}

test('CLI publication failure preserves the previous output and removes its temporary file', (t) => {
  const dir = setup(t);
  const output = join(dir, 'evidence.json');
  mkdirSync(output);
  writeFileSync(join(output, 'keep'), SENTINEL);
  const result = spawnSync(process.execPath, [SCRIPT, '--run-dir', dir, '--write'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.ok(!result.stderr.includes(dir));
  assert.ok(!result.stderr.includes(SENTINEL));
  assert.equal(readFileSync(join(output, 'keep'), 'utf8'), SENTINEL);
  assert.ok(!readdirSync(dir).some((name) => name.startsWith('.evidence-')));
});


test('failed exit attempts cleanup before discarding keys and retains original status', (t) => {
  const dir = setup(t, null);
  startRun(dir, {});
  writeFileSync(join(dir, 'run.json'), JSON.stringify(fixture()));
  const secrets = join(dir, 'temporary-keys');
  mkdirSync(secrets);
  writeFileSync(join(secrets, 'keys.json'), 'test-only');
  const prelude = `node() {
    if [[ "$1" == */failure-cleanup.mjs ]]; then
      test -f "$SECRETS/keys.json" || return 99
      printf checked > "$RUN/cleanup-attempt"
      return 17
    fi
    command node "$@"
  }`;
  const result = exitHandler(dir, 42, prelude, secrets);
  assert.equal(result.status, 42, result.stderr);
  assert.equal(readFileSync(join(dir, 'cleanup-attempt'), 'utf8'), 'checked');
  assert.equal(existsSync(secrets), false);
  assert.equal(JSON.parse(readFileSync(join(dir, 'provenance.json'))).exit_code, 42);
});

for (const change of ['matching', 'account code', 'installation', 'reviewed address', 'reviewed code', 'reviewed period', 'missing reviewed', 'unexpected reviewed']) {
  test(`verified failure cleanup binds its original installation: ${change}`, (t) => {
    const run = fixture();
    if (change !== 'unexpected reviewed') run.subscription = { schema_version: 1, mode: 'short_test_window', period_ledgers: 12,
      policy_address: C, policy_code_hash: HASH };
    run.lifecycle = { removals: [{ rule_id: 1, transaction: HASH, ledger: 20,
      event: 'verified', rule_readback: 'absent', policy_cleanup: 'not_installed' }] };
    run.failure_cleanup = { status: 'removed', reason: 'verified_removal', transaction: HASH,
      network: run.network, account: C, account_code_hash: HASH, rule_id: 1, installation: HASH,
      policy: C, policy_wasm_hash: wasmHash, subscription: structuredClone(run.subscription ?? null) };
    const c = run.failure_cleanup;
    if (change === 'account code') c.account_code_hash = 'cd'.repeat(32);
    if (change === 'installation') c.installation = 'cd'.repeat(32);
    if (change === 'reviewed address') c.subscription.policy_address = 'C' + 'B'.repeat(55);
    if (change === 'reviewed code') c.subscription.policy_code_hash = 'cd'.repeat(32);
    if (change === 'reviewed period') c.subscription.period_ledgers = 13;
    if (change === 'missing reviewed') c.subscription = null;
    if (change === 'unexpected reviewed') c.subscription = { schema_version: 1, mode: 'short_test_window', period_ledgers: 12,
      policy_address: C, policy_code_hash: HASH };
    const dir = setup(t, run);
    if (change === 'matching') assert.equal(exportEvidence(dir).failure_cleanup.status, 'removed');
    else assert.throws(() => exportEvidence(dir), /invalid or inconsistent/);
  });
}


test('an unexpectedly permitted negative simulation is retained without a transaction identity', (t) => {
  const run = fixture();
  run.invocations.push({ signer: 'delegate', rule: 1, amount: run.amount, to: run.recipient,
    result: 'permit', observation: 'enforcing_simulation', ledger: 100 });
  const dir = setup(t, run);
  const observation = exportEvidence(dir).run.invocations.at(-1);
  assert.equal(observation.observation, 'enforcing_simulation');
  assert.equal(observation.result, 'permit');
  assert.equal(observation.transaction, null);
  run.invocations.at(-1).hash = HASH;
  writeFileSync(join(dir, 'run.json'), JSON.stringify(run));
  assert.throws(() => exportEvidence(dir), /invalid or inconsistent/);
});


test('unreaped cleanup keeps original exit and discards keys without finalizing child-owned files', (t) => {
  const dir = setup(t, null);
  startRun(dir, {});
  writeFileSync(join(dir, 'run.json'), JSON.stringify(fixture()));
  const before = readFileSync(join(dir, 'provenance.json'), 'utf8');
  const secrets = join(dir, 'temporary-keys');
  mkdirSync(secrets); writeFileSync(join(secrets, 'keys.json'), 'test-only');
  const prelude = `node() {
    if [[ "$1" == */failure-cleanup.mjs ]]; then return 2; fi
    command node "$@"
  }`;
  const result = exitHandler(dir, 42, prelude, secrets);
  assert.equal(result.status, 42);
  assert.equal(existsSync(secrets), false);
  assert.equal(readFileSync(join(dir, 'provenance.json'), 'utf8'), before);
  assert.equal(existsSync(join(dir, 'evidence.json')), false);
  assert.match(result.stderr, /termination.*unconfirmed/i);
});
