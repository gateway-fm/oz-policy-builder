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
function exitHandler(dir, code = 0, prelude = '', secrets = '', extraEnv = {}) {
  const script = readFileSync(join(ROOT, 'testnet-harness/run.sh'), 'utf8');
  const start = script.indexOf('finish_run() {');
  const end = script.indexOf('trap finish_run EXIT', start) + 'trap finish_run EXIT'.length;
  assert.ok(start >= 0 && end > start);
  return spawnSync('bash', ['-c', `set -euo pipefail\n${prelude}\n${script.slice(start, end)}\nexit "$HARNESS_TEST_EXIT"\n`], {
    env: { ...process.env, RUN: dir, SCRIPTS: join(ROOT, 'testnet-harness/scripts'), SECRETS: secrets, HARNESS_TEST_EXIT: String(code),
      ...extraEnv },
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

test('a failed protocol walkthrough removes its bundle grants before discarding keys', (t) => {
  const dir = setup(t, null);
  startRun(dir, {});
  writeFileSync(join(dir, 'run.json'), JSON.stringify(fixture()));
  const secrets = join(dir, 'temporary-keys');
  mkdirSync(secrets);
  writeFileSync(join(secrets, 'keys.json'), 'test-only');
  const prelude = `node() {
    if [[ "$1" == */failure-cleanup.mjs ]]; then return 98; fi
    if [[ "$1" == */protocol-finish.mjs ]]; then
      test -f "$SECRETS/keys.json" || return 99
      printf bundle > "$RUN/cleanup-attempt"
      return 1
    fi
    command node "$@"
  }`;
  const result = exitHandler(dir, 42, prelude, secrets, { WALKTHROUGH: 'soroswap' });
  assert.equal(result.status, 42, result.stderr);
  assert.equal(readFileSync(join(dir, 'cleanup-attempt'), 'utf8'), 'bundle');
  assert.equal(existsSync(secrets), false);
  assert.match(result.stderr, /cleanup incomplete/i);
});

for (const closeStatus of [0, 1]) {
  test(`a failed Blend walkthrough closes its position, then removes its grants, before discarding keys (close exit ${closeStatus})`, (t) => {
    const dir = setup(t, null);
    startRun(dir, {});
    writeFileSync(join(dir, 'run.json'), JSON.stringify(fixture()));
    const secrets = join(dir, 'temporary-keys');
    mkdirSync(secrets);
    writeFileSync(join(secrets, 'keys.json'), 'test-only');
    const prelude = `node() {
      if [[ "$1" == */failure-cleanup.mjs ]]; then return 98; fi
      if [[ "$1" == */blend-position.mjs ]]; then
        test "$2" = close && test -f "$SECRETS/keys.json" || return 99
        printf close >> "$RUN/cleanup-attempt"
        return ${closeStatus}
      fi
      if [[ "$1" == */protocol-finish.mjs ]]; then
        test -f "$SECRETS/keys.json" || return 99
        printf ,bundle >> "$RUN/cleanup-attempt"
        return 0
      fi
      command node "$@"
    }`;
    const result = exitHandler(dir, 42, prelude, secrets, { WALKTHROUGH: 'blend' });
    assert.equal(result.status, 42, result.stderr);
    assert.equal(readFileSync(join(dir, 'cleanup-attempt'), 'utf8'), 'close,bundle');
    assert.equal(existsSync(secrets), false);
    if (closeStatus) assert.match(result.stderr, /cleanup incomplete/i);
    else assert.doesNotMatch(result.stderr, /cleanup incomplete/i);
  });
}

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

const ROOT_POLICY = 'C' + 'D'.repeat(55);
const CHILD_POLICY = 'C' + 'E'.repeat(55);
const LEGACY_SWAP_STEPS = ['input_cap', 'output_floor', 'exact_deadline', 'wrong_signer', 'zero_signers', 'independent_token',
  'delegate_swap', 'count_cap', 'expiry_wait', 'expired_rule', 'cleanup', 'post_revocation'];
const SWAP_STEPS = ['input_cap', 'output_floor', 'exact_deadline', 'wrong_signer', 'zero_signers', 'independent_token',
  'token_cap', 'delegate_swap', 'count_cap', 'token_count_cap', 'expiry_wait', 'expired_rule', 'cleanup', 'post_revocation'];
const ADAPTER_SWAP_STEPS = ['input_cap', 'output_floor', 'path_reordered', 'path_extended', 'path_truncated', 'foreign_recipient',
  'router_function', 'any_deadline', 'wrong_signer', 'zero_signers', 'independent_token', 'token_cap', 'delegate_swap', 'count_cap',
  'token_count_cap', 'expiry_wait', 'expired_rule', 'cleanup', 'post_revocation'];
const ROUTER_CODE = '4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c';
const CONSTRUCTED = ['path_reordered', 'path_extended', 'path_truncated', 'foreign_recipient', 'router_function'];
const ADAPTER_CONTROLS = [...CONSTRUCTED, 'any_deadline'];
const DECISIONS = { schema: 'ozpb-soroswap-operator-decisions/v1', output_floor: { min: '100000', intent: SENTINEL },
  transfer_cap: { max: '1000000', intent: SENTINEL }, adapter_deadline: 'accept_any_value_high_blast_radius', source_sha256: 'cd'.repeat(32) };
function protocolFixture(names = SWAP_STEPS) {
  const run = fixture();
  delete run.policy; delete run.policy_wasm_hash; delete run.rule_id; delete run.tx.add_context_rule;
  run.invocations = []; run.valid_until_ledger = 200;
  const denial = { enforcer: ROOT_POLICY, code: 6 };
  const expected = { input_cap: denial, output_floor: denial, exact_deadline: denial, path_reordered: denial,
    path_extended: denial, path_truncated: denial, router_function: { enforcer: ROOT_POLICY, code: 5 },
    wrong_signer: { enforcer: C, code: 3016 }, zero_signers: { enforcer: ROOT_POLICY, code: 1 },
    count_cap: { enforcer: ROOT_POLICY, code: 7 }, expired_rule: { enforcer: C, code: 3002 }, post_revocation: { enforcer: C, code: 3000 },
    token_cap: { enforcer: CHILD_POLICY, code: 6 }, token_count_cap: { enforcer: CHILD_POLICY, code: 7 } };
  const steps = names.map((name, i) => {
    const ledger = name === 'expired_rule' || name === 'post_revocation' ? 201 + i : 100 + i;
    if (name === 'cleanup') return { name, result: 'removed' };
    if (name === 'expiry_wait') return { name, result: 'ledger_reached', target_ledger: 201, ledger: 201 };
    if (name === 'delegate_swap') return { name, result: 'confirmed', ledger, transaction: 'cd'.repeat(32) };
    if (name === 'independent_token') return { name, result: 'verified_independent_permission', ledger };
    if (name === 'any_deadline') return { name, result: 'verified_disclosed_permission', ledger };
    if (name === 'foreign_recipient') return { name, result: 'verified_recipient_refusal', ledger };
    return { name, result: 'verified_denial', ledger, ...expected[name] };
  });
  const invocations = [{ name: 'owner_record', control: 'baseline', signer: 'owner', rule_ids: [0, 0], status: 'confirmed',
    observation: 'submitted_transaction', transaction: HASH, ledger: 90, returned_amount: '150000', output_token: C,
    balance_before: '0', balance_after: '150000' },
  ...steps.filter((s) => !['cleanup', 'expiry_wait'].includes(s.name)).map((s) => ({ name: s.name,
    control: ADAPTER_CONTROLS.includes(s.name) ? s.name : 'baseline',
    ...(CONSTRUCTED.includes(s.name) ? { authorization: 'signed_without_recording' } : {}),
    signer: 'delegate', rule_ids: [8, 9], status: s.result, ledger: s.ledger,
    observation: s.transaction ? 'submitted_transaction' : 'enforcing_simulation',
    ...(s.transaction ? { transaction: s.transaction, returned_amount: '150000' } : {}),
    ...(s.code ? { enforcer: s.enforcer, code: s.code } : {}), host_error: SENTINEL }))];
  const entry = (rule_index, policy) => ({ rule_index, wasm_hash: wasmHash, spec_hash: HASH, policy,
    authority: { trust_basis: 'operator-supplied test configuration', authority_commitment: 'ef'.repeat(32),
      checked_at_ledger: 92 + rule_index, rechecked_at_ledger: 93 + rule_index, accepted_entries: [{ label: SENTINEL }], status: 'rechecked' },
    readback: { rule_index, rule_id: 8 + rule_index, configuration: 'matched', observation: 'non_atomic',
      read_ledgers: { account: 95, policy: 95, rule: 95, installed: 95 } },
    installation: { rule_id: 8 + rule_index, transaction: HASH, ledger: 95 }, tx: { upload: HASH, create: HASH, install: HASH },
    removal: { transaction: HASH, ledger: 206, event: 'verified', rule_readback: 'absent', policy_cleanup: 'not_installed',
      before: { configuration: 'matched', private_note: SENTINEL } } });
  run.walkthrough = { kind: 'soroswap_swap', account: C, amount_in: '1000000', minimum_out: '100000', deadline: 1,
    owner_transaction: { hash: HASH, ledger: 90, output_token: C, balance_before: '0', balance_after: '150000', returned_amount: '150000' },
    invocations, bundle: { status: 'installed', account: C, spec_hash: HASH, registry_root: HASH,
      entries: [entry(0, ROOT_POLICY), entry(1, CHILD_POLICY)], cleanup: { status: 'removed' } },
    controls: { status: 'completed', ...(names === SWAP_STEPS ? { control_set: 2 } : names === ADAPTER_SWAP_STEPS
      ? { control_set: 3 } : {}), steps }, prerequisites: { note: SENTINEL } };
  if (names === ADAPTER_SWAP_STEPS) {
    run.walkthrough.operator_decisions = structuredClone(DECISIONS);
    run.registry_root = HASH;
  }
  return run;
}
const protocolPipeline = { schema_version: 1, account: C, kind: 'soroswap_swap', recorded_transaction: HASH,
  recording_hash: HASH, acquisition_trust: 'rpc_reported', synthesis_recording_hash: HASH, synthesis_trust: 'self_supplied',
  spec_hash: HASH, reference_cases: 40, artifact_reproduction: 'matched', current_network_preflight: 'not_checked_here',
  adapter: { name: 'soroswap-router@1', code_hash: ROUTER_CODE, rule_index: 0, registry_root: HASH, registry: 'development_root' },
  high_blast_radius: [{ rule_index: 0, fn: 'swap_exact_tokens_for_tokens', arg_index: 4, constraint: 'any_value',
    provenance: 'adapter_derived', blast_radius: 'high' }],
  artifacts: [0, 1].map((rule_index) => ({ rule_index, wasm_hash: wasmHash, normalized_input_hash: HASH })) };
// The same pipeline as the published pre-adapter runs recorded it: no adapter fields at all.
const legacyPipeline = Object.fromEntries(Object.entries(protocolPipeline).filter(([key]) => !['adapter', 'high_blast_radius'].includes(key)));
const withPipeline = (t, run, pipeline = protocolPipeline) => {
  const dir = setup(t, run);
  writeFileSync(join(dir, 'protocol-pipeline.json'), JSON.stringify(pipeline));
  return dir;
};

test('protocol walkthrough summary keeps typed bundle, controls and per-rule artifacts only', (t) => {
  const dir = setup(t, protocolFixture());
  writeFileSync(join(dir, 'protocol-pipeline.json'), JSON.stringify(legacyPipeline));
  for (const i of [0, 1]) {
    mkdirSync(join(dir, 'policies', `rule-${i}`), { recursive: true });
    writeFileSync(join(dir, 'policies', `rule-${i}`, 'policy.wasm'), wasm);
    writeFileSync(join(dir, 'policies', `rule-${i}`, 'build-manifest.json'), '{}');
  }
  const report = exportEvidence(dir);
  assert.equal(report.walkthrough.kind, 'soroswap_swap');
  assert.equal(report.walkthrough.controls.status, 'completed');
  assert.deepEqual(report.walkthrough.bundle.entries.map((e) => e.rule_id), [8, 9]);
  assert.equal(report.walkthrough.bundle.entries[1].removal.rule_readback, 'absent');
  assert.equal(report.walkthrough.invocations.find((i) => i.name === 'delegate_swap').transaction, 'cd'.repeat(32));
  assert.equal(report.walkthrough.invocations.find((i) => i.name === 'input_cap').transaction, null);
  assert.equal(report.protocol_pipeline.reference_cases, 40);
  assert.equal(report.artifacts.policy_wasm_rule_1.sha256, wasmHash);
  assert.equal(report.run.installation, 'not_recorded');
  assert.equal(report.walkthrough.controls.control_set, 'transfer_rule_denials_included');
  assert.deepEqual(report.walkthrough.bundle.entries[1].authority, { status: 'rechecked',
    authority_commitment: 'ef'.repeat(32), checked_at_ledger: 93, rechecked_at_ledger: 94 });
  assert.deepEqual(report.walkthrough.bundle.entries[0].readback, { configuration: 'matched', observation: 'non_atomic',
    read_ledgers: { account: 95, policy: 95, rule: 95, installed: 95 } });
  // Native-setup funding fields say nothing about the swap; they are not exported as its target or amount.
  assert.deepEqual([report.run.target, report.run.recipient, report.run.amount], [null, null, null]);
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('W3 evidence refused without adapter identity', (t) => {
  const run = protocolFixture(ADAPTER_SWAP_STEPS);
  assert.equal(exportEvidence(withPipeline(t, run)).protocol_pipeline.adapter.name, 'soroswap-router@1');
  for (const [mode, change] of [
    ['no adapter', (p) => { delete p.adapter; }],
    ['a null adapter', (p) => { p.adapter = null; }],
    ['another adapter', (p) => { p.adapter.name = 'soroswap-router@2'; }],
    ['other router code', (p) => { p.adapter.code_hash = 'ef'.repeat(32); }],
    ['another rule', (p) => { p.adapter.rule_index = 1; }],
    ['a registry other than the installed one', (p) => { p.adapter.registry_root = 'ef'.repeat(32); }],
    ['an unnamed registry', (p) => { p.adapter.registry = 'governance'; }],
    ['a self-declared committed registry', (p) => { p.adapter.registry = 'committed_development'; }],
  ]) {
    const pipeline = structuredClone(protocolPipeline);
    change(pipeline);
    assert.throws(() => exportEvidence(withPipeline(t, structuredClone(run), pipeline)), /invalid or inconsistent/, mode);
  }
  // A Blend claim has no adapter, and claiming one is refused.
  const blend = structuredClone(protocolPipeline);
  Object.assign(blend, { kind: 'blend_claim', artifacts: blend.artifacts.slice(0, 1) });
  const claim = protocolFixture();
  claim.walkthrough.kind = 'blend_claim';
  claim.walkthrough.invocations = claim.walkthrough.invocations.filter((i) => i.name === 'owner_record');
  claim.walkthrough.invocations[0].rule_ids = [0];
  claim.walkthrough.bundle.entries.pop();
  delete claim.walkthrough.controls;
  assert.throws(() => exportEvidence(withPipeline(t, structuredClone(claim), blend)), /invalid or inconsistent/);
  Object.assign(blend, { adapter: null, high_blast_radius: [] });
  assert.equal(exportEvidence(withPipeline(t, claim, blend)).protocol_pipeline.adapter, null);
});

test('report flags adapter deadline as high blast radius', (t) => {
  const report = exportEvidence(withPipeline(t, protocolFixture(ADAPTER_SWAP_STEPS)));
  assert.deepEqual(report.protocol_pipeline.adapter, { name: 'soroswap-router@1', code_hash: ROUTER_CODE, rule_index: 0,
    registry_root: HASH, registry: 'development_root', binding: 'development_registry_assertion_not_governance' });
  assert.equal(report.protocol_pipeline.adapter_status, 'adapter_bound');
  const operator = structuredClone(protocolPipeline);
  operator.adapter.registry = 'operator_root';
  assert.equal(exportEvidence(withPipeline(t, protocolFixture(ADAPTER_SWAP_STEPS), operator)).protocol_pipeline.adapter.binding,
    'operator_registry');
  assert.deepEqual(report.protocol_pipeline.high_blast_radius, [{ rule_index: 0, fn: 'swap_exact_tokens_for_tokens', arg_index: 4,
    constraint: 'any_value', provenance: 'adapter_derived', blast_radius: 'high' }]);
  // The control that observes it is a disclosed permit, never a denial.
  assert.equal(report.walkthrough.controls.steps.find((s) => s.name === 'any_deadline').result, 'verified_disclosed_permission');
  for (const change of [(p) => { p.high_blast_radius = []; }, (p) => { p.high_blast_radius[0].blast_radius = 'medium'; },
    (p) => { p.high_blast_radius[0].arg_index = 3; }, (p) => { delete p.high_blast_radius; }]) {
    const pipeline = structuredClone(protocolPipeline);
    change(pipeline);
    assert.throws(() => exportEvidence(withPipeline(t, protocolFixture(ADAPTER_SWAP_STEPS), pipeline)), /invalid or inconsistent/);
  }
});

test('an adapter-bound W3 run exports its route, recipient, function and open-deadline controls and the operator decisions', (t) => {
  const report = exportEvidence(withPipeline(t, protocolFixture(ADAPTER_SWAP_STEPS)));
  assert.equal(report.walkthrough.controls.status, 'completed');
  assert.equal(report.walkthrough.controls.control_set, 'adapter_route_recipient_function_controls');
  assert.deepEqual(report.walkthrough.controls.steps.map((s) => s.name).slice(0, 8), ADAPTER_SWAP_STEPS.slice(0, 8));
  assert.deepEqual(report.walkthrough.controls.steps.find((s) => s.name === 'router_function').code, 5);
  const recipient = report.walkthrough.controls.steps.find((s) => s.name === 'foreign_recipient');
  assert.deepEqual([recipient.result, recipient.enforcer, recipient.code], ['verified_recipient_refusal', null, null]);
  // The decisions, by value and file hash; the operator's free-text intents stay local.
  assert.deepEqual(report.walkthrough.operator_decisions, { output_floor: '100000', transfer_cap: '1000000',
    adapter_deadline: 'accept_any_value_high_blast_radius', source_sha256: 'cd'.repeat(32) });
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('W3 evidence from before the adapter re-exports, labeled pre-adapter', (t) => {
  // The published 20 and 22 October runs: no operator decisions, control set 2, no adapter.
  const legacy = structuredClone(protocolPipeline);
  delete legacy.adapter; delete legacy.high_blast_radius;
  const report = exportEvidence(withPipeline(t, protocolFixture(), legacy));
  assert.deepEqual([report.protocol_pipeline.adapter, report.protocol_pipeline.adapter_status, report.protocol_pipeline.high_blast_radius],
    [null, 'pre_adapter', []]);
  assert.equal(report.walkthrough.controls.control_set, 'transfer_rule_denials_included');
  // An adapter-derived pipeline next to a journal that claims an exact-deadline denial is mixed evidence.
  assert.throws(() => exportEvidence(withPipeline(t, protocolFixture())), /invalid or inconsistent/);
  const decided = protocolFixture();
  decided.walkthrough.operator_decisions = structuredClone(DECISIONS);
  assert.throws(() => exportEvidence(withPipeline(t, decided, legacy)), /invalid or inconsistent/);
});

test('constructed authorizations are exported and required for the controls signed without a recording', (t) => {
  const report = exportEvidence(withPipeline(t, protocolFixture(ADAPTER_SWAP_STEPS)));
  const byName = Object.fromEntries(report.walkthrough.invocations.map((i) => [i.name, i.authorization]));
  for (const name of CONSTRUCTED) assert.equal(byName[name], 'signed_without_recording', name);
  for (const name of ['any_deadline', 'input_cap', 'delegate_swap']) assert.equal(byName[name], 'recorded', name);
  for (const change of [(r) => { delete r.walkthrough.invocations.find((i) => i.name === 'path_truncated').authorization; },
    (r) => { r.walkthrough.invocations.find((i) => i.name === 'any_deadline').authorization = 'signed_without_recording'; }]) {
    const run = protocolFixture(ADAPTER_SWAP_STEPS);
    change(run);
    assert.throws(() => exportEvidence(withPipeline(t, run)), /invalid or inconsistent/);
  }
});

const adapterInvalid = {
  'the open deadline recorded as a denial': (r) => Object.assign(r.walkthrough.controls.steps.find((s) => s.name === 'any_deadline'),
    { result: 'verified_denial', enforcer: ROOT_POLICY, code: 6 }),
  'a foreign recipient attributed to a policy': (r) => Object.assign(r.walkthrough.controls.steps.find((s) => s.name === 'foreign_recipient'),
    { result: 'verified_denial', enforcer: ROOT_POLICY, code: 6 }),
  'another router function refused for its arguments': (r) => { r.walkthrough.controls.steps.find((s) => s.name === 'router_function').code = 6; },
  'a route denial from the transfer rule': (r) => { r.walkthrough.controls.steps.find((s) => s.name === 'path_truncated').enforcer = CHILD_POLICY; },
  'a missing route control': (r) => { r.walkthrough.controls.steps = r.walkthrough.controls.steps.filter((s) => s.name !== 'path_extended'); },
  'no operator decisions': (r) => { delete r.walkthrough.operator_decisions; },
  'operator decisions without the deadline acceptance': (r) => { r.walkthrough.operator_decisions.adapter_deadline = 'exact'; },
  'adapter controls on a Blend claim': (r) => { r.walkthrough.kind = 'blend_claim'; },
};
for (const [name, mutate] of Object.entries(adapterInvalid)) {
  test(`adapter-bound W3 summary refuses ${name}`, (t) => {
    const run = protocolFixture(ADAPTER_SWAP_STEPS);
    mutate(run);
    assert.throws(() => exportEvidence(withPipeline(t, run)), /invalid or inconsistent/);
  });
}

test('an adapter-bound control journal without its pipeline is refused, completed or not', (t) => {
  assert.throws(() => exportEvidence(setup(t, protocolFixture(ADAPTER_SWAP_STEPS))), /invalid or inconsistent/);
  const partial = protocolFixture(ADAPTER_SWAP_STEPS);
  partial.walkthrough.controls = { status: 'incomplete', control_set: 3, steps: partial.walkthrough.controls.steps.slice(0, 2) };
  assert.throws(() => exportEvidence(setup(t, partial)), /invalid or inconsistent/);
});

test('the adapter names the registry the run resolved even before anything is installed', (t) => {
  const run = protocolFixture(ADAPTER_SWAP_STEPS);
  delete run.walkthrough.bundle; delete run.walkthrough.controls;
  run.walkthrough.invocations = run.walkthrough.invocations.filter((i) => i.name === 'owner_record');
  assert.equal(exportEvidence(withPipeline(t, structuredClone(run))).protocol_pipeline.adapter.registry_root, HASH);
  run.registry_root = 'ef'.repeat(32);
  assert.throws(() => exportEvidence(withPipeline(t, run)), /invalid or inconsistent/);
});

test('a run with the earlier control set exports its actual steps and says which set it was', (t) => {
  const report = exportEvidence(setup(t, protocolFixture(LEGACY_SWAP_STEPS)));
  assert.equal(report.walkthrough.controls.status, 'completed');
  assert.equal(report.walkthrough.controls.control_set, 'router_rule_denials_only');
  assert.equal(report.walkthrough.controls.steps.some((s) => s.name === 'token_cap'), false);
});

test('per-rule Wasm bytes must be the journaled deployed Wasm', (t) => {
  const dir = setup(t, protocolFixture());
  mkdirSync(join(dir, 'policies', 'rule-1'), { recursive: true });
  writeFileSync(join(dir, 'policies', 'rule-1', 'policy.wasm'), 'other bytes');
  assert.throws(() => exportEvidence(dir), /invalid or inconsistent/);
});

const protocolInvalid = {
  'missing control step': (r) => r.walkthrough.controls.steps.splice(1, 1),
  'reordered control steps': (r) => r.walkthrough.controls.steps.reverse(),
  'denial from the wrong enforcer': (r) => { r.walkthrough.controls.steps[0].enforcer = CHILD_POLICY; },
  'expiry denial before expiry': (r) => { r.walkthrough.controls.steps.find((s) => s.name === 'expired_rule').ledger = 150; },
  'tuple denial after expiry': (r) => { r.walkthrough.controls.steps[0].ledger = 250; },
  'positive without its confirmed invocation': (r) => { r.walkthrough.controls.steps.find((s) => s.name === 'delegate_swap').transaction = 'ef'.repeat(32); },
  'owner output without balance effect': (r) => { r.walkthrough.owner_transaction.balance_after = '1'; },
  'owner output without its invocation': (r) => { r.walkthrough.owner_transaction.hash = 'ef'.repeat(32); },
  'simulation with a transaction': (r) => { r.walkthrough.invocations[1].transaction = HASH; },
  'other account': (r) => { r.walkthrough.account = 'C' + 'F'.repeat(55); },
  'removed without readback': (r) => { r.walkthrough.bundle.entries[0].removal.rule_readback = 'not_checked'; },
  'completed controls with incomplete cleanup': (r) => { r.walkthrough.bundle.cleanup.status = 'incomplete'; },
  'completed controls with an incomplete cleanup step': (r) => {
    r.walkthrough.controls.steps.find((s) => s.name === 'cleanup').result = 'incomplete';
  },
  'bundle removed while a policy stays installed': (r) => {
    r.walkthrough.bundle.entries[1].removal.policy_cleanup = 'still_installed';
  },
  'independent authority recorded as a positive': (r) => {
    r.walkthrough.controls.steps.find((s) => s.name === 'independent_token').result = 'confirmed';
  },
  'transfer-rule denial from the router policy': (r) => {
    r.walkthrough.controls.steps.find((s) => s.name === 'token_count_cap').enforcer = ROOT_POLICY;
  },
  'transfer-rule steps without control set 2': (r) => { delete r.walkthrough.controls.control_set; },
  'installed rule without a rechecked authority answer': (r) => { r.walkthrough.bundle.entries[0].authority = { status: 'refused' }; },
  'recheck before the check': (r) => { r.walkthrough.bundle.entries[0].authority.rechecked_at_ledger = 91; },
  'readback of another rule ID': (r) => { r.walkthrough.bundle.entries[0].readback.rule_id = 9; },
  'mismatched readback on a completed run': (r) => { r.walkthrough.bundle.entries[0].readback.configuration = 'drift_or_unavailable'; },
};
for (const [name, mutate] of Object.entries(protocolInvalid)) {
  test(`protocol walkthrough summary refuses ${name}`, (t) => {
    const run = protocolFixture();
    mutate(run);
    assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
  });
}

test('an incomplete protocol walkthrough exports its partial journal without completion claims', (t) => {
  const run = protocolFixture();
  run.walkthrough.controls = { status: 'incomplete', steps: run.walkthrough.controls.steps.slice(0, 2) };
  delete run.walkthrough.bundle.entries[1].removal;
  run.walkthrough.bundle.entries[1].pending_removal = { transaction: 'ef'.repeat(32), status: 'prepared_for_submission' };
  run.walkthrough.bundle.cleanup = { status: 'incomplete' };
  const report = exportEvidence(setup(t, run));
  assert.equal(report.walkthrough.controls.status, 'incomplete');
  assert.equal(report.walkthrough.bundle.entries[1].removal, null);
  assert.equal(report.walkthrough.bundle.entries[1].pending_removal.transaction, 'ef'.repeat(32));
  assert.equal(report.walkthrough.bundle.cleanup, 'incomplete');
});

test('a refused bundle exports no local approval stage or diagnostic text', (t) => {
  const run = protocolFixture();
  delete run.walkthrough.controls;
  run.walkthrough.invocations = run.walkthrough.invocations.slice(0, 1);
  run.walkthrough.bundle.status = 'incomplete';
  run.walkthrough.bundle.cleanup = { status: 'no_installed_grants' };
  for (const entry of run.walkthrough.bundle.entries) {
    delete entry.installation;
    delete entry.readback;
    delete entry.removal;
    delete entry.tx.install;
    entry.authority = { status: 'refused', stage: SENTINEL, reasons: [SENTINEL] };
  }
  const report = exportEvidence(setup(t, run));
  assert.deepEqual(report.walkthrough.bundle.entries[0].authority, { status: 'refused' });
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('a single-rule Blend journal is not labelled with transfer-rule denials', (t) => {
  const run = protocolFixture();
  run.walkthrough.kind = 'blend_claim';
  run.walkthrough.invocations = run.walkthrough.invocations.filter((i) => i.name === 'owner_record');
  run.walkthrough.invocations[0].rule_ids = [0];
  run.walkthrough.bundle.entries.pop();
  run.walkthrough.controls = { status: 'incomplete', control_set: 2,
    steps: [{ name: 'reserve_ids', result: 'verified_denial', ledger: 100, enforcer: ROOT_POLICY, code: 6 }] };
  const report = exportEvidence(setup(t, run));
  assert.equal(report.walkthrough.controls.control_set, 'single_rule');
});

function blendFixture() {
  const run = protocolFixture();
  run.walkthrough.kind = 'blend_claim';
  run.walkthrough.invocations = run.walkthrough.invocations.filter((i) => i.name === 'owner_record');
  run.walkthrough.invocations[0].rule_ids = [0];
  run.walkthrough.bundle.entries.pop();
  run.walkthrough.controls = { status: 'incomplete', control_set: 2,
    steps: [{ name: 'reserve_ids', result: 'verified_denial', ledger: 100, enforcer: ROOT_POLICY, code: 6 }] };
  run.walkthrough.emission_refresh = { status: 'gulped', transaction: 'ab'.repeat(32), ledger: 80 };
  const step = (n, ledger) => ({ status: 'confirmed', transaction: String(n).repeat(64), ledger });
  run.walkthrough.position_journal = { status: 'withdrawn', note: SENTINEL,
    funding_transfer: step(1, 81), funding_swap: { ...step(2, 82), returned_amount: '213000000', usdc_before: '0', usdc_after: '213000000' },
    supply: { ...step(3, 83), amount: '100000000', b_tokens: '99888800', usdc_spent: '100000000' },
    owner_wait: { target_ledger: 95, ledger: 96 },
    withdrawal: { ...step(4, 300), usdc_returned: '100000005', readback: 'empty' } };
  return run;
}

const BLEND_STEPS = ['reserve_ids', 'claim_recipient', 'pool_function', 'wrong_signer', 'zero_signers', 'accrual_wait',
  'delegate_claim', 'count_cap', 'expiry_wait', 'expired_rule', 'cleanup', 'post_revocation'];
function completedBlend(poolFunctionCode) {
  const run = blendFixture();
  const base = protocolFixture(BLEND_STEPS.map((n) => n === 'accrual_wait' ? 'expiry_wait' : n));
  const steps = base.walkthrough.controls.steps.map((s, i) => {
    if (BLEND_STEPS[i] === 'accrual_wait') return { name: 'accrual_wait', result: 'ledger_reached', target_ledger: 104, ledger: 105 };
    if (['reserve_ids', 'claim_recipient'].includes(s.name)) return { ...s, enforcer: ROOT_POLICY, code: 6 };
    if (s.name === 'pool_function') return { ...s, enforcer: ROOT_POLICY, code: poolFunctionCode };
    if (s.name === 'delegate_claim') return { name: s.name, result: 'confirmed', ledger: s.ledger, transaction: 'cd'.repeat(32) };
    return s;
  });
  const owner = run.walkthrough.invocations[0];
  run.walkthrough.invocations = [owner, ...steps.filter((s) => !['cleanup', 'expiry_wait', 'accrual_wait'].includes(s.name))
    .map((s) => ({ name: s.name, control: ['reserve_ids', 'claim_recipient', 'pool_function'].includes(s.name) ? s.name : 'baseline',
      signer: 'delegate', rule_ids: [8], status: s.result, ledger: s.ledger,
      observation: s.transaction ? 'submitted_transaction' : 'enforcing_simulation',
      ...(s.transaction ? { transaction: s.transaction, returned_amount: '150' } : {}),
      ...(s.code ? { enforcer: s.enforcer, code: s.code } : {}) }))];
  run.walkthrough.controls = { status: 'completed', control_set: 2, steps };
  return run;
}

test('a completed Blend journal attributes another pool function to FunctionNotAllowed (#5), not #6', (t) => {
  const report = exportEvidence(setup(t, completedBlend(5)));
  assert.equal(report.walkthrough.controls.status, 'completed');
  assert.equal(report.walkthrough.controls.steps.find((s) => s.name === 'pool_function').code, 5);
  assert.throws(() => exportEvidence(setup(t, completedBlend(6))), /invalid or inconsistent/);
});

test('a Blend walkthrough exports its typed position journal and emission refresh', (t) => {
  const report = exportEvidence(setup(t, blendFixture()));
  const position = report.walkthrough.position;
  assert.equal(position.status, 'withdrawn');
  assert.deepEqual(position.emission_refresh, { status: 'gulped', transaction: 'ab'.repeat(32) });
  assert.deepEqual(position.supply, { status: 'confirmed', transaction: '3'.repeat(64), ledger: 83, amount: '100000000' });
  assert.deepEqual(position.withdrawal, { status: 'confirmed', transaction: '4'.repeat(64), ledger: 300, readback: 'empty' });
  assert.equal(position.reason, null);
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('a Blend position still open at export is reported with its reason', (t) => {
  const run = blendFixture();
  Object.assign(run.walkthrough.position_journal, { status: 'incomplete', reason: 'position_still_open' });
  run.walkthrough.position_journal.withdrawal.readback = 'still_open';
  const report = exportEvidence(setup(t, run));
  assert.equal(report.walkthrough.position.status, 'incomplete');
  assert.equal(report.walkthrough.position.reason, 'position_still_open');
});

for (const [name, mutate] of Object.entries({
  'a withdrawn position without an empty readback': (r) => { r.walkthrough.position_journal.withdrawal.readback = 'still_open'; },
  'a withdrawn position without a withdrawal': (r) => { delete r.walkthrough.position_journal.withdrawal; },
  'a pending step without its transaction': (r) => { delete r.walkthrough.position_journal.supply.transaction; },
  'an unknown position status': (r) => { r.walkthrough.position_journal.status = 'closed'; },
  'a refresh that did not complete': (r) => { r.walkthrough.emission_refresh = { status: 'refused' }; },
  'a withdrawn position whose withdrawal was never sent': (r) => {
    r.walkthrough.position_journal.withdrawal = { status: 'started', readback: 'empty' };
  },
  'no position after a confirmed supply': (r) => {
    r.walkthrough.position_journal.status = 'no_position'; delete r.walkthrough.position_journal.withdrawal;
  },
})) {
  test(`Blend position summary refuses ${name}`, (t) => {
    const run = blendFixture();
    mutate(run);
    assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
  });
}

test('a gulp sent before the Blend plan existed is still exported', (t) => {
  const run = fixture();
  run.blend_emission_refresh = { status: 'gulped_still_not_live', reason: 'emission_expired', transaction: 'ab'.repeat(32),
    ledger: 80, gulped: '1', note: SENTINEL };
  const report = exportEvidence(setup(t, run));
  assert.deepEqual(report.blend_emission_refresh, { status: 'gulped_still_not_live', transaction: 'ab'.repeat(32) });
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
  assert.equal(exportEvidence(setup(t, fixture())).blend_emission_refresh, undefined);
});

const provenanceRecord = (exit) => ({ schema_version: 1, started_at: '2026-10-21T18:06:42.737Z',
  finished_at: '2026-10-21T18:34:33.283Z', exit_code: exit, checkout_commit: 'ab'.repeat(20), checkout_dirty: false,
  node_version: '24.15.0', cli: { mode: 'cargo', binary_sha256: null } });
for (const status of ['open', 'incomplete', 'no_position']) {
  test(`a Blend run that exited 0 with its position ${status} is refused`, (t) => {
    const run = blendFixture();
    run.walkthrough.position_journal.status = status;
    if (status !== 'incomplete') delete run.walkthrough.position_journal.withdrawal;
    if (status === 'no_position') delete run.walkthrough.position_journal.supply;
    const dir = setup(t, run);
    writeFileSync(join(dir, 'provenance.json'), JSON.stringify(provenanceRecord(0)));
    assert.throws(() => exportEvidence(dir), /invalid or inconsistent/);
    writeFileSync(join(dir, 'provenance.json'), JSON.stringify(provenanceRecord(1)));
    assert.equal(exportEvidence(dir).walkthrough.position.status, status);
  });
}
test('an exit-0 Blend run with its position withdrawn exports normally', (t) => {
  const dir = setup(t, blendFixture());
  writeFileSync(join(dir, 'provenance.json'), JSON.stringify(provenanceRecord(0)));
  assert.equal(exportEvidence(dir).walkthrough.position.status, 'withdrawn');
});
test('withdrawals and removals that did not land are exported by hash; a reconciled removal says so', (t) => {
  const run = blendFixture();
  run.walkthrough.position_journal.failed_withdrawals = [{ status: 'not_applied', transaction: 'e1'.repeat(32), ledger: 90, note: SENTINEL }];
  const entry = run.walkthrough.bundle.entries[0];
  entry.removal.confirmation = 'reconciled';
  entry.failed_removals = [{ transaction: 'e2'.repeat(32), status: 'expired_unseen' }];
  const report = exportEvidence(setup(t, run));
  assert.deepEqual(report.walkthrough.position.failed_withdrawals, [{ transaction: 'e1'.repeat(32), status: 'not_applied' }]);
  assert.equal(report.walkthrough.bundle.entries[0].removal.confirmation, 'reconciled');
  assert.deepEqual(report.walkthrough.bundle.entries[0].failed_removals, [{ transaction: 'e2'.repeat(32), status: 'expired_unseen' }]);
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
  const plain = exportEvidence(setup(t, blendFixture()));
  assert.equal(Object.hasOwn(plain.walkthrough.position, 'failed_withdrawals'), false, 'absent unless recorded');
  assert.equal(Object.hasOwn(plain.walkthrough.bundle.entries[0].removal, 'confirmation'), false);
});
test('a W2 removal reconciled from its hash, and one that did not land, are exported', (t) => {
  const run = fixture();
  run.lifecycle = { removals: [{ rule_id: run.rule_id, transaction: HASH, ledger: 20, event: 'verified', rule_readback: 'absent',
    policy_cleanup: 'not_installed', confirmation: 'reconciled' }],
  failed_removals: [{ rule_id: run.rule_id, transaction: 'e3'.repeat(32), status: 'failed' }] };
  const report = exportEvidence(setup(t, run));
  assert.equal(report.lifecycle.removals[0].confirmation, 'reconciled');
  assert.deepEqual(report.lifecycle.failed_removals, [{ rule_id: run.rule_id, transaction: 'e3'.repeat(32), status: 'failed' }]);
});
test('run.sh withdraws the Blend supply after the controls and before reporting done', () => {
  const script = readFileSync(join(ROOT, 'testnet-harness/run.sh'), 'utf8');
  const branch = script.slice(script.indexOf('if [ "$WALKTHROUGH" = soroswap ] || [ "$WALKTHROUGH" = blend ]; then'));
  const controls = branch.indexOf('protocol-controls.mjs" --run-dir');
  const close = branch.indexOf('blend-position.mjs" close --run-dir');
  const done = branch.indexOf('say "done"');
  assert.ok(controls > 0 && close > controls && done > close, 'step 6 closes the position on the success path');
  assert.match(branch.slice(controls, close), /if \[ "\$WALKTHROUGH" = blend \]; then/);
});

test('a Soroswap walkthrough has no Blend position field', (t) => {
  assert.equal(exportEvidence(setup(t, protocolFixture())).walkthrough.position, undefined);
});

test('a removal after a mismatched or unreadable pre-removal readback says so', (t) => {
  const run = protocolFixture();
  run.walkthrough.bundle.entries[1].removal.before = { configuration: 'mismatch_or_unavailable' };
  const report = exportEvidence(setup(t, run));
  assert.equal(report.walkthrough.bundle.entries[1].removal.pre_removal_readback, 'mismatch_or_unavailable');
  // A matching pre-removal readback adds nothing, so earlier summaries keep their exact bytes.
  assert.equal(Object.hasOwn(report.walkthrough.bundle.entries[0].removal, 'pre_removal_readback'), false);
  run.walkthrough.bundle.entries[1].removal.before = { configuration: 'something_else' };
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});

const unresolved = {
  'install still pending': (e) => { delete e.installation; delete e.tx.install; delete e.authority; delete e.readback; delete e.removal;
    e.pending = { operation: 'install', transaction: 'ef'.repeat(32), status: 'prepared_for_submission' }; },
  'confirmed install with unknown rule ID': (e) => { e.installation.rule_id = null; delete e.readback; delete e.removal; },
  'removal still pending': (e) => { delete e.removal; e.pending_removal = { transaction: 'ef'.repeat(32), status: 'prepared_for_submission' }; },
};
for (const [name, mutate] of Object.entries(unresolved)) {
  test(`a bundle is not exported as removed while a grant is unresolved: ${name}`, (t) => {
    const run = protocolFixture();
    run.walkthrough.controls.status = 'incomplete';
    mutate(run.walkthrough.bundle.entries[1]);
    run.walkthrough.bundle.cleanup = { status: 'incomplete' };
    assert.equal(exportEvidence(setup(t, run)).walkthrough.bundle.cleanup, 'incomplete');
    run.walkthrough.bundle.cleanup = { status: 'removed' };
    assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
  });
}
test('no_installed_grants is refused while an installation was confirmed', (t) => {
  const run = protocolFixture();
  run.walkthrough.controls.status = 'incomplete';
  run.walkthrough.bundle.cleanup = { status: 'no_installed_grants' };
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});
const contradictions = {
  'unexpected permit behind a denial step': (i) => { i.status = 'unexpected_permit'; delete i.enforcer; delete i.code; },
  'invocation at another ledger': (i) => { i.ledger += 1; },
  'invocation attributed elsewhere': (i) => { i.enforcer = CHILD_POLICY; },
  'invocation with another code': (i) => { i.code = 7; },
  'missing invocation': (i, list) => { list.splice(list.indexOf(i), 1); },
  'duplicate invocation': (i, list) => { list.push({ ...i }); },
};
for (const [name, mutate] of Object.entries(contradictions)) {
  test(`completed controls must match exactly one invocation record: ${name}`, (t) => {
    const run = protocolFixture();
    const list = run.walkthrough.invocations;
    mutate(list.find((i) => i.name === 'input_cap'), list);
    assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
  });
}
test('the independent permit step must match its invocation too', (t) => {
  const run = protocolFixture();
  run.walkthrough.invocations.find((i) => i.name === 'independent_token').status = 'independent_permission_not_observed';
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});

test('the positive step and its own record must name the same transaction', (t) => {
  // Another confirmed delegate record carrying the step's transaction must not stand in for it.
  const run = protocolFixture();
  const list = run.walkthrough.invocations;
  const own = list.find((i) => i.name === 'delegate_swap');
  list.push({ ...own, name: 'other_swap' });
  own.transaction = 'ab'.repeat(32);
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});
test('removed is refused when nothing was installed or removed', (t) => {
  const run = protocolFixture();
  run.walkthrough.controls.status = 'incomplete';
  for (const e of run.walkthrough.bundle.entries) {
    for (const key of ['installation', 'authority', 'readback', 'removal']) delete e[key];
    delete e.tx.install;
  }
  run.walkthrough.bundle.cleanup = { status: 'no_installed_grants' };
  assert.equal(exportEvidence(setup(t, run)).walkthrough.bundle.cleanup, 'no_installed_grants');
  run.walkthrough.bundle.cleanup = { status: 'removed' };
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});
test('a pending removal alone keeps a removed bundle unresolved', (t) => {
  // Entry 1 completed its removal and also journals a later pending one; only that clause refuses.
  const run = protocolFixture();
  run.walkthrough.controls.status = 'incomplete';
  run.walkthrough.bundle.entries[1].pending_removal = { transaction: 'ef'.repeat(32), status: 'prepared_for_submission' };
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});
test('no_installed_grants is refused while a removal is pending', (t) => {
  const run = protocolFixture();
  run.walkthrough.controls.status = 'incomplete';
  for (const e of run.walkthrough.bundle.entries) {
    for (const key of ['installation', 'authority', 'readback', 'removal']) delete e[key];
    delete e.tx.install;
  }
  run.walkthrough.bundle.entries[1].pending_removal = { transaction: 'ef'.repeat(32), status: 'prepared_for_submission' };
  run.walkthrough.bundle.cleanup = { status: 'no_installed_grants' };
  assert.throws(() => exportEvidence(setup(t, run)), /invalid or inconsistent/);
});

// --- live derived denials -----------------------------------------------------------------------

const D_ACCOUNT = 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526';
const D_MERCHANT = 'CACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAINCW';
const D_DELEGATE = 'GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U';
// Real StrKeys: the replay decodes these addresses, unlike the exporter's own fixtures.
const D_GENERATED = 'CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U', D_SPENDING = 'CADAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMSST';
const D_ROUTER_POLICY = 'CAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQMCJ', D_TRANSFER_POLICY = 'CAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQTD2L';
const derivedFile = (name) => readFileSync(new URL(`./fixtures/derived/${name}`, import.meta.url), 'utf8');

/** The journal derived-denials.mjs writes for a completed replay of a committed fixture suite. */
async function derivedReplay(run, walkthrough, order) {
  const replay = await import('./derived-denials.mjs');
  const emitted = JSON.parse(derivedFile(`${walkthrough}-cases.json`));
  const rules = replay.liveRules(run, JSON.parse(derivedFile(`${walkthrough}-spec.json`)));
  const plan = replay.planDerivedDenials({ cases: emitted.cases, rules, account: run.account, delegate: run.delegate,
    standIns: (rule) => replay.liveStandIns(run, rule) });
  const orderOf = (rule) => order.filter((a) => rule.policies.some((p) => p.address === a))
    .map((a) => ({ ...rule.policies.find((p) => p.address === a), limit: 10000000n, spent: 0n }));
  return {
    schema_version: 1, status: 'completed', labels: { post_install: true, state_dependent: true, simulation_only: true, submitted: false },
    suite: { spec_hash: emitted.spec_hash, suite_hash: emitted.suite_hash, total: emitted.total, minimum_denials: 5 },
    selection: 'every deny case of a live-realizable class that the recorded call can carry, in suite order',
    offline: plan.offline.map(({ rule_index, class: cls, reason, cases, ids }) => ({ rule_index, class: cls, reason, cases, ids })),
    permits_not_replayed: plan.permits_not_replayed, policy_order: order,
    originals: plan.originals.map((o) => ({ id: o.id, rule_index: o.rule_index, status: 'permitted', ledger: 100 })),
    cases: plan.denials.map((d) => {
      const expected = replay.predictEnforcer(d, rules[d.rule_index], orderOf(rules[d.rule_index]), run.account);
      return { id: d.id, rule_index: d.rule_index, class: d.class, family: d.family, label: d.label, realization: d.realization,
        stand_in: d.stand_in, expected, status: 'verified_denial', ledger: 101, observed: { result: 'deny', ...expected },
        host_error: SENTINEL };
    }),
  };
}

async function w2Derived(t, { order = [D_SPENDING, D_GENERATED], mutate = () => {}, cases = derivedFile('w2-cases.json') } = {}) {
  const run = { ...fixture(), payer: G, account: D_ACCOUNT, delegate: D_DELEGATE, recipient: D_MERCHANT,
    sac: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC', policy: D_GENERATED, rule_id: 1 };
  run.subscription = { schema_version: 1, mode: 'short_test_window', period_ledgers: 12, policy_address: D_SPENDING,
    policy_code_hash: '4e67aa6ca226d3c16106ff2d95f3b44a8efabc2f2a7655683957e3553ed6a40c', other_token: D_TRANSFER_POLICY,
    installation_readback: 'matched' };
  run.invocations.push({ signer: 'owner', rule: 0, result: 'permit', hash: HASH, amount: run.amount, to: run.recipient });
  run.derived_denials = await derivedReplay(run, 'w2', order);
  mutate(run);
  const dir = setup(t, run);
  const spec = JSON.parse(derivedFile('w2-cases.json')).spec_hash;
  writeFileSync(join(dir, 'pipeline.json'), JSON.stringify({ schema_version: 1, account: run.account, recorded_transaction: HASH,
    recording_hash: HASH, acquisition_trust: 'rpc_reported', synthesis_recording_hash: HASH, synthesis_trust: 'self_supplied',
    spec_hash: spec, normalized_input_hash: HASH, reference_cases: 30, artifact_reproduction: 'matched',
    current_network_preflight: 'not_checked_here', models_all_policies: false, unmodeled_reviewed_policies: ['rule[0]: oz:spending_limit'] }));
  if (cases !== null) writeFileSync(join(dir, 'derived-cases.json'), cases);
  writeFileSync(join(dir, 'spec.json'), derivedFile('w2-spec.json'));
  return { dir, run };
}

test('a W2 derived-denial replay exports suite identity, predictions and observations, not host errors', async (t) => {
  const { dir } = await w2Derived(t);
  const report = exportEvidence(dir);
  const d = report.derived_denials;
  assert.equal(d.status, 'completed');
  assert.deepEqual(d.labels, { post_install: true, state_dependent: true, simulation_only: true, submitted: false });
  assert.equal(d.suite.total, 30);
  assert.equal(d.denials_verified, 10);
  // Spending first: amounts over its limit and the empty signer set are its own refusals.
  assert.deepEqual(d.cases.map((c) => [c.id, c.expected.code]), [['case-1', 3002], ['case-5', 6], ['case-7', 3221], ['case-8', 6],
    ['case-9', 3221], ['case-10', 6], ['case-11', 3221], ['case-15', 3223], ['case-16', 3016], ['case-18', 3016]]);
  assert.equal(d.cases[0].stand_in, 'w2_control_token');
  assert.ok(d.offline.some((o) => o.class === 'time_boundary' && o.reason === 'ledger_time'));
  assert.equal(report.artifacts.derived_cases.sha256, createHash('sha256').update(derivedFile('w2-cases.json')).digest('hex'));
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});

test('derived replay exports an early failure with an incomplete policy order only before simulation', async (t) => {
  for (const status of ['running', 'incomplete']) {
    for (const order of [[], [D_SPENDING]]) {
      const { dir } = await w2Derived(t, { mutate: (r) => {
        Object.assign(r.derived_denials, { status, policy_order: order, originals: [], cases: [] });
      } });
      const report = exportEvidence(dir).derived_denials;
      assert.equal(report.status, status);
      assert.deepEqual(report.policy_order, order);
      assert.equal(report.denials_verified, 0);
    }
  }
  for (const change of [
    (d) => { d.status = 'completed'; },
    (d) => { d.originals = [{ id: 'case-0', rule_index: 0, status: 'started' }]; },
    (d, original) => { d.cases = original.cases.slice(0, 1); },
    (d) => { d.policy_order = [D_SPENDING, D_SPENDING]; },
    (d) => { d.policy_order = [D_TRANSFER_POLICY]; },
  ]) {
    const { dir } = await w2Derived(t, { mutate: (r) => {
      const original = structuredClone(r.derived_denials);
      Object.assign(r.derived_denials, { status: 'incomplete', policy_order: [], originals: [], cases: [] });
      change(r.derived_denials, original);
    } });
    assert.throws(() => exportEvidence(dir), /invalid or inconsistent/);
  }
});

test('derived denials refuse an observation, prediction or suite that does not hold', async (t) => {
  const mutations = {
    'observed differs from a verified denial': (r) => { r.derived_denials.cases[1].observed.code = 7; },
    'wrong signer attributed to a policy': (r) => { const c = r.derived_denials.cases[8];
      c.expected = { enforcer: r.policy, code: 3016 }; c.observed = { result: 'deny', ...c.expected }; },
    'argument refused by the account': (r) => { const c = r.derived_denials.cases[1];
      c.expected = { enforcer: D_ACCOUNT, code: 6 }; c.observed = { result: 'deny', ...c.expected }; },
    'empty signer set attributed against the live order': (r) => { const c = r.derived_denials.cases[7];
      c.expected = { enforcer: D_GENERATED, code: 1 }; c.observed = { result: 'deny', ...c.expected }; },
    'order that is not the installed policies': (r) => { r.derived_denials.policy_order = [D_SPENDING, C]; },
    'spec hash differs from the pipeline': (r) => { r.derived_denials.suite.spec_hash = 'ef'.repeat(32); },
    'suite size differs from the reference count': (r) => { r.derived_denials.suite.total = 31; },
    'a denial silently dropped': (r) => { r.derived_denials.cases.splice(2, 1); },
    'an offline reason another class owns': (r) => { r.derived_denials.offline.find((o) => o.class === 'time_boundary').reason = 'authorizer_replaced'; },
    'fewer than five completed': (r) => { r.derived_denials.cases.splice(5); },
    'original not permitted': (r) => { r.derived_denials.originals[0].status = 'unexpected_denial'; },
    'original id swapped': (r) => { r.derived_denials.originals[0].id = 'case-17'; },
    'original given another rule': (r) => { r.derived_denials.originals[0].rule_index = 1; },
    'labelled as submitted': (r) => { r.derived_denials.labels.submitted = true; },
    'stand-in from another walkthrough': (r) => { r.derived_denials.cases[0].stand_in = 'blend_pool_submit'; },
    'case outside the suite': (r) => { r.derived_denials.cases[1].id = 'case-30'; },
    'case relabelled': (r) => { r.derived_denials.cases[1].label = 'rule[0] hand-written control'; },
    'case of another class': (r) => { r.derived_denials.cases[2].id = 'case-5'; },
    'a verified case moved into offline': (r) => { const [moved] = r.derived_denials.cases.splice(1, 1);
      const entry = r.derived_denials.offline.find((o) => o.class === 'different_address_arg');
      entry.cases++; entry.ids.push(moved.id); },
    'a verified case given another rule': (r) => { r.derived_denials.cases[1].rule_index = 1; },
    'a permit case presented as a denial': (r) => { Object.assign(r.derived_denials.cases[9], { id: 'case-17' }); },
    'permit accounting': (r) => { r.derived_denials.permits_not_replayed++; },
    'offline ids that are not the plan\'s': (r) => { r.derived_denials.offline[0].ids = ['case-29']; },
    'a realization the plan did not make': (r) => { Object.assign(r.derived_denials.cases[0], { realization: 'mutation_on_recorded_call', stand_in: null }); },
    'permit labelled unattributed': (r) => { Object.assign(r.derived_denials.cases[1], { status: 'unattributed_denial',
      observed: { result: 'permit', enforcer: null, code: null } }); },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const { dir } = await w2Derived(t, { mutate });
    assert.throws(() => exportEvidence(dir), /invalid or inconsistent evidence record/, name);
  }
  // The emitted suite must be present, unedited, and the one the journal names.
  for (const [name, cases] of [['missing', null], ['empty', '{"cases":[]}'],
    ['edited', derivedFile('w2-cases.json').replace('"10000001"', '"10000002"')]]) {
    const { dir } = await w2Derived(t, { cases });
    assert.throws(() => exportEvidence(dir), /invalid or inconsistent evidence record/, name);
  }
  // A failed replay is exported as incomplete with what it saw, without completion claims.
  const { dir } = await w2Derived(t, { mutate: (r) => {
    r.derived_denials.status = 'incomplete';
    Object.assign(r.derived_denials.cases[2], { status: 'unattributed_denial', observed: { result: 'deny', enforcer: D_GENERATED, code: 6 } });
    r.derived_denials.cases.splice(3);
  } });
  const d = exportEvidence(dir).derived_denials;
  assert.equal(d.status, 'incomplete');
  assert.equal(d.denials_verified, 2);
  assert.deepEqual(d.cases[2].observed, { result: 'deny', enforcer: D_GENERATED, code: 6 });
});

test('protocol derived denials are attributed to the rule each case exercises', async (t) => {
  const make = async (mutate = () => {}) => {
    const run = protocolFixture();
    run.account = D_ACCOUNT; run.delegate = D_DELEGATE;
    Object.assign(run.walkthrough, { account: D_ACCOUNT, deadline: 1792505380 });
    run.walkthrough.bundle.account = D_ACCOUNT;
    run.walkthrough.bundle.entries[0].policy = D_ROUTER_POLICY;
    run.walkthrough.bundle.entries[1].policy = D_TRANSFER_POLICY;
    // The hand-written controls name the exporter's own placeholder policies; they are not this test's subject.
    delete run.walkthrough.controls;
    run.derived_denials = await derivedReplay(run, 'w3', [D_ROUTER_POLICY, D_TRANSFER_POLICY]);
    mutate(run);
    const dir = setup(t, run);
    const emitted = JSON.parse(derivedFile('w3-cases.json'));
    writeFileSync(join(dir, 'protocol-pipeline.json'), JSON.stringify({ ...legacyPipeline, account: D_ACCOUNT,
      spec_hash: emitted.spec_hash, reference_cases: emitted.total }));
    writeFileSync(join(dir, 'derived-cases.json'), derivedFile('w3-cases.json'));
    writeFileSync(join(dir, 'spec.json'), derivedFile('w3-spec.json'));
    return dir;
  };
  const d = exportEvidence(await make()).derived_denials;
  assert.equal(d.status, 'completed');
  assert.deepEqual(d.originals.map((o) => o.rule_index), [0, 1]);
  assert.deepEqual(d.cases.filter((c) => c.rule_index === 1 && c.expected.code === 6).map((c) => c.expected.enforcer),
    [D_TRANSFER_POLICY, D_TRANSFER_POLICY]);
  // A transfer-rule case is the transfer rule's policy's to refuse, not the router rule's.
  const misattributed = await make((r) => {
    const c = r.derived_denials.cases.find((x) => x.rule_index === 1 && x.expected.code === 6);
    c.expected.enforcer = D_ROUTER_POLICY; c.observed.enforcer = D_ROUTER_POLICY;
  });
  assert.throws(() => exportEvidence(misattributed), /invalid or inconsistent evidence record/);
  // Each original is the plan's, on its own rule: not the swap's twice, not the transfer's on the router rule.
  for (const [name, mutate] of [['original id swapped', (r) => { r.derived_denials.originals[1].id = 'case-0'; }],
    ['original given another rule', (r) => { r.derived_denials.originals[1].rule_index = 0; }]]) {
    const dir = await make(mutate);
    assert.throws(() => exportEvidence(dir), /invalid or inconsistent evidence record/, name);
  }
  // Every installed rule's original must be permitted before the replay counts as complete.
  const unpermitted = await make((r) => { r.derived_denials.originals.pop(); r.derived_denials.permits_not_replayed++; });
  assert.throws(() => exportEvidence(unpermitted), /invalid or inconsistent evidence record/);
});

test('a derived-denial journal without its spec cannot be rechecked and is refused', async (t) => {
  const { dir } = await w2Derived(t);
  rmSync(join(dir, 'spec.json'));
  assert.throws(() => exportEvidence(dir), /invalid or inconsistent evidence record/);
});

function withAccountReports(t) {
  const run = protocolFixture(ADAPTER_SWAP_STEPS), dir = withPipeline(t, run);
  const network = createHash('sha256').update('Test SDF Network ; September 2015').digest('hex');
  const reports = [ROOT_POLICY, CHILD_POLICY].map((policy_address, rule_index) => ({ rule_index,
    run_hash: HASH, suite_hash: HASH, policy_address, policy_code_hash: wasmHash,
    original_permitted: true, reverted_denials: 5, complete: false }));
  const summary = { schema_version: 1, account: C, spec_hash: HASH,
    execution: 'offline_synthetic_policy_addresses_and_proposed_rule_ids', source_ledger: 100, reports, private_note: SENTINEL };
  const raw = reports.map((e) => ({ schema: 'ozpb:dry-run:v1', run_hash: HASH, complete: false,
    artifact_verification: { matches: true }, binding: { spec_hash: HASH, account_address: C,
      account_code_hash: run.account_code_hash, registry_snapshot_root: HASH, network_id: network,
      rule_index: e.rule_index, candidate_context_rule_id: e.rule_index + 1, suite_hash: HASH },
    layers: ['reference', 'account_wasm', 'captured_target', 'live_enforcement'].map((id, i) => ({ id,
      status: i < 2 ? 'passed' : 'unavailable', writes_committed: false, cases: i === 1 ? 6 : 0,
      ...(i === 1 ? { execution: { run_hash: HASH, suite_hash: HASH, source_ledger: 100,
        source_network_id: network, execution_network_id: 'cd'.repeat(32), policy_address: e.policy_address,
        policy_code_hash: wasmHash, cases: Array.from({ length: 6 }, (_, j) => ({ class: j ? 'arg_equality' : 'original',
          expected_permit: j === 0, permitted: j === 0, agree: true, state_unchanged: j > 0,
          refused_by: j ? 'policy' : null, refusal_code: j ? 6 : null, label: SENTINEL })) } } : {}) })),
    acceptance: { required_reverted_denials: 5, original_permitted: true, meets_minimum: true }, private_note: SENTINEL }));
  const save = () => {
    writeFileSync(join(dir, 'account-dry-runs.json'), JSON.stringify(summary));
    raw.forEach((r, i) => writeFileSync(join(dir, `account-dry-run-${i}.json`), JSON.stringify(r)));
  };
  save(); return { dir, summary, raw, save };
}
test('exports bound offline account report identities and counts without private labels', (t) => {
  const f = withAccountReports(t), report = exportEvidence(f.dir);
  assert.equal(report.account_dry_runs.status, 'recorded');
  assert.deepEqual(report.account_dry_runs.reports.map((r) => r.reverted_denials), [5, 5]);
  assert.equal(report.account_dry_runs.reports[1].complete, false);
  assert.ok(report.artifacts.account_dry_run_rule_1.sha256);
  assert.ok(!JSON.stringify(report).includes(SENTINEL));
});
for (const [name, change] of [
  ['invented count', (f) => { f.summary.reports[1].reverted_denials = 6; }],
  ['report from another rule', (f) => { f.raw[1].binding.rule_index = 0; }],
  ['different source ledger', (f) => { f.raw[1].layers[1].execution.source_ledger++; }],
  ['different policy code', (f) => { f.raw[1].layers[1].execution.policy_code_hash = HASH; }],
  ['claimed live enforcement', (f) => { f.raw[1].layers[3].status = 'passed'; }],
  ['denial changed state', (f) => { f.raw[1].layers[1].execution.cases[1].state_unchanged = false; }],
  ['duplicate policy identities', (f) => { f.summary.reports[1].policy_address = ROOT_POLICY; }],
]) test(`account report export refuses ${name}`, (t) => {
  const f = withAccountReports(t); change(f); f.save(); assert.throws(() => exportEvidence(f.dir));
});
