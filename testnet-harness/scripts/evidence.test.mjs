import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
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

test('real run.sh retains its nonzero exit and exports partial evidence before any network operation', (t) => {
  const dir = setup(t, null);
  const binDir = setup(t, null);
  for (const [name, code] of [['npm', 42], ['stellar', 0], ['cargo', 0]]) {
    const path = join(binDir, name);
    writeFileSync(path, `#!/bin/sh\nexit ${code}\n`);
    chmodSync(path, 0o755);
  }
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('OZPB_')));
  Object.assign(env, { PATH: `${binDir}:${process.env.PATH}`, OZPB_HARNESS_OUT: dir, OZPB_HARNESS_OWNER: 'ed25519' });
  const result = spawnSync('bash', [join(ROOT, 'testnet-harness/run.sh')], { env, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.status, 42, result.stderr);
  const report = JSON.parse(readFileSync(join(dir, 'evidence.json'), 'utf8'));
  assert.equal(report.provenance.exit_code, 42);
  assert.equal(report.run, null);
  assert.ok(!existsSync(join(dir, 'run.json')));
  assert.ok(!existsSync(join(dir, 'keys.json')));
});
