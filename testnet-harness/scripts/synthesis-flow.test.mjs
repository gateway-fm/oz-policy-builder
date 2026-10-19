import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('./synthesis-flow.mjs', import.meta.url));
const fixture = readFileSync(new URL('./fixtures/synthesis-cli.mjs', import.meta.url), 'utf8');
const hash = 'ab'.repeat(32);
const normalized = 'cd'.repeat(32);
const acquisition = 'ef'.repeat(32);
const template = JSON.parse(readFileSync(new URL('../native-sac-policy-spec.json', import.meta.url), 'utf8'));
const network = 'Test SDF Network ; September 2015';

function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-synthesis '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fixtureDir = join(dir, 'fixture');
  mkdirSync(fixtureDir);
  const cli = join(dir, 'fake ozpb');
  writeFileSync(cli, fixture);
  chmodSync(cli, 0o700);
  const spec = structuredClone(template);
  spec.registry_snapshot = '1'.repeat(64);
  spec.smart_account.registry_resolution = 'resolved registry capability';
  spec.rules[0].valid_until.ledger = 100 + 17280;
  spec.evidence.recordings[0] = { hash, trust: 'self_supplied' };
  const rule = spec.rules[0];
  rule.allowed_calls[0].justified_by = ['recordings[0]/auth[0]'];
  const run = {
    network, protocol: 29, account: spec.smart_account.address,
    account_code_hash: spec.smart_account.observed_code_hash, sac: rule.context.contract,
    owner: { kind: 'ed25519', address: 'G' + 'A'.repeat(55) },
    delegate: rule.authorization.signers[0].delegated.address,
    recipient: rule.allowed_calls[0].args[1].c.eq_address.value,
    amount: rule.allowed_calls[0].args[2].c.eq_i128.value, tx: {},
  };
  run.invocations = [{ signer: 'owner', rule: 0, amount: run.amount, to: run.recipient, result: 'permit', hash }];
  const record = {
    recording_hash: acquisition, trust: 'rpc_reported', bundle: {
      network_id: spec.network_id, execution: 'executed_success', ledger: 100,
      contract_executables: { [run.account]: { executable: { wasm: { code_hash: run.account_code_hash } }, observed_ledger: 101 } },
      authorizations: [{ authorizer: run.account, root: { call: { contract: {
        contract: run.sac, fn_name: 'transfer', args: [{ address: run.account }, { address: run.recipient }, { i128: 10000000 }],
      } }, sub_invocations: [] } }],
    },
  };
  const files = {
    'run.json': run, 'record.json': record, 'synthesize.json': { spec, spec_hash: hash, rationale: [] },
    'reference-suite.json': { report: { spec_hash: hash }, total: 20, disagreements: 0, all_agree: true, missing_classes: [], unmodeled_reviewed_policies: [] },
    'manifest.json': { spec_hash: hash, registry_snapshot: spec.registry_snapshot, rule_index: 0, wasm_hash: createHash('sha256').update('fixture wasm').digest('hex'), normalized_input_hash: normalized },
    'verify.json': {
      spec_conformance: 'conforms (validated PolicySpec v1)', source_reproduction: 'reproduced: generated non-lock files are byte-identical',
      offline_behavioral_conformance: 'pass: 20 constraint-derived cases all agree',
      wasm_reproduction: 'reproduced: Wasm and BuildManifest are identical',
      current_network_preflight: 'not_checked_here: state-dependent (wallet/live)',
      models_all_policies: true, unmodeled_reviewed_policies: [], normalized_input_hash: normalized, matches: true,
    },
  };
  function save() { for (const [name, value] of Object.entries(files)) writeFileSync(join(name === 'run.json' ? dir : fixtureDir, name), JSON.stringify(value)); }
  function execute(env = {}) {
    save();
    return spawnSync(process.execPath, [script, '--run-dir', dir], { encoding: 'utf8', env: {
      ...process.env, OZPB_BIN: cli, OZPB_FLOW_FIXTURE: fixtureDir, OZPB_RPC_URL: 'https://rpc.invalid/path',
      OZPB_SIGNED_REGISTRY_SNAPSHOT: '', OZPB_REGISTRY_ROOTS_FILE: '', OZPB_REGISTRY_MIN_VERSION: '',
      OZPB_REGISTRY_SNAPSHOT_ROOT: '', ...env,
    } });
  }
  const commands = () => existsSync(join(fixtureDir, 'commands.jsonl'))
    ? readFileSync(join(fixtureDir, 'commands.jsonl'), 'utf8').trim().split('\n').map(JSON.parse) : [];
  return { dir, files, execute, commands };
}

test('runs recording, synthesis, reference, generation and verification through the selected CLI', (t) => {
  const f = setup(t);
  const result = f.execute();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(f.commands().map((c) => c.command), ['record', 'synthesize', 'reference-suite', 'generate', 'verify']);
  const syn = f.commands()[1].args;
  assert.equal(syn[syn.indexOf('--selected-authorizer') + 1], f.files['run.json'].account);
  assert.ok(!syn.includes('--spending-limit-capability'));
  const decisions = JSON.parse(readFileSync(join(f.dir, 'decisions.json')));
  assert.equal(decisions.max_calls, 1);
  assert.equal(decisions.spending_limit, null);
  assert.deepEqual(decisions.widenings, []);
  const ready = JSON.parse(readFileSync(join(f.dir, 'pipeline.json')));
  assert.equal(ready.spec_hash, hash);
  assert.equal(ready.recording_hash, acquisition);
  assert.equal(ready.synthesis_recording_hash, hash);
  assert.equal(ready.synthesis_trust, 'self_supplied');
  assert.equal(ready.current_network_preflight, 'not_checked_here');
});

const corruptions = {
  'false verification despite zero exit': (f) => { f['verify.json'].matches = false; },
  'missing verification verdict': (f) => { delete f['verify.json'].matches; },
  'unverified Wasm despite true matches': (f) => { f['verify.json'].wasm_reproduction = 'not_verified: no claimed Wasm was supplied'; },
  'unverified source': (f) => { f['verify.json'].source_reproduction = 'MISMATCH'; },
  'missing behavioral coverage': (f) => { f['reference-suite.json'].missing_classes = ['signer']; },
  'reference disagreement': (f) => { f['reference-suite.json'].disagreements = 1; },
  'unmodeled policy': (f) => { f['reference-suite.json'].unmodeled_reviewed_policies = ['spending_limit']; },
  'wrong observed account': (f) => { f['record.json'].bundle.contract_executables = {}; },
  'wrong observed code': (f) => { Object.values(f['record.json'].bundle.contract_executables)[0].executable.wasm.code_hash = hash; },
  'wrong recorded network': (f) => { f['record.json'].bundle.network_id = hash; },
  'wrong recorded recipient': (f) => { f['record.json'].bundle.authorizations[0].root.call.contract.args[1].address = f['run.json'].delegate; },
  'unsafe ledger': (f) => { f['record.json'].bundle.ledger = 0xffff_ffff; },
  'different synthesized signer': (f) => { f['synthesize.json'].spec.rules[0].authorization.signers[0].delegated.address = f['run.json'].recipient; },
  'widened synthesized amount': (f) => { f['synthesize.json'].spec.rules[0].allowed_calls[0].args[2].c = { le_i128: { max: '10000000' } }; },
  'different synthesized expiry': (f) => { f['synthesize.json'].spec.rules[0].valid_until.ledger++; },
  'extra synthesized policy': (f) => { f['synthesize.json'].spec.rules[0].policies.push({ reviewed: {} }); },
  'synthesis questions': (f) => { f['synthesize.json'].questions = ['Who may sign?']; },
  'reference hash mismatch': (f) => { f['reference-suite.json'].report.spec_hash = normalized; },
  'manifest hash mismatch': (f) => { f['manifest.json'].spec_hash = normalized; },
  'verify input mismatch': (f) => { f['verify.json'].normalized_input_hash = hash; },
  'claimed stronger synthesis trust': (f) => { f['synthesize.json'].spec.evidence.recordings[0].trust = 'rpc_reported'; },
};
for (const [name, corrupt] of Object.entries(corruptions)) {
  test(`refuses ${name} without a completed pipeline record`, (t) => {
    const f = setup(t); corrupt(f.files);
    assert.notEqual(f.execute().status, 0);
    assert.equal(existsSync(join(f.dir, 'pipeline.json')), false);
  });
}

test('a failed CLI stage stops before the next command', (t) => {
  const f = setup(t);
  assert.notEqual(f.execute({ OZPB_FLOW_FAIL: 'synthesize' }).status, 0);
  assert.deepEqual(f.commands().map((c) => c.command), ['record', 'synthesize']);
  assert.equal(existsSync(join(f.dir, 'pipeline.json')), false);
});

test('refuses existing pipeline artifacts before invoking the CLI', (t) => {
  const f = setup(t);
  writeFileSync(join(f.dir, 'pipeline.json'), '{"matches":true}');
  assert.notEqual(f.execute().status, 0);
  assert.deepEqual(f.commands(), []);
});
