import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runProtocolFlow } from './protocol-flow.mjs';
const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-protocol-flow '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fixtureDir = join(dir, 'fixture'); mkdirSync(fixtureDir);
  const bin = join(dir, 'fake cli');
  writeFileSync(bin, readFileSync(new URL('./fixtures/protocol-pipeline-cli.mjs', import.meta.url))); chmodSync(bin, 0o700);
  const { plan, record, synthesis } = structuredClone(capture);
  record.bundle.execution = 'executed_success';
  const run = { network: 'Test SDF Network ; September 2015', account: plan.account,
    account_code_hash: synthesis.spec.smart_account.observed_code_hash,
    delegate: synthesis.spec.rules[0].authorization.signers[0].delegated.address,
    walkthrough: { ...plan, owner_transaction: { hash: 'ab'.repeat(32), ledger: record.bundle.ledger,
      output_token: 'CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F',
      balance_before: '0', balance_after: '150000', returned_amount: '150000' } } };
  const files = { 'record.json': record, 'synthesize.json': synthesis,
    'reference-suite.json': { report: { spec_hash: synthesis.spec_hash }, all_agree: true, disagreements: 0, missing_classes: [],
      unmodeled_reviewed_policies: [], total: 40 } };
  for (let i = 0; i < 2; i++) {
    files[`manifest-${i}.json`] = { rule_index: i, spec_hash: synthesis.spec_hash, registry_snapshot: synthesis.spec.registry_snapshot,
      normalized_input_hash: String(i + 1).repeat(64), wasm_hash: createHash('sha256').update(`fixture wasm${i}`).digest('hex') };
    files[`verify-${i}.json`] = { matches: true, models_all_policies: true, unmodeled_reviewed_policies: [],
      spec_conformance: 'conforms (validated PolicySpec v1)', source_reproduction: 'reproduced: generated non-lock files are byte-identical',
      wasm_reproduction: 'reproduced: Wasm and BuildManifest are identical', normalized_input_hash: String(i + 1).repeat(64),
      offline_behavioral_conformance: 'pass: 40 constraint-derived cases all agree',
      current_network_preflight: 'not_checked_here: state-dependent (wallet/live)' };
  }
  const execute = () => {
    writeFileSync(join(dir, 'run.json'), JSON.stringify(run));
    for (const [name, value] of Object.entries(files)) writeFileSync(join(fixtureDir, name), JSON.stringify(value));
    return runProtocolFlow(dir, { ...process.env, OZPB_BIN: bin, OZPB_PROTOCOL_FIXTURE: fixtureDir,
      OZPB_REGISTRY_SNAPSHOT_ROOT: synthesis.spec.registry_snapshot,
      OZPB_SIGNED_REGISTRY_SNAPSHOT: '', OZPB_REGISTRY_ROOTS_FILE: '', OZPB_REGISTRY_MIN_VERSION: '' });
  };
  return { dir, fixtureDir, run, files, execute };
}
for (const mode of ['matching', 'simulation only', 'zero effect', 'missing child', 'wrong second manifest', 'failed second reproduction']) {
  test(`protocol pipeline preserves all rule artifacts and partial outcomes: ${mode}`, (t) => {
    const f = fixture(t);
    if (mode === 'simulation only') f.files['record.json'].bundle.execution = 'simulated';
    if (mode === 'zero effect') f.run.walkthrough.owner_transaction.balance_after = '0';
    if (mode === 'missing child') f.files['record.json'].bundle.authorizations[0].root.sub_invocations = [];
    if (mode === 'wrong second manifest') f.files['manifest-1.json'].rule_index = 0;
    if (mode === 'failed second reproduction') f.files['verify-1.json'].matches = false;
    if (mode !== 'matching') {
      assert.throws(f.execute);
      assert.equal(existsSync(join(f.dir, 'protocol-pipeline.json')), false);
      if (mode === 'zero effect') assert.equal(existsSync(join(f.fixtureDir, 'commands.jsonl')), false);
      return;
    }
    const artifacts = f.execute();
    assert.equal(artifacts.length, 2);
    const pipeline = JSON.parse(readFileSync(join(f.dir, 'protocol-pipeline.json')));
    assert.deepEqual(pipeline.artifacts.map((a) => a.rule_index), [0, 1]);
    assert.equal(pipeline.artifact_reproduction, 'matched');
    const calls = readFileSync(join(f.fixtureDir, 'commands.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(calls.map((c) => c.command), ['record', 'synthesize', 'reference-suite', 'generate', 'verify', 'generate', 'verify']);
    const specPaths = calls.filter((c) => ['generate', 'verify'].includes(c.command)).map((c) => c.args[c.args.indexOf('--spec') + 1]);
    assert.equal(new Set(specPaths).size, 1, 'each indexed artifact uses the same complete spec');
  });
}
