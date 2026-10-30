import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { PINNED_ACCOUNT_WASM } from './rpc.mjs';
import { runProtocolDryRuns } from './protocol-dry-run.mjs';
const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
const blendSpec = JSON.parse(readFileSync(new URL('./fixtures/synthetic-blend-claim-spec.json', import.meta.url)));
const H = (n) => String(n).repeat(64);
function reportFor(request, ledger = 100) {
  const c = request.candidate;
  const policy = c.binding_set.bindings[c.rule_index];
  const cases = Array.from({ length: 6 }, (_, i) => ({ case_id: `case:${i}`, class: i ? 'arg_equality' : 'original',
    expected_permit: i === 0, permitted: i === 0, agree: true, state_unchanged: i > 0,
    refused_by: i ? 'policy' : null, refusal_code: i ? 6 : null }));
  return { schema: 'ozpb:dry-run:v1', run_hash: H(1), complete: false, artifact_verification: { matches: true },
    binding: { spec_hash: c.binding_set.spec_hash, binding_set_hash: H(2), suite_hash: H(3),
      registry_snapshot_root: c.spec.registry_snapshot, account_address: c.account_address, account_code_hash: PINNED_ACCOUNT_WASM,
      network_id: c.network_id, rule_index: c.rule_index, candidate_context_rule_id: request.candidate_context_rule_id,
      policy_code_hashes: Object.fromEntries(c.binding_set.bindings.map((b) => [b.contract_address, b.observed_wasm_hash])) },
    layers: ['reference', 'account_wasm', 'captured_target', 'live_enforcement'].map((id, i) => ({ id,
      status: i < 2 ? 'passed' : 'unavailable', writes_committed: false, cases: i < 2 ? cases.length : 0,
      ...(i === 1 ? { execution: { run_hash: H(1), suite_hash: H(3), policy_address: policy.contract_address,
        policy_code_hash: policy.observed_wasm_hash, source_network_id: c.network_id, execution_network_id: H(4),
        source_ledger: ledger, delegate_address: c.spec.rules[c.rule_index].authorization.signers[0].delegated.address, cases } } : {}) })),
    acceptance: { required_reverted_denials: 5, original_permitted: true,
      executed_layers: [{ layer: 'account_wasm', status: 'passed', original_permitted: true, reverted_denials: 5 }], meets_minimum: true } };
}
function fixture(t, count = 2) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-protocol-reports '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const spec = structuredClone(count === 1 ? blendSpec : capture.synthesis.spec);
  const delegate = Keypair.random();
  for (const rule of spec.rules) rule.authorization.signers = [{ delegated: { address: delegate.publicKey() } }];
  const inventory = spec.rules.map((_r, i) => {
    const directory = join(dir, 'policies', `rule-${i}`); mkdirSync(join(directory, 'src'), { recursive: true });
    for (const name of ['Cargo.toml', 'rust-toolchain.toml', 'rustfmt.toml', 'src/lib.rs', 'src/contract.rs']) {
      writeFileSync(join(directory, name), `fixture ${name}`);
    }
    const wasm = join(directory, 'policy.wasm'); writeFileSync(wasm, `fixture wasm ${i}`);
    const manifest = join(directory, 'build-manifest.json');
    const wasmHash = createHash('sha256').update(readFileSync(wasm)).digest('hex');
    writeFileSync(manifest, JSON.stringify({ rule_index: i, spec_hash: H(5), registry_snapshot: spec.registry_snapshot,
      wasm_hash: wasmHash, normalized_input_hash: H(6) }));
    return { rule_index: i, directory, wasm, manifest, wasm_hash: wasmHash, normalized_input_hash: H(6) };
  });
  const run = { network: 'Test SDF Network ; September 2015', account: spec.smart_account.address,
    account_code_hash: PINNED_ACCOUNT_WASM, delegate: delegate.publicKey(), spec: join(dir, 'spec.json'),
    walkthrough: { kind: count === 1 ? 'blend_claim' : 'soroswap_swap', artifacts: inventory } };
  writeFileSync(join(dir, 'run.json'), JSON.stringify(run)); writeFileSync(run.spec, JSON.stringify(spec));
  const snapshot = join(dir, 'snapshot.json'); writeFileSync(snapshot, '{"snapshot":{"integer":9223372036854775807}}');
  const secrets = join(dir, 'private-secrets'); mkdirSync(secrets, { mode: 0o700 });
  const env = { ...process.env, OZPB_HARNESS_SECRETS: join(secrets, 'keys.json'), OZPB_BIN: 'fake-ozpb', OZPB_NATIVE_WORKER: '/fake-worker',
    OZPB_REGISTRY_ROOTS_FILE: '/roots.json', OZPB_REGISTRY_MIN_VERSION: '4',
    OZPB_RPC_SOURCES_FILE: '/sources.json', OZPB_SIGNED_REGISTRY_SNAPSHOT: snapshot };
  const requests = [], temporary = [], state = { change: () => {}, exit: 0 };
  const execute = () => runProtocolDryRuns(dir, env, {
    checkArtifacts: async () => spec.rules.map((_r, i) => ({ rule_index: i, spec_hash: H(5) })), loadKey: () => delegate,
    nativeSource: async () => ({ accountWasmBase64: Buffer.from('fixture pinned account').toString('base64'), ledger: { sequence: 100 } }),
    execute: (binary, args) => {
      assert.equal(binary, 'fake-ozpb'); assert.equal(args[0], 'dry-run');
      const path = args[args.indexOf('--request') + 1]; temporary.push(path);
      const key = args[args.indexOf('--delegate-key-file') + 1];
      assert.equal(statSync(key).mode & 0o777, 0o600);
      assert.equal(readFileSync(key, 'utf8').trim(), delegate.secret());
      assert.ok(!JSON.stringify(args).includes(delegate.secret()));
      const raw = readFileSync(path, 'utf8'); assert.ok(raw.includes('9223372036854775807'), 'registry integers remain exact');
      const request = JSON.parse(raw); requests.push(request);
      const report = reportFor(request); state.change(report, request);
      return { status: state.exit, stdout: JSON.stringify(report), stderr: delegate.secret() };
    },
  });
  return { dir, env, execute, requests, temporary, state, run };
}
for (const count of [1, 2]) test(`executes every indexed rule with the full spec/bindings (${count} rules) and removes its seed file`, async (t) => {
  const f = fixture(t, count), summary = await f.execute();
  assert.equal(summary.reports.length, count);
  assert.deepEqual(f.requests.map((r) => r.candidate.rule_index), Array.from({ length: count }, (_, i) => i));
  for (const request of f.requests) {
    assert.equal(request.candidate.spec.rules.length, count); assert.equal(request.candidate.binding_set.bindings.length, count);
    assert.equal(request.artifact.rule_index, request.candidate.rule_index);
    assert.match(request.run_nonce, /^[0-9a-f]{64}$/);
  }
  assert.ok(f.temporary.every((p) => p.startsWith(join(f.dir, 'private-secrets')) && !existsSync(p)));
  assert.match(summary.execution, /offline_synthetic/);
  assert.equal(summary.reports[0].complete, false);
  assert.equal(JSON.stringify(summary).includes('fixture'), false);
  await assert.rejects(f.execute(), /already exists/);
});
for (const [name, change] of [
  ['wrong rule', (r) => { r.binding.rule_index = 9; }],
  ['wrong account', (r) => { r.binding.account_address = 'different'; }],
  ['different policy hash', (r) => { r.layers[1].execution.policy_code_hash = H(8); }],
  ['reference failure', (r) => { r.layers[0].status = 'failed'; }],
  ['claimed live execution', (r) => { r.layers[3].status = 'passed'; }],
  ['claimed completion', (r) => { r.complete = true; }],
  ['wrong delegate', (r) => { r.layers[1].execution.delegate_address = 'different'; }],
  ['wrong source ledger', (r) => { r.layers[1].execution.source_ledger++; }],
  ['wrong run hash', (r) => { r.layers[1].execution.run_hash = H(8); }],
  ['changed denial state', (r) => { r.layers[1].execution.cases[1].state_unchanged = false; }],
  ['fewer than five actual denials', (r) => { r.layers[1].execution.cases.pop(); r.layers[1].cases--; }],
  ['missing original', (r) => { r.layers[1].execution.cases[0].class = 'numeric_boundary'; }],
]) test(`refuses ${name}, clears the temporary key, and records no successful inventory`, async (t) => {
  const f = fixture(t); f.state.change = change;
  await assert.rejects(f.execute());
  assert.ok(f.temporary.every((p) => !existsSync(p)));
  assert.equal(existsSync(join(f.dir, 'account-dry-runs.json')), false);
  assert.ok(existsSync(join(f.dir, 'account-dry-run-0.failed.json')));
});
test('a second-rule process failure preserves only the first report and blocks retry', async (t) => {
  const f = fixture(t); f.state.change = (_r, request) => { if (request.candidate.rule_index === 0) f.state.exit = 0; else f.state.exit = 1; };
  await assert.rejects(f.execute(), /dry-run failed/);
  assert.ok(existsSync(join(f.dir, 'account-dry-run-0.json')));
  assert.equal(existsSync(join(f.dir, 'account-dry-run-1.json')), false);
  const failed = join(f.dir, 'account-dry-run-1.failed.json');
  assert.equal(JSON.parse(readFileSync(failed)).binding.rule_index, 1);
  assert.equal(statSync(failed).mode & 0o777, 0o600);
  assert.equal(existsSync(join(f.dir, 'account-dry-runs.json')), false);
  assert.ok(f.temporary.every((p) => !existsSync(p)));
  await assert.rejects(f.execute(), /already exists/);
});
