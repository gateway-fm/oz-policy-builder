import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { fixture } from './approval-fixture.mjs';
import { ACCOUNT_WASM, NETWORK_ID } from '../shared/approval.mjs';
import { WalletToolchain } from '../server/toolchain.mjs';

function setup(t, change = () => {}, pipeline) {
  const root = mkdtempSync(join(tmpdir(), 'ozpb-wallet-tools-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const account = fixture().wallet.contractId;
  const record = { recording_hash: '1'.repeat(64), trust: 'rpc_reported', bundle: {
    network_id: NETWORK_ID, ledger: 100, execution: 'executed_success',
    contract_executables: { [account]: { executable: { wasm: { code_hash: ACCOUNT_WASM } }, observed_ledger: 101 } },
    authorizations: [{ authorizer: account, nonce: 1, root: { call: { contract: {
      contract: fixture().expected.target, fn_name: 'transfer', args: [{ address: account }, { address: account }, { i128: '1' }],
    } }, sub_invocations: [] } }],
  } };
  change(record);
  const calls = [];
  const raw = JSON.stringify(record).replace('"nonce":1', '"nonce":9223372036854775807');
  const runner = async (executable, args) => {
    calls.push({ executable, args });
    return args[0] === 'record' ? raw : JSON.stringify(await pipeline(args));
  };
  const toolchain = new WalletToolchain({ executable: '/fixed/ozpb', workRoot: root,
    rpcUrl: 'https://example.invalid/rpc', registrySnapshot: '{"valid_until":9223372036854775807}',
    registryRoots: '{}', registryMinimumVersion: 3, runner });
  return { toolchain, root, account, calls, raw };
}

test('wallet recording keeps exact raw integer bytes and only fixed operator RPC arguments', async (t) => {
  const { toolchain, account, calls, raw } = setup(t);
  const value = await toolchain.record({ transactionHash: '2'.repeat(64), accountAddress: account });
  assert.match(value.recordId, /^[0-9a-f]{64}$/);
  assert.equal(value.recordingHash, '1'.repeat(64));
  assert.equal(value.accountAddress, account);
  assert.equal(value.authorizations[0].nonce, '9223372036854775807');
  assert.equal(readFileSync(toolchain.recordFile(value.recordId), 'utf8'), raw);
  assert.deepEqual(calls, [{ executable: '/fixed/ozpb', args: ['record', '--tx-hash', '2'.repeat(64),
    '--rpc-url', 'https://example.invalid/rpc', '--network', 'Test SDF Network ; September 2015'] }]);
  assert.ok(!JSON.stringify(value).includes('/ozpb-wallet-tools-'));
});

function generatedPipeline(account, delegate, mutate = () => {}) {
  const specHash = '3'.repeat(64);
  const normalized = '4'.repeat(64);
  const spec = { network_id: NETWORK_ID, smart_account: { address: account, observed_code_hash: ACCOUNT_WASM },
    registry_snapshot: '5'.repeat(64), rules: [{ valid_until: { ledger: 200 },
      authorization: { signers: [{ delegated: { address: delegate } }] },
      policies: [{ generated: { kind: 'gen:scope+count' } }],
      state: [{ call_count_per_installation: { max_calls: 1 } }],
    }] };
  const wasm = Buffer.from([0,97,115,109,1,0,0,0]);
  const wasmHash = createHash('sha256').update(wasm).digest('hex');
  const manifest = { wasm_hash: wasmHash, spec_hash: specHash, registry_snapshot: spec.registry_snapshot,
    rule_index: 0, normalized_input_hash: normalized };
  const results = {
    synthesize: { spec, spec_hash: specHash, questions: [] },
    'reference-suite': { report: { spec_hash: specHash }, all_agree: true, disagreements: 0, total: 30,
      missing_classes: [], unmodeled_reviewed_policies: [] },
    generate: { files: Object.fromEntries(['Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'rustfmt.toml',
      'src/contract.rs', 'src/lib.rs'].map((name) => [name, 'fixture'])),
      build_manifest: manifest, wasm_hash: wasmHash, wasm_base64: wasm.toString('base64') },
    verify: { matches: true, models_all_policies: true, unmodeled_reviewed_policies: [],
      normalized_input_hash: normalized, offline_behavioral_conformance: 'pass: 30 constraint-derived cases all agree',
      spec_conformance: 'conforms (validated PolicySpec v1)',
      source_reproduction: 'reproduced: generated non-lock files are byte-identical',
      wasm_reproduction: 'reproduced: Wasm and BuildManifest are identical' },
  };
  mutate(results);
  return async ([command]) => results[command];
}

test('generation retains bounded reproduced artifacts without claiming runtime acceptance', async (t) => {
  const account = fixture().wallet.contractId;
  const delegate = Keypair.random().publicKey();
  const { toolchain } = setup(t, undefined, generatedPipeline(account, delegate));
  const recorded = await toolchain.record({ transactionHash: '2'.repeat(64), accountAddress: account });
  const result = await toolchain.generate({ recordId: recorded.recordId, delegateAddress: delegate,
    validUntilLedger: 200, maxCalls: 1, grantName: 'wallet-grant', currentLedger: 101 });
  assert.equal(result.verification.matches, true);
  assert.equal(result.complete, undefined);
  assert.match(result.limitations[0], /do not constitute a complete four-layer/);
  assert.equal(Object.isFrozen(toolchain.artifact(result.artifactId).response), true);
});

for (const failure of ['source reproduction', 'wasm reproduction', 'spec conformance', 'path traversal', 'wrong wasm', 'unmodeled']) {
  test(`generation refuses ${failure} even when matches is asserted`, async (t) => {
    const account = fixture().wallet.contractId;
    const delegate = Keypair.random().publicKey();
    const pipeline = generatedPipeline(account, delegate, (results) => {
      if (failure === 'source reproduction') results.verify.source_reproduction = 'not checked';
      if (failure === 'wasm reproduction') results.verify.wasm_reproduction = 'not checked';
      if (failure === 'spec conformance') results.verify.spec_conformance = 'not checked';
      if (failure === 'path traversal') results.generate.files['../outside'] = 'injected';
      if (failure === 'wrong wasm') results.generate.wasm_hash = 'f'.repeat(64);
      if (failure === 'unmodeled') results['reference-suite'].unmodeled_reviewed_policies = [{ reason: 'unsupported' }];
    });
    const { toolchain } = setup(t, undefined, pipeline);
    const recorded = await toolchain.record({ transactionHash: '2'.repeat(64), accountAddress: account });
    await assert.rejects(() => toolchain.generate({ recordId: recorded.recordId, delegateAddress: delegate,
      validUntilLedger: 200, maxCalls: 1, grantName: 'wallet-grant', currentLedger: 101 }), /refused/);
  });
}

for (const change of ['network', 'account code', 'missing account', 'failed', 'ambiguous']) {
  test(`recording refuses ${change} before making an installable artifact`, async (t) => {
    const { toolchain, account } = setup(t, (record) => {
      if (change === 'network') record.bundle.network_id = '0'.repeat(64);
      if (change === 'account code') Object.values(record.bundle.contract_executables)[0].executable.wasm.code_hash = '0'.repeat(64);
      if (change === 'missing account') record.bundle.contract_executables = {};
      if (change === 'failed') record.bundle.execution = 'executed_failed';
      if (change === 'ambiguous') record.bundle.authorizations.push(record.bundle.authorizations[0]);
    });
    await assert.rejects(() => toolchain.record({ transactionHash: '2'.repeat(64), accountAddress: account }), /refused/);
  });
}

test('bad caller identifiers and unbounded decisions never become process arguments', async (t) => {
  const { toolchain, account, calls } = setup(t);
  await assert.rejects(() => toolchain.record({ transactionHash: '../secret', accountAddress: account }), /refused/);
  assert.equal(calls.length, 0);
  const record = await toolchain.record({ transactionHash: '2'.repeat(64), accountAddress: account });
  for (const delta of [{ recordId: '../file' }, { maxCalls: 0 }, { maxCalls: 10001 }, { validUntilLedger: 99 },
    { delegateAddress: account }, { grantName: '../crate' }, { grantName: 'a'.repeat(21) }]) {
    await assert.rejects(() => toolchain.generate({ recordId: record.recordId, delegateAddress: Keypair.random().publicKey(),
      validUntilLedger: 200, maxCalls: 1, grantName: 'wallet-grant', currentLedger: 101, ...delta }), /refused/);
  }
  assert.equal(calls.length, 1);
});
