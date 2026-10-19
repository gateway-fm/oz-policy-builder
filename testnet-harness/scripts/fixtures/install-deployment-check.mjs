// Execute the actual installer with local transaction results and an approval test double.
// Verify the persisted checkpoint before approval/signing and the final success/refusal state.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import * as sdk from '@stellar/stellar-sdk';
import * as lib from '../lib.mjs';
import { signedRuleArgs } from '../approve-install.mjs';
import { cliSpecHash } from '../check-runner.mjs';

const mode = process.argv[2];
const readbackFailure = process.argv[3];
const succeeds = mode === 'approved' || mode === 'default';
const sourceUrl = new URL('../install.mjs', import.meta.url);
const dir = mkdtempSync(join(tmpdir(), 'ozpb-deployment-test-'));
try {
  const spec = JSON.parse(readFileSync(new URL('../../native-sac-policy-spec.json', import.meta.url), 'utf8'));
  spec.registry_snapshot = '1'.repeat(64);
  const rule = spec.rules[0];
  const account = spec.smart_account.address;
  const payer = rule.authorization.signers[0].delegated.address;
  const policy = sdk.StrKey.encodeContract(Buffer.alloc(32, 42));
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const wasmHash = createHash('sha256').update(wasm).digest('hex');
  const runPath = join(dir, 'run.json');
  const readRun = () => JSON.parse(readFileSync(runPath, 'utf8'));
  const writeJson = (path, value) => writeFileSync(path, JSON.stringify(value));
  writeJson(join(dir, 'spec.json'), spec);
  writeFileSync(join(dir, 'policy.wasm'), wasm);
  writeJson(join(dir, 'build-manifest.json'), {
    wasm_hash: wasmHash, rule_index: 0, registry_snapshot: spec.registry_snapshot,
    spec_hash: await cliSpecHash(spec),
  });
  writeJson(join(dir, 'registry.json'), {});
  writeJson(runPath, { account, spec: join(dir, 'spec.json'), owner: { kind: 'ed25519', address: payer },
    policy: 'old-policy', rule_id: 99, authority_check: { old: true },
    tx: { setup: 'setup-tx', add_context_rule: 'old-install' } });
  const deploymentSaved = () => {
    const run = readRun();
    assert.equal(run.policy, policy);
    assert.equal(run.policy_wasm_hash, wasmHash);
    assert.deepEqual(run.tx, { setup: 'setup-tx', upload_policy: 'upload-tx', create_policy: 'create-tx' });
    assert.equal(run.rule_id, undefined);
    assert.equal(run.authority_check?.old, undefined);
  };
  let approvals = 0;
  let signatures = 0;
  const stages = [];
  const readbacks = [];
  const approveInstall = async () => {
    approvals++;
    deploymentSaved();
    if (!succeeds) return { approved: false, reasons: [mode === 'declined' ? 'the operator declined' : 'untrusted owner'] };
    return { approved: true, commitment: 'fixture-commitment', evidence: { rechecked_at_ledger: 10 }, args: {
      account, context: rule.context.contract, name: spec.name, validUntil: rule.valid_until.ledger,
      signers: rule.authorization.signers.map((s) => ({ kind: 'delegated', address: s.delegated.address })),
      policies: [{ address: policy, install_params: { kind: 'generated' } }],
    } };
  };
  const rpc = {
    NETWORK_PASSPHRASE: sdk.Networks.TESTNET, log: () => {}, writeJson,
    args: () => ({ 'run-dir': dir, wasm: join(dir, 'policy.wasm'),
      ...(mode === 'default' ? {} : { 'authority-check': 'cli', confirm: 'operator' }) }),
    readJson: (path) => JSON.parse(readFileSync(path, 'utf8')),
    loadKey: () => ({ publicKey: () => payer }), assertTestnet: async () => {},
    contractCodeHash: async () => wasmHash, contractIdOf: () => policy, latestLedger: async () => 10,
    recordAuth: async () => { deploymentSaved(); return [{}]; },
    submit: async (_payer, _operation, { stage }) => {
      stages.push(stage);
      if (stage === 'upload policy wasm') return { hash: 'upload-tx', returnValue: sdk.xdr.ScVal.scvBytes(Buffer.from(wasmHash, 'hex')) };
      if (stage === 'create policy') return { hash: 'create-tx', returnValue: null };
      assert.equal(stage, 'add_context_rule');
      return { hash: 'install-tx', returnValue: sdk.nativeToScVal({ id: 7, name: spec.name }) };
    },
    viewCall: async (_payer, _contract, fn) => {
      readbacks.push(fn);
      const checkpoint = readRun();
      assert.equal(checkpoint.rule_id, 7, 'confirmed rule must be saved before any readback');
      assert.equal(checkpoint.tx.add_context_rule, 'install-tx');
      if (readbackFailure === fn) throw new Error('fixture readback failure');
      return fn === 'is_installed' ? sdk.xdr.ScVal.scvBool(readbackFailure !== 'not_installed') : sdk.xdr.ScVal.scvU32(1);
    },
  };
  const context = vm.createContext({ Buffer, process: { env: {
    ...process.env, OZPB_BIN: 'unused-authority-runner', OZPB_REGISTRY_ROOTS_FILE: 'unused-roots',
    OZPB_REGISTRY_MIN_VERSION: '1', OZPB_RPC_SOURCES_FILE: 'unused-sources',
    OZPB_SIGNED_REGISTRY_SNAPSHOT: join(dir, 'registry.json'),
  } } });
  const module = new vm.SourceTextModule(readFileSync(sourceUrl, 'utf8'), { context });
  await module.link(async (name) => {
    const exports = name === './rpc.mjs' ? rpc
      : name === './owner.mjs' ? { ownerSigner: async () => ({}) }
      : name === './approve-install.mjs' ? { approveInstall, signedRuleArgs }
      : name === './lib.mjs' ? { ...lib, entryAddress: () => account,
        signForSmartAccount: async () => { signatures++; return {}; } }
      : name === '@stellar/stellar-sdk' ? sdk
      : await import(name.startsWith('.') ? new URL(name, sourceUrl) : name);
    return new vm.SyntheticModule(Object.keys(exports), function () {
      for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    }, { context });
  });
  if (succeeds && readbackFailure) {
    await assert.rejects(module.evaluate(), readbackFailure === 'not_installed'
      ? /policy does not report itself installed/ : /fixture readback failure/);
  } else if (succeeds) await module.evaluate();
  else await assert.rejects(module.evaluate(), /nothing was signed/);
  const saved = readRun();
  assert.equal(approvals, mode === 'default' ? 0 : 1);
  assert.equal(signatures, succeeds ? 1 : 0);
  assert.equal(stages.length, succeeds ? 3 : 2);
  assert.equal(saved.policy, policy);
  assert.equal(saved.rule_id, succeeds ? 7 : undefined);
  assert.equal(saved.tx.add_context_rule, succeeds ? 'install-tx' : undefined);
  assert.deepEqual(readbacks, !succeeds ? [] : readbackFailure === 'is_installed'
    ? ['is_installed'] : ['is_installed', 'remaining_calls']);
  if (!succeeds) {
    deploymentSaved();
    assert.deepEqual(saved.authority_check.refused, [mode === 'declined' ? 'the operator declined' : 'untrusted owner']);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
