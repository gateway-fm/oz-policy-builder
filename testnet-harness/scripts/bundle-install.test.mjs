import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, Keypair, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import { installPermissionBundle } from './bundle-install.mjs';
import { decide, walletTrust } from './wallet-decision.mjs';
import { contractCall } from './lib.mjs';
import { RawJson } from './raw-json.mjs';
const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const hash = (n) => n.toString(16).padStart(64, '0');
function fixture() {
  const { plan, record, synthesis } = structuredClone(capture);
  // Unit fixture: the original capture remains a read-only simulation, not a live execution.
  record.bundle.execution = 'executed_success';
  const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 9));
  const run = { network: 'Test SDF Network ; September 2015', account: plan.account, payer: payer.publicKey(),
    account_code_hash: synthesis.spec.smart_account.observed_code_hash,
    delegate: synthesis.spec.rules[0].authorization.signers[0].delegated.address,
    registry_root: synthesis.spec.registry_snapshot, walkthrough: plan };
  const spec = synthesis.spec;
  const artifacts = spec.rules.map((_r, rule_index) => {
    const wasm = Buffer.from(`unit wasm ${rule_index}`);
    return { wasm, manifest: { rule_index, spec_hash: synthesis.spec_hash,
      registry_snapshot: spec.registry_snapshot, wasm_hash: createHash('sha256').update(wasm).digest('hex') } };
  });
  const policies = [C(20), C(21)];
  const history = [], sends = [], approvals = [], signatures = [];
  let counter = 0, createIndex = 0, codeChecks = 0;
  const controls = {};
  const owner = { verifier: C(22), keyData: Buffer.alloc(66, 7), sign: async (digest) => {
    signatures.push(Buffer.from(digest)); return Buffer.alloc(64, 1);
  } };
  const deps = {
    hashSpec: async () => synthesis.spec_hash, assertTestnet: async () => {}, loadKey: () => payer,
    ownerSigner: async () => owner, log: () => {},
    latestLedger: async () => controls.expired ? spec.rules[0].valid_until.ledger : record.bundle.ledger + 10,
    contractCodeHash: async (address) => address === run.account ? run.account_code_hash
      : controls.wrongDeployedCode ? hash(99)
        // One address deployed twice must reach the duplicate check, not the code check.
        : controls.samePolicy ? artifacts[codeChecks++].manifest.wasm_hash : artifacts[policies.indexOf(address)].manifest.wasm_hash,
    approveInstall: async (args) => {
      approvals.push(args);
      const i = args.request.rule_index;
      if (controls.refuseSecond && i === 1) return { approved: false, reasons: ['fixture refused'] };
      const result = { account: run.account, context: spec.rules[i].context.contract, name: spec.name,
        validUntil: spec.rules[i].valid_until.ledger, signers: [{ kind: 'delegated', address: run.delegate }],
        policies: [{ address: policies[i], install_params: { kind: 'generated' } }] };
      if (controls.mutateIntent) result.context = C(30);
      return { approved: true, args: result, commitment: hash(100 + i),
        evidence: { authority_commitment: hash(100 + i), rechecked_at_ledger: record.bundle.ledger + 10 } };
    },
    recordAuth: async (_payer, op) => {
      const call = op.body.invokeHostFunctionOp.hostFunction.invokeContract;
      const root = contractCall(run.account, 'add_context_rule', call.args);
      if (controls.extraChild) root.subInvocations = [contractCall(C(30), 'transfer', [])];
      return [new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
          address: new Address(run.account).toScAddress(), nonce: 1n, signatureExpirationLedger: 0,
          signature: xdr.ScVal.scvVoid(),
        })), rootInvocation: root,
      })];
    },
    submit: async (_payer, op, options) => {
      const tx = hash(++counter);
      await options.onSubmitting(tx);
      const confirmed = controls.hashSwap ? hash(98) : tx;
      const pending = history.at(-1).walkthrough.bundle.entries.find((entry) => entry.pending?.transaction === tx);
      assert.ok(pending, 'public transaction hash is saved before every network send');
      sends.push({ op, tx, stage: options.stage });
      if (controls.failSend && counter === controls.failSend) throw new Error('ambiguous send');
      const host = op.body.invokeHostFunctionOp.hostFunction;
      if (host.type === 'hostFunctionTypeUploadContractWasm') {
        return { hash: confirmed, returnValue: xdr.ScVal.scvBytes(controls.wrongUpload ? Buffer.alloc(32, 9)
          : createHash('sha256').update(host.wasm).digest()) };
      }
      if (host.type === 'hostFunctionTypeCreateContractV2') {
        return { hash: confirmed, returnValue: new Address(policies[controls.samePolicy ? 0 : createIndex++]).toScVal() };
      }
      const args = host.invokeContract.args;
      const id = controls.duplicateRuleId ? 8 : 7 + approvals.length;
      return { hash: confirmed, receipt: { ledger: record.bundle.ledger + 11 }, returnValue: xdr.ScVal.scvMap([
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('id'), val: xdr.ScVal.scvU32(controls.ownerRule ? 0 : id) }),
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('name'), val: args[1] }),
      ]) };
    },
    inspectGrant: async (_run, _spec, entry) => {
      assert.ok(history.at(-1).walkthrough.bundle.entries[entry.rule_index].installation?.transaction,
        'confirmed install is saved before any readback');
      if (controls.failReadback) throw new Error('readback failed');
      return { configuration: 'matched', observation: 'non_atomic' };
    },
  };
  const checker = { runner: {}, trust: {}, signedRegistrySnapshot: new RawJson('{}'), rpcSource: 'testnet',
    confirm: async () => true };
  const execute = () => installPermissionBundle({ run, spec, artifacts, recording: record, checker,
    save: () => history.push(structuredClone(run)) }, deps);
  return { run, spec, artifacts, controls, sends, approvals, signatures, history, execute };
}
test('bundle installation deploys every artifact then checks and signs each exact indexed grant', async () => {
  const f = fixture();
  const result = await f.execute();
  assert.equal(result.status, 'installed');
  assert.equal(f.sends.length, 6);
  assert.equal(f.signatures.length, 2);
  assert.deepEqual(result.entries.map((e) => [e.rule_index, e.installation.rule_id]), [[0, 8], [1, 9]]);
  for (const [i, approval] of f.approvals.entries()) {
    assert.equal(approval.request.spec, f.spec);
    assert.equal(approval.request.rule_index, i);
    assert.deepEqual(approval.request.binding_set.bindings.map((b) => b.rule_index), [0, 1]);
  }
  for (const { op } of f.sends.slice(-2)) {
    const body = op.body.invokeHostFunctionOp;
    const auth = body.auth[0].credentials.address.signature;
    assert.deepEqual(scValToNative(auth).context_rule_ids, [0], 'owner alone authorizes installation');
    assert.deepEqual(body.auth[0].rootInvocation.subInvocations, []);
    xdr.Operation.fromXDR(op.toXDR());
  }
});
test('wallet expectation matches the scope a bundle check answers: every bound policy, this rule target', async () => {
  // Shape observed from the CLI on testnet: a bundle request's verdict covers all bindings.
  const f = fixture();
  await f.execute();
  for (const [i, { request, expect }] of f.approvals.entries()) {
    const bound = request.binding_set.bindings.map((b) => b.contract_address);
    const target = f.spec.rules[i].context.contract;
    const verdict = { account_address: expect.account, network_id: expect.networkId, bound_policy_addresses: bound,
      grant: { target, rule_index: i, valid_until: null }, scope: { targets: [target], account: expect.account, bound_policies: bound },
      spec_hash: expect.specHash };
    const check = { verdict, spec_hash: expect.specHash, registry_snapshot_root: expect.registrySnapshotRoot };
    const { reasons } = decide(check, { trust: walletTrust({ own: [], operator: [] }), expect });
    // Only identity mismatches matter here; the fixture verdict has no authority entries.
    assert.deepEqual(reasons.filter((r) => r.startsWith('the answer is about')), []);
  }
});
for (const kind of ['partial install refusal', 'unconfirmed send', 'readback failure', 'intent substitution', 'nested authorization', 'owner rule response']) {
  test(`bundle retains exact partial state and refuses automatic retry: ${kind}`, async () => {
    const f = fixture();
    if (kind === 'partial install refusal') f.controls.refuseSecond = true;
    if (kind === 'unconfirmed send') f.controls.failSend = 6;
    if (kind === 'readback failure') f.controls.failReadback = true;
    if (kind === 'intent substitution') f.controls.mutateIntent = true;
    if (kind === 'nested authorization') f.controls.extraChild = true;
    if (kind === 'owner rule response') f.controls.ownerRule = true;
    const expected = {
      'partial install refusal': /did not approve/, 'unconfirmed send': /ambiguous send/,
      'readback failure': /readback failed/, 'intent substitution': /not the rule this spec asks for/,
      'nested authorization': /not the intended call/, 'owner rule response': /invalid or duplicate installed/,
    };
    await assert.rejects(f.execute(), expected[kind]);
    const bundle = f.run.walkthrough.bundle;
    assert.equal(bundle.status, 'incomplete');
    if (kind === 'partial install refusal' || kind === 'unconfirmed send' || kind === 'readback failure') {
      assert.ok(bundle.entries[0].installation.transaction);
      assert.equal(bundle.entries[0].installation.rule_id, 8);
    }
    if (kind === 'unconfirmed send') {
      assert.equal(bundle.entries[1].pending.transaction, hash(6));
      assert.equal(bundle.entries[1].pending.operation, 'install');
    }
    if (kind === 'intent substitution' || kind === 'nested authorization') assert.equal(f.signatures.length, 0);
    if (kind === 'owner rule response') {
      assert.equal(bundle.entries[0].installation.transaction, hash(5), 'known confirmed transaction survives invalid returned ID');
      assert.equal(bundle.entries[0].installation.rule_id, null);
    }
    const before = f.sends.length;
    await assert.rejects(f.execute(), /already/);
    assert.equal(f.sends.length, before);
  });
}
for (const kind of ['mutated wasm', 'missing child spec', 'foreign account', 'previous journal']) {
  test(`invalid bundle fails before loading keys or sending: ${kind}`, async () => {
    const f = fixture();
    if (kind === 'mutated wasm') f.artifacts[1].wasm = Buffer.from('wrong');
    if (kind === 'missing child spec') { f.spec.rules.pop(); f.artifacts.pop(); }
    if (kind === 'foreign account') f.run.account = C(31);
    if (kind === 'previous journal') f.run.walkthrough.bundle = {};
    await assert.rejects(f.execute());
    assert.equal(f.sends.length, 0);
    assert.equal(f.signatures.length, 0);
  });
}

const sendKinds = (f) => f.sends.map((send) => send.op.body.invokeHostFunctionOp.hostFunction.type);
for (const [kind, pattern] of [['grant expired before signing', /expired before signing/], ['deployed code differs', /deployed code/],
  ['uploaded Wasm differs', /uploaded Wasm/], ['confirmed hash differs from the journal', /differs from journaled submission/],
  ['same policy deployed twice', /duplicate deployed bundle policy/], ['rule ID returned twice', /invalid or duplicate installed/]]) {
  test(`bundle installation stops before the next step: ${kind}`, async () => {
    const f = fixture();
    if (kind === 'grant expired before signing') f.controls.expired = true;
    if (kind === 'deployed code differs') f.controls.wrongDeployedCode = true;
    if (kind === 'uploaded Wasm differs') f.controls.wrongUpload = true;
    if (kind === 'confirmed hash differs from the journal') f.controls.hashSwap = true;
    if (kind === 'same policy deployed twice') f.controls.samePolicy = true;
    if (kind === 'rule ID returned twice') f.controls.duplicateRuleId = true;
    await assert.rejects(f.execute(), pattern);
    const entries = f.run.walkthrough.bundle.entries;
    assert.equal(f.run.walkthrough.bundle.status, 'incomplete');
    if (kind === 'grant expired before signing') {
      assert.equal(f.signatures.length, 0);
      assert.equal(sendKinds(f).includes('hostFunctionTypeInvokeContract'), false);
    }
    if (['deployed code differs', 'uploaded Wasm differs', 'confirmed hash differs from the journal', 'same policy deployed twice'].includes(kind)) {
      assert.equal(f.approvals.length, 0);
    }
    if (kind === 'uploaded Wasm differs' || kind === 'confirmed hash differs from the journal') assert.deepEqual(sendKinds(f), ['hostFunctionTypeUploadContractWasm']);
    if (kind === 'confirmed hash differs from the journal') assert.equal(entries[0].pending.transaction, hash(1));
    if (kind === 'rule ID returned twice') {
      assert.equal(entries[0].installation.rule_id, 8);
      assert.equal(entries[1].installation.rule_id, null);
      assert.ok(entries[1].installation.transaction);
    }
  });
}
