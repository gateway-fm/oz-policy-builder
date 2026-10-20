import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, Keypair, StrKey, xdr } from '@stellar/stellar-sdk';
import { revokePermissionBundle } from './bundle-cleanup.mjs';
import { contractCall } from './lib.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM, SimulationError } from './rpc.mjs';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const H = (n) => n.toString(16).padStart(64, '0');
function fixture() {
  const spec = JSON.parse(readFileSync(new URL('../native-sac-policy-spec.json', import.meta.url)));
  spec.rules.push(structuredClone(spec.rules[0]));
  const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8));
  const run = { account: spec.smart_account.address, account_code_hash: PINNED_ACCOUNT_WASM, network: NETWORK_PASSPHRASE,
    payer: payer.publicKey(), delegate: spec.rules[0].authorization.signers[0].delegated.address, registry_root: spec.registry_snapshot,
    walkthrough: { bundle: { account: spec.smart_account.address, account_code_hash: PINNED_ACCOUNT_WASM,
      network: NETWORK_PASSPHRASE, spec_hash: H(1), registry_root: spec.registry_snapshot, status: 'incomplete',
      entries: [0, 1].map((rule_index) => ({ rule_index, spec_hash: H(1), wasm_hash: H(10 + rule_index),
        policy: C(20 + rule_index), tx: { install: H(30 + rule_index) },
        installation: { rule_id: rule_index + 8, transaction: H(30 + rule_index), ledger: 100 } })) } } };
  const artifacts = run.walkthrough.bundle.entries.map((entry) => ({ manifest: { rule_index: entry.rule_index,
    spec_hash: entry.spec_hash, wasm_hash: entry.wasm_hash, registry_snapshot: spec.registry_snapshot } }));
  const history = [], sends = [], signs = [], ops = [];
  const controls = {};
  const deps = {
    checkArtifacts: async () => artifacts.map(({ manifest }) => ({ rule_index: manifest.rule_index, spec_hash: manifest.spec_hash,
      wasm_hash: manifest.wasm_hash })),
    inspectGrant: async (_run, _spec, entry) => {
      if (controls.inspectFails === entry.rule_index) throw new Error('grant changed');
      return { configuration: 'matched', rule_index: entry.rule_index, observation: 'non_atomic' };
    },
    loadKey: () => payer, latestLedger: async () => 110,
    assertTestnet: async () => { if (controls.wrongNetwork) throw new Error('not testnet'); },
    contractCodeHash: async (address) => {
      assert.equal(address, run.account);
      return controls.accountUpgraded ? H(99) : PINNED_ACCOUNT_WASM;
    },
    ownerSigner: async () => ({ verifier: C(40), keyData: Buffer.alloc(66, 1), sign: async (digest) => {
      signs.push(digest); return Buffer.alloc(64, 2);
    } }),
    recordAuth: async (_payer, op) => {
      const call = op.body.invokeHostFunctionOp.hostFunction.invokeContract;
      return [new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
          address: new Address(run.account).toScAddress(), nonce: 1n, signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid(),
        })), rootInvocation: contractCall(run.account, controls.wrongAuth ? 'remove_signer' : 'remove_context_rule', call.args),
      })];
    },
    submit: async (_payer, op, options) => {
      const id = op.body.invokeHostFunctionOp.hostFunction.invokeContract.args[0].u32;
      const hash = H(100 + id);
      await options.onSubmitting(hash);
      const latest = history.at(-1).walkthrough.bundle.entries.find((e) => e.installation?.rule_id === id);
      assert.equal(latest.pending_removal.transaction, hash, 'hash retained before send');
      sends.push(id);
      ops.push(op);
      if (controls.ambiguous === id) throw new Error('send status unknown');
      return { hash, receipt: { ledger: 111, fixture_id: id } };
    },
    removalEvent: (_receipt, { ruleId }) => {
      const saved = history.at(-1).walkthrough.bundle.entries.find((e) => e.installation?.rule_id === ruleId);
      assert.equal(saved.removal.transaction, H(100 + ruleId), 'confirmed removal saved before validation');
      if (controls.eventFails === ruleId) throw new Error('event missing');
    },
    viewCall: async (_payer, contract, name) => {
      if (name === 'get_context_rule') {
        if (controls.stillPresent) return xdr.ScVal.scvMap([]);
        if (controls.readbackError === 'other contract code') {
          throw new SimulationError(name, `contract:${contract}, topics:[error, Error(Contract, #3001)], data:["failing with contract error", 3001]`);
        }
        if (controls.readbackError === 'transport') throw new Error('fetch failed');
        throw new SimulationError(name, `contract:${contract}, topics:[error, Error(Contract, #3000)], data:["failing with contract error", 3000]`);
      }
      return xdr.ScVal.scvBool(controls.stillInstalled === contract);
    },
  };
  const execute = () => revokePermissionBundle({ run, spec, artifacts, save: () => history.push(structuredClone(run)) }, deps);
  return { run, spec, artifacts, controls, history, sends, signs, ops, execute };
}
test('bundle cleanup removes every confirmed non-owner grant in reverse order', async () => {
  const f = fixture();
  assert.equal((await f.execute()).status, 'removed');
  assert.deepEqual(f.sends, [9, 8]);
  for (const entry of f.run.walkthrough.bundle.entries) {
    assert.equal(entry.removal.event, 'verified');
    assert.equal(entry.removal.rule_readback, 'absent');
    assert.equal(entry.removal.policy_cleanup, 'not_installed');
    assert.equal(entry.installation.transaction, entry.tx.install);
  }
  await f.execute();
  assert.deepEqual(f.sends, [9, 8], 'confirmed removals are never resubmitted');
});
for (const failure of ['ambiguous send', 'missing event', 'wrong authorization', 'policy cleanup remains', 'unknown second install', 'confirmed unknown rule ID']) {
  test(`bundle cleanup retains incomplete outcomes while cleaning other known grants: ${failure}`, async () => {
    const f = fixture();
    if (failure === 'ambiguous send') f.controls.ambiguous = 9;
    if (failure === 'missing event') f.controls.eventFails = 9;
    if (failure === 'wrong authorization') f.controls.wrongAuth = true;
    if (failure === 'policy cleanup remains') f.controls.stillInstalled = C(21);
    if (failure === 'unknown second install') {
      delete f.run.walkthrough.bundle.entries[1].installation;
      delete f.run.walkthrough.bundle.entries[1].tx.install;
      f.run.walkthrough.bundle.entries[1].pending = { operation: 'install', transaction: H(77), status: 'prepared_for_submission' };
    }
    if (failure === 'confirmed unknown rule ID') f.run.walkthrough.bundle.entries[1].installation.rule_id = null;
    assert.equal((await f.execute()).status, 'incomplete');
    if (failure !== 'wrong authorization') assert.equal(f.run.walkthrough.bundle.entries[0].removal.rule_readback, 'absent');
    else assert.equal(f.signs.length, 0);
    if (failure === 'ambiguous send') assert.equal(f.run.walkthrough.bundle.entries[1].pending_removal.transaction, H(109));
    if (failure === 'missing event') assert.equal(f.run.walkthrough.bundle.entries[1].removal.transaction, H(109));
    const count = f.sends.length;
    await f.execute();
    assert.equal(f.sends.length, count, 'known hash or unsuccessful cleanup attempt must prevent another send');
  });
}
for (const field of ['account', 'account_code_hash', 'network', 'spec_hash', 'registry_root', 'installation hash', 'owner rule', 'policy hash']) {
  test(`cleanup refuses mutated recorded bundle identity before signing: ${field}`, async () => {
    const f = fixture(), b = f.run.walkthrough.bundle;
    if (['account', 'account_code_hash', 'network', 'spec_hash', 'registry_root'].includes(field)) b[field] = 'different';
    if (field === 'installation hash') b.entries[1].installation.transaction = H(99);
    if (field === 'owner rule') b.entries[1].installation.rule_id = 0;
    if (field === 'policy hash') b.entries[1].wasm_hash = H(99);
    await assert.rejects(f.execute());
    assert.equal(f.sends.length, 0);
    assert.equal(f.signs.length, 0);
  });
}

test('a readback mismatch before removal still removes the journaled rule ID from our confirmed install', async () => {
  // Rule IDs come from the account's monotonic counter and are never reused.
  const f = fixture();
  f.controls.inspectFails = 1;
  assert.equal((await f.execute()).status, 'removed');
  assert.deepEqual(f.sends, [9, 8]);
  assert.deepEqual(f.run.walkthrough.bundle.entries[1].removal.before, { configuration: 'mismatch_or_unavailable' });
  assert.equal(f.run.walkthrough.bundle.entries[0].removal.before.configuration, 'matched');
});
test('an attempt that prepared nothing can be retried; a sent removal never is', async () => {
  const f = fixture();
  f.controls.wrongAuth = true;
  assert.equal((await f.execute()).status, 'incomplete');
  assert.deepEqual(f.sends, []);
  f.controls.wrongAuth = false;
  assert.equal((await f.execute()).status, 'removed');
  assert.deepEqual(f.sends, [9, 8]);
});
for (const mode of ['still present', 'other contract code', 'transport']) {
  test(`only the account's missing-rule error counts as an absent readback: ${mode}`, async () => {
    const f = fixture();
    if (mode === 'still present') f.controls.stillPresent = true;
    else f.controls.readbackError = mode;
    assert.equal((await f.execute()).status, 'incomplete');
    for (const entry of f.run.walkthrough.bundle.entries) {
      assert.equal(entry.removal.rule_readback, mode === 'still present' ? 'still_present' : 'not_checked');
      assert.equal(entry.cleanup_attempt.status, 'incomplete');
    }
  });
}
test('the owner signs each removal through its own rule 0, not the removed rule', async () => {
  const f = fixture();
  await f.execute();
  for (const op of f.ops) {
    const signature = op.body.invokeHostFunctionOp.auth[0].credentials.address.signature;
    const ids = signature.map.find((e) => e.key.sym.toString() === 'context_rule_ids').val.vec.map((v) => v.u32);
    assert.deepEqual(ids, [0]);
  }
});

for (const mode of ['wrong network', 'upgraded account code']) {
  test(`cleanup signs nothing when the network or account identity fails: ${mode}`, async () => {
    // Rule IDs are only known not to be reused by the pinned account implementation.
    const f = fixture();
    if (mode === 'wrong network') f.controls.wrongNetwork = true;
    else f.controls.accountUpgraded = true;
    assert.equal((await f.execute()).status, 'incomplete');
    assert.equal(f.signs.length, 0);
    assert.deepEqual(f.sends, []);
    for (const entry of f.run.walkthrough.bundle.entries) {
      assert.equal(entry.removal, undefined);
      assert.equal(entry.cleanup_attempt.status, 'incomplete');
    }
  });
}
