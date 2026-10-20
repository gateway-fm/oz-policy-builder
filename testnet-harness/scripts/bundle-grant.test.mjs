import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, StrKey, xdr } from '@stellar/stellar-sdk';
import { inspectBundleGrant } from './bundle-grant.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM } from './rpc.mjs';
const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const A = (value) => new Address(value).toScVal();
function fixture(index) {
  const spec = structuredClone(capture.synthesis.spec), rule = spec.rules[index];
  const run = { network: NETWORK_PASSPHRASE, account: spec.smart_account.address, account_code_hash: PINNED_ACCOUNT_WASM,
    payer: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 7)), delegate: rule.authorization.signers[0].delegated.address };
  const entry = { rule_index: index, policy: C(30 + index), wasm_hash: 'aa'.repeat(32),
    installation: { rule_id: 8 + index, transaction: 'bb'.repeat(32) } };
  const fields = {
    id: xdr.ScVal.scvU32(entry.installation.rule_id),
    context_type: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'), A(rule.context.contract)]),
    name: xdr.ScVal.scvString(spec.name), valid_until: xdr.ScVal.scvU32(rule.valid_until.ledger),
    signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'), A(run.delegate)])]),
    policies: xdr.ScVal.scvVec([A(entry.policy)]),
  };
  const control = {}, reads = [];
  const deps = {
    assertTestnet: async () => {},
    contractCodeObservation: async (address) => {
      reads.push(address);
      return { value: address === run.account ? (control.accountCode ?? run.account_code_hash)
        : (control.policyCode ?? entry.wasm_hash), ledger: 101 + reads.length };
    },
    viewCallObservation: async (payer, contract, fn, args) => {
      assert.equal(payer.publicKey(), run.payer);
      if (fn === 'get_context_rule') {
        assert.equal(contract, run.account);
        assert.equal(args[0].u32, entry.installation.rule_id);
        const map = Object.entries(fields).sort(([a], [b]) => a.localeCompare(b))
          .map(([key, val]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val }));
        if (control.duplicate) map.push(map[0]);
        return { value: xdr.ScVal.scvMap(map), ledger: 104 };
      }
      assert.equal(contract, entry.policy);
      assert.equal(fn, 'is_installed');
      assert.equal(args[0].u32, entry.installation.rule_id);
      assert.equal(Buffer.from(args[1].toXDR()).toString('hex'), Buffer.from(A(run.account).toXDR()).toString('hex'));
      return { value: xdr.ScVal.scvBool(!control.uninstalled), ledger: 105 };
    },
  };
  return { run, entry, fields, control, execute: () => inspectBundleGrant(run, spec, entry, deps) };
}
for (const index of [0, 1]) {
  test(`readback checks exact indexed protocol grant ${index} with separate observation ledgers`, async () => {
    const f = fixture(index);
    assert.deepEqual(await f.execute(), { rule_index: index, rule_id: index + 8, configuration: 'matched',
      observation: 'non_atomic', read_ledgers: { account: 102, policy: 103, rule: 104, installed: 105 } });
  });
}
for (const kind of ['account code', 'policy code', 'rule ID', 'context', 'name', 'expiry', 'signers', 'policies', 'duplicate field', 'not installed', 'owner rule']) {
  test(`grant readback rejects ${kind} substitution`, async () => {
    const f = fixture(1);
    if (kind === 'account code') f.control.accountCode = 'cc'.repeat(32);
    if (kind === 'policy code') f.control.policyCode = 'cc'.repeat(32);
    if (kind === 'rule ID') f.fields.id = xdr.ScVal.scvU32(0);
    if (kind === 'context') f.fields.context_type.vec[1] = A(C(40));
    if (kind === 'name') f.fields.name = xdr.ScVal.scvString('foreign');
    if (kind === 'expiry') f.fields.valid_until = xdr.ScVal.scvVoid();
    if (kind === 'signers') f.fields.signers = xdr.ScVal.scvVec([]);
    if (kind === 'policies') f.fields.policies = xdr.ScVal.scvVec([A(C(40))]);
    if (kind === 'duplicate field') f.control.duplicate = true;
    if (kind === 'not installed') f.control.uninstalled = true;
    if (kind === 'owner rule') f.entry.installation.rule_id = 0;
    await assert.rejects(f.execute());
  });
}
