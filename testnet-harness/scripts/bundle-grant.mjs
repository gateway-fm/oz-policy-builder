// Exact per-rule readback for independently installed protocol capabilities.
import assert from 'node:assert/strict';
import { Address, scValToNative, xdr } from '@stellar/stellar-sdk';
import { addContextRuleArgs } from './lib.mjs';
import * as rpc from './rpc.mjs';
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected bundle ${field}`);
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const hex = (v) => Buffer.from(v.toXDR()).toString('hex');

export function bundleGrantDescription(run, spec, entry) {
  same(run.network, rpc.NETWORK_PASSPHRASE, 'network');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  same(spec.smart_account?.address, run.account, 'account');
  same(spec.smart_account?.observed_code_hash, run.account_code_hash, 'spec account pin');
  requireThat(Number.isInteger(entry.rule_index) && entry.rule_index >= 0 && entry.rule_index < spec.rules.length,
    'invalid bundle rule index');
  const rule = spec.rules[entry.rule_index];
  same(rule.context.type, 'CallContract', 'context');
  same(rule.authorization, { kind: 'any_of', strict_signer_set: true,
    signers: [{ delegated: { address: run.delegate } }] }, 'delegate');
  requireThat(rule.policies.length === 1 && rule.policies[0].generated?.kind === 'gen:scope+count',
    'unsupported bundle policy');
  return { context: rule.context.contract, name: spec.name, validUntil: rule.valid_until?.ledger,
    signers: [{ kind: 'delegated', address: run.delegate }],
    policies: [{ address: entry.policy, install_params: { kind: 'generated' } }] };
}

export async function inspectBundleGrant(run, spec, entry, deps = rpc) {
  const expected = addContextRuleArgs(bundleGrantDescription(run, spec, entry));
  const id = entry.installation?.rule_id;
  requireThat(Number.isInteger(id) && id > 0 && id <= 0xffff_ffff
    && /^[0-9a-f]{64}$/.test(entry.installation?.transaction ?? '') && /^[0-9a-f]{64}$/.test(entry.wasm_hash ?? ''),
  'bundle lacks confirmed non-owner installation identity');
  await deps.assertTestnet();
  const account = await deps.contractCodeObservation(run.account);
  same(account.value, run.account_code_hash, 'live account code');
  const policy = await deps.contractCodeObservation(entry.policy);
  same(policy.value, entry.wasm_hash, 'live policy code');
  const source = { publicKey: () => run.payer };
  const live = await deps.viewCallObservation(source, run.account, 'get_context_rule', [xdr.ScVal.scvU32(id)]);
  const fields = { id: xdr.ScVal.scvU32(id), context_type: expected[0], name: expected[1], valid_until: expected[2],
    signers: expected[3], policies: xdr.ScVal.scvVec(expected[4].map.map((field) => field.key)) };
  for (const [name, value] of Object.entries(fields)) {
    const values = live.value.map?.filter((field) => field.key.type === 'scvSymbol' && field.key.sym.toString() === name);
    same(values?.length, 1, `live rule ${name} count`);
    same(hex(values[0].val), hex(value), `live rule ${name}`);
  }
  const installed = await deps.viewCallObservation(source, entry.policy, 'is_installed',
    [xdr.ScVal.scvU32(id), new Address(run.account).toScVal()]);
  same(scValToNative(installed.value), true, 'policy installation');
  return { rule_index: entry.rule_index, rule_id: id, configuration: 'matched', observation: 'non_atomic',
    read_ledgers: { account: account.ledger, policy: policy.ledger, rule: live.ledger, installed: installed.ledger } };
}
