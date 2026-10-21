import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, StrKey, xdr } from '@stellar/stellar-sdk';
import { prepareSoroswap, recheckSoroswapTargets } from './soroswap-preflight.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { i128 } from './lib.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM } from './rpc.mjs';
const FACTORY = 'CDP3HMUH6SMS3S7NPGNDJLULCOXXEPSHY4JKUKMBNQMATHDHWXRRJTBY';
const FACTORY_CODE = '86285a9234d3f0d687eaf88efe8d5d72172b38c9a86624c9934c0cbf2aff2993';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const A = (v) => new Address(v).toScVal();
function fixture() {
  const run = { account: C(1), account_code_hash: PINNED_ACCOUNT_WASM, payer: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 2)),
    network: NETWORK_PASSPHRASE, protocol: 29 };
  const control = {};
  const deps = {
    assertTestnet: async () => {}, now: () => 1_700_000_000_000,
    contractCodeObservation: async (id) => ({ ledger: 100, value: id === PROTOCOL_TARGETS.router
      ? (control.routerCode ?? PROTOCOL_TARGETS.router_code) : id === FACTORY ? FACTORY_CODE : (control.pairCode ?? 'aa'.repeat(32)) }),
    viewCallObservation: async (_payer, contract, name) => {
      let value;
      if (name === 'get_factory' || name === 'factory') value = A(control.factory ?? FACTORY);
      if (name === 'router_pair_for') value = A(control.pair ?? PROTOCOL_TARGETS.pair);
      if (name === 'token_0') value = A(PROTOCOL_TARGETS.native);
      if (name === 'token_1') value = A(control.token ?? PROTOCOL_TARGETS.swap_output);
      if (name === 'get_reserves') value = xdr.ScVal.scvVec([i128(10000000), i128(control.empty ? 0 : 20000000)]);
      if (name === 'router_get_amounts_out') value = xdr.ScVal.scvVec([i128(1000000), i128(control.quote ?? 174580)]);
      if (name === 'balance') { assert.equal(contract, PROTOCOL_TARGETS.native); value = i128(control.balance ?? 5000000); }
      assert.ok(value, `unexpected view ${name}`);
      return { value, ledger: 101 };
    },
  };
  return { run, control, deps };
}
test('Soroswap preflight records inspected route and an explicit fixed positive output floor without keys', async () => {
  const f = fixture();
  const plan = await prepareSoroswap(f.run, f.deps);
  assert.equal(plan.amount_in, '1000000');
  assert.equal(plan.minimum_out, '100000');
  assert.equal(plan.deadline, 1_700_003_600);
  assert.equal(plan.prerequisites.quote.amount_out, '174580');
  assert.equal(plan.prerequisites.pair.code_hash, 'aa'.repeat(32));
  f.run.walkthrough = plan;
  await recheckSoroswapTargets(f.run, f.deps);
  f.control.pairCode = 'bb'.repeat(32);
  await assert.rejects(recheckSoroswapTargets(f.run, f.deps), /pair code/);
});
for (const mode of ['router changed', 'different factory', 'different pair', 'wrong token', 'empty reserves', 'insufficient quote', 'insufficient balance']) {
  test(`Soroswap preflight refuses ${mode} before fixture execution`, async () => {
    const f = fixture();
    if (mode === 'router changed') f.control.routerCode = 'bb'.repeat(32);
    if (mode === 'different factory') f.control.factory = C(10);
    if (mode === 'different pair') f.control.pair = C(10);
    if (mode === 'wrong token') f.control.token = C(10);
    if (mode === 'empty reserves') f.control.empty = true;
    if (mode === 'insufficient quote') f.control.quote = 99999;
    if (mode === 'insufficient balance') f.control.balance = 1999999;
    await assert.rejects(prepareSoroswap(f.run, f.deps));
  });
}
