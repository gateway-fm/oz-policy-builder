// Execute the actual invocation script with fake RPC replies and real local authorization signing.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import * as sdk from '@stellar/stellar-sdk';
import * as lib from '../lib.mjs';

const mode = process.argv[2];
const account = sdk.StrKey.encodeContract(Buffer.alloc(32, 1));
const policy = sdk.StrKey.encodeContract(Buffer.alloc(32, 2));
const sac = sdk.StrKey.encodeContract(Buffer.alloc(32, 3));
const key = sdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 4));
const run = { account, policy, sac, rule_id: 1, owner: { kind: 'ed25519' },
  lifecycle: { removals: [{ rule_id: 1, event: 'verified', rule_readback: 'absent' }] } };
if (mode === 'unrecorded removal') delete run.lifecycle;
let saved; let submissions = 0; let exitCode = 0;
class SimulationError extends Error { constructor(error) { super('simulated refusal'); this.error = error; } }
const transferArgs = [new sdk.Address(account).toScVal(), new sdk.Address(key.publicKey()).toScVal(), lib.i128(10n)];
const rpc = {
  NETWORK_PASSPHRASE: sdk.Networks.TESTNET, RPC_URL: 'https://unused.invalid', SimulationError,
  args: () => ({ 'run-dir': '/unused', amount: '10', to: key.publicKey(), expect: 'deny-account:3000' }),
  readJson: () => run, loadKey: () => key, log: () => {}, assertTestnet: async () => {}, latestLedger: async () => 500,
  writeJson: (_path, value) => { saved = value; },
  recordAuth: async () => [new sdk.xdr.SorobanAuthorizationEntry({
    credentials: sdk.xdr.SorobanCredentials.sorobanCredentialsAddress(new sdk.xdr.SorobanAddressCredentials({
      address: new sdk.Address(account).toScAddress(), nonce: 1n, signatureExpirationLedger: 600, signature: sdk.xdr.ScVal.scvVoid(),
    })), rootInvocation: lib.contractCall(sac, 'transfer', transferArgs),
  })],
  submit: async () => {
    submissions++;
    if (mode === 'permit') return { hash: 'ab'.repeat(32) };
    const code = mode === 'exhausted policy' ? 7 : 3000;
    const enforcer = mode === 'account refusal' ? account : policy;
    throw new SimulationError(`topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${account}, Error(Contract, #${code})]\n`
      + `contract:${enforcer}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`);
  },
};
const context = vm.createContext({ console: { error() {}, log() {} }, process: { exit(code) { exitCode = code; } } });
const modules = new Map([
  ['node:path', await import('node:path')], ['@stellar/stellar-sdk', sdk], ['./lib.mjs', lib],
  ['./owner.mjs', { ownerSigner: () => assert.fail('owner must not sign this control') }], ['./rpc.mjs', rpc],
]);
const source = new vm.SourceTextModule(readFileSync(new URL('../invoke.mjs', import.meta.url), 'utf8'), { context });
await source.link(async (name) => {
  const exports = modules.get(name); assert.ok(exports, name);
  const module = new vm.SyntheticModule(Object.keys(exports), function () {
    for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
  }, { context });
  return module;
});
if (mode === 'unrecorded removal') {
  await assert.rejects(source.evaluate(), /confirmed removal/);
  assert.equal(submissions, 0);
} else {
  await source.evaluate();
  assert.equal(exitCode, mode === 'account refusal' ? 0 : 1);
  assert.equal(saved.invocations[0].control, 'post_revocation');
  assert.equal(saved.invocations[0].result, mode === 'permit' ? 'permit' : 'deny');
  if (mode === 'account refusal') assert.equal(saved.invocations[0].enforcer, account);
}
