// Exercise actual negative-control dispatch with real SDK auth encoding and local signing.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import * as sdk from '@stellar/stellar-sdk';
import * as lib from '../lib.mjs';

const mode = process.argv[2];
const scope = mode.startsWith('scope');
const wrongChallenge = mode.startsWith('wrong challenge');
const negative = scope || wrongChallenge;
const permitted = mode.endsWith('permit');
const account = sdk.StrKey.encodeContract(Buffer.alloc(32, 1));
const policy = sdk.StrKey.encodeContract(Buffer.alloc(32, 2));
const sac = sdk.StrKey.encodeContract(Buffer.alloc(32, 3));
const verifier = sdk.StrKey.encodeContract(Buffer.alloc(32, 5));
const key = sdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 4));
const run = { account, policy, sac, rule_id: 1, owner: { kind: 'ed25519', verifier },
  lifecycle: { removals: [{ rule_id: 1, event: 'verified', rule_readback: 'absent' }] } };
if (mode === 'unrecorded removal') delete run.lifecycle;
let saved; let submissions = 0; let simulations = 0; let exitCode = 0; let keyReads = 0;
class SimulationError extends Error { constructor(_stage, error) { super('simulated refusal'); this.error = error; } }
const transferArgs = [new sdk.Address(account).toScVal(), new sdk.Address(key.publicKey()).toScVal(), lib.i128(10n)];
const rpc = {
  NETWORK_PASSPHRASE: sdk.Networks.TESTNET, RPC_URL: 'https://unused.invalid', SimulationError,
  args: () => ({ 'run-dir': '/unused', amount: '10', to: key.publicKey(),
    ...(mode.includes('implicit') ? {} : { expect: mode.includes('conflicting') ? 'permit' : scope ? 'deny:6' : wrongChallenge ? 'deny:3114' : 'deny-account:3000' }),
    ...(wrongChallenge ? { signer: 'owner', rule: '0', 'wrong-challenge': 'yes' } : {}) }),
  readJson: () => run, loadKey: () => { keyReads++; return key; }, log: () => {}, assertTestnet: async () => {}, latestLedger: async () => 500,
  writeJson: (_path, value) => { saved = value; },
  recordAuth: async () => [new sdk.xdr.SorobanAuthorizationEntry({
    credentials: sdk.xdr.SorobanCredentials.sorobanCredentialsAddress(new sdk.xdr.SorobanAddressCredentials({
      address: new sdk.Address(account).toScAddress(), nonce: 1n, signatureExpirationLedger: 600, signature: sdk.xdr.ScVal.scvVoid(),
    })), rootInvocation: lib.contractCall(sac, 'transfer', transferArgs),
  })],
  submit: async () => { submissions++; assert.fail('a negative control must never submit a fee transaction'); },
  enforceSimulation: async (_payer, op) => {
    simulations++;
    sdk.xdr.Operation.fromXDR(op.toXDR());
    if (permitted) return { result: 'permit', ledger: 501 };
    const code = scope ? 6 : wrongChallenge ? 3114 : mode === 'exhausted policy' ? 7 : 3000;
    const enforcer = scope ? policy : wrongChallenge ? verifier : mode === 'account refusal' ? account : policy;
    return { result: 'deny', ledger: 501,
      error: `topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${account}, Error(Contract, #${code})]\n`
      + `contract:${enforcer}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]` };
  },
};
const context = vm.createContext({ console: { error() {}, log() {} }, process: { exit(code) { exitCode = code; } } });
const modules = new Map([
  ['node:path', await import('node:path')], ['@stellar/stellar-sdk', sdk], ['./lib.mjs', lib],
  ['./owner.mjs', { ownerSigner: () => { assert.ok(wrongChallenge); return key; } }], ['./rpc.mjs', rpc],
]);
const source = new vm.SourceTextModule(readFileSync(new URL('../invoke.mjs', import.meta.url), 'utf8'), { context });
await source.link(async (name) => {
  const exports = modules.get(name); assert.ok(exports, name);
  return new vm.SyntheticModule(Object.keys(exports), function () {
    for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
  }, { context });
});
if (mode.includes('conflicting')) {
  await assert.rejects(source.evaluate(), /expected verifier denial/);
  assert.equal(keyReads, 0);
  assert.equal(simulations, 0);
} else if (mode === 'unrecorded removal') {
  await assert.rejects(source.evaluate(), /confirmed removal/);
  assert.equal(simulations, 0);
} else {
  await source.evaluate();
  assert.equal(exitCode, mode === 'account refusal' || (negative && !permitted) ? 0 : 1);
  assert.equal(saved.invocations[0].control, negative ? undefined : 'post_revocation');
  assert.equal(saved.invocations[0].result, permitted ? 'permit' : 'deny');
  assert.equal(saved.invocations[0].hash, undefined);
  if (permitted) assert.equal(saved.invocations[0].observation, 'enforcing_simulation');
  if (mode === 'account refusal') assert.equal(saved.invocations[0].enforcer, account);
  assert.equal(simulations, 1);
}
assert.equal(submissions, 0);
