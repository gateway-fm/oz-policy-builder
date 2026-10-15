// Step 1 of a run: throwaway identities and the pinned OpenZeppelin smart account.
//
//   OZPB_HARNESS_SECRETS=<file> node setup.mjs --run-dir <dir> [--amount <stroops>]
//
// Four Friendbot-funded testnet keys, generated here and worth nothing:
//   payer     — pays every fee and funds the account. Signs transactions, never authorizations.
//   owner     — the account's administrator: the one `Delegated` signer of rule 0, the Default
//               rule the constructor creates. It authorizes the recorded transfer and the
//               install.
//   delegate  — the grantee: the one signer of the rule the generated policy guards.
//   recipient — the transfer's destination. Funded only so that it exists; its key is dropped.
//
// The account is deployed from the pinned wasm hash rather than built here, and the code hash
// the network then reports for it is checked against the pin before anything else happens.
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { Address, Keypair, Operation, xdr } from '@stellar/stellar-sdk';

import { delegatedSigner, i128 } from './lib.mjs';
import {
  NATIVE_SAC, PINNED_ACCOUNT_WASM, NETWORK_PASSPHRASE, RPC_ORIGIN, args, assertTestnet, contractCodeHash,
  contractIdOf, fund, log, submit, writeJson, writeSecrets,
} from './rpc.mjs';

const opts = args();
const runDir = opts['run-dir'];
if (!runDir) throw new Error('--run-dir is required');
const amount = BigInt(opts.amount ?? '10000000'); // 1 XLM in stroops
mkdirSync(runDir, { recursive: true });

const net = await assertTestnet();
log(`network   ${net.passphrase} (protocol ${net.protocolVersion}) via ${RPC_ORIGIN}`);

const keys = {
  payer: Keypair.random(), owner: Keypair.random(), delegate: Keypair.random(), recipient: Keypair.random(),
};
writeSecrets({ payer: keys.payer.secret(), owner: keys.owner.secret(), delegate: keys.delegate.secret() });
await Promise.all(Object.values(keys).map((k) => fund(k.publicKey())));
for (const [name, k] of Object.entries(keys)) log(`${name.padEnd(9)} ${k.publicKey()}`);

// --- the account ------------------------------------------------------------------------------
// `__constructor(signers: Vec<Signer>, policies: Map<Address, Val>)`: one Delegated signer, no
// policies — the smallest account that can authorize anything, as in scripts/demo-tranche1.sh.
const deploy = await submit(keys.payer, Operation.createCustomContract({
  address: new Address(keys.payer.publicKey()),
  wasmHash: Buffer.from(PINNED_ACCOUNT_WASM, 'hex'),
  salt: randomBytes(32),
  constructorArgs: [xdr.ScVal.scvVec([delegatedSigner(keys.owner.publicKey())]), xdr.ScVal.scvMap([])],
}), { stage: 'deploy account' });
const account = contractIdOf(deploy.returnValue);
log(`account   ${account}  (deploy ${deploy.hash})`);

const observed = await contractCodeHash(account);
if (observed !== PINNED_ACCOUNT_WASM) {
  throw new Error(`account runs ${observed}, not the pinned ${PINNED_ACCOUNT_WASM}`);
}
log(`          code hash ${observed} = pinned OpenZeppelin account`);

// Five transfers' worth: the run spends two (the recorded one and the permitted one).
const funding = await submit(keys.payer, Operation.invokeContractFunction({
  contract: NATIVE_SAC,
  function: 'transfer',
  args: [new Address(keys.payer.publicKey()).toScVal(), new Address(account).toScVal(), i128(amount * 5n)],
}), { stage: 'fund account' });
log(`funded    ${amount * 5n} stroops  (transfer ${funding.hash})`);

writeJson(join(runDir, 'run.json'), {
  network: NETWORK_PASSPHRASE,
  protocol: net.protocolVersion,
  rpc: RPC_ORIGIN,
  sac: NATIVE_SAC,
  account,
  account_code_hash: observed,
  payer: keys.payer.publicKey(),
  owner: keys.owner.publicKey(),
  delegate: keys.delegate.publicKey(),
  recipient: keys.recipient.publicKey(),
  amount: amount.toString(),
  tx: { deploy_account: deploy.hash, fund_account: funding.hash },
});
