// Step 1 of a run: throwaway identities and the pinned OpenZeppelin smart account.
//
//   OZPB_HARNESS_SECRETS=<file> node setup.mjs --run-dir <dir> [--amount <stroops>]
//       [--owner ed25519|passkey] [--verifier <C…>]
//
// Friendbot-funded testnet keys, generated here and worth nothing:
//   payer     — pays every fee, deploys the contracts and funds the account. Signs transactions,
//               never authorizations.
//   owner     — with `--owner ed25519` (the default): the account's administrator, the one
//               `Delegated` signer of rule 0, the Default rule the constructor creates. It
//               authorizes the recorded transfer and the install.
//   delegate  — the grantee: the one signer of the rule the generated policy guards.
//   recipient — the transfer's destination. Funded only so that it exists; its key is dropped.
//
// With `--owner passkey` there is no owner key. The administrator is a passkey, created headless
// in Chrome's virtual authenticator, and rule 0's one signer is `External`: the pinned
// OpenZeppelin WebAuthn verifier with the passkey's public key and credential id. That is the
// shape of a pollywallet account (the same constructor arguments and key-data layout as its
// `useWallet.ts` and `passkey.ts`), on the pinned account and verifier builds instead of
// pollywallet's own. pollywallet's page, relayer and deployer are not involved. The verifier is
// deployed from its pinned hash, or `--verifier` names an existing instance; its code hash is
// checked either way. The passkey is created first, so a missing browser fails before anything
// is funded or deployed.
//
// The account is deployed from the pinned wasm hash rather than built here. The code hash the
// network then reports for it is checked against the pin, and rule 0 is read back and must hold
// exactly the intended signer and no policy, before anything else happens.
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { Address, Keypair, Operation, StrKey, xdr } from '@stellar/stellar-sdk';

import { delegatedSigner, externalSigner, i128, p256PublicKeyRaw, passkeyKeyData } from './lib.mjs';
import {
  NATIVE_SAC, PINNED_ACCOUNT_WASM, PINNED_WEBAUTHN_VERIFIER_WASM, NETWORK_PASSPHRASE, RPC_ORIGIN, args,
  assertTestnet, contractCodeHash, contractIdOf, fund, log, submit, viewCall, writeJson, writeSecrets,
} from './rpc.mjs';

const opts = args();
const runDir = opts['run-dir'];
if (!runDir) throw new Error('--run-dir is required');
const amount = BigInt(opts.amount ?? '10000000'); // 1 XLM in stroops
const ownerKind = opts.owner ?? 'ed25519';
if (!['ed25519', 'passkey'].includes(ownerKind)) throw new Error('--owner is ed25519 or passkey');
if (opts.verifier && ownerKind !== 'passkey') throw new Error('--verifier applies only to --owner passkey');
mkdirSync(runDir, { recursive: true });

const net = await assertTestnet();
log(`network   ${net.passphrase} (protocol ${net.protocolVersion}) via ${RPC_ORIGIN}`);

const passkey = ownerKind === 'passkey' ? await (await import('../browser/passkey.mjs')).createPasskey() : null;

const keys = {
  payer: Keypair.random(),
  ...(ownerKind === 'ed25519' ? { owner: Keypair.random() } : {}),
  delegate: Keypair.random(),
  recipient: Keypair.random(),
};
const secrets = { payer: keys.payer.secret(), delegate: keys.delegate.secret() };
if (keys.owner) secrets.owner = keys.owner.secret();
await Promise.all(Object.values(keys).map((k) => fund(k.publicKey())));
for (const [name, k] of Object.entries(keys)) log(`${name.padEnd(9)} ${k.publicKey()}`);
const tx = {};

// --- the owner ----------------------------------------------------------------------------------
let owner;
let ownerScVal;
if (ownerKind === 'ed25519') {
  owner = { kind: 'ed25519', address: keys.owner.publicKey() };
  ownerScVal = delegatedSigner(owner.address);
} else {
  let verifier = opts.verifier;
  if (verifier) {
    if (!StrKey.isValidContract(verifier)) throw new Error(`--verifier ${verifier} is not a contract address`);
  } else {
    const deployed = await submit(keys.payer, Operation.createCustomContract({
      address: new Address(keys.payer.publicKey()),
      wasmHash: Buffer.from(PINNED_WEBAUTHN_VERIFIER_WASM, 'hex'),
      salt: randomBytes(32),
    }), { stage: 'deploy verifier' });
    verifier = contractIdOf(deployed.returnValue);
    tx.deploy_verifier = deployed.hash;
  }
  const verifierCode = await contractCodeHash(verifier);
  if (verifierCode !== PINNED_WEBAUTHN_VERIFIER_WASM) {
    throw new Error(`verifier ${verifier} runs ${verifierCode}, not the pinned ${PINNED_WEBAUTHN_VERIFIER_WASM}`);
  }
  log(`verifier  ${verifier}${tx.deploy_verifier ? `  (deploy ${tx.deploy_verifier})` : ' (given)'}`);
  log(`          code hash ${verifierCode} = pinned OpenZeppelin WebAuthn verifier`);

  const publicKey = p256PublicKeyRaw(passkey.publicKeySpki);
  const keyData = passkeyKeyData(publicKey, passkey.credentialId);
  secrets.passkey = {
    credential: passkey.credential,
    credentialId: passkey.credentialId.toString('base64url'),
    publicKeySpki: passkey.publicKeySpki.toString('base64url'),
  };
  owner = {
    kind: 'passkey',
    verifier,
    verifier_code_hash: verifierCode,
    credential_id: passkey.credentialId.toString('base64url'),
    public_key: publicKey.toString('hex'),
    key_data: keyData.toString('hex'),
  };
  ownerScVal = externalSigner(verifier, keyData);
  log(`passkey   ES256 credential ${owner.credential_id}`);
  log(`          public key ${owner.public_key}`);
}
writeSecrets(secrets);

// --- the account ------------------------------------------------------------------------------
// `__constructor(signers: Vec<Signer>, policies: Map<Address, Val>)`: one signer, no policies —
// the smallest account that can authorize anything, as in scripts/demo-tranche1.sh.
const deploy = await submit(keys.payer, Operation.createCustomContract({
  address: new Address(keys.payer.publicKey()),
  wasmHash: Buffer.from(PINNED_ACCOUNT_WASM, 'hex'),
  salt: randomBytes(32),
  constructorArgs: [xdr.ScVal.scvVec([ownerScVal]), xdr.ScVal.scvMap([])],
}), { stage: 'deploy account' });
const account = contractIdOf(deploy.returnValue);
tx.deploy_account = deploy.hash;
log(`account   ${account}  (deploy ${deploy.hash})`);

const observed = await contractCodeHash(account);
if (observed !== PINNED_ACCOUNT_WASM) {
  throw new Error(`account runs ${observed}, not the pinned ${PINNED_ACCOUNT_WASM}`);
}
log(`          code hash ${observed} = pinned OpenZeppelin account`);

// Rule 0 as the account reports it: the Default context, exactly the owner (compared as XDR, the
// way the account matches signers), no policy, no expiry.
const rule0 = await viewCall(keys.payer, account, 'get_context_rule', [xdr.ScVal.scvU32(0)]);
const field = (name) => rule0.map.find((e) => e.key.sym.toString() === name)?.val;
const hexOf = (v) => Buffer.from(v.toXDR()).toString('hex');
const signers = field('signers').vec;
if (hexOf(field('context_type')) !== hexOf(xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]))
  || signers.length !== 1 || hexOf(signers[0]) !== hexOf(ownerScVal) || field('policies').vec.length !== 0
  || field('valid_until').type !== 'scvVoid') {
  throw new Error('rule 0 is not the Default rule with exactly the owner, no policy and no expiry');
}
log(`          rule 0: Default, one ${ownerKind === 'passkey' ? 'External (passkey)' : 'Delegated'} signer, no policy, no expiry`);

// Five transfers' worth: the run spends two (the recorded one and the permitted one).
const funding = await submit(keys.payer, Operation.invokeContractFunction({
  contract: NATIVE_SAC,
  function: 'transfer',
  args: [new Address(keys.payer.publicKey()).toScVal(), new Address(account).toScVal(), i128(amount * 5n)],
}), { stage: 'fund account' });
tx.fund_account = funding.hash;
log(`funded    ${amount * 5n} stroops  (transfer ${funding.hash})`);

writeJson(join(runDir, 'run.json'), {
  network: NETWORK_PASSPHRASE,
  protocol: net.protocolVersion,
  rpc: RPC_ORIGIN,
  sac: NATIVE_SAC,
  account,
  account_code_hash: observed,
  payer: keys.payer.publicKey(),
  owner,
  delegate: keys.delegate.publicKey(),
  recipient: keys.recipient.publicKey(),
  amount: amount.toString(),
  tx,
});
