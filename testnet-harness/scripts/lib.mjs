// The encodings an OpenZeppelin smart account (stellar-accounts 0.7.2) signs over, and the two
// authorization entries a call from that account needs when its signer is a `Delegated` Stellar
// account. Pure: no network, no clock. Tested offline by `lib.test.mjs`.
//
// How the account authorizes, which is what these functions reproduce:
//
//   1. The host hands `__check_auth` a `signature_payload`: the hash of the auth entry's preimage.
//   2. The account binds the rule selection into it:
//        auth_digest = sha256(signature_payload || xdr(context_rule_ids))
//      (`stellar-accounts` `smart_account/storage.rs`, `do_check_auth`).
//   3. For each `Signer::Delegated(addr)` in the payload it calls
//        addr.require_auth_for_args((auth_digest,))
//      so the delegated Stellar account must present its *own* authorization entry, rooted at
//      `account.__check_auth(auth_digest)` and signed with its ed25519 key.
//
// The account's entry therefore carries no signature bytes for a delegated signer — an
// `AuthPayload` naming the signer with an empty proof — and the proof is the second entry.
import { Address, Keypair, StrKey, xdr, authorizeEntry, authorizeInvocation } from '@stellar/stellar-sdk';
import { createHash } from 'node:crypto';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

/** `Vec<u32>` as the account serializes it with `to_xdr` — the bytes appended to the payload. */
export function ruleIdsXdr(ids) {
  return Buffer.from(xdr.ScVal.scvVec(ids.map((id) => xdr.ScVal.scvU32(id))).toXDR());
}

/** `sha256(signature_payload || xdr(context_rule_ids))`, the value delegated signers authorize. */
export function authDigest(signaturePayload, ruleIds) {
  const payload = Buffer.from(signaturePayload);
  if (payload.length !== 32) throw new Error(`signature_payload must be 32 bytes, got ${payload.length}`);
  return sha256(Buffer.concat([payload, ruleIdsXdr(ruleIds)]));
}

/** `Signer::Delegated(Address)`: a contracttype enum variant, `Vec[Symbol, Address]`. */
export function delegatedSigner(address) {
  return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'), new Address(address).toScVal()]);
}

/**
 * `AuthPayload { signers: Map<Signer, Bytes>, context_rule_ids: Vec<u32> }`. A contracttype
 * struct is an `ScMap` keyed by field-name symbols in ascending order, so `context_rule_ids`
 * comes first. A delegated signer's proof is its own auth entry, so its bytes are empty.
 *
 * Exactly one signer: the host requires map keys in its own ordering, and these scripts never
 * need more than one, so a second is refused rather than ordered by a guess.
 */
export function authPayload(signerAddresses, ruleIds) {
  if (signerAddresses.length !== 1) {
    throw new Error(`exactly one delegated signer is supported, got ${signerAddresses.length}`);
  }
  const signers = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: delegatedSigner(signerAddresses[0]), val: xdr.ScVal.scvBytes(Buffer.alloc(0)) }),
  ]);
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('context_rule_ids'),
      val: xdr.ScVal.scvVec(ruleIds.map((id) => xdr.ScVal.scvU32(id))),
    }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('signers'), val: signers }),
  ]);
}

/** An `i128` amount. Transfer amounts are non-negative, and a negative one here is a bug. */
export function i128(value) {
  const v = BigInt(value);
  if (v < 0n) throw new Error(`amount must be non-negative, got ${v}`);
  return xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: v >> 64n, lo: v & ((1n << 64n) - 1n) }));
}

/** `ContextRuleType::CallContract(Address)`. */
export function callContractRule(contract) {
  return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'), new Address(contract).toScVal()]);
}

/** `Option<u32>`: `None` is `Void`, `Some(v)` is the bare value. */
export function optionU32(value) {
  return value === null || value === undefined ? xdr.ScVal.scvVoid() : xdr.ScVal.scvU32(value);
}

/** A contract call as an authorization tree node with no sub-invocations. */
export function contractCall(contract, functionName, args) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({ contractAddress: new Address(contract).toScAddress(), functionName, args }),
    ),
    subInvocations: [],
  });
}

/** The invocation a delegated signer authorizes: `account.__check_auth(auth_digest)`. */
export function checkAuthInvocation(account, digest) {
  return contractCall(account, '__check_auth', [xdr.ScVal.scvBytes(Buffer.from(digest))]);
}

/** The address an entry's credentials name, or `null` for source-account credentials. */
export function entryAddress(entry) {
  const c = entry.credentials;
  const creds = c.address ?? c.addressV2 ?? c.addressWithDelegates?.addressCredentials ?? null;
  return creds ? Address.fromScAddress(creds.address).toString() : null;
}

/**
 * Sign a smart account's recorded auth entry with a delegated signer.
 *
 * `entry` is the account's own entry from a recording simulation, and `expect` the invocation the
 * caller means the account to authorize. The recorded tree comes from an RPC endpoint, and signing
 * it would authorize whatever it says, so it must equal `expect` byte for byte first.
 *
 * Returns the account entry with its `AuthPayload` and expiry set, the delegate's entry
 * authorizing `account.__check_auth(auth_digest)`, and the digest itself. Both entries must go
 * into the transaction; the account's `__check_auth` fails without the second. The delegate's
 * entry uses classic Address credentials, whose preimage `lib.test.mjs` re-derives by hand.
 */
export async function signForSmartAccount({ entry, expect, signer, ruleIds, validUntilLedger, networkPassphrase }) {
  const account = entryAddress(entry);
  if (account === null || !StrKey.isValidContract(account)) {
    throw new Error(`expected the smart account's own entry (a contract address), got ${account}`);
  }
  if (!(signer instanceof Keypair)) throw new Error('signer must be a Keypair');
  if (!(expect instanceof xdr.SorobanAuthorizedInvocation)) throw new Error('expect must be the intended invocation');
  if (!Buffer.from(entry.rootInvocation.toXDR()).equals(Buffer.from(expect.toXDR()))) {
    throw new Error('the recorded authorization is not the intended call; refusing to sign it');
  }

  let digest;
  let delegateEntry;
  const accountEntry = await authorizeEntry(entry, async (_preimage, payload) => {
    digest = authDigest(payload, ruleIds);
    delegateEntry = await authorizeInvocation({
      signer,
      validUntilLedgerSeq: validUntilLedger,
      invocation: checkAuthInvocation(account, digest),
      networkPassphrase,
      authV2: false,
    });
    return { signatureScVal: authPayload([signer.publicKey()], ruleIds) };
  }, validUntilLedger, networkPassphrase);
  return { accountEntry, delegateEntry, digest };
}

/**
 * The code with which `policy` refused an authorization of `account`, read from a host error, or
 * `null` when the error is anything else.
 *
 * Two things must both be present, because each alone is satisfied by failures that are not a
 * policy decision. The top-level event must be the host's "failed account authentication" naming
 * the account — the denial happened while the account was authorizing this call. And the policy
 * contract itself must have raised the code (`"failing with contract error", N` from the policy's
 * id) — the same number from another contract means something else: the native SAC's #6 is
 * `AccountMissingError`, the generated policy's is `NoTupleMatched`.
 */
export function policyDenial(text, account, policy) {
  const str = String(text);
  const authFailed = new RegExp(
    `topics:\\[error, Error\\(Auth, InvalidAction\\)\\], data:\\["failed account authentication with error", ${account}, Error\\(Contract, #(\\d+)\\)\\]`,
  ).exec(str);
  const raised = new RegExp(
    `contract:${policy}, topics:\\[error, Error\\(Contract, #(\\d+)\\)\\], data:\\["failing with contract error", (\\d+)\\]`,
  ).exec(str);
  if (!authFailed || !raised || raised[1] !== raised[2] || raised[1] !== authFailed[1]) return null;
  return Number(raised[1]);
}
