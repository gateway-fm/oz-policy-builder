// The encodings an OpenZeppelin smart account (stellar-accounts 0.7.2) signs over, and the
// authorization entries a call from that account needs when its signer is a `Delegated` Stellar
// account or an `External` passkey behind the OpenZeppelin WebAuthn verifier. Pure: no network, no
// clock, no browser. Tested offline by `lib.test.mjs`.
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
//
//   4. For each `Signer::External(verifier, key_data)` it calls
//        verifier.verify(auth_digest, key_data, sig_data)
//      with `sig_data` the bytes the payload gives that signer. There is no second entry: the
//      proof is in the account's own entry. For the WebAuthn verifier, `key_data` is a 65-byte
//      uncompressed P-256 key followed by the credential id, and `sig_data` is the XDR of
//      `WebAuthnSigData`, whose `client_data` must carry `base64url(auth_digest)` as its challenge
//      (`stellar-accounts` `verifiers/webauthn.rs`).
import { Address, Keypair, StrKey, xdr, authorizeEntry, authorizeInvocation } from '@stellar/stellar-sdk';
import { createHash, createPublicKey } from 'node:crypto';

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
 * comes first.
 *
 * Each signer is either a `Delegated` address, whose proof is its own auth entry and whose bytes
 * here are therefore empty, or `{ signer, proof }`: a `Signer` ScVal and the bytes its verifier
 * reads.
 *
 * Exactly one signer: the host requires map keys in its own ordering, and these scripts never
 * need more than one, so a second is refused rather than ordered by a guess.
 */
export function authPayload(signers, ruleIds) {
  if (signers.length !== 1) {
    throw new Error(`exactly one signer is supported, got ${signers.length}`);
  }
  const [one] = signers;
  const [key, proof] = typeof one === 'string' ? [delegatedSigner(one), Buffer.alloc(0)] : [one.signer, Buffer.from(one.proof)];
  const map = xdr.ScVal.scvMap([new xdr.ScMapEntry({ key, val: xdr.ScVal.scvBytes(proof) })]);
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('context_rule_ids'),
      val: xdr.ScVal.scvVec(ruleIds.map((id) => xdr.ScVal.scvU32(id))),
    }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('signers'), val: map }),
  ]);
}

// --- External signers: a passkey behind the OpenZeppelin WebAuthn verifier ----------------------

/** `Signer::External(Address, Bytes)`: a contracttype enum variant, `Vec[Symbol, Address, Bytes]`. */
export function externalSigner(verifier, keyData) {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol('External'), new Address(verifier).toScVal(), xdr.ScVal.scvBytes(Buffer.from(keyData)),
  ]);
}

/**
 * The WebAuthn verifier's `key_data`: the 65-byte uncompressed P-256 key, then the credential id.
 * The verifier reads bytes 0..65 as the key and ignores the rest; the credential id is there so a
 * wallet can tell its passkeys apart. pollywallet lays it out the same way (`buildKeyData`).
 */
export function passkeyKeyData(publicKey, credentialId) {
  const key = Buffer.from(publicKey);
  const id = Buffer.from(credentialId);
  if (key.length !== 65) throw new Error(`the passkey public key must be a 65-byte P-256 point, got ${key.length}`);
  if (key[0] !== 0x04) throw new Error('the passkey public key must be an uncompressed point (0x04 prefix)');
  if (id.length === 0) throw new Error('a credential id is required');
  return Buffer.concat([key, id]);
}

/** `04 ‖ X ‖ Y` from the DER SubjectPublicKeyInfo `getPublicKey()` returns at registration. */
export function p256PublicKeyRaw(spki) {
  const key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('the credential key is not a P-256 (secp256r1) key');
  }
  const { x, y } = key.export({ format: 'jwk' });
  const [bx, by] = [Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url')];
  if (bx.length !== 32 || by.length !== 32) throw new Error('P-256 coordinates must be 32 bytes');
  return Buffer.concat([Buffer.from([0x04]), bx, by]);
}

const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

/**
 * WebAuthn returns ECDSA signatures as DER; the verifier takes `BytesN<64>`, r ‖ s, and the
 * host's secp256r1 check wants s in the lower half of the group order. (r, s) and (r, n − s) are
 * the same signature, so folding s changes nothing a verifier should care about. Strict DER:
 * anything that is not exactly SEQUENCE { INTEGER r, INTEGER s } is refused, not trimmed.
 */
export function derToLowS(signature) {
  const der = Buffer.from(signature);
  if (der.length < 8 || der[0] !== 0x30 || der[1] >= 0x80 || der[1] + 2 !== der.length) {
    throw new Error('not a DER ECDSA signature');
  }
  let at = 2;
  const integer = () => {
    if (der[at] !== 0x02) throw new Error('not a DER ECDSA signature');
    const len = der[at + 1];
    const body = der.subarray(at + 2, at + 2 + len);
    if (len === 0 || body.length !== len || body[0] & 0x80 || (len > 1 && body[0] === 0 && !(body[1] & 0x80))) {
      throw new Error('not a DER ECDSA signature');
    }
    at += 2 + len;
    return BigInt(`0x${body.toString('hex')}`);
  };
  const r = integer();
  let s = integer();
  if (at !== der.length) throw new Error('not a DER ECDSA signature');
  if (r < 1n || r >= P256_ORDER || s < 1n || s >= P256_ORDER) throw new Error('signature value out of range');
  if (s > P256_ORDER / 2n) s = P256_ORDER - s;
  const be32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex');
  return Buffer.concat([be32(r), be32(s)]);
}

/**
 * `sig_data` for the WebAuthn verifier: the XDR of
 * `WebAuthnSigData { signature: BytesN<64>, authenticator_data: Bytes, client_data: Bytes }`,
 * a struct map with its fields in symbol order.
 */
export function webAuthnSigData({ authenticatorData, clientDataJSON, signature }) {
  const sig = Buffer.from(signature);
  if (sig.length !== 64) throw new Error(`signature must be 64 bytes (r ‖ s), got ${sig.length}`);
  const field = (name, bytes) => new xdr.ScMapEntry({
    key: xdr.ScVal.scvSymbol(name), val: xdr.ScVal.scvBytes(Buffer.from(bytes)),
  });
  return Buffer.from(xdr.ScVal.scvMap([
    field('authenticator_data', authenticatorData),
    field('client_data', clientDataJSON),
    field('signature', sig),
  ]).toXDR());
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
 * Sign a smart account's recorded auth entry, as one of its signers.
 *
 * `entry` is the account's own entry from a recording simulation, and `expect` the invocation the
 * caller means the account to authorize. The recorded tree comes from an RPC endpoint, and signing
 * it would authorize whatever it says, so it must equal `expect` byte for byte first.
 *
 * `signer` is one of:
 *   - a `Keypair`: a `Delegated` Stellar account. Returns the account entry with its `AuthPayload`
 *     and expiry set, and the delegate's entry authorizing `account.__check_auth(auth_digest)`.
 *     Both must go into the transaction; the account's `__check_auth` fails without the second.
 *     The delegate's entry uses classic Address credentials, whose preimage `lib.test.mjs`
 *     re-derives by hand.
 *   - `{ verifier, keyData, sign }`: an `External` signer. `sign(auth_digest)` returns the bytes
 *     the verifier reads (for a passkey, `webAuthnSigData`). They go into the account's own entry,
 *     and `delegateEntry` is `null`.
 *
 * Also returns the digest itself.
 */
export async function signForSmartAccount({ entry, expect, signer, ruleIds, validUntilLedger, networkPassphrase }) {
  const account = entryAddress(entry);
  if (account === null || !StrKey.isValidContract(account)) {
    throw new Error(`expected the smart account's own entry (a contract address), got ${account}`);
  }
  const delegated = signer instanceof Keypair;
  if (!delegated && !(StrKey.isValidContract(signer?.verifier ?? '') && signer.keyData && typeof signer.sign === 'function')) {
    throw new Error('signer must be a Keypair or an External signer { verifier, keyData, sign }');
  }
  if (!(expect instanceof xdr.SorobanAuthorizedInvocation)) throw new Error('expect must be the intended invocation');
  if (!Buffer.from(entry.rootInvocation.toXDR()).equals(Buffer.from(expect.toXDR()))) {
    throw new Error('the recorded authorization is not the intended call; refusing to sign it');
  }

  let digest;
  let delegateEntry = null;
  const accountEntry = await authorizeEntry(entry, async (_preimage, payload) => {
    digest = authDigest(payload, ruleIds);
    if (!delegated) {
      const proof = await signer.sign(digest);
      return { signatureScVal: authPayload([{ signer: externalSigner(signer.verifier, signer.keyData), proof }], ruleIds) };
    }
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
