// Offline checks for the encodings the testnet scripts sign over. Expected bytes are written out
// from the XDR definitions by hand rather than produced by the SDK, so a test here fails when the
// SDK and the account disagree — which is the case worth catching, since the network would only
// say "signature invalid".
//
//   node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign as nodeSign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Address, Keypair, Networks, StrKey, xdr } from '@stellar/stellar-sdk';

import {
  ruleIdsXdr, authDigest, delegatedSigner, authPayload, i128, callContractRule, optionU32,
  checkAuthInvocation, contractCall, signForSmartAccount, policyDenial,
  externalSigner, passkeyKeyData, p256PublicKeyRaw, derToLowS, webAuthnSigData, addContextRuleArgs,
} from './lib.mjs';
import { PINNED_ACCOUNT_WASM, PINNED_WEBAUTHN_VERIFIER_WASM } from './rpc.mjs';

const bytesOf = (b) => Buffer.from(b?.value ?? b); // SDK 17 wraps ScVal bytes in `ScBytes { value }`
const hex = (b) => bytesOf(b).toString('hex');
const sha256 = (b) => createHash('sha256').update(b).digest();

// A minimal XDR encoder, written from the definitions and sharing nothing with the SDK, for the
// structures the account and the host hash.
const X = {
  u32: (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; },
  i64: (n) => { const b = Buffer.alloc(8); b.writeBigInt64BE(BigInt(n)); return b; },
  u64: (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; },
  opaque: (bytes) => {
    const raw = Buffer.from(bytes);
    return Buffer.concat([X.u32(raw.length), raw, Buffer.alloc((4 - (raw.length % 4)) % 4)]);
  },
  contract: (c) => Buffer.concat([X.u32(1), StrKey.decodeContract(c)]),                  // SC_ADDRESS_TYPE_CONTRACT
  account: (g) => Buffer.concat([X.u32(0), X.u32(0), StrKey.decodeEd25519PublicKey(g)]), // ACCOUNT, ED25519
  scAddress: (a) => Buffer.concat([X.u32(18), a.startsWith('C') ? X.contract(a) : X.account(a)]),
  scSymbol: (s) => Buffer.concat([X.u32(15), X.opaque(Buffer.from(s))]),
  scBytes: (b) => Buffer.concat([X.u32(13), X.opaque(b)]),
  scI128: (v) => Buffer.concat([X.u32(10), X.i64(BigInt(v) >> 64n), X.u64(BigInt(v) & ((1n << 64n) - 1n))]),
  scVec: (items) => Buffer.concat([X.u32(16), X.u32(1), X.u32(items.length), ...items]),
  scMap: (pairs) => Buffer.concat([X.u32(17), X.u32(1), X.u32(pairs.length), ...pairs.flat()]),
  // SorobanAuthorizedInvocation { SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN(InvokeContractArgs), sub: [] }
  invocation: (contract, fn, args) => Buffer.concat([
    X.u32(0), X.contract(contract), X.opaque(Buffer.from(fn)), X.u32(args.length), ...args, X.u32(0),
  ]),
  // HashIdPreimage ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9): networkID, nonce, expiration, invocation
  authPreimage: (passphrase, nonce, until, invocation) => Buffer.concat([
    X.u32(9), sha256(Buffer.from(passphrase)), X.i64(nonce), X.u32(until), invocation,
  ]),
};

// XDR: ScValType SCV_VEC = 16, Option<ScVec> present = 1, length, then SCV_U32 = 3 + value.
test('context_rule_ids encode as ScVal::Vec of U32, exactly as the account hashes them', () => {
  assert.equal(hex(ruleIdsXdr([0])), '00000010' + '00000001' + '00000001' + '00000003' + '00000000');
  assert.equal(
    hex(ruleIdsXdr([2, 7])),
    '00000010' + '00000001' + '00000002' + '00000003' + '00000002' + '00000003' + '00000007',
  );
});

test('auth_digest is sha256(signature_payload || xdr(context_rule_ids))', () => {
  const payload = Buffer.alloc(32, 0xab);
  const expected = sha256(Buffer.concat([payload, Buffer.from('0000001000000001000000010000000300000004', 'hex')]));
  assert.equal(hex(authDigest(payload, [4])), hex(expected));
  // The rule selection is inside the digest: the same payload under another rule signs differently.
  assert.notEqual(hex(authDigest(payload, [4])), hex(authDigest(payload, [5])));
  assert.throws(() => authDigest(Buffer.alloc(31), [0]), /32 bytes/);
});

// Signer::Delegated(Address) is a contracttype enum variant: Vec[Symbol("Delegated"), Address].
// SCV_SYMBOL = 15, "Delegated" is 9 bytes padded to 12; SCV_ADDRESS = 18, SC_ADDRESS_TYPE_ACCOUNT
// = 0, PUBLIC_KEY_TYPE_ED25519 = 0, then the raw key.
test('Signer::Delegated encodes as a two-element vector', () => {
  const raw = Buffer.alloc(32, 0x11);
  const g = StrKey.encodeEd25519PublicKey(raw);
  assert.equal(
    hex(delegatedSigner(g).toXDR()),
    '00000010' + '00000001' + '00000002'
      + '0000000f' + '00000009' + hex(Buffer.from('Delegated')) + '000000'
      + '00000012' + '00000000' + '00000000' + hex(raw),
  );
});

test('AuthPayload is a struct map with keys in symbol order and an empty proof per delegated signer', () => {
  const g = Keypair.random().publicKey();
  const scv = authPayload([g], [3]);
  assert.equal(scv.type, 'scvMap');
  assert.deepEqual(scv.map.map((e) => e.key.sym.toString()), ['context_rule_ids', 'signers']);
  assert.equal(hex(scv.map[0].val.toXDR()), hex(ruleIdsXdr([3])));
  const signers = scv.map[1].val.map;
  assert.equal(signers.length, 1);
  assert.equal(hex(signers[0].key.toXDR()), hex(delegatedSigner(g).toXDR()));
  assert.equal(bytesOf(signers[0].val.bytes).length, 0);
  // One signer is all these scripts need, and a second would need host map ordering.
  assert.throws(() => authPayload([g, Keypair.random().publicKey()], [0]), /exactly one/);
});

test('AuthPayload bytes, written out from the struct definition', () => {
  const raw = Buffer.alloc(32, 0x12);
  const g = StrKey.encodeEd25519PublicKey(raw);
  const expected = X.scMap([
    [X.scSymbol('context_rule_ids'), X.scVec([Buffer.concat([X.u32(3), X.u32(3)])])],
    [X.scSymbol('signers'), X.scMap([[X.scVec([X.scSymbol('Delegated'), X.scAddress(g)]), X.scBytes(Buffer.alloc(0))]])],
  ]);
  assert.equal(hex(authPayload([g], [3]).toXDR()), hex(expected));
});

test('i128 splits into signed hi and unsigned lo halves', () => {
  assert.equal(hex(i128(10_000_000n).toXDR()), '0000000a' + '0000000000000000' + '0000000000989680');
  assert.equal(hex(i128(1n << 64n).toXDR()), '0000000a' + '0000000000000001' + '0000000000000000');
  assert.throws(() => i128(-1n), /non-negative/);
});

test('add_context_rule arguments: CallContract(Address) and Option<u32>', () => {
  const sac = StrKey.encodeContract(Buffer.alloc(32, 0x22));
  const ctx = callContractRule(sac);
  assert.equal(ctx.type, 'scvVec');
  assert.equal(ctx.vec[0].sym.toString(), 'CallContract');
  assert.equal(Address.fromScVal(ctx.vec[1]).toString(), sac);
  assert.equal(hex(optionU32(null).toXDR()), '00000001');          // SCV_VOID
  assert.equal(hex(optionU32(5).toXDR()), '00000003' + '00000005'); // SCV_U32
});

test('__check_auth invocation names the account and carries the digest as its only argument', () => {
  const account = StrKey.encodeContract(Buffer.alloc(32, 0x33));
  const digest = Buffer.alloc(32, 0x44);
  const inv = checkAuthInvocation(account, digest);
  const fn = inv.function.contractFn;
  assert.equal(Address.fromScAddress(fn.contractAddress).toString(), account);
  assert.equal(fn.functionName.toString(), '__check_auth');
  assert.equal(fn.args.length, 1);
  assert.equal(hex(fn.args[0].bytes), hex(digest));
  assert.equal(inv.subInvocations.length, 0);
});

// The shape of what the network returns from a recording simulation: the smart account's own
// entry, Address credentials, signature still void.
const TOKEN = StrKey.encodeContract(Buffer.alloc(32, 0x55));
const transferTo = (account, amount = 1n) => contractCall(TOKEN, 'transfer', [new Address(account).toScVal(), i128(amount)]);
function recordedAccountEntry(account, invocation = transferTo(account)) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(account).toScAddress(),
      nonce: 42n,
      signatureExpirationLedger: 0,
      signature: xdr.ScVal.scvVoid(),
    })),
    rootInvocation: invocation,
  });
}

function ed25519Verify(publicKeyG, message, signature) {
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), StrKey.decodeEd25519PublicKey(publicKeyG)]);
  return verify(null, message, createPublicKey({ key: spki, format: 'der', type: 'spki' }), signature);
}

test('contractCall builds the invocation the host hashes, with no sub-invocations', () => {
  const account = StrKey.encodeContract(Buffer.alloc(32, 0x61));
  assert.equal(hex(transferTo(account, 5n).toXDR()), hex(X.invocation(TOKEN, 'transfer', [X.scAddress(account), X.scI128(5n)])));
});

test('signing for the smart account binds the delegate signature to this entry and this rule', async () => {
  const account = StrKey.encodeContract(Buffer.alloc(32, 0x66));
  const delegate = Keypair.random();
  const entry = recordedAccountEntry(account);
  const until = 123456;

  const { accountEntry, delegateEntry, digest } = await signForSmartAccount({
    entry, expect: transferTo(account), signer: delegate, ruleIds: [9], validUntilLedger: until,
    networkPassphrase: Networks.TESTNET,
  });

  // The account entry now carries the AuthPayload and the expiry it was signed under.
  const creds = accountEntry.credentials.address;
  assert.equal(creds.signatureExpirationLedger, until);
  assert.equal(hex(creds.signature.toXDR()), hex(authPayload([delegate.publicKey()], [9]).toXDR()));

  // The digest is the account's: sha256 of *this* entry's preimage, hand-encoded, then rule 9.
  const accountPreimage = X.authPreimage(Networks.TESTNET, 42n, until,
    X.invocation(TOKEN, 'transfer', [X.scAddress(account), X.scI128(1n)]));
  assert.equal(hex(digest), hex(authDigest(sha256(accountPreimage), [9])));

  // The delegate's entry authorizes account.__check_auth(digest), and its ed25519 signature
  // verifies over its own hand-encoded preimage under the delegate's key.
  const dCreds = delegateEntry.credentials.address;
  assert.ok(dCreds, 'the delegate entry uses classic Address credentials');
  assert.equal(Address.fromScAddress(dCreds.address).toString(), delegate.publicKey());
  assert.equal(dCreds.signatureExpirationLedger, until);
  const delegatePreimage = X.authPreimage(Networks.TESTNET, dCreds.nonce, until,
    X.invocation(account, '__check_auth', [X.scBytes(digest)]));
  assert.equal(hex(delegateEntry.rootInvocation.toXDR()), hex(X.invocation(account, '__check_auth', [X.scBytes(digest)])));
  const sigMap = dCreds.signature.vec[0].map;
  const field = (name) => bytesOf(sigMap.find((e) => e.key.sym.toString() === name).val.bytes);
  assert.equal(StrKey.encodeEd25519PublicKey(field('public_key')), delegate.publicKey());
  assert.ok(ed25519Verify(delegate.publicKey(), sha256(delegatePreimage), field('signature')));
});

test('signing refuses an entry that is not the smart account\'s own', async () => {
  const g = Keypair.random().publicKey();
  await assert.rejects(
    signForSmartAccount({
      entry: recordedAccountEntry(g), expect: transferTo(g), signer: Keypair.random(), ruleIds: [0],
      validUntilLedger: 1, networkPassphrase: Networks.TESTNET,
    }),
    /contract/,
  );
});

test('signing refuses a recorded invocation that is not the intended call', async () => {
  // The recording simulation comes from an RPC endpoint; what it says the account must authorize
  // is checked against the call the script means to make before anything is signed.
  const account = StrKey.encodeContract(Buffer.alloc(32, 0x67));
  const entry = recordedAccountEntry(account, transferTo(account, 2n));
  await assert.rejects(
    signForSmartAccount({
      entry, expect: transferTo(account, 1n), signer: Keypair.random(), ruleIds: [0],
      validUntilLedger: 1, networkPassphrase: Networks.TESTNET,
    }),
    /not the intended call/,
  );
});

test('the pinned account hash is the one crates/domain pins', () => {
  // Read from the Rust byte literal, so the two copies cannot drift apart unnoticed.
  const rust = readFileSync(new URL('../../crates/domain/src/lib.rs', import.meta.url), 'utf8');
  const literal = /OZ_SMART_ACCOUNT_WASM: Hash32 = Hash32\(\[([^\]]+)\]\)/.exec(rust);
  assert.ok(literal, 'OZ_SMART_ACCOUNT_WASM not found in crates/domain/src/lib.rs');
  const bytes = literal[1].split(',').map((t) => t.trim()).filter(Boolean).map((t) => Number(t));
  assert.equal(Buffer.from(bytes).toString('hex'), PINNED_ACCOUNT_WASM);
});

// Verbatim lines from a real enforcing simulation on testnet (protocol 29), where the generated
// policy refused a transfer one stroop over its exact amount. Middle events elided.
const ACCOUNT = 'CCABK6EOMBG7SU4IRQE5BZED2AAZUN524K676G3II62VX5R4VJHQP25O';
const POLICY = 'CAC6J6YAMQZIGBE2RJI2FLBK3KRR4DW2C5MQJOMMYKNJEGCM5HYTPFJN';
const SAC = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
const REAL_DENIAL = [
  'HostError: Error(Auth, InvalidAction)',
  '',
  'Event log (newest first):',
  `   0: [Diagnostic Event] contract:${SAC}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${ACCOUNT}, Error(Contract, #6)]`,
  `   1: [Failed Diagnostic Event (not emitted)] contract:${ACCOUNT}, topics:[log], data:["VM call trapped with HostError", __check_auth, Error(Contract, #6)]`,
  `   5: [Failed Diagnostic Event (not emitted)] contract:${POLICY}, topics:[error, Error(Contract, #6)], data:"escalating error to VM trap from failed host function call: fail_with_error"`,
  `   6: [Failed Diagnostic Event (not emitted)] contract:${POLICY}, topics:[error, Error(Contract, #6)], data:["failing with contract error", 6]`,
].join('\n');

test('a denial counts only when the policy itself raised the code inside the account\'s authentication', () => {
  assert.equal(policyDenial(REAL_DENIAL, ACCOUNT, POLICY), 6);
  // The same code raised by another contract — the SAC's #6 is AccountMissingError — is not a
  // policy decision.
  assert.equal(policyDenial(REAL_DENIAL.replaceAll(POLICY, SAC), ACCOUNT, POLICY), null);
  // Nor is a policy error outside the account's authentication of this call.
  assert.equal(policyDenial(REAL_DENIAL.split('\n').slice(4).join('\n'), ACCOUNT, POLICY), null);
  assert.equal(policyDenial('HostError: Error(Budget, ExceededLimit)', ACCOUNT, POLICY), null);
  // The account's failure must carry the code the policy raised.
  assert.equal(policyDenial(REAL_DENIAL.replace(`${ACCOUNT}, Error(Contract, #6)]`, `${ACCOUNT}, Error(Contract, #7)]`), ACCOUNT, POLICY), null);
});

// --- External signers: a passkey behind the OpenZeppelin WebAuthn verifier ------------------------
//
// stellar-accounts 0.7.2 hands an External signer's proof to `verifier.verify(auth_digest,
// key_data, sig_data)`. The WebAuthn verifier reads `key_data` as a 65-byte uncompressed P-256 key
// followed by the credential id, and `sig_data` as the XDR of `WebAuthnSigData`.

const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const p256 = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const rawOf = (publicKey) => {
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
};
// DER for ECDSA-Sig-Value { r INTEGER, s INTEGER }, written from X.690 by hand.
const derInt = (v) => {
  let b = Buffer.from(v.toString(16).padStart(2, '0').replace(/^(.(..)*)$/, '0$1'), 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([Buffer.from([0x02, b.length]), b]);
};
const der = (r, s) => {
  const body = Buffer.concat([derInt(r), derInt(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
};
const be32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex');

// Signer::External(Address, Bytes): Vec[Symbol("External"), Address, Bytes].
test('Signer::External encodes as a three-element vector', () => {
  const verifier = StrKey.encodeContract(Buffer.alloc(32, 0x71));
  const keyData = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 0x72), Buffer.from('cred')]);
  assert.equal(
    hex(externalSigner(verifier, keyData).toXDR()),
    hex(X.scVec([X.scSymbol('External'), X.scAddress(verifier), X.scBytes(keyData)])),
  );
});

test('passkey key data is the uncompressed P-256 key followed by the credential id', () => {
  const key = rawOf(p256().publicKey);
  const credentialId = Buffer.from('a credential id');
  assert.equal(hex(passkeyKeyData(key, credentialId)), hex(Buffer.concat([key, credentialId])));
  // The verifier reads exactly bytes 0..65 as the key: anything else would verify against the
  // wrong key or not at all.
  assert.throws(() => passkeyKeyData(key.subarray(1), credentialId), /65-byte/);
  assert.throws(() => passkeyKeyData(Buffer.concat([Buffer.from([2]), key.subarray(1)]), credentialId), /uncompressed/);
  assert.throws(() => passkeyKeyData(key, Buffer.alloc(0)), /credential id/);
});

test('the P-256 public key comes out of the SPKI WebAuthn returns as 04 ‖ X ‖ Y', () => {
  const { publicKey } = p256();
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  assert.equal(hex(p256PublicKeyRaw(spki)), hex(rawOf(publicKey)));
  const ed = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' });
  assert.throws(() => p256PublicKeyRaw(ed), /P-256/);
});

test('a DER signature becomes 64-byte r ‖ s with s in the lower half of the order', () => {
  const { publicKey, privateKey } = p256();
  const message = Buffer.from('authenticatorData ‖ sha256(clientDataJSON)');
  for (let i = 0; i < 8; i += 1) {
    const sig = nodeSign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
    const raw = derToLowS(sig);
    assert.equal(raw.length, 64);
    assert.ok(BigInt(`0x${hex(raw.subarray(32))}`) <= P256_N / 2n, 'low-S');
    assert.ok(verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, raw), 'still verifies');
  }
});

test('a high-S signature is folded to n - s, and short integers are left-padded', () => {
  const r = 5n;
  const lowS = 7n;
  assert.equal(hex(derToLowS(der(r, lowS))), hex(Buffer.concat([be32(r), be32(lowS)])));
  assert.equal(hex(derToLowS(der(r, P256_N - lowS))), hex(Buffer.concat([be32(r), be32(lowS)])));
  // A 32-byte value with its top bit set is a 33-byte DER INTEGER with a leading zero.
  const big = (1n << 255n) + 3n;
  assert.equal(der(big, lowS)[3], 33);
  assert.equal(hex(derToLowS(der(big, lowS))), hex(Buffer.concat([be32(big), be32(lowS)])));
  // And a real one: both halves of the pair verify, only the low one is what we send.
  const { publicKey, privateKey } = p256();
  const message = Buffer.from('m');
  const sig = nodeSign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const [rr, ss] = [BigInt(`0x${hex(sig.subarray(0, 32))}`), BigInt(`0x${hex(sig.subarray(32))}`)];
  const high = ss > P256_N / 2n ? ss : P256_N - ss;
  const folded = derToLowS(der(rr, high));
  assert.equal(hex(folded.subarray(32)), hex(be32(P256_N - high)));
  assert.ok(verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, folded));
});

test('malformed DER signatures are refused rather than truncated', () => {
  const good = der(5n, 7n);
  assert.throws(() => derToLowS(Buffer.concat([good, Buffer.from([0])])), /DER/);
  assert.throws(() => derToLowS(Buffer.from([0x31, ...good.subarray(1)])), /DER/);
  assert.throws(() => derToLowS(der(0n, 7n)), /range/);
  assert.throws(() => derToLowS(der(5n, P256_N)), /range/);
  assert.throws(() => derToLowS(der(1n << 256n, 7n)), /range|DER/);
  // A negative INTEGER (top bit set, no leading zero), a non-minimal leading zero, and a
  // long-form sequence length: valid BER at best, not the DER WebAuthn specifies.
  assert.throws(() => derToLowS(Buffer.from('3006020180020107', 'hex')), /DER/);
  assert.throws(() => derToLowS(Buffer.from('300702020005020107', 'hex')), /DER/);
  assert.throws(() => derToLowS(Buffer.from('30810602010502010700', 'hex').subarray(0, 9)), /DER/);
});

// WebAuthnSigData { signature: BytesN<64>, authenticator_data: Bytes, client_data: Bytes } is a
// contracttype struct: an ScMap keyed by field-name symbols in ascending order.
test('WebAuthnSigData is the XDR of a struct map with fields in symbol order', () => {
  const authenticatorData = Buffer.alloc(37, 0x05);
  const clientDataJSON = Buffer.from('{"type":"webauthn.get","challenge":"x"}');
  const signature = Buffer.alloc(64, 0x09);
  assert.equal(
    hex(webAuthnSigData({ authenticatorData, clientDataJSON, signature })),
    hex(X.scMap([
      [X.scSymbol('authenticator_data'), X.scBytes(authenticatorData)],
      [X.scSymbol('client_data'), X.scBytes(clientDataJSON)],
      [X.scSymbol('signature'), X.scBytes(signature)],
    ])),
  );
  assert.throws(() => webAuthnSigData({ authenticatorData, clientDataJSON, signature: Buffer.alloc(70) }), /64/);
});

test('AuthPayload for an External signer carries the verifier proof as the signer\'s bytes', () => {
  const verifier = StrKey.encodeContract(Buffer.alloc(32, 0x73));
  const keyData = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 0x74), Buffer.from('id')]);
  const proof = Buffer.from('sig data xdr');
  const expected = X.scMap([
    [X.scSymbol('context_rule_ids'), X.scVec([Buffer.concat([X.u32(3), X.u32(0)])])],
    [X.scSymbol('signers'), X.scMap([[X.scVec([X.scSymbol('External'), X.scAddress(verifier), X.scBytes(keyData)]), X.scBytes(proof)]])],
  ]);
  assert.equal(hex(authPayload([{ signer: externalSigner(verifier, keyData), proof }], [0]).toXDR()), hex(expected));
});

test('signing with an External signer: one entry, and the passkey signs exactly the account digest', async () => {
  const account = StrKey.encodeContract(Buffer.alloc(32, 0x68));
  const verifier = StrKey.encodeContract(Buffer.alloc(32, 0x69));
  const keyData = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 0x6a), Buffer.from('id')]);
  const until = 654321;
  const asked = [];
  const passkey = { verifier, keyData, sign: async (digest) => { asked.push(Buffer.from(digest)); return Buffer.from('proof'); } };

  const { accountEntry, delegateEntry, digest } = await signForSmartAccount({
    entry: recordedAccountEntry(account), expect: transferTo(account), signer: passkey, ruleIds: [0],
    validUntilLedger: until, networkPassphrase: Networks.TESTNET,
  });

  assert.equal(delegateEntry, null, 'an External signer is verified by its verifier, not by a second entry');
  const accountPreimage = X.authPreimage(Networks.TESTNET, 42n, until,
    X.invocation(TOKEN, 'transfer', [X.scAddress(account), X.scI128(1n)]));
  assert.equal(hex(digest), hex(authDigest(sha256(accountPreimage), [0])));
  assert.deepEqual(asked.map(hex), [hex(digest)]);
  const creds = accountEntry.credentials.address;
  assert.equal(creds.signatureExpirationLedger, until);
  assert.equal(hex(creds.signature.toXDR()),
    hex(authPayload([{ signer: externalSigner(verifier, keyData), proof: Buffer.from('proof') }], [0]).toXDR()));
});

test('an External signer is not asked to sign a recorded invocation that is not the intended call', async () => {
  const account = StrKey.encodeContract(Buffer.alloc(32, 0x6b));
  let asked = 0;
  const passkey = { verifier: account, keyData: Buffer.alloc(66, 4), sign: async () => { asked += 1; return Buffer.alloc(0); } };
  await assert.rejects(
    signForSmartAccount({
      entry: recordedAccountEntry(account, transferTo(account, 2n)), expect: transferTo(account, 1n), signer: passkey,
      ruleIds: [0], validUntilLedger: 1, networkPassphrase: Networks.TESTNET,
    }),
    /not the intended call/,
  );
  assert.equal(asked, 0);
});

test('the pinned WebAuthn verifier hash is the one the README quotes', () => {
  assert.match(PINNED_WEBAUTHN_VERIFIER_WASM, /^[0-9a-f]{64}$/);
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes(PINNED_WEBAUTHN_VERIFIER_WASM), 'README does not quote the pinned verifier hash');
});

// add_context_rule(context_type, name, valid_until, signers, policies), from one description that
// both the spec path and the install-intent path produce, so the two can be compared as bytes.
test('add_context_rule arguments, written out from the contract signature', () => {
  const sac = StrKey.encodeContract(Buffer.alloc(32, 0x81));
  const policy = StrKey.encodeContract(Buffer.alloc(32, 0x82));
  const verifier = StrKey.encodeContract(Buffer.alloc(32, 0x83));
  const g = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x84));
  const keyHex = `04${'85'.repeat(64)}${'86'.repeat(16)}`;
  const args = addContextRuleArgs({
    context: sac, name: 'cap', validUntil: 9,
    signers: [{ kind: 'delegated', address: g }, { kind: 'external', verifier, key_hex: keyHex }],
    policies: [{ address: policy, install_params: { kind: 'generated' } }],
  });
  assert.deepEqual(args.map((a) => hex(a.toXDR())), [
    hex(X.scVec([X.scSymbol('CallContract'), X.scAddress(sac)])),
    hex(Buffer.concat([X.u32(14), X.opaque(Buffer.from('cap'))])),          // SCV_STRING
    hex(Buffer.concat([X.u32(3), X.u32(9)])),
    hex(X.scVec([
      X.scVec([X.scSymbol('Delegated'), X.scAddress(g)]),
      X.scVec([X.scSymbol('External'), X.scAddress(verifier), X.scBytes(Buffer.from(keyHex, 'hex'))]),
    ])),
    hex(X.scMap([[X.scAddress(policy), Buffer.concat([X.u32(3), X.u32(0)])]])),
  ]);
  assert.equal(hex(addContextRuleArgs({ context: sac, name: 'cap', validUntil: null, signers: [], policies: [] })[2].toXDR()), '00000001');
  assert.throws(() => addContextRuleArgs({
    context: sac, name: 'cap', validUntil: null, signers: [],
    policies: [{ address: policy, install_params: { kind: 'unknown' } }],
  }), /unknown/);
  const generated = { address: policy, install_params: { kind: 'generated' } };
  assert.throws(() => addContextRuleArgs({ context: sac, name: 'cap', validUntil: null, signers: [], policies: [generated, generated] }), /duplicate/);
});

test('composed install parameters are exact i128/u32 and map keys follow contract-address bytes', () => {
  const smaller = StrKey.encodeContract(Buffer.alloc(32, 1));
  const larger = StrKey.encodeContract(Buffer.alloc(32, 2));
  const policies = [
    { address: larger, install_params: { kind: 'generated' } },
    { address: smaller, install_params: { kind: 'spending_limit', spending_limit: '9007199254740993', period_ledgers: 12 } },
  ];
  const input = { context: TOKEN, name: 'sub', validUntil: 55, signers: [], policies };
  const expected = X.scMap([
    [X.scAddress(smaller), X.scMap([
      [X.scSymbol('period_ledgers'), Buffer.concat([X.u32(3), X.u32(12)])],
      [X.scSymbol('spending_limit'), X.scI128(9007199254740993n)],
    ])],
    [X.scAddress(larger), Buffer.concat([X.u32(3), X.u32(0)])],
  ]);
  assert.equal(hex(addContextRuleArgs(input)[4].toXDR()), hex(expected));
  for (const bad of ['0', '-1', '01', (1n << 127n).toString()]) {
    policies[1].install_params.spending_limit = bad;
    assert.throws(() => addContextRuleArgs(input), /spending limit/);
  }
  policies[1].install_params.spending_limit = '1';
  for (const bad of [0, -1, 1.2, 0x1_0000_0000]) {
    policies[1].install_params.period_ledgers = bad;
    assert.throws(() => addContextRuleArgs(input), /period/);
  }
});
