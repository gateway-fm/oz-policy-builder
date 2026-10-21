import { Buffer } from 'buffer';
import { Address, Networks, buildAuthorizationEntryPreimage, hash, xdr } from '#wallet-stellar-sdk';
import { freezeCopy } from './approval.mjs';
import { decodeEnvelope } from './assembly.mjs';
import { decodeBase64Url, encodeBase64Url } from './base64url.mjs';
import { directAddressCredentials } from './auth-credentials.mjs';

const refuse = () => { throw new Error('wallet signature refused; refresh and approve again'); };
const digest = (value) => Buffer.from(hash(value));
const same = (a, b) => Buffer.from(a.toXDR()).equals(Buffer.from(b.toXDR()));
const field = (name, val) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val });

/** Re-validate the serialized SDK16 result in the isolated SDK17 wallet module. */
export async function validateSignedAuthorization({ approval, checked, signedAuthEntriesXdr, origin }) {
  try {
    if (!Array.isArray(signedAuthEntriesXdr) || signedAuthEntriesXdr.length !== 1) refuse();
    const raw = signedAuthEntriesXdr[0];
    if (typeof raw !== 'string' || raw.length > 32 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) refuse();
    const entry = xdr.SorobanAuthorizationEntry.fromXDR(raw, 'base64');
    if (entry.toXDR('base64') !== raw) refuse();
    const credentials = directAddressCredentials(entry.credentials);
    const signature = credentials.signature;
    credentials.signature = xdr.ScVal.scvVoid();
    if (entry.toXDR('base64') !== checked.authEntriesXdr[0] || checked.ownerRuleId !== approval.ownerRuleId
      || checked.authorityCommitment !== approval.commitment) refuse();
    credentials.signature = signature;
    if (signature.type !== 'scvMap' || signature.map?.length !== 2) refuse();
    const ruleIds = xdr.ScVal.scvVec([xdr.ScVal.scvU32(approval.ownerRuleId)]);
    const signers = signature.map[1].val;
    if (signers.type !== 'scvMap' || signers.map?.length !== 1 || signers.map[0].val.type !== 'scvBytes') refuse();
    const proofBytes = Buffer.from(signers.map[0].val.bytes.value);
    if (proofBytes.length > 16 * 1024) refuse();
    const key = Buffer.concat([Buffer.from(approval.wallet.publicKey, 'hex'), decodeBase64Url(approval.wallet.credentialId)]);
    const expected = xdr.ScVal.scvMap([
      field('context_rule_ids', ruleIds), field('signers', xdr.ScVal.scvMap([new xdr.ScMapEntry({
        key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'), new Address(approval.wallet.verifier).toScVal(), xdr.ScVal.scvBytes(key)]),
        val: xdr.ScVal.scvBytes(proofBytes),
      })])),
    ]);
    if (!same(signature, expected)) refuse();
    const proof = xdr.ScVal.fromXDR(proofBytes);
    if (proof.type !== 'scvMap' || proof.map?.length !== 3 || !Buffer.from(proof.toXDR()).equals(proofBytes)) refuse();
    for (let i = 0; i < 3; i++) {
      if (!same(proof.map[i].key, xdr.ScVal.scvSymbol(['authenticator_data', 'client_data', 'signature'][i]))
        || proof.map[i].val.type !== 'scvBytes') refuse();
    }
    const [auth, clientBytes, sig] = proof.map.map((item) => Buffer.from(item.val.bytes.value));
    const url = new URL(origin);
    if (url.origin !== origin || !['http:', 'https:'].includes(url.protocol)
      || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password) refuse();
    const client = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(clientBytes));
    const preimage = buildAuthorizationEntryPreimage(entry, checked.expirationLedger, Networks.TESTNET);
    const challenge = encodeBase64Url(digest(Buffer.concat([digest(preimage.toXDR()), ruleIds.toXDR()])));
    if (client.type !== 'webauthn.get' || client.challenge !== challenge || client.origin !== origin
      || (client.crossOrigin !== undefined && client.crossOrigin !== false) || client.topOrigin !== undefined
      || auth.length < 37 || auth.length > 4096 || sig.length !== 64 || (auth[32] & 5) !== 5
      || !auth.subarray(0, 32).equals(digest(Buffer.from(url.hostname)))) refuse();
    const publicKey = await globalThis.crypto.subtle.importKey('raw', Buffer.from(approval.wallet.publicKey, 'hex'),
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    if (!await globalThis.crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sig,
      Buffer.concat([auth, digest(clientBytes)]))) refuse();
    const envelope = decodeEnvelope(checked.envelopeXdr);
    const op = envelope.v1.tx.operations[0].body.invokeHostFunctionOp;
    if (op.auth.length !== 1 || op.auth[0].toXDR('base64') !== checked.authEntriesXdr[0]) refuse();
    op.auth = [entry];
    return freezeCopy({ envelopeXdr: envelope.toXDR('base64'), signedAuthEntriesXdr: [raw],
      authentication: 'webauthn_user_verified', human_approval_attested: false });
  } catch { refuse(); }
}
