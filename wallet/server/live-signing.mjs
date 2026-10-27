// The live signing capability: the wallet's in-memory automation delegate signing one case of the
// live-enforcement check (docs/ATOMIC-LIVE-HELPER.md) on testnet. It is the only path by which that
// key signs anything a live network accepts, and it signs nothing it did not build.
//
// It takes the structure of one transfer — account, asset, recipient, amount, expected rule, nonce and
// expiry — never bytes, a preimage or an entry, and in particular nothing from a recording-mode
// simulation. From that structure it builds both of the delegate's authorization entries itself:
//
//   - the account's entry for exactly `asset.transfer(account, recipient, amount)`, with no
//     sub-invocations, checked under exactly `[expected_rule_id]`, signed by `Delegated(delegate)`
//     (address-bound credentials; the account's own signature is the AuthPayload, whose delegated
//     proof is empty);
//   - the delegate's own entry for `account.__check_auth(sha256(signature_payload || xdr(rule ids)))`,
//     which is the only thing the key signs: the preimage of that entry, in the testnet network.
//
// Its network allowlist is testnet alone. The offline execution capability (native-protocol.mjs)
// signs only preimages in the derived offline network, so neither can sign in the other's domain.
// A capability is minted for one consented check (`approved`): the account, recipient, rule, the
// two amounts and the one expiry the owner saw, which lies at most LIVE_SIGNATURE_LEDGERS past the
// ledger read when the statement was prepared. It signs each of the two amounts once and nothing else.
import { randomBytes } from 'node:crypto';
import { Address, Asset, Networks, StrKey, hash, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { LIVE_SIGNATURE_LEDGERS } from '../shared/live-consent.mjs';

const sha256 = (bytes) => Buffer.from(hash(bytes));
const networkId = (passphrase) => sha256(Buffer.from(passphrase)).toString('hex');
/** The networks a live case may be signed for. */
export const LIVE_NETWORK_IDS = Object.freeze([networkId(Networks.TESTNET)]);
/** The helper executes at most the 1,000,000-stroop sample permit plus its one-stroop adjacent denial. */
export const LIVE_MAX_AMOUNT = 1_000_001n;
const SAC = Asset.native().contractId(Networks.TESTNET);
const STRUCTURE = ['network_id', 'account', 'asset', 'recipient', 'amount', 'expected_rule_id', 'nonce', 'signature_expiration_ledger'];
const MAX_SIGNATURES = 2;
const I64_MIN = -(1n << 63n), I64_MAX = (1n << 63n) - 1n;

const refuse = () => { throw new Error('live signature refused; no live authorization was created'); };
const u32 = (n, min = 0) => Number.isSafeInteger(n) && n >= min && n <= 0xffffffff;
const sym = (value) => xdr.ScVal.scvSymbol(value);
/** A contracttype struct: a map keyed by field-name symbols in ascending order. */
const struct = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort()
  .map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));
const invocation = (contract, functionName, args) => new xdr.SorobanAuthorizedInvocation({
  function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
    contractAddress: new Address(contract).toScAddress(), functionName, args })),
  subInvocations: [],
});
const int64 = (text) => {
  if (typeof text !== 'string' || !/^(0|-?[1-9][0-9]{0,18})$/.test(text)) refuse();
  const value = BigInt(text);
  if (value < I64_MIN || value > I64_MAX) refuse();
  return value;
};

const APPROVED = ['network_id', 'account', 'recipient', 'expected_rule_id', 'signature_expiration_ledger', 'read_ledger', 'amounts'];
/** The consented check a capability is minted for, refused unless it is itself a bounded live case. */
function checkApproved(input, delegate) {
  if (!input || typeof input !== 'object' || Object.keys(input).length !== APPROVED.length
    || APPROVED.some((field) => !Object.hasOwn(input, field)) || !Array.isArray(input.amounts) || input.amounts.length !== 2) refuse();
  const [permit, denial] = input.amounts;
  const shape = (amount) => checkStructure({ network_id: input.network_id, account: input.account, asset: SAC, recipient: input.recipient,
    amount, expected_rule_id: input.expected_rule_id, nonce: '0', signature_expiration_ledger: input.signature_expiration_ledger }, delegate);
  shape(permit); shape(denial);
  if (BigInt(denial) !== BigInt(permit) + 1n || !u32(input.read_ledger, 1)
    || input.signature_expiration_ledger <= input.read_ledger
    || input.signature_expiration_ledger - input.read_ledger > LIVE_SIGNATURE_LEDGERS) refuse();
  return Object.freeze({ ...input, amounts: Object.freeze([permit, denial]) });
}

function checkStructure(input, delegate) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || ArrayBuffer.isView(input)
    || Object.getPrototypeOf(input) !== Object.prototype || Object.keys(input).length !== STRUCTURE.length
    || STRUCTURE.some((field) => !Object.hasOwn(input, field))) refuse();
  const s = input;
  if (typeof s.network_id !== 'string' || !LIVE_NETWORK_IDS.includes(s.network_id) || s.asset !== SAC
    || typeof s.account !== 'string' || !StrKey.isValidContract(s.account)
    || typeof s.recipient !== 'string' || !(StrKey.isValidEd25519PublicKey(s.recipient) || StrKey.isValidContract(s.recipient))
    || new Set([s.account, s.asset, s.recipient, delegate]).size !== 4
    || typeof s.amount !== 'string' || !/^[1-9][0-9]{0,6}$/.test(s.amount) || BigInt(s.amount) > LIVE_MAX_AMOUNT
    || !u32(s.expected_rule_id, 1) || !u32(s.signature_expiration_ledger, 1)) refuse();
  return { ...s, amount: BigInt(s.amount), nonce: int64(s.nonce) };
}

/**
 * The live capability of one in-memory key (`publicKey`, `sign`, `verify`) for one consented check.
 * Only `DelegateCapabilities.live` creates it; the result exposes the address and `authorizeTransfer`.
 */
export function createLiveCapability(key, approvedCheck) {
  const address = key.publicKey();
  if (!StrKey.isValidEd25519PublicKey(address)) refuse();
  const approved = checkApproved(approvedCheck, address);
  const remaining = new Set(approved.amounts);
  const nonces = new Set();
  let signatures = 0;
  /** Sign the preimage this module built, only if it is a plain authorization preimage on an allowed network. */
  function signLive(preimage) {
    if (preimage.type !== 'envelopeTypeSorobanAuthorization'
      || !LIVE_NETWORK_IDS.includes(Buffer.from(preimage.sorobanAuthorization.networkId.value).toString('hex'))) refuse();
    const digest = sha256(preimage.toXDR());
    const signature = Buffer.from(key.sign(digest));
    if (signature.length !== 64 || !key.verify(digest, signature)) refuse();
    return signature;
  }
  return Object.freeze({
    address,
    authorizeTransfer(structure) {
      try {
        const s = checkStructure(structure, address);
        if (signatures >= MAX_SIGNATURES || nonces.has(s.nonce) || !remaining.has(structure.amount)
          || ['network_id', 'account', 'recipient', 'expected_rule_id', 'signature_expiration_ledger']
            .some((field) => structure[field] !== approved[field])) refuse();
        const network = Buffer.from(s.network_id, 'hex');
        const transfer = invocation(s.asset, 'transfer', [new Address(s.account).toScVal(), new Address(s.recipient).toScVal(),
          nativeToScVal(s.amount, { type: 'i128' })]);
        const ruleIds = xdr.ScVal.scvVec([xdr.ScVal.scvU32(s.expected_rule_id)]);
        const credentials = new xdr.SorobanAddressCredentials({
          address: new Address(s.account).toScAddress(), nonce: s.nonce, signatureExpirationLedger: s.signature_expiration_ledger,
          signature: struct({ context_rule_ids: ruleIds, signers: xdr.ScVal.scvMap([new xdr.ScMapEntry({
            key: xdr.ScVal.scvVec([sym('Delegated'), new Address(address).toScVal()]), val: xdr.ScVal.scvBytes(Buffer.alloc(0)) })]) }),
        });
        const transferEntry = new xdr.SorobanAuthorizationEntry({
          credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(credentials), rootInvocation: transfer });
        // The host's signature payload for an address-bound entry, and what a delegated signer authorizes.
        const payload = sha256(xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(
          new xdr.HashIdPreimageSorobanAuthorizationWithAddress({ networkId: network, nonce: s.nonce,
            signatureExpirationLedger: s.signature_expiration_ledger, invocation: transfer, address: credentials.address })).toXDR());
        const digest = sha256(Buffer.concat([payload, ruleIds.toXDR()]));
        const checkAuth = invocation(s.account, '__check_auth', [xdr.ScVal.scvBytes(digest)]);
        const delegateNonce = randomBytes(8).readBigInt64BE();
        const signature = signLive(xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
          networkId: network, nonce: delegateNonce, signatureExpirationLedger: s.signature_expiration_ledger, invocation: checkAuth })));
        nonces.add(s.nonce);
        remaining.delete(structure.amount);
        signatures++;
        const delegateEntry = new xdr.SorobanAuthorizationEntry({
          credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
            address: new Address(address).toScAddress(), nonce: delegateNonce, signatureExpirationLedger: s.signature_expiration_ledger,
            signature: xdr.ScVal.scvVec([struct({ public_key: xdr.ScVal.scvBytes(StrKey.decodeEd25519PublicKey(address)),
              signature: xdr.ScVal.scvBytes(signature) })]),
          })),
          rootInvocation: checkAuth,
        });
        return Object.freeze({ transferEntryXdr: transferEntry.toXDR('base64'), delegateEntryXdr: delegateEntry.toXDR('base64') });
      } catch { return refuse(); }
    },
  });
}
