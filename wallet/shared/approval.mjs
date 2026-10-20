// Browser-side semantic review. This runs in the wallet, independently of MCP output.
import { Buffer } from 'buffer';
import { scValToNative, xdr } from '#wallet-stellar-sdk';
import { decide, intentMismatches, walletTrust } from './authority.mjs';
import { decodeBase64Url } from './base64url.mjs';

export const NETWORK_ID = 'cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472';
export const ACCOUNT_WASM = 'a12747ff6c139dc14fc2fd30d200d6bbb5da7b5d59812c047ce1f9cad226b289';
export const WEBAUTHN_WASM = 'e63a030d0f1a1481e36059a4837c433083b33e704c1f9625b7314795b6d72b76';
const refuse = () => { throw new Error('wallet review refused; refresh and review the exact grant'); };
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const isHash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

export function freezeCopy(value) {
  const copy = JSON.parse(JSON.stringify(value));
  const freeze = (part) => {
    if (part && typeof part === 'object') {
      for (const value of Object.values(part)) freeze(value);
      Object.freeze(part);
    }
    return part;
  };
  return freeze(copy);
}

/** Match the full stored credential, not only the 65-byte identity reported by authority. */
export function ownerRule(intent, wallet, raw) {
  if (typeof raw !== 'string' || raw.length > 32 * 1024 || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) refuse();
  let decoded;
  try {
    const value = xdr.ScVal.fromXDR(raw, 'base64');
    if (value.toXDR('base64') !== raw) refuse();
    decoded = scValToNative(value);
  } catch { refuse(); }
  const ledger = intent.authority.verdict.observed_ledger;
  const choices = intent.authority.verdict.authority_list.filter((entry) =>
    ['any_call', 'account_calls'].includes(entry.reach?.kind) && entry.requirement?.kind === 'all_of'
    && (entry.valid_until === null || entry.valid_until > ledger) && entry.requirement.signers?.length === 1);
  const choice = choices.find((entry) => entry.rule_id === decoded?.id);
  const signer = choice?.requirement.signers[0];
  if (!signer || signer.kind !== 'external' || signer.scheme !== 'webauthn_p256' || signer.aliases_restricted_key
    || signer.public_key !== wallet.publicKey || signer.verifier !== wallet.verifier
    || signer.verifier_code_hash !== WEBAUTHN_WASM) refuse();
  if (typeof wallet.credentialId !== 'string' || !/^[A-Za-z0-9_-]{1,1366}$/.test(wallet.credentialId)
    || !/^04[0-9a-f]{128}$/.test(wallet.publicKey)) refuse();
  const credential = decodeBase64Url(wallet.credentialId);
  const key = Buffer.concat([Buffer.from(wallet.publicKey, 'hex'), credential]);
  const stored = decoded?.signers;
  if (!Array.isArray(stored) || stored.length !== 1 || !Array.isArray(stored[0])
    || stored[0].length !== 3 || stored[0][0] !== 'External' || stored[0][1] !== wallet.verifier
    || !Buffer.from(stored[0][2]).equals(key) || !equal(decoded.policies, [])
    || !(equal(decoded.context_type, ['Default']) || equal(decoded.context_type, ['CallContract', wallet.contractId]))
    || (decoded.valid_until ?? null) !== choice.valid_until) refuse();
  return choice.rule_id;
}

/** Returned immutable data is the approval display and all subsequent signing expectations. */
export function reviewIntent({ intent, expected, wallet, ownerRuleXdr }) {
  try {
    const v = intent.authority.verdict;
    if (intentMismatches(intent).length || expected.networkId !== NETWORK_ID
      || expected.account !== wallet.contractId || v.account_code_hash !== ACCOUNT_WASM
      || ![expected.specHash, expected.bindingSetHash, expected.registrySnapshotRoot].every(isHash)
      || intent.authority.binding_set_hash !== expected.bindingSetHash || v.binding_set_hash !== expected.bindingSetHash) refuse();
    const trust = walletTrust({ own: [{ scheme: 'webauthn_p256', public_key: wallet.publicKey }] });
    const decision = decide(intent.authority, { trust, expect: expected });
    if (!decision.accept) refuse();
    const ownerRuleId = ownerRule(intent, wallet, ownerRuleXdr);
    return freezeCopy({ intent, expected, wallet, ownerRuleId, ownerRuleXdr,
      commitment: decision.commitment, observedLedger: decision.observedLedger,
      authorities: decision.entries, approval_state: 'reviewed_not_signed', trust_basis: 'wallet_owned_passkey_identity' });
  } catch { refuse(); }
}
