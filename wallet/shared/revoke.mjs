// Revocation: the owner's passkey signs `remove_context_rule(rule_id)` for one rule this wallet
// installed and recorded. Validated in the browser and the backend before the passkey is asked.
import { Buffer } from 'buffer';
import { Address, StrKey, hash, scValToNative, xdr } from '#wallet-stellar-sdk';
import { NETWORK_ID, freezeCopy } from './approval.mjs';
import { decodeEnvelope, resources } from './assembly.mjs';
import { directAddressCredentials } from './auth-credentials.mjs';
import { decodeBase64Url } from './base64url.mjs';

/** The fee payer's ceiling for the removal, as for every other wallet transaction. */
export const REMOVAL_MAX_FEE_STROOPS = 10_000_000;
const refuse = () => { throw new Error('wallet revocation refused; refresh and review again'); };
const integer = (n, min = 1, max = 0xffffffff) => Number.isSafeInteger(n) && n >= min && n <= max;
const same = (a, b) => Buffer.from(a.toXDR()).equals(Buffer.from(b.toXDR()));
const sequence = (text) => typeof text === 'string' && /^(0|[1-9][0-9]{0,18})$/.test(text) && BigInt(text) < 9223372036854775807n;

/** `account.remove_context_rule(rule_id)`. */
export function removalCall(account, ruleId) {
  if (!StrKey.isValidContract(account) || !integer(ruleId)) refuse();
  return new xdr.InvokeContractArgs({ contractAddress: new Address(account).toScAddress(), functionName: 'remove_context_rule',
    args: [xdr.ScVal.scvU32(ruleId)] });
}

/** The stored owner rule is still exactly this wallet's credential, alone, with no policies. */
function ownerRuleMatches(wallet, ownerRuleId, raw) {
  if (typeof raw !== 'string' || raw.length > 32 * 1024 || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) refuse();
  const value = xdr.ScVal.fromXDR(raw, 'base64');
  if (value.toXDR('base64') !== raw) refuse();
  const rule = scValToNative(value);
  const key = Buffer.concat([Buffer.from(wallet.publicKey, 'hex'), decodeBase64Url(wallet.credentialId)]);
  const signers = rule?.signers;
  const context = JSON.stringify(rule?.context_type);
  if (rule?.id !== ownerRuleId || !Array.isArray(signers) || signers.length !== 1 || signers[0]?.[0] !== 'External'
    || signers[0][1] !== wallet.verifier || !Buffer.from(signers[0][2]).equals(key) || JSON.stringify(rule.policies) !== '[]'
    || !(context === '["Default"]' || context === JSON.stringify(['CallContract', wallet.contractId]))) refuse();
}

/**
 * The removal approval: the wallet's own owner rule and passkey, bound to one recorded
 * installation (account, rule ID, installation transaction). Its commitment is what the
 * signature checks compare.
 */
export function reviewRemoval({ wallet, ownerRuleId, ownerRuleXdr, installation }) {
  try {
    if (!StrKey.isValidContract(wallet.contractId) || !StrKey.isValidContract(wallet.verifier)
      || !/^04[0-9a-f]{128}$/.test(wallet.publicKey) || !/^[A-Za-z0-9_-]{1,1366}$/.test(wallet.credentialId)
      || !integer(ownerRuleId, 0) || installation.account !== wallet.contractId || !integer(installation.ruleId)
      || installation.ruleId === ownerRuleId || !/^[0-9a-f]{64}$/.test(installation.transactionHash)) refuse();
    ownerRuleMatches(wallet, ownerRuleId, ownerRuleXdr);
    const commitment = Buffer.from(hash(Buffer.from(JSON.stringify(['wallet-revoke/v1', NETWORK_ID, wallet.contractId, wallet.verifier,
      wallet.publicKey, wallet.credentialId, ownerRuleId, ownerRuleXdr, installation.ruleId, installation.transactionHash])))).toString('hex');
    return freezeCopy({ wallet, ownerRuleId, ownerRuleXdr, commitment,
      installation: { account: installation.account, ruleId: installation.ruleId, transactionHash: installation.transactionHash } });
  } catch { return refuse(); }
}

/** Independently validate the unsigned removal before the passkey signs it (as the sample transfer). */
export function validateRemovalAssembly({ approval, assembly, ownerRuleXdr, limits }) {
  try {
    const fresh = reviewRemoval({ wallet: approval.wallet, ownerRuleId: approval.ownerRuleId, ownerRuleXdr,
      installation: approval.installation });
    if (fresh.commitment !== approval.commitment || limits.maxFeeStroops !== REMOVAL_MAX_FEE_STROOPS || !sequence(limits.sourceSequence)
      || !integer(limits.validityLedgers, 2, 120) || !integer(limits.currentLedger) || !integer(limits.ownerReadLedger)
      || limits.currentLedger < limits.ownerReadLedger || limits.currentLedger - limits.ownerReadLedger > 12
      || !StrKey.isValidEd25519PublicKey(limits.feePayer)
      || assembly.network_id !== NETWORK_ID || assembly.fee_payer !== limits.feePayer
      || assembly.source_sequence !== limits.sourceSequence || assembly.simulation_auth_mode !== 'record'
      || assembly.evidence_trust !== 'rpc_reported' || assembly.state_dependent !== true || assembly.writes_committed !== false
      || !['none', 'automatic_within_invocation'].includes(assembly.restoration)) refuse();
    for (const n of [assembly.sequence_read_ledger, assembly.simulation_ledger, assembly.min_ledger, assembly.max_ledger]) {
      if (!integer(n)) refuse();
    }
    if (assembly.sequence_read_ledger < limits.ownerReadLedger
      || assembly.simulation_ledger < assembly.sequence_read_ledger || limits.currentLedger < assembly.simulation_ledger
      || assembly.min_ledger !== assembly.sequence_read_ledger
      || assembly.max_ledger !== assembly.min_ledger + limits.validityLedgers
      || limits.currentLedger + 1 >= assembly.max_ledger) refuse();
    const envelope = decodeEnvelope(assembly.envelope_xdr_base64);
    if (Buffer.from(hash(envelope.toXDR())).toString('hex') !== assembly.envelope_xdr_sha256 || envelope.v1.signatures.length) refuse();
    const tx = envelope.v1.tx;
    if (tx.sourceAccount.type !== 'keyTypeEd25519' || StrKey.encodeEd25519PublicKey(tx.sourceAccount.ed25519.value) !== limits.feePayer
      || tx.seqNum !== BigInt(limits.sourceSequence) + 1n || !integer(tx.fee, 100, REMOVAL_MAX_FEE_STROOPS)
      || tx.fee !== assembly.fee_stroops || tx.memo.type !== 'memoNone' || tx.cond.type !== 'precondV2') refuse();
    const cond = tx.cond.v2;
    if ((cond.timeBounds && (cond.timeBounds.minTime !== 0n || cond.timeBounds.maxTime !== 0n))
      || cond.minSeqNum !== null || cond.minSeqAge !== 0n || cond.minSeqLedgerGap !== 0 || cond.extraSigners.length
      || cond.ledgerBounds?.minLedger !== assembly.min_ledger || cond.ledgerBounds.maxLedger !== assembly.max_ledger
      || tx.operations.length !== 1 || tx.operations[0].sourceAccount !== null) refuse();
    const op = tx.operations[0].body;
    const call = removalCall(approval.installation.account, approval.installation.ruleId);
    if (op.type !== 'invokeHostFunction' || op.invokeHostFunctionOp.hostFunction.type !== 'hostFunctionTypeInvokeContract'
      || !same(op.invokeHostFunctionOp.hostFunction.invokeContract, call) || op.invokeHostFunctionOp.auth.length !== 1) refuse();
    const entry = op.invokeHostFunctionOp.auth[0];
    const credentials = directAddressCredentials(entry.credentials);
    if (entry.rootInvocation.function.type !== 'sorobanAuthorizedFunctionTypeContractFn'
      || !same(entry.rootInvocation.function.contractFn, call) || entry.rootInvocation.subInvocations.length
      || Address.fromScAddress(credentials.address).toString() !== approval.wallet.contractId
      || credentials.signature.type !== 'scvVoid' || credentials.signatureExpirationLedger !== assembly.max_ledger - 1
      || tx.ext.type !== 'sorobanData') refuse();
    resources(tx.ext.sorobanData, assembly.restoration, tx.fee);
    return freezeCopy({ envelopeXdr: assembly.envelope_xdr_base64, authEntriesXdr: [entry.toXDR('base64')],
      expirationLedger: credentials.signatureExpirationLedger, ownerRuleId: approval.ownerRuleId, feeStroops: tx.fee,
      minLedger: assembly.min_ledger, maxLedger: assembly.max_ledger, authorityCommitment: approval.commitment });
  } catch { return refuse(); }
}

/** What the owner's removal signature does, shown before the passkey is asked. */
export function revokeConsent({ approval, checked, maxFeeStroops }) {
  try {
    const { account, ruleId, transactionHash } = approval.installation;
    if (checked.authorityCommitment !== approval.commitment || checked.ownerRuleId !== approval.ownerRuleId
      || maxFeeStroops !== REMOVAL_MAX_FEE_STROOPS || !integer(checked.feeStroops, 100, maxFeeStroops)) refuse();
    return freezeCopy({
      schema: 'ozpb-revoke-consent/v1', network: 'testnet', network_id: NETWORK_ID,
      owner_signs: { contract: account, function: 'remove_context_rule', args: [ruleId], context_rule_ids: [approval.ownerRuleId] },
      installation: { rule_id: ruleId, transaction: transactionHash },
      transaction: { min_ledger: checked.minLedger, max_ledger: checked.maxLedger, signature_expiration_ledger: checked.expirationLedger },
      fee: { prepared_fee_stroops: checked.feeStroops, max_fee_stroops: maxFeeStroops, paid_by: 'the local testnet fee payer, not this account' },
      warning: `Your passkey signs one transaction that removes rule ${ruleId} from account ${account}. Once it is confirmed, the `
        + 'delegate can no longer act under that rule. The account removes the rule\'s policies on a best effort basis: the wallet '
        + 'reports separately whether the policy still holds installation state for the rule. Your signature is valid until ledger '
        + `${checked.expirationLedger}; the fee payer pays at most ${maxFeeStroops} stroops.`,
      labels: ['owner_passkey_signs_removal', 'human_approval_attested:false'],
    });
  } catch { return refuse(); }
}
