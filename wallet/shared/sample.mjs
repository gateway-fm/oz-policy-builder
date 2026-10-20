import { Buffer } from 'buffer';
import { Address, Asset, Networks, StrKey, hash, xdr } from '#wallet-stellar-sdk';
import { NETWORK_ID, freezeCopy } from './approval.mjs';
import { decodeBase64Url } from './base64url.mjs';
import { decodeEnvelope, resources } from './assembly.mjs';

export const SAMPLE_AMOUNT_STROOPS = '1000000';
export const SAMPLE_MAX_FEE_STROOPS = 10_000_000;
const refuse = () => { throw new Error('sample transfer refused; refresh and review again'); };
const bytes = (value) => Buffer.from(value.toXDR());
const same = (a, b) => bytes(a).equals(bytes(b));
const integer = (n, min = 1, max = 0xffffffff) => Number.isSafeInteger(n) && n >= min && n <= max;
const seq = (n) => typeof n === 'string' && /^(0|[1-9][0-9]{0,18})$/.test(n) && BigInt(n) < 9223372036854775807n;

/** Fixed sample operation, never a caller-selected contract, function or amount. */
export function sampleCall({ wallet, recipient }) {
  return new xdr.InvokeContractArgs({
    contractAddress: new Address(Asset.native().contractId(Networks.TESTNET)).toScAddress(),
    functionName: 'transfer', args: [new Address(wallet.contractId).toScVal(), new Address(recipient).toScVal(),
      xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: BigInt(SAMPLE_AMOUNT_STROOPS) }))],
  });
}

/** Descriptor belongs to the successful account-creation response retained by this wallet. */
export function reviewSample({ wallet, descriptor, ownerRuleXdr }) {
  try {
    if (!StrKey.isValidContract(wallet.contractId) || !StrKey.isValidContract(wallet.verifier)
      || wallet.contractId === wallet.verifier || !/^04[0-9a-f]{128}$/.test(wallet.publicKey)
      || !StrKey.isValidEd25519PublicKey(descriptor.recipient) || descriptor.amountStroops !== SAMPLE_AMOUNT_STROOPS
      || ownerRuleXdr !== descriptor.ownerRuleXdr || typeof ownerRuleXdr !== 'string'
      || ownerRuleXdr.length > 32 * 1024) refuse();
    const owner = xdr.ScVal.fromXDR(ownerRuleXdr, 'base64');
    if (owner.toXDR('base64') !== ownerRuleXdr || owner.type !== 'scvMap' || owner.map.length !== 6) refuse();
    const names = ['context_type', 'id', 'name', 'policies', 'signers', 'valid_until'];
    if (owner.map.some((field, index) => field.key.type !== 'scvSymbol' || field.key.sym.toString() !== names[index])) refuse();
    const values = Object.fromEntries(owner.map.map((field, i) => [names[i], field.val]));
    const signer = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'), new Address(wallet.verifier).toScVal(),
      xdr.ScVal.scvBytes(Buffer.concat([Buffer.from(wallet.publicKey, 'hex'), decodeBase64Url(wallet.credentialId)]))]);
    if (values.id.type !== 'scvU32' || values.id.u32 !== 0 || values.name.type !== 'scvString'
      || !same(values.context_type, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]))
      || !same(values.policies, xdr.ScVal.scvVec([])) || !same(values.signers, xdr.ScVal.scvVec([signer]))
      || values.valid_until.type !== 'scvVoid') refuse();
    const commitment = Buffer.from(hash(Buffer.from(JSON.stringify([
      'wallet-sample/v1', NETWORK_ID, wallet.contractId, wallet.verifier, wallet.publicKey, wallet.credentialId,
      descriptor.recipient, SAMPLE_AMOUNT_STROOPS, ownerRuleXdr,
    ])))).toString('hex');
    return freezeCopy({ wallet, descriptor, ownerRuleXdr, ownerRuleId: 0, commitment });
  } catch { refuse(); }
}

/** Independently validate serialized XDR before Pollywallet may sign the fixed sample. */
export function validateSampleAssembly({ approval, assembly, ownerRuleXdr, limits }) {
  try {
    const fresh = reviewSample({ wallet: approval.wallet, descriptor: approval.descriptor, ownerRuleXdr });
    if (fresh.commitment !== approval.commitment || limits.feePayer !== approval.descriptor.recipient
      || limits.maxFeeStroops !== SAMPLE_MAX_FEE_STROOPS || !seq(limits.sourceSequence)
      || !integer(limits.validityLedgers, 2, 120) || !integer(limits.currentLedger) || !integer(limits.ownerReadLedger)
      || limits.currentLedger < limits.ownerReadLedger || limits.currentLedger - limits.ownerReadLedger > 12
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
    if (Buffer.from(hash(bytes(envelope))).toString('hex') !== assembly.envelope_xdr_sha256 || envelope.v1.signatures.length) refuse();
    const tx = envelope.v1.tx;
    if (tx.sourceAccount.type !== 'keyTypeEd25519' || StrKey.encodeEd25519PublicKey(tx.sourceAccount.ed25519.value) !== limits.feePayer
      || tx.seqNum !== BigInt(limits.sourceSequence) + 1n || !integer(tx.fee, 100, SAMPLE_MAX_FEE_STROOPS)
      || tx.fee !== assembly.fee_stroops || tx.memo.type !== 'memoNone' || tx.cond.type !== 'precondV2') refuse();
    const cond = tx.cond.v2;
    if ((cond.timeBounds && (cond.timeBounds.minTime !== 0n || cond.timeBounds.maxTime !== 0n))
      || cond.minSeqNum !== null || cond.minSeqAge !== 0n || cond.minSeqLedgerGap !== 0 || cond.extraSigners.length
      || cond.ledgerBounds?.minLedger !== assembly.min_ledger || cond.ledgerBounds.maxLedger !== assembly.max_ledger
      || tx.operations.length !== 1 || tx.operations[0].sourceAccount !== null) refuse();
    const op = tx.operations[0].body;
    const call = sampleCall({ wallet: approval.wallet, recipient: approval.descriptor.recipient });
    if (op.type !== 'invokeHostFunction' || op.invokeHostFunctionOp.hostFunction.type !== 'hostFunctionTypeInvokeContract'
      || !same(op.invokeHostFunctionOp.hostFunction.invokeContract, call) || op.invokeHostFunctionOp.auth.length !== 1) refuse();
    const entry = op.invokeHostFunctionOp.auth[0];
    if (entry.credentials.type !== 'sorobanCredentialsAddress'
      || entry.rootInvocation.function.type !== 'sorobanAuthorizedFunctionTypeContractFn'
      || !same(entry.rootInvocation.function.contractFn, call) || entry.rootInvocation.subInvocations.length) refuse();
    const credentials = entry.credentials.address;
    if (Address.fromScAddress(credentials.address).toString() !== approval.wallet.contractId
      || credentials.signature.type !== 'scvVoid' || credentials.signatureExpirationLedger !== assembly.max_ledger - 1
      || tx.ext.type !== 'sorobanData') refuse();
    resources(tx.ext.sorobanData, assembly.restoration, tx.fee);
    return freezeCopy({ envelopeXdr: assembly.envelope_xdr_base64, authEntriesXdr: [entry.toXDR('base64')],
      expirationLedger: credentials.signatureExpirationLedger, ownerRuleId: 0, feeStroops: tx.fee,
      minLedger: assembly.min_ledger, maxLedger: assembly.max_ledger, authorityCommitment: approval.commitment });
  } catch { refuse(); }
}
