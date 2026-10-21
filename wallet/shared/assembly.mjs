// SDK 17 stays in this nested package. The upstream wallet exchanges serialized XDR only.
import { Buffer } from 'buffer';
import { Address, StrKey, hash, nativeToScVal, xdr } from '#wallet-stellar-sdk';
import { NETWORK_ID, freezeCopy, reviewIntent } from './approval.mjs';

const refuse = () => { throw new Error('wallet transaction refused; refresh and review again'); };
const bytes = (value) => Buffer.from(value.toXDR());
const same = (a, b) => bytes(a).equals(bytes(b));
const integer = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;
const address = (text, contract = false) => {
  if (!(StrKey.isValidContract(text) || (!contract && StrKey.isValidEd25519PublicKey(text)))) refuse();
  return new Address(text);
};
const vec = (values) => xdr.ScVal.scvVec(values);
const sym = (value) => xdr.ScVal.scvSymbol(value);
const canonicalUnsigned = (text) => typeof text === 'string' && /^(0|[1-9][0-9]{0,18})$/.test(text) && BigInt(text) < 9223372036854775807n;

export function installCall(intent) {
  const signers = intent.delegate_signers.map((signer) => {
    if (signer.kind === 'delegated') return vec([sym('Delegated'), address(signer.address).toScVal()]);
    if (signer.kind !== 'external' || !/^(?:[0-9a-f]{2}){1,1024}$/.test(signer.key_hex)) refuse();
    return vec([sym('External'), address(signer.verifier, true).toScVal(), xdr.ScVal.scvBytes(Buffer.from(signer.key_hex, 'hex'))]);
  });
  const policies = intent.policies.map((policy, index) => {
    if (policy.policy_index !== index) refuse();
    const params = policy.install_params;
    let val;
    if (params.kind === 'generated') val = xdr.ScVal.scvU32(0);
    else if (params.kind === 'spending_limit' && /^[1-9][0-9]{0,38}$/.test(params.spending_limit)
      && BigInt(params.spending_limit) < (1n << 127n) && integer(params.period_ledgers, 1, 0xffffffff)) {
      val = xdr.ScVal.scvMap([
        new xdr.ScMapEntry({ key: sym('period_ledgers'), val: xdr.ScVal.scvU32(params.period_ledgers) }),
        new xdr.ScMapEntry({ key: sym('spending_limit'), val: nativeToScVal(BigInt(params.spending_limit), { type: 'i128' }) }),
      ]);
    } else refuse();
    return new xdr.ScMapEntry({ key: address(policy.address, true).toScVal(), val });
  }).sort((a, b) => Buffer.compare(bytes(a.key), bytes(b.key)));
  if (!signers.length || signers.length > 32 || !policies.length || policies.length > 16
    || new Set(signers.map((s) => s.toXDR('base64'))).size !== signers.length
    || new Set(policies.map((p) => p.key.toXDR('base64'))).size !== policies.length
    || typeof intent.rule_name !== 'string' || Buffer.byteLength(intent.rule_name) > 256
    || !(intent.valid_until_ledger === null || integer(intent.valid_until_ledger, 1, 0xffffffff))) refuse();
  return new xdr.InvokeContractArgs({ contractAddress: address(intent.account_contract, true).toScAddress(),
    functionName: 'add_context_rule', args: [
      vec([sym('CallContract'), address(intent.context_contract, true).toScVal()]), xdr.ScVal.scvString(intent.rule_name),
      intent.valid_until_ledger === null ? xdr.ScVal.scvVoid() : xdr.ScVal.scvU32(intent.valid_until_ledger),
      vec(signers), xdr.ScVal.scvMap(policies),
    ] });
}

export function decodeEnvelope(raw) {
  if (typeof raw !== 'string' || raw.length > 256 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) refuse();
  const envelope = xdr.TransactionEnvelope.fromXDR(raw, 'base64');
  if (envelope.toXDR('base64') !== raw || envelope.type !== 'envelopeTypeTx') refuse();
  return envelope;
}

export function resources(data, restoration, fee) {
  if (!data || data.resourceFee < 0n || data.resourceFee > BigInt(fee)) refuse();
  const footprint = data.resources.footprint;
  const keys = [...footprint.readOnly, ...footprint.readWrite];
  if (keys.length > 200 || new Set(keys.map((key) => key.toXDR('base64'))).size !== keys.length) refuse();
  for (const key of keys) {
    if (!['contractData', 'contractCode', 'account', 'trustline'].includes(key.type)) refuse();
  }
  const indices = data.ext.type === 'resourceExt' ? data.ext.resourceExt.archivedSorobanEntries : [];
  if (!['v0', 'resourceExt'].includes(data.ext.type) || new Set(indices).size !== indices.length
    || (restoration === 'none' && indices.length) || (restoration === 'automatic_within_invocation' && !indices.length)) refuse();
  for (const index of indices) {
    const key = footprint.readWrite[index];
    if (!integer(index, 0, footprint.readWrite.length - 1) || !(key.type === 'contractCode'
      || (key.type === 'contractData' && key.contractData.durability.name === 'persistent'))) refuse();
  }
}

/** Validate the service draft against the immutable wallet display and wallet-owned fresh reads. */
export function validateAssembly({ approval, assembly, ownerRuleXdr, limits }) {
  try {
    const fresh = reviewIntent({ intent: assembly.intent, expected: approval.expected, wallet: approval.wallet, ownerRuleXdr });
    if (fresh.commitment !== approval.commitment || fresh.ownerRuleId !== approval.ownerRuleId
      || fresh.ownerRuleXdr !== approval.ownerRuleXdr || fresh.observedLedger < approval.observedLedger
      || JSON.stringify(fresh.intent.authority.verdict.grant) !== JSON.stringify(approval.intent.authority.verdict.grant)) refuse();
    if (assembly.network_id !== NETWORK_ID || assembly.fee_payer !== limits.feePayer
      || !canonicalUnsigned(limits.sourceSequence) || assembly.source_sequence !== limits.sourceSequence
      || !integer(limits.maxFeeStroops, 100, 0xffffffff) || !integer(limits.validityLedgers, 1, 120)
      || !integer(limits.currentLedger, 1, 0xffffffff) || assembly.simulation_auth_mode !== 'record'
      || assembly.evidence_trust !== 'rpc_reported' || assembly.state_dependent !== true || assembly.writes_committed !== false
      || !['none', 'automatic_within_invocation'].includes(assembly.restoration)) refuse();
    for (const n of [assembly.sequence_read_ledger, assembly.simulation_ledger, assembly.min_ledger, assembly.max_ledger]) {
      if (!integer(n, 1, 0xffffffff)) refuse();
    }
    if (assembly.sequence_read_ledger < fresh.observedLedger || assembly.simulation_ledger < assembly.sequence_read_ledger
      || limits.currentLedger < assembly.simulation_ledger || limits.currentLedger - fresh.observedLedger > 12
      || assembly.min_ledger !== assembly.sequence_read_ledger
      || assembly.max_ledger !== assembly.sequence_read_ledger + limits.validityLedgers
      || limits.currentLedger + 1 >= assembly.max_ledger) refuse();
    const envelope = decodeEnvelope(assembly.envelope_xdr_base64);
    if (Buffer.from(hash(envelope.toXDR())).toString('hex') !== assembly.envelope_xdr_sha256
      || envelope.v1.signatures.length) refuse();
    const tx = envelope.v1.tx;
    if (tx.sourceAccount.type !== 'keyTypeEd25519' || StrKey.encodeEd25519PublicKey(tx.sourceAccount.ed25519.value) !== limits.feePayer
      || tx.seqNum !== BigInt(limits.sourceSequence) + 1n || !integer(tx.fee, 100, limits.maxFeeStroops)
      || tx.fee !== assembly.fee_stroops || tx.memo.type !== 'memoNone' || tx.cond.type !== 'precondV2') refuse();
    const cond = tx.cond.v2;
    if ((cond.timeBounds && (cond.timeBounds.minTime !== 0n || cond.timeBounds.maxTime !== 0n))
      || cond.minSeqNum !== null || cond.minSeqAge !== 0n || cond.minSeqLedgerGap !== 0 || cond.extraSigners.length
      || cond.ledgerBounds?.minLedger !== assembly.min_ledger || cond.ledgerBounds.maxLedger !== assembly.max_ledger
      || tx.operations.length !== 1 || tx.operations[0].sourceAccount !== null) refuse();
    const op = tx.operations[0].body;
    const expected = installCall(approval.intent);
    if (op.type !== 'invokeHostFunction' || op.invokeHostFunctionOp.hostFunction.type !== 'hostFunctionTypeInvokeContract'
      || !same(op.invokeHostFunctionOp.hostFunction.invokeContract, expected) || op.invokeHostFunctionOp.auth.length !== 1) refuse();
    const entry = op.invokeHostFunctionOp.auth[0];
    const root = entry.rootInvocation;
    if (entry.credentials.type !== 'sorobanCredentialsAddress' || root.function.type !== 'sorobanAuthorizedFunctionTypeContractFn'
      || !same(root.function.contractFn, expected) || root.subInvocations.length) refuse();
    const credentials = entry.credentials.address;
    if (Address.fromScAddress(credentials.address).toString() !== approval.wallet.contractId
      || credentials.signature.type !== 'scvVoid' || credentials.signatureExpirationLedger !== assembly.max_ledger - 1) refuse();
    if (tx.ext.type !== 'sorobanData') refuse();
    resources(tx.ext.sorobanData, assembly.restoration, tx.fee);
    return freezeCopy({ envelopeXdr: assembly.envelope_xdr_base64, authEntriesXdr: [entry.toXDR('base64')],
      expirationLedger: credentials.signatureExpirationLedger, ownerRuleId: approval.ownerRuleId,
      feeStroops: tx.fee, minLedger: assembly.min_ledger, maxLedger: assembly.max_ledger,
      authorityCommitment: approval.commitment });
  } catch { refuse(); }
}
