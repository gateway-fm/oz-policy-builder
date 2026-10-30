// A reviewed sample grant taken through all four layers (fake worker, faked operator RPC in the
// shapes testnet returns), then the CLI's unsigned installation assembly, the fee payer's
// submission and the account's events, each replaceable by a test.
import assert from 'node:assert/strict';
import { Account, Address, Networks, Operation, SorobanDataBuilder, StrKey, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { NETWORK_ID } from '../shared/approval.mjs';
import { installCall } from '../shared/assembly.mjs';
import { LIVE_SIGNATURE_LEDGERS } from '../shared/live-consent.mjs';
import { removalCall } from '../shared/revoke.mjs';
import { consented, liveReviewed, passkeySign } from './live-check-fixture.mjs';
import { CAPTURE_LEDGER, fakeNative, stubNativeChecks } from './native-actions-fixture.mjs';

/** The ledger the checks start at: the recorded capture's entries were last modified before it. */
export const BASE_LEDGER = CAPTURE_LEDGER - 2;
/** The reviewed grant's expiry, moved with the ledgers. */
export const VALID_UNTIL = BASE_LEDGER + 50_000;
export const RULE_ID = 1;
const sym = (value) => xdr.ScVal.scvSymbol(value);
const u32 = (value) => xdr.ScVal.scvU32(value);
const vec = (items) => xdr.ScVal.scvVec(items);
const struct = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));
const txHash = (char) => char.repeat(64);

/** The CLI's `assemble-install-transaction` output for `intent`, sourced from `payer` at `sequence`. */
export function assemblyFor({ intent, payer, sequence, ledger, validity = 120, credentials = 'sorobanCredentialsAddressV2', mutate = () => {} }) {
  const call = installCall(intent);
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials[credentials](new xdr.SorobanAddressCredentials({
      address: new Address(intent.account_contract).toScAddress(), nonce: xdr.Int64.fromString('99'),
      signatureExpirationLedger: ledger + validity - 1, signature: xdr.ScVal.scvVoid() })),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [] }),
  });
  const envelope = new TransactionBuilder(new Account(payer, sequence), { fee: '1000', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] }))
    .setLedgerbounds(ledger, ledger + validity).setTimeout(0).setSorobanData(new SorobanDataBuilder().setResourceFee('100').build())
    .build().toEnvelope();
  mutate(envelope.v1.tx, envelope, entry);
  return { intent, envelope_xdr_base64: envelope.toXDR('base64'), envelope_xdr_sha256: Buffer.from(hash(envelope.toXDR())).toString('hex'),
    network_id: NETWORK_ID, fee_payer: payer, source_sequence: sequence, fee_stroops: envelope.v1.tx.fee,
    sequence_read_ledger: ledger, simulation_ledger: ledger, min_ledger: ledger, max_ledger: ledger + validity,
    restoration: 'none', simulation_auth_mode: 'record', evidence_trust: 'rpc_reported', state_dependent: true,
    writes_committed: false, wallet_requirements: ['re-run the authority check'] };
}

/** The account's `ContextRule` for the installed grant, as `add_context_rule` returns it. */
export function installedRule(intent, { ruleId = RULE_ID, signerIds = [1], policyIds = [0] } = {}) {
  return struct({
    context_type: vec([sym('CallContract'), new Address(intent.context_contract).toScVal()]), id: u32(ruleId),
    name: xdr.ScVal.scvString(intent.rule_name), policies: vec(intent.policies.map((p) => new Address(p.address).toScVal())),
    policy_ids: vec(policyIds.map(u32)), signer_ids: vec(signerIds.map(u32)),
    signers: vec(intent.delegate_signers.map((s) => vec([sym('Delegated'), new Address(s.address).toScVal()]))),
    valid_until: intent.valid_until_ledger === null ? xdr.ScVal.scvVoid() : u32(intent.valid_until_ledger),
  });
}

/** A contract event as the confirmed transaction's metadata carries it. */
export function contractEvent(contract, topics, data) {
  return new xdr.ContractEvent({ ext: xdr.ExtensionPoint.v0(), contractId: new xdr.ContractId(StrKey.decodeContract(contract)),
    type: xdr.ContractEventType.contract, body: xdr.ContractEventBody.v0(new xdr.ContractEventV0({ topics, data })) });
}

/** `context_rule_added`: topics `[context_rule_added, id]`, data the rule's summary fields. */
export function addedEvent(account, rule, ruleId = RULE_ID) {
  const fields = Object.fromEntries(rule.map.map((e) => [e.key.sym.toString(), e.val]));
  return contractEvent(account, [sym('context_rule_added'), u32(ruleId)], struct({ context_type: fields.context_type,
    name: fields.name, policy_ids: fields.policy_ids, signer_ids: fields.signer_ids, valid_until: fields.valid_until }));
}

export const removedEvent = (account, ruleId = RULE_ID) => contractEvent(account, [sym('context_rule_removed'), u32(ruleId)], xdr.ScVal.scvMap([]));

/** The unsigned `remove_context_rule` assembly the fee payer's record-mode simulation produces. */
export function removalFor({ account, ruleId = RULE_ID, payer, sequence, ledger, validity = 120, mutate = () => {} }) {
  const call = removalCall(account, ruleId);
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(new xdr.SorobanAddressCredentials({
      address: new Address(account).toScAddress(), nonce: xdr.Int64.fromString('77'),
      signatureExpirationLedger: ledger + validity - 1, signature: xdr.ScVal.scvVoid() })),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [] }),
  });
  const envelope = new TransactionBuilder(new Account(payer, sequence), { fee: '1000', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] }))
    .setLedgerbounds(ledger, ledger + validity).setTimeout(0).setSorobanData(new SorobanDataBuilder().setResourceFee('100').build())
    .build().toEnvelope();
  mutate(envelope.v1.tx, envelope, entry);
  return { assembly: { envelope_xdr_base64: envelope.toXDR('base64'), envelope_xdr_sha256: Buffer.from(hash(envelope.toXDR())).toString('hex'),
    network_id: NETWORK_ID, fee_payer: payer, source_sequence: sequence, fee_stroops: envelope.v1.tx.fee,
    sequence_read_ledger: ledger, simulation_ledger: ledger, min_ledger: ledger, max_ledger: ledger + validity, restoration: 'none',
    simulation_auth_mode: 'record', evidence_trust: 'rpc_reported', state_dependent: true, writes_committed: false },
  limits: { feePayer: payer, sourceSequence: sequence, currentLedger: ledger, ownerReadLedger: ledger, maxFeeStroops: 10_000_000,
    validityLedgers: validity } };
}

/**
 * A review whose account, captured and live layers have run (all passed unless an option changes
 * one), with every RPC read, CLI call and submission the installation and revocation make faked.
 * `f.onSubmit(envelopeXdr, stage)` may replace a submission's result.
 */
export async function installable({ captureLedger = CAPTURE_LEDGER } = {}) {
  const holder = { runs: [] };
  const f = await liveReviewed({ native: fakeNative(holder), ledger: BASE_LEDGER, maxCalls: 1, intentChange: (intent) => {
    // The fixture intent was read at ledger 123456; this review reads it just before the checks start.
    intent.authority.verdict.observed_ledger = BASE_LEDGER - 4;
    intent.valid_until_ledger = VALID_UNTIL;
    intent.authority.verdict.grant.valid_until = VALID_UNTIL;
  } });
  f.artifact.spec.rules[0].valid_until = { ledger: VALID_UNTIL };
  stubNativeChecks(f, f.delegate, holder, { maxCalls: 1, captureLedger });
  const n = f.network;
  const requireInstance = n.requireInstance;
  n.requireInstance = async (contractId, wasmHash) => {
    await requireInstance(contractId, wasmHash);
    return { contractId, wasmHash, ledger: f.state.ledger, instanceLedger: f.state.ledger, codeLedger: f.state.ledger, nonAtomic: true };
  };
  const authority = [];
  const submissions = [];
  const intent = f.f.intent;
  const fresh = () => {
    const value = structuredClone(intent);
    value.authority.verdict.observed_ledger = f.state.ledger;
    f.freshChange?.(value);
    return value;
  };
  f.sequence = '4242';
  f.assemblyChange = () => {};
  f.toolchain.authority = async (command, request) => {
    authority.push([command, request]);
    if (command === 'prepare-install-intent') { f.onIntent?.(); return fresh(); }
    if (command === 'assemble-install-transaction') {
      assert.deepEqual(Object.keys(request).sort(), ['fee_payer', 'intent_request', 'max_fee_stroops', 'validity_ledgers']);
      const value = assemblyFor({ intent: fresh(), payer: n.payerAddress, sequence: f.sequence, ledger: f.state.ledger,
        validity: request.validity_ledgers });
      f.assemblyChange(value);
      return value;
    }
    assert.fail(`unexpected authority command ${command}`);
  };
  // Offsets a test may set: how far the owner-rule and fee-payer reads lie from the latest ledger.
  f.ownerLedgerOffset = 0;
  f.sourceLedgerOffset = 0;
  n.sourceCapture = async () => ({ sourceSequence: f.sequence, ledger: f.state.ledger + f.sourceLedgerOffset });
  f.obligations = [];
  n.recordInstallObligation = (record) => { f.obligations.push(structuredClone(record)); };
  n.view = async (account, method, args) => {
    assert.equal(account, f.f.wallet.contractId); assert.equal(method, 'get_context_rule'); assert.equal(args[0].u32, 7);
    return { value: xdr.ScVal.fromXDR(f.f.ownerRuleXdr, 'base64'), ledger: f.state.ledger + f.ownerLedgerOffset };
  };
  const rule = installedRule(intent);
  f.rule = rule;
  f.readback = () => (f.state.installed
    ? { status: 'present', xdr: f.rule.toXDR('base64'), ledger: f.state.ledger }
    : { status: 'absent', ledger: f.state.ledger });
  n.ruleReadback = async (account, ruleId) => {
    assert.equal(account, f.f.wallet.contractId); assert.equal(ruleId, RULE_ID);
    return f.readback();
  };
  n.prepareRemoval = async ({ wallet, ruleId }) => {
    assert.equal(wallet.contractId, f.f.wallet.contractId); assert.equal(ruleId, RULE_ID);
    const value = removalFor({ account: wallet.contractId, payer: n.payerAddress, sequence: f.sequence, ledger: f.state.ledger });
    f.removalChange?.(value);
    return value;
  };
  f.onSubmit = null;
  n.submitEnvelope = async (envelopeXdr, stage) => {
    submissions.push({ envelopeXdr, stage });
    if (f.onSubmit) return f.onSubmit(envelopeXdr, stage);
    f.state.ledger += 1;
    if (stage === 'install-policy') {
      Object.assign(f.state, { nextId: RULE_ID + 1, count: f.state.count + 1, installed: true,
        rules: [...f.state.rules, { id: RULE_ID, xdr: 'installed rule' }] });
      return { hash: txHash('e'), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: rule,
        events: [addedEvent(f.f.wallet.contractId, rule)] };
    }
    assert.equal(stage, 'revoke-policy');
    Object.assign(f.state, { count: f.state.count - 1, installed: false, rules: f.state.rules.filter((r) => r.id !== RULE_ID) });
    return { hash: txHash('f'), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: xdr.ScVal.scvVoid(),
      events: [removedEvent(f.f.wallet.contractId)] };
  };
  return Object.assign(f, { holder, authority, submissions, intent, fresh,
    signEntry: (entryXdr, change) => passkeySign({ privateKey: f.keys.privateKey, wallet: f.f.wallet, ownerRuleId: 7,
      ownerEntryXdr: entryXdr, change }) });
}

/** Run every layer: the local checks, then the consented live check, then wait out its signatures. */
export async function verified(f, { expire = true } = {}) {
  const local = await f.actions['check-account']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const { consent, input } = await consented(f);
  const live = await f.actions['run-live'](input);
  if (expire) f.state.ledger = consent.signatureExpirationLedger + 1;
  return { local, live, signaturesValidUntil: consent.signatureExpirationLedger, liveLedger: f.state.ledger };
}

/** The unsigned owner entry from an assemble response, signed by the fixture's software passkey. */
export async function signInstall(f, assembled, change) {
  const envelope = xdr.TransactionEnvelope.fromXDR(assembled.assembly.envelope_xdr_base64, 'base64');
  const entry = envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64');
  return f.signEntry(entry, change);
}

export const LIVE_WINDOW = LIVE_SIGNATURE_LEDGERS;
