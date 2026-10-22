// A deployed, reviewed sample grant whose owner is a software passkey (a generated P-256 key, the
// automation stand-in for the authenticator) and whose delegate is a backend-created capability, with
// an operator RPC faked in the shapes the live helper and the pinned account produce on testnet.
import { webcrypto } from 'node:crypto';
import { Address, Networks, StrKey, buildAuthorizationEntryPreimage, hash, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM } from '../shared/approval.mjs';
import { encodeBase64Url } from '../shared/base64url.mjs';
import { LIVE_HELPER_WASM } from '../shared/live-consent.mjs';
import { DelegateCapabilities } from '../server/native-execution.mjs';
import { deploymentFixture } from './actions-fixture.mjs';
import { RECIPIENT } from './captured-execution-fixture.mjs';
import { denialSimulation, permitChanges, permitSimulation, withProbe } from './live-enforcement-fixture.mjs';

export const HELPER = StrKey.encodeContract(Buffer.alloc(32, 0x4c));
export const START_LEDGER = 1000;
const sha256 = (bytes) => Buffer.from(hash(bytes));
const sym = (value) => xdr.ScVal.scvSymbol(value);
const map = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));

/** Delegate capabilities whose key use is counted, so a test can say no live signature exists. */
class CountingCapabilities extends DelegateCapabilities {
  liveMints = 0;
  liveSignatures = 0;
  live(...args) {
    const capability = super.live(...args);
    this.liveMints++;
    return { address: capability.address, authorizeTransfer: (structure) => {
      const signed = capability.authorizeTransfer(structure);
      this.liveSignatures++;
      return signed;
    } };
  }
}

/** A WebAuthn assertion by `key` over the owner entry's testnet challenge, as the upstream passkey helper returns it. */
export async function passkeySign({ privateKey, wallet, ownerRuleId, ownerEntryXdr, origin = 'http://localhost:3000', change = () => {} }) {
  const entry = xdr.SorobanAuthorizationEntry.fromXDR(ownerEntryXdr, 'base64');
  const credentials = entry.credentials.addressV2;
  const ruleIds = xdr.ScVal.scvVec([xdr.ScVal.scvU32(ownerRuleId)]);
  const preimage = buildAuthorizationEntryPreimage(entry, credentials.signatureExpirationLedger, Networks.TESTNET);
  const challenge = encodeBase64Url(sha256(Buffer.concat([sha256(preimage.toXDR()), ruleIds.toXDR()])));
  const client = { type: 'webauthn.get', challenge, origin, crossOrigin: false };
  change(client);
  const clientBytes = Buffer.from(JSON.stringify(client));
  const auth = Buffer.concat([sha256(Buffer.from('localhost')), Buffer.from([5, 0, 0, 0, 1])]);
  const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey,
    Buffer.concat([auth, sha256(clientBytes)])));
  const proof = map({ authenticator_data: xdr.ScVal.scvBytes(auth), client_data: xdr.ScVal.scvBytes(clientBytes),
    signature: xdr.ScVal.scvBytes(signature) });
  const key = Buffer.concat([Buffer.from(wallet.publicKey, 'hex'), Buffer.from(wallet.credentialId, 'base64url')]);
  credentials.signature = map({ context_rule_ids: ruleIds, signers: xdr.ScVal.scvMap([new xdr.ScMapEntry({
    key: xdr.ScVal.scvVec([sym('External'), new Address(wallet.verifier).toScVal(), xdr.ScVal.scvBytes(key)]),
    val: xdr.ScVal.scvBytes(proof.toXDR()) })]) });
  return [entry.toXDR('base64')];
}

/**
 * `respond(kind, entries, P)` may replace the simulated response: `kind` is `permit` or `denial`,
 * `entries` the envelope's authorization entries and `P` the identities to build with.
 */
export async function liveReviewed({ maxCalls = 1, amount = '1000000', respond, helperState, policyHash, readiness, nextId = 1, live = { helper: HELPER },
  liveUntil = START_LEDGER + 100_000, onSimulate = () => {} } = {}) {
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicKey = Buffer.from(await webcrypto.subtle.exportKey('raw', keys.publicKey)).toString('hex');
  const delegates = new CountingCapabilities();
  const f = deploymentFixture((d) => {
    d.f.wallet.publicKey = publicKey;
    d.f.intent.authority.verdict.authority_list[0].requirement.signers[0].public_key = publicKey;
    d.f.ownerRuleXdr = d.f.ruleXdr();
  }, { live, delegates });
  const delegate = await f.actions['create-delegate']({});
  const grantSigners = [{ kind: 'delegated', address: delegate.address }];
  f.f.intent.delegate_signers = grantSigners;
  f.f.intent.authority.verdict.grant.signers = grantSigners;
  const rule = f.artifact.spec.rules[0];
  rule.authorization = { signers: [{ delegated: { address: delegate.address } }] };
  rule.state = maxCalls === null ? [] : [{ call_count_per_installation: { max_calls: maxCalls } }];
  rule.allowed_calls = [{ fn: 'transfer', args: [
    { i: 0, c: { eq_address: { value: 'SELF' } } }, { i: 1, c: { eq_address: { value: RECIPIENT } } },
    { i: 2, c: { eq_i128: { value: amount } } }] }];
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  const review = await f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet });

  // `closeTime` (seconds) is the latest ledger's close time; `readLedger` the ledger a lagging node's state read reports.
  const state = { ledger: START_LEDGER, nextId, count: 1, installed: false, rules: [{ id: 0, xdr: 'owner rule' }], closeTime: null, readLedger: null };
  const simulations = [];
  const records = [];
  const funded = [];
  const n = f.network;
  n.latestLedger = async () => state.ledger;
  n.ledgerClock = async () => ({ sequence: state.ledger, closeTime: state.closeTime ?? Math.floor(Date.now() / 1000) });
  n.contractLiveness = async (contract) => {
    if (contract === HELPER) return helperState ?? { found: true, wasmHash: LIVE_HELPER_WASM, instanceLiveUntil: liveUntil, codeLiveUntil: liveUntil, ledger: state.ledger };
    return { found: true, wasmHash: policyHash ?? f.artifact.wasmHash, instanceLiveUntil: liveUntil, codeLiveUntil: liveUntil, ledger: state.ledger };
  };
  n.transferReadiness = async () => readiness ?? { ledger: state.ledger, recipientExists: true, covered: true };
  n.liveState = async ({ account, policy, ruleId }) => ({ ledger: state.readLedger ?? state.ledger, account, policy, ruleId, nextId: state.nextId,
    count: state.count, accountWasmHash: ACCOUNT_WASM, rules: state.rules, installed: state.installed });
  n.ensureDelegateAccount = async (address) => { funded.push(address); return { ledger: state.ledger, createdNow: true }; };
  n.recordLiveObligation = (record) => { records.push(structuredClone(record)); };
  n.source = async () => ({ accountId: () => n.payerAddress, sequenceNumber: () => '4242' });
  n.simulateRaw = async (envelopeXdr) => {
    simulations.push(envelopeXdr);
    await onSimulate(simulations.length);
    const tx = xdr.TransactionEnvelope.fromXDR(envelopeXdr, 'base64').v1.tx;
    const op = tx.operations[0].body.invokeHostFunctionOp;
    const candidate = op.hostFunction.invokeContract.args[0];
    const amount = candidate.map.find((e) => e.key.sym.toString() === 'amount').val.i128.lo;
    const entries = op.auth;
    const expiry = entries[0].credentials.addressV2.signatureExpirationLedger;
    const P = { helper: HELPER, account: f.f.wallet.contractId, accountCodeHash: ACCOUNT_WASM, policy: f.policy,
      policyCodeHash: f.artifact.wasmHash, ruleName: f.f.intent.rule_name, validUntil: f.f.intent.valid_until_ledger,
      delegate: delegate.address, recipient: RECIPIENT, ruleId: nextId, expiry, simulationLedger: state.ledger + 1,
      permitAmount: 1000000n, denialAmount: 1000001n, denialCode: 6, accountBalance: 9_000_000n };
    const kind = amount === 1000000n ? 'permit' : 'denial';
    const custom = respond?.(kind, entries, P);
    if (custom) return custom;
    return withProbe(P, () => (kind === 'permit' ? permitSimulation(permitChanges(entries), { entries }) : denialSimulation(entries)));
  };
  return { ...f, keys, delegates, delegate, deployed, review, state, simulations, records, funded,
    sign: (ownerEntryXdr, change) => passkeySign({ privateKey: keys.privateKey, wallet: f.f.wallet, ownerRuleId: 7, ownerEntryXdr, change }) };
}

/** Prepare, consent and sign: the run-live input, plus what each step returned. */
export async function consented(f) {
  const prepared = await f.actions['prepare-live']({ reviewId: f.review.reviewId, capabilityId: f.delegate.capabilityId });
  const consent = await f.actions['consent-live']({ id: prepared.live.action.id, statementSha256: prepared.live.statementSha256 });
  const signedAuthEntriesXdr = await f.sign(consent.ownerEntryXdr);
  return { prepared, consent, input: { id: consent.action.id, signedAuthEntriesXdr } };
}
