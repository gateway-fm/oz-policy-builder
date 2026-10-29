// Closed walkthrough calls: actual positives retain confirmed outputs; every control is an
// enforcing simulation. Unexpected permission never reaches transaction submission.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Address, Operation, StrKey, authorizeEntry, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { contractCall, entryAddress, i128, policyDenial, recipientAuthorizationMissing, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import { protocolInvocation, PROTOCOL_TARGETS, soroswapDecisions } from './protocol-calls.mjs';
import { recheckSoroswapTargets } from './soroswap-preflight.mjs';
import { BLEND_FEE_CEILING } from './blend-preflight.mjs';
import * as rpc from './rpc.mjs';
const BLND = 'CB22KRA3YZVCNCQI64JQ5WE7UY2VAV7WFLK6A2JN3HEX56T2EDAFO7QF';
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected protocol ${field}`);
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const A = (address) => new Address(address).toScVal();
const hex = (v) => Buffer.from(v.toXDR()).toString('hex');
// The account receives one authorization context per node of its tree, root first, and
// rejects a signature whose rule-ID list has a different length (ContextRuleIdsLengthMismatch).
const contexts = (node) => 1 + node.subInvocations.reduce((n, child) => n + contexts(child), 0);
// The foreign-recipient claim control must be recorded before the policy can refuse it, and the
// pool pays the accrued BLND to `to` while recording. A classic account without a BLND trustline
// fails that transfer (#13) first; a contract address needs no trustline. This one is derived from
// a label, holds nothing and is never sent anything: the control is only simulated.
export const BLEND_FOREIGN_RECIPIENT = StrKey.encodeContract(createHash('sha256').update('ozpb-w1-foreign-claim-recipient').digest());
// The swap's `to` both pays the input and receives the output, and it is the only address the
// router asks to authorize. A swap naming this address therefore asks it, never the account; it is
// derived from a label, holds nothing, and is never the transaction source.
export const SOROSWAP_FOREIGN_RECIPIENT = StrKey.encodeContract(createHash('sha256').update('ozpb-w3-foreign-swap-recipient').digest());
const U64_MAX = (1n << 64n) - 1n;
// Controls signed over a tree built here rather than recorded, so they do not depend on whether the
// router could quote, fund or accept the call while recording: a truncated route cannot be quoted,
// and a foreign recipient's recording would name that recipient, not the account. The account
// decides each when the router first asks `to` to authorize, before it reads the route.
const CONSTRUCTED = new Set(['path_reordered', 'path_extended', 'path_truncated', 'foreign_recipient', 'router_function']);
// A permit observation signs a live authorization of a real call, and the endpoint sees it; it lasts
// only long enough to be simulated.
const PERMIT_AUTH_LEDGERS = 5;
const PERMITS = Object.freeze({ direct_token: 'verified_independent_permission' });
const UNOBSERVED = Object.freeze({ direct_token: 'independent_permission_not_observed' });

export function protocolControlInvocation(plan, control, foreign) {
  const intended = protocolInvocation(plan);
  const call = intended.function.contractFn;
  if (control === 'baseline') return intended;
  if (plan.kind === 'soroswap_swap') {
    // The adapter bounds the input at the recorded amount; the floor and the transfer cap are the
    // operator's journaled decisions, so each control steps just past the bound actually installed.
    const decided = soroswapDecisions(plan.operator_decisions, { journal: true });
    const route = (...tokens) => xdr.ScVal.scvVec(tokens.map(A));
    const { native, swap_output: output } = PROTOCOL_TARGETS;
    if (control === 'input_cap') {
      call.args[0] = i128(BigInt(plan.amount_in) + 1n);
      intended.subInvocations[0].function.contractFn.args[2] = call.args[0];
    } else if (control === 'output_floor') {
      call.args[1] = i128(BigInt(decided.output_floor.min) - 1n);
    } else if (control === 'path_reordered') call.args[2] = route(output, native);
    else if (control === 'path_extended') call.args[2] = route(native, output, native);
    else if (control === 'path_truncated') call.args[2] = route(native);
    else if (control === 'foreign_recipient') call.args[3] = A(SOROSWAP_FOREIGN_RECIPIENT);
    else if (control === 'router_function') {
      // The router's other swap, by the account, for the same route: exact output, bounded input.
      return contractCall(PROTOCOL_TARGETS.router, 'swap_tokens_for_exact_tokens', [i128(BigInt(plan.minimum_out)),
        i128(BigInt(plan.amount_in)), call.args[2], A(plan.account), xdr.ScVal.scvU64(BigInt(plan.deadline))]);
    } else if (control === 'deadline_plus_one') {
      requireThat(BigInt(plan.deadline) < U64_MAX, 'deadline cannot be incremented');
      call.args[4] = xdr.ScVal.scvU64(BigInt(plan.deadline) + 1n);
    } else if (control === 'maximum_deadline') call.args[4] = xdr.ScVal.scvU64(U64_MAX);
    else if (control === 'direct_token') return intended.subInvocations[0];
    else if (control === 'direct_token_cap') {
      const child = intended.subInvocations[0];
      child.function.contractFn.args[2] = i128(BigInt(decided.transfer_cap.max) + 1n);
      return child;
    }
    else throw new Error('unsupported swap control');
  } else {
    if (control === 'reserve_ids') call.args[1] = xdr.ScVal.scvVec([xdr.ScVal.scvU32(7)]);
    else if (control === 'claim_recipient') {
      requireThat(foreign && foreign !== plan.account, 'claim recipient control needs a different address');
      call.args[2] = A(foreign);
    } else if (control === 'pool_function') return contractCall(PROTOCOL_TARGETS.blend_pool, 'submit',
      [A(plan.account), A(plan.account), A(plan.account), xdr.ScVal.scvVec([])]);
    else throw new Error('unsupported claim control');
  }
  return intended;
}

export async function invokeProtocol({ run, name, mode, signer = 'delegate', control = 'baseline', expected, save }, overrides = {}) {
  const deps = { ...rpc, ownerSigner, recheckSoroswapTargets, ...overrides };
  requireThat(typeof name === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(name), 'invalid invocation name');
  requireThat(['execute', 'simulate'].includes(mode) && ['owner', 'delegate', 'payer', 'none'].includes(signer), 'invalid protocol invocation mode');
  requireThat(mode !== 'execute' || (control === 'baseline' && ['owner', 'delegate'].includes(signer) && expected === undefined),
    'negative protocol controls are only simulated');
  // Each simulated control names one kind of expected outcome, and only the controls that can have
  // it: a permit (the independent transfer), the recipient's own refusal
  // (a foreign `to`), or a denial attributed to an enforcer.
  const swap = run.walkthrough.kind === 'soroswap_swap' && signer === 'delegate';
  const expectsPermit = swap && expected?.permit === true && Object.hasOwn(PERMITS, control);
  const expectsRecipient = swap && expected?.recipient_refusal === true && control === 'foreign_recipient';
  // A foreign recipient is refused before the account; deadline mutations must fail at the policy;
  // a denial claimed for either is refused. The direct transfer is also denied (above its cap or
  // count), so only its permit observation is keyed on the expectation.
  const expectsDenial = Boolean(expected?.enforcer) && Number.isInteger(expected?.code)
    && !['any_deadline', 'foreign_recipient'].includes(control);
  requireThat(mode !== 'simulate' || expectsPermit || expectsRecipient || expectsDenial,
    'simulation needs an attributed expected denial');
  same(run.network, rpc.NETWORK_PASSPHRASE, 'network');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  same(run.walkthrough.account, run.account, 'plan account');
  requireThat(!run.walkthrough.invocations?.some((item) => item.name === name), 'an invocation with this name is already recorded');
  const intended = protocolControlInvocation(run.walkthrough, control, BLEND_FOREIGN_RECIPIENT);
  const call = intended.function.contractFn;
  const operation = (auth = []) => Operation.invokeContractFunction({
    contract: Address.fromScAddress(call.contractAddress).toString(), function: call.functionName.toString(), args: call.args, auth,
  });
  const entries = run.walkthrough.bundle?.entries;
  let ruleIds;
  if (signer === 'owner') ruleIds = new Array(contexts(intended)).fill(0);
  else {
    requireThat(Array.isArray(entries) && entries.length === (run.walkthrough.kind === 'blend_claim' ? 1 : 2)
      && entries.every((entry, index) => entry.rule_index === index && Number.isInteger(entry.installation?.rule_id)
        && entry.installation.rule_id > 0 && entry.installation.rule_id <= 0xffff_ffff), 'missing complete installed protocol rule IDs');
    ruleIds = entries.map((entry) => entry.installation.rule_id);
    requireThat(new Set(ruleIds).size === ruleIds.length, 'duplicate protocol rule IDs');
    if (control.startsWith('direct_token')) ruleIds = [entries[1].installation.rule_id];
    if (control === 'router_function') ruleIds = [entries[0].installation.rule_id];
  }
  requireThat(ruleIds.length === contexts(intended), 'rule IDs do not align with the authorization contexts');
  await deps.assertTestnet();
  same(await deps.contractCodeHash(run.account), run.account_code_hash, 'live account code');
  const target = run.walkthrough.kind === 'blend_claim' ? PROTOCOL_TARGETS.blend_pool : PROTOCOL_TARGETS.router;
  same(await deps.contractCodeHash(target), run.walkthrough.kind === 'blend_claim' ? PROTOCOL_TARGETS.blend_code : PROTOCOL_TARGETS.router_code,
    'live target code');
  if (run.walkthrough.kind === 'soroswap_swap') await deps.recheckSoroswapTargets(run, deps);
  const payer = deps.loadKey('payer');
  same(payer.publicKey(), run.payer, 'fee payer');
  const outputToken = run.walkthrough.kind === 'blend_claim' ? BLND : PROTOCOL_TARGETS.swap_output;
  const balance = async () => {
    const value = scValToNative(await deps.viewCall(payer, outputToken, 'balance', [A(run.account)]));
    requireThat(typeof value === 'bigint' && value >= 0n, 'invalid protocol output balance');
    return value;
  };
  const constructed = CONSTRUCTED.has(control);
  const observed = { name, control, signer, rule_ids: ruleIds, status: 'started',
    observation: mode === 'execute' ? 'submitted_transaction' : 'enforcing_simulation',
    ...(constructed ? { authorization: 'signed_without_recording' } : {}) };
  run.walkthrough.invocations ??= [];
  run.walkthrough.invocations.push(observed);
  save();
  const before = mode === 'execute' ? await balance() : null;
  if (before !== null) { observed.balance_before = before.toString(); observed.output_token = outputToken; save(); }
  let recorded;
  if (constructed) {
    recorded = [new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
        address: new Address(run.account).toScAddress(), nonce: randomBytes(8).readBigInt64BE(),
        signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid() })),
      rootInvocation: intended,
    })];
  } else {
    recorded = await deps.recordAuth(payer, operation(), 'protocol authorization');
    requireThat(recorded.length === 1 && entryAddress(recorded[0]) === run.account && hex(recorded[0].rootInvocation) === hex(intended),
      'recorded authorization differs from the exact intended invocation');
  }
  const until = (await deps.latestLedger()) + (expectsPermit ? PERMIT_AUTH_LEDGERS : 100);
  let auth;
  if (signer === 'none') {
    const signed = await authorizeEntry(recorded[0], async () => ({ signatureScVal: xdr.ScVal.scvMap([
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('context_rule_ids'), val: xdr.ScVal.scvVec(ruleIds.map((id) => xdr.ScVal.scvU32(id))) }),
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('signers'), val: xdr.ScVal.scvMap([]) }),
    ]) }), until, rpc.NETWORK_PASSPHRASE);
    auth = [signed];
  } else {
    const key = signer === 'owner' ? await deps.ownerSigner(run) : deps.loadKey(signer);
    if (signer === 'delegate') same(key.publicKey(), run.delegate, 'delegate key');
    const signed = await signForSmartAccount({ entry: recorded[0], expect: intended, signer: key, ruleIds,
      validUntilLedger: until, networkPassphrase: rpc.NETWORK_PASSPHRASE });
    auth = [signed.accountEntry, signed.delegateEntry].filter(Boolean);
  }
  if (mode === 'simulate') {
    const simulated = await deps.enforceSimulation(payer, operation(auth));
    requireThat(Number.isInteger(simulated.ledger) && simulated.ledger > 0, 'missing enforcing-simulation ledger');
    if (expectsPermit) {
      Object.assign(observed, { ledger: simulated.ledger, status: simulated.result === 'permit' ? PERMITS[control] : UNOBSERVED[control] });
      save();
      requireThat(simulated.result === 'permit', `${control === 'direct_token' ? 'independent token capability'
        : 'any-deadline permission'} was not observed in simulation`);
      return observed;
    }
    if (expectsRecipient) {
      const refused = simulated.result === 'deny'
        && recipientAuthorizationMissing(simulated.error, run.account, SOROSWAP_FOREIGN_RECIPIENT);
      Object.assign(observed, { ledger: simulated.ledger,
        status: refused ? 'verified_recipient_refusal' : simulated.result === 'permit' ? 'unexpected_permit' : 'unattributed_denial' });
      save();
      requireThat(refused, 'unexpected simulation result; no transaction was submitted');
      return observed;
    }
    const attributed = simulated.result === 'deny'
      && policyDenial(simulated.error, run.account, expected.enforcer) === expected.code;
    Object.assign(observed, { ledger: simulated.ledger,
      status: attributed ? 'verified_denial' : simulated.result === 'permit' ? 'unexpected_permit' : 'unattributed_denial' });
    if (attributed) Object.assign(observed, { enforcer: expected.enforcer, code: expected.code });
    save();
    requireThat(attributed, 'unexpected simulation result; no transaction was submitted');
    return observed;
  }
  // A claim pays rent for the BLND balance and emission entries it creates; it names the Blend ceiling.
  const fee = run.walkthrough.kind === 'blend_claim' ? { maxFee: BLEND_FEE_CEILING } : {};
  const sent = await deps.submit(payer, operation(auth), { ...fee, stage: `protocol ${name}`, onSubmitting: (transaction) => {
    requireThat(/^[0-9a-f]{64}$/.test(transaction), 'invalid prepared protocol transaction');
    Object.assign(observed, { status: 'pending', transaction });
    save();
  } });
  same(sent.hash, observed.transaction, 'confirmed transaction');
  Object.assign(observed, { status: 'confirmed_unverified', ledger: sent.receipt?.ledger ?? null });
  save();
  requireThat(Number.isInteger(observed.ledger) && observed.ledger > 0, 'missing confirmed protocol ledger');
  const result = scValToNative(sent.returnValue);
  const amount = run.walkthrough.kind === 'blend_claim' ? result : Array.isArray(result) && result.length === 2 ? result[1] : null;
  requireThat(typeof amount === 'bigint' && amount > 0n, 'protocol positive returned no nonzero amount');
  observed.returned_amount = amount.toString();
  const after = await balance();
  observed.balance_after = after.toString();
  save();
  requireThat(after - before === amount, 'protocol output balance effect differs from its returned amount');
  observed.status = 'confirmed';
  if (signer === 'owner') run.walkthrough.owner_transaction = { hash: sent.hash, ledger: observed.ledger, output_token: outputToken,
    balance_before: before.toString(), balance_after: after.toString(), returned_amount: amount.toString() };
  save();
  return observed;
}

// The command line performs only the owner's recorded call through rule 0. Delegate positives
// and negative controls run through protocol-controls.mjs against the installed bundle.
if (isMainModule(import.meta.url)) {
  const options = rpc.args();
  requireThat(options['run-dir'] && Object.keys(options).length === 1, 'usage: protocol-invoke.mjs --run-dir DIRECTORY');
  const path = join(options['run-dir'], 'run.json');
  const run = rpc.readJson(path);
  const observed = await invokeProtocol({ run, name: 'owner_record', mode: 'execute', signer: 'owner',
    save: () => rpc.writeJson(path, run) });
  console.log(`owner ${run.walkthrough.kind}: ${observed.returned_amount} received in ${observed.transaction}`);
}
