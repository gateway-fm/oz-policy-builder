// Closed walkthrough calls: actual positives retain confirmed outputs; every control is an
// enforcing simulation. Unexpected permission never reaches transaction submission.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { Address, Operation, authorizeEntry, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { contractCall, entryAddress, i128, policyDenial, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import { protocolInvocation, PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { recheckSoroswapTargets } from './soroswap-preflight.mjs';
import * as rpc from './rpc.mjs';
const BLND = 'CB22KRA3YZVCNCQI64JQ5WE7UY2VAV7WFLK6A2JN3HEX56T2EDAFO7QF';
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected protocol ${field}`);
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const A = (address) => new Address(address).toScVal();
const hex = (v) => Buffer.from(v.toXDR()).toString('hex');
// The account receives one authorization context per node of its tree, root first, and
// rejects a signature whose rule-ID list has a different length (ContextRuleIdsLengthMismatch).
const contexts = (node) => 1 + node.subInvocations.reduce((n, child) => n + contexts(child), 0);

export function protocolControlInvocation(plan, control, foreign) {
  const intended = protocolInvocation(plan);
  const call = intended.function.contractFn;
  if (control === 'baseline') return intended;
  if (plan.kind === 'soroswap_swap') {
    if (control === 'input_cap') {
      call.args[0] = i128(BigInt(plan.amount_in) + 1n);
      intended.subInvocations[0].function.contractFn.args[2] = call.args[0];
    } else if (control === 'output_floor') {
      requireThat(BigInt(plan.minimum_out) > 1n, 'output floor control needs a positive smaller floor');
      call.args[1] = i128(BigInt(plan.minimum_out) - 1n);
    } else if (control === 'deadline') call.args[4] = xdr.ScVal.scvU64(BigInt(plan.deadline) + 1n);
    else if (control === 'direct_token') return intended.subInvocations[0];
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
  const independentPermission = control === 'direct_token' && signer === 'delegate'
    && run.walkthrough.kind === 'soroswap_swap' && expected?.permit === true;
  requireThat(mode !== 'simulate' || independentPermission || (expected?.enforcer && Number.isInteger(expected.code)),
    'simulation needs an attributed expected denial');
  same(run.network, rpc.NETWORK_PASSPHRASE, 'network');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  same(run.walkthrough.account, run.account, 'plan account');
  requireThat(!run.walkthrough.invocations?.some((item) => item.name === name), 'an invocation with this name is already recorded');
  const intended = protocolControlInvocation(run.walkthrough, control, run.payer);
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
    if (control === 'direct_token') ruleIds = [entries[1].installation.rule_id];
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
  const observed = { name, control, signer, rule_ids: ruleIds, status: 'started',
    observation: mode === 'execute' ? 'submitted_transaction' : 'enforcing_simulation' };
  run.walkthrough.invocations ??= [];
  run.walkthrough.invocations.push(observed);
  save();
  const before = mode === 'execute' ? await balance() : null;
  if (before !== null) { observed.balance_before = before.toString(); observed.output_token = outputToken; save(); }
  const recorded = await deps.recordAuth(payer, operation(), 'protocol authorization');
  requireThat(recorded.length === 1 && entryAddress(recorded[0]) === run.account && hex(recorded[0].rootInvocation) === hex(intended),
    'recorded authorization differs from the exact intended invocation');
  const until = (await deps.latestLedger()) + 100;
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
    if (independentPermission) {
      Object.assign(observed, { ledger: simulated.ledger, status: simulated.result === 'permit'
        ? 'verified_independent_permission' : 'independent_permission_not_observed' });
      save();
      requireThat(simulated.result === 'permit', 'independent token capability was not permitted in simulation');
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
  const sent = await deps.submit(payer, operation(auth), { stage: `protocol ${name}`, onSubmitting: (transaction) => {
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
