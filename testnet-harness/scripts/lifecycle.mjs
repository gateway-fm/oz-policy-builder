// Owner-driven removal of the harness's recorded grant. Removal, its event and policy cleanup
// are distinct observations: stellar-accounts 0.7.2 uninstalls policies on a best-effort basis.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Address, Operation, StrKey, TransactionBuilder, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { addContextRuleArgs, contractCall, entryAddress, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import { parseJsonExact } from './raw-json.mjs';
import { composedPolicies, subscriptionConfig } from './subscription.mjs';
import * as rpc from './rpc.mjs';

const same = (actual, expected, what) => assert.deepEqual(actual, expected, `unexpected ${what}`);
const requireThat = (condition, text) => { if (!condition) throw new Error(text); };
const hex = (value) => Buffer.from(value.toXDR()).toString('hex');
const ruleArg = (id) => [xdr.ScVal.scvU32(id)];
const removeOperation = (account, id, auth = []) => Operation.invokeContractFunction({
  contract: account, function: 'remove_context_rule', args: ruleArg(id), auth,
});

/** Pinned account event schema, extracted from its embedded contractspecv0. The release's
 * function comment says data=[], but the actual event declares data_format=map. */
export function removalEvent(receipt, { hash, account, ruleId }) {
  same(receipt?.status, 'SUCCESS', 'removal transaction status');
  same(receipt.txHash, hash, 'removal transaction identity');
  const tx = TransactionBuilder.fromXDR(receipt.envelopeXdr, rpc.NETWORK_PASSPHRASE);
  same(Buffer.from(tx.hash()).toString('hex'), hash, 'returned envelope identity');
  const envelope = receipt.envelopeXdr;
  same(envelope.type, 'envelopeTypeTx', 'removal envelope type');
  const ops = envelope.v1.tx.operations;
  same(ops.length, 1, 'removal operation count');
  same(hex(ops[0].body.invokeHostFunctionOp?.hostFunction), hex(removeOperation(account, ruleId).body.invokeHostFunctionOp.hostFunction), 'removal call');
  const result = receipt.resultXdr?.result;
  same(result?.type, 'txSuccess', 'removal result');
  same(result.results?.length, 1, 'removal result count');
  same(result.results[0].tr?.invokeHostFunctionResult?.type, 'invokeHostFunctionSuccess', 'removal operation result');
  requireThat(Number.isSafeInteger(receipt.ledger) && receipt.ledger > 0 && receipt.ledger <= 0xffff_ffff, 'missing removal ledger');
  const perOperation = receipt.events?.contractEventsXdr;
  requireThat(Array.isArray(perOperation) && perOperation.length === 1 && Array.isArray(perOperation[0]), 'missing removal contract events');
  const removals = perOperation[0].filter((event) => event.type?.name === 'contract'
    && event.contractId && StrKey.encodeContract(Buffer.from(event.contractId.value)) === account
    && event.body?.v0?.topics?.[0]?.type === 'scvSymbol'
    && event.body.v0.topics[0].sym.toString() === 'context_rule_removed');
  same(removals.length, 1, 'account removal event count');
  const event = removals[0].body.v0;
  same(event.topics.length, 2, 'removal event topic count');
  same(hex(event.topics[1]), hex(xdr.ScVal.scvU32(ruleId)), 'removed rule identity');
  same(hex(event.data), hex(xdr.ScVal.scvMap([])), 'removal event data');
  return { contract: account, rule_id: ruleId, ledger: receipt.ledger };
}

function expectedGrant(run, spec) {
  same(run.network, rpc.NETWORK_PASSPHRASE, 'run network');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  same(spec.smart_account?.address, run.account, 'spec account');
  same(spec.smart_account?.observed_code_hash, run.account_code_hash, 'spec account code');
  same(spec.rules?.length, 1, 'spec rule count');
  requireThat(Number.isSafeInteger(run.rule_id) && run.rule_id > 0 && run.rule_id <= 0xffff_ffff,
    'only the non-owner installed rule can be removed');
  requireThat(/^[0-9a-f]{64}$/.test(run.tx?.add_context_rule ?? '') && /^[0-9a-f]{64}$/.test(run.policy_wasm_hash ?? ''),
    'run lacks confirmed installation identity');
  const rule = spec.rules[0];
  same(rule.context?.type, 'CallContract', 'grant context');
  same(rule.context.contract, run.sac, 'grant target');
  same(rule.authorization?.signers, [{ delegated: { address: run.delegate } }], 'grant delegate');
  const policies = composedPolicies(run, spec, run.policy);
  return addContextRuleArgs({ context: run.sac, name: spec.name, validUntil: rule.valid_until?.ledger ?? null,
    signers: [{ kind: 'delegated', address: run.delegate }], policies });
}

/** Read the configured rule and code pins. This checks this grant, not the account's complete
 * authority surface. Reads are non-atomic, carry their own ledger anchors and cannot prevent
 * later changes. Even equal ledger numbers do not establish an authenticated snapshot. */
export async function inspectInstalledGrant(run, spec, deps = rpc) {
  const expected = expectedGrant(run, spec);
  await deps.assertTestnet();
  const accountCode = await deps.contractCodeObservation(run.account);
  same(accountCode.value, run.account_code_hash, 'live account code');
  const policyCode = await deps.contractCodeObservation(run.policy);
  same(policyCode.value, run.policy_wasm_hash, 'live policy code');
  const subscription = subscriptionConfig(run);
  const spending = subscription ? await deps.contractCodeObservation(subscription.policy_address) : null;
  if (spending) same(spending.value, subscription.policy_code_hash, 'live spending policy code');
  // Read-only simulation needs a public fee-source address, not its signing seed.
  const rule = await deps.viewCallObservation({ publicKey: () => run.payer }, run.account, 'get_context_rule', ruleArg(run.rule_id));
  const live = rule.value;
  const fields = { id: xdr.ScVal.scvU32(run.rule_id), context_type: expected[0], name: expected[1],
    valid_until: expected[2], signers: expected[3], policies: xdr.ScVal.scvVec(expected[4].map.map((entry) => entry.key)) };
  for (const [name, expectedValue] of Object.entries(fields)) {
    const values = live.map?.filter((entry) => entry.key.type === 'scvSymbol' && entry.key.sym.toString() === name);
    same(values?.length, 1, `live rule ${name} field`);
    same(hex(values[0].val), hex(expectedValue), `live rule ${name}`);
  }
  let spendingData;
  if (subscription) {
    spendingData = await deps.viewCallObservation({ publicKey: () => run.payer }, subscription.policy_address,
      'get_spending_limit_data', [xdr.ScVal.scvU32(run.rule_id), new Address(run.account).toScVal()]);
    const data = scValToNative(spendingData.value);
    same(data.spending_limit, BigInt(run.amount), 'live spending limit');
    same(data.period_ledgers, subscription.period_ledgers, 'live spending period');
  }
  return { observation: 'non_atomic', read_ledgers: { account_code: accountCode.ledger,
    policy_code: policyCode.ledger, rule: rule.ledger }, account_code_hash: run.account_code_hash,
    policy_code_hash: run.policy_wasm_hash, rule_id: run.rule_id, configuration: 'matched',
    ...(subscription ? { reviewed_policy: { address: subscription.policy_address, code_hash: spending.value,
      code_ledger: spending.ledger, configuration_ledger: spendingData.ledger } } : {}) };
}

function missingRule(error, account) {
  return contractError(error, account, 3000);
}

function contractError(error, contract, code) {
  if (!(error instanceof rpc.SimulationError)) return false;
  const pattern = new RegExp(`contract:${contract}, topics:\\[error, Error\\(Contract, #${code}\\)\\], data:\\["failing with contract error", ${code}\\]`);
  return pattern.test(error.error);
}

export async function revokePolicy(dir, overrides = {}) {
  const deps = { ...rpc, ownerSigner, ...overrides };
  // `dir` is the run directory `run.sh` created, or one its operator names on the command
  // line; no server or remote request reaches this function. The basename is fixed to that
  // run's own journal, whose digest can pin the revoke to the exact snapshot.
  // nosec
  const path = join(dir, 'run.json');
  const bytes = readFileSync(path, 'utf8');
  if (deps.expectedRunHash !== undefined) requireThat(/^[0-9a-f]{64}$/.test(deps.expectedRunHash)
    && createHash('sha256').update(bytes).digest('hex') === deps.expectedRunHash, 'cleanup run snapshot changed');
  const run = parseJsonExact(bytes);
  // `dir` is the run directory `run.sh` created, or one its operator names on the command
  // line; no server or remote request reaches this function. The basename is fixed to
  // the spec that run generated its policy from.
  // nosec
  const spec = parseJsonExact(readFileSync(join(dir, 'spec.json'), 'utf8'));
  requireThat(run.lifecycle === undefined || (run.lifecycle && Array.isArray(run.lifecycle.removals)), 'malformed lifecycle journal');
  const previous = run.lifecycle?.removals ?? [];
  requireThat(run.lifecycle?.pending_removal === undefined, 'a pending removal is already recorded; inspect it before retrying');
  requireThat(!previous.some((r) => r.rule_id === run.rule_id), 'a removal for this rule is already recorded; inspect it before retrying');
  const observed = await inspectInstalledGrant(run, spec, deps);
  const payer = deps.loadKey('payer');
  same(payer.publicKey(), run.payer, 'fee payer');
  const entries = await deps.recordAuth(payer, removeOperation(run.account, run.rule_id), 'remove_context_rule');
  requireThat(entries.length === 1 && entryAddress(entries[0]) === run.account, 'unexpected removal authorization entries');
  const owner = await deps.ownerSigner(run);
  const signed = await signForSmartAccount({ entry: entries[0],
    expect: contractCall(run.account, 'remove_context_rule', ruleArg(run.rule_id)), signer: owner, ruleIds: [0],
    validUntilLedger: (await deps.latestLedger()) + 100, networkPassphrase: rpc.NETWORK_PASSPHRASE });
  const sent = await deps.submit(payer, removeOperation(run.account, run.rule_id, [signed.accountEntry, signed.delegateEntry].filter(Boolean)),
    { stage: 'remove_context_rule', onSubmitting: (hash) => {
      run.lifecycle = { ...(run.lifecycle ?? {}), removals: previous,
        pending_removal: { rule_id: run.rule_id, transaction: hash, status: 'prepared_for_submission' } };
      deps.writeJson(path, run);
    } });
  const removal = { rule_id: run.rule_id, transaction: sent.hash, ledger: sent.receipt?.ledger ?? null,
    event: 'not_verified', rule_readback: 'not_checked', policy_cleanup: 'not_checked', before: observed };
  // Submission was confirmed; preserve its identity before event or readback validation can fail.
  run.lifecycle = { ...(run.lifecycle ?? {}), removals: [...previous, removal] };
  delete run.lifecycle.pending_removal;
  deps.writeJson(path, run);
  removalEvent(sent.receipt, { hash: sent.hash, account: run.account, ruleId: run.rule_id });
  removal.event = 'verified';
  deps.writeJson(path, run);
  try {
    await deps.viewCall(payer, run.account, 'get_context_rule', ruleArg(run.rule_id));
    removal.rule_readback = 'still_present';
    deps.writeJson(path, run);
    throw new Error('removal transaction confirmed, but the rule remains in the readback');
  } catch (error) {
    if (!missingRule(error, run.account)) throw error;
    removal.rule_readback = 'absent';
    deps.writeJson(path, run);
  }
  const installed = scValToNative(await deps.viewCall(payer, run.policy, 'is_installed', [
    xdr.ScVal.scvU32(run.rule_id), new Address(run.account).toScVal(),
  ]));
  requireThat(typeof installed === 'boolean', 'removal confirmed, but policy cleanup readback is malformed');
  removal.policy_cleanup = installed ? 'still_installed' : 'not_installed';
  deps.writeJson(path, run);
  const subscription = subscriptionConfig(run);
  if (subscription) {
    removal.reviewed_policy_cleanup = 'not_checked';
    deps.writeJson(path, run);
    try {
      await deps.viewCall(payer, subscription.policy_address, 'get_spending_limit_data', [
        xdr.ScVal.scvU32(run.rule_id), new Address(run.account).toScVal(),
      ]);
      removal.reviewed_policy_cleanup = 'still_installed';
    } catch (error) {
      if (!contractError(error, subscription.policy_address, 3220)) throw error;
      removal.reviewed_policy_cleanup = 'not_installed';
    }
    deps.writeJson(path, run);
  }
  return removal;
}

if (isMainModule(import.meta.url)) {
  const opts = rpc.args();
  requireThat(opts['run-dir'], 'usage: lifecycle.mjs --run-dir DIRECTORY');
  const removed = await revokePolicy(opts['run-dir'], { expectedRunHash: opts['expected-run-sha256'] });
  console.log(`REMOVED rule ${removed.rule_id}, transaction ${removed.transaction}; policy cleanup: ${removed.policy_cleanup}`);
}
