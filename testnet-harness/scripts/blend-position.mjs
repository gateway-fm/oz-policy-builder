// W1's Blend position: the supply the recorded claim is earned on, and its withdrawal while the
// throwaway keys still exist. Testnet only. Every owner call goes through rule 0 and is signed only
// after the recorded authorization equals the exact intended tree; every prepared transaction is
// journaled before it is sent and never resubmitted.
//
//   node blend-position.mjs refresh --run-dir DIR  # before blend-preflight: gulp an expired emission, or nothing
//   node blend-position.mjs open    --run-dir DIR  # fund, swap XLM -> USDC, supply, wait before the owner claim
//   node blend-position.mjs close   --run-dir DIR  # withdraw an open position; exit 1 if one may remain
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { Address, Operation, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { contractCall, entryAddress, i128, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { BLEND_FEE_CEILING, BLEND_FUNDING, BLEND_POSITION, emissionStatus, readEmission } from './blend-preflight.mjs';
import * as rpc from './rpc.mjs';

const p = PROTOCOL_TARGETS;
const A = (address) => new Address(address).toScVal();
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected Blend ${field}`);
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const hex = (v) => Buffer.from(v.toXDR()).toString('hex');
const positiveLedger = (n) => Number.isSafeInteger(n) && n > 0 && n <= 0xffff_ffff;
const contexts = (node) => 1 + node.subInvocations.reduce((n, child) => n + contexts(child), 0);
const ownerWaitLimit = 120;
// Asking for more than was supplied makes the pool burn every bToken the account holds; the
// interest a run can earn is far below another full supply.
const WITHDRAW_FACTOR = 2n;
// A withdrawal the network definitively did not apply may be rebuilt; at most this many are sent.
const MAX_WITHDRAWALS = 2;
const CLOSE_DEADLINE_MS = 180_000;
// rpc.submit's own words for a transaction that was rejected, never queued, or applied as failed.
const notApplied = (error) => /sendTransaction ERROR|was not accepted \(TRY_AGAIN_LATER\)|ended FAILED/.test(String(error?.message));

/** `Request { request_type, address, amount }` as the pool's contracttype map (keys sorted). */
function request(type, asset, amount) {
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('address'), val: A(asset) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('amount'), val: i128(amount) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('request_type'), val: xdr.ScVal.scvU32(type) }),
  ]);
}

/** The plan's position and funding must be exactly the fixed W1 values; run.json cannot widen them. */
function checkedPlan(plan) {
  const ok = plan?.kind === 'blend_claim' && typeof plan.account === 'string'
    && plan.position?.pool === p.blend_pool && plan.position.asset === p.blend_asset
    && plan.position.reserve_index === BLEND_POSITION.reserve_index && plan.position.request_type === BLEND_POSITION.request_type
    && plan.position.amount === BLEND_POSITION.amount.toString()
    && plan.funding?.amount_in === BLEND_FUNDING.amount_in.toString() && plan.funding.minimum_out === BLEND_POSITION.amount.toString()
    && plan.funding.pair === BLEND_FUNDING.pair && Number.isSafeInteger(plan.funding.deadline) && plan.funding.deadline > 0
    && Number.isInteger(plan.owner_wait_ledgers) && plan.owner_wait_ledgers >= 1 && plan.owner_wait_ledgers <= ownerWaitLimit;
  requireThat(ok, 'invalid Blend position plan');
  return plan;
}

export function fundingSwapInvocation(plan) {
  const { account, funding } = checkedPlan(plan);
  const root = contractCall(p.router, 'swap_exact_tokens_for_tokens', [i128(funding.amount_in), i128(funding.minimum_out),
    xdr.ScVal.scvVec([A(p.native), A(p.blend_asset)]), A(account), xdr.ScVal.scvU64(xdr.Uint64.fromString(String(funding.deadline)))]);
  root.subInvocations = [contractCall(p.native, 'transfer', [A(account), A(funding.pair), i128(funding.amount_in)])];
  return root;
}

export function supplyInvocation(plan) {
  const { account, position } = checkedPlan(plan);
  const root = contractCall(p.blend_pool, 'submit', [A(account), A(account), A(account),
    xdr.ScVal.scvVec([request(BLEND_POSITION.request_type, p.blend_asset, position.amount)])]);
  root.subInvocations = [contractCall(p.blend_asset, 'transfer', [A(account), A(p.blend_pool), i128(position.amount)])];
  return root;
}

export function withdrawInvocation(plan) {
  const { account, position } = checkedPlan(plan);
  return contractCall(p.blend_pool, 'submit', [A(account), A(account), A(account),
    xdr.ScVal.scvVec([request(1, p.blend_asset, BigInt(position.amount) * WITHDRAW_FACTOR)])]);
}

const operationOf = (invocation, auth = []) => {
  const call = invocation.function.contractFn;
  return Operation.invokeContractFunction({ contract: Address.fromScAddress(call.contractAddress).toString(),
    function: call.functionName.toString(), args: call.args, auth });
};

/** `{ collateral, liabilities, supply }`, each as `[[reserve index, amount]]`. */
function positionsOf(value) {
  const native = scValToNative(value);
  requireThat(native && typeof native === 'object', 'invalid Blend positions');
  const entries = (m) => {
    requireThat(m && typeof m === 'object' && !Array.isArray(m), 'invalid Blend positions');
    return Object.entries(m).map(([k, v]) => {
      requireThat(/^(0|[1-9][0-9]*)$/.test(k) && typeof v === 'bigint' && v >= 0n, 'invalid Blend positions');
      return [Number(k), v];
    }).filter(([, v]) => v > 0n);
  };
  return { collateral: entries(native.collateral), liabilities: entries(native.liabilities), supply: entries(native.supply) };
}
const isEmpty = (pos) => !pos.collateral.length && !pos.liabilities.length && !pos.supply.length;
const supplyOnly = (pos) => !pos.collateral.length && !pos.liabilities.length && pos.supply.length === 1
  && pos.supply[0][0] === BLEND_POSITION.reserve_index;

const defaults = { ...rpc, ownerSigner, delay: () => new Promise((resolve) => setTimeout(resolve, 5000)), now: () => Date.now() };

async function checkIdentities(run, deps) {
  same(run.network, rpc.NETWORK_PASSPHRASE, 'network');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  await deps.assertTestnet();
  same(await deps.contractCodeHash(run.account), run.account_code_hash, 'live account code');
  same(await deps.contractCodeHash(p.blend_pool), p.blend_code, 'live pool code');
}

function payerOf(run, deps) {
  const payer = deps.loadKey('payer');
  same(payer.publicKey(), run.payer, 'fee payer');
  return payer;
}

/** One owner call through rule 0: exact recorded tree, owner signature, journal before send. */
async function ownerCall({ run, step, invocation, stage, save }, deps) {
  const payer = payerOf(run, deps);
  const recorded = await deps.recordAuth(payer, operationOf(invocation), stage);
  requireThat(recorded.length === 1 && entryAddress(recorded[0]) === run.account && hex(recorded[0].rootInvocation) === hex(invocation),
    'recorded authorization differs from the exact intended Blend position call');
  const key = await deps.ownerSigner(run);
  const until = (await deps.latestLedger()) + 100;
  const signed = await signForSmartAccount({ entry: recorded[0], expect: invocation, signer: key,
    ruleIds: new Array(contexts(invocation)).fill(0), validUntilLedger: until, networkPassphrase: rpc.NETWORK_PASSPHRASE });
  return submitStep({ step, save, stage }, () => deps.submit(payer, operationOf(invocation,
    [signed.accountEntry, signed.delegateEntry].filter(Boolean)), { stage, onSubmitting: prepared(step, save), maxFee: BLEND_FEE_CEILING }));
}

const prepared = (step, save) => (transaction) => {
  requireThat(/^[0-9a-f]{64}$/.test(transaction), 'invalid prepared Blend transaction');
  Object.assign(step, { status: 'pending', transaction });
  save();
};

async function submitStep({ step, save }, send) {
  const sent = await send();
  same(sent.hash, step.transaction, 'confirmed transaction');
  Object.assign(step, { status: 'confirmed_unverified', ledger: sent.receipt?.ledger ?? null });
  save();
  requireThat(positiveLedger(step.ledger), 'missing confirmed Blend ledger');
  return sent;
}

// A read after a confirmed transaction counts only from an endpoint at or after its ledger.
const observe = (deps, payer, contract, fn, args, minimum) => rpc.observeAtOrAfter(minimum ?? 0,
  () => deps.viewCallObservation(payer, contract, fn, args), { delay: deps.delay });

async function usdcBalance(run, payer, deps, minimum) {
  const value = scValToNative((await observe(deps, payer, p.blend_asset, 'balance', [A(run.account)], minimum)).value);
  requireThat(typeof value === 'bigint' && value >= 0n, 'invalid USDC balance');
  return value;
}

async function livePositions(run, payer, deps, minimum) {
  return positionsOf((await observe(deps, payer, p.blend_pool, 'get_positions', [A(run.account)], minimum)).value);
}

/**
 * Before the preflight: if the claimed ID's emission has expired or would expire within the run,
 * call the pool's permissionless `gulp_emissions` once and record it. A missing or zero schedule,
 * or a gulp the pool refuses, stops the run with that reason.
 */
export async function refreshEmission({ run, save }, overrides = {}) {
  const deps = { ...defaults, ...overrides };
  requireThat(run.walkthrough === undefined, 'refresh runs before the Blend plan is recorded');
  requireThat(run.blend_emission_refresh === undefined, 'a Blend emission refresh is already recorded');
  same(run.network, rpc.NETWORK_PASSPHRASE, 'network');
  await deps.assertTestnet();
  same(await deps.contractCodeHash(p.blend_pool), p.blend_code, 'live pool code');
  const payer = payerOf(run, deps);
  const id = p.blend_claim_id;
  const read = async () => {
    const clock = await deps.latestLedgerClose();
    const emission = emissionStatus(readEmission(await deps.viewCall(payer, p.blend_pool, 'get_reserve_emissions',
      [xdr.ScVal.scvU32(id)])), clock.close_time);
    return { clock, emission };
  };
  const { clock, emission } = await read();
  if (emission.status === 'live') {
    run.blend_emission_refresh = { status: 'not_needed', ledger: clock.ledger, expiration: Number(emission.expiration) };
    save();
    return run.blend_emission_refresh;
  }
  if (emission.status === 'missing' || emission.status === 'zero') {
    run.blend_emission_refresh = { status: 'refused', reason: `emission_${emission.status}`, ledger: clock.ledger };
    save();
    throw new Error(`Blend emission for reserve token ${id} is ${emission.status}; refusing: this harness does not configure `
      + 'emission schedules, and gulp_emissions only refreshes one the pool already lists');
  }
  const record = { status: 'started', reason: `emission_${emission.status}`, expiration_before: Number(emission.expiration) };
  run.blend_emission_refresh = record;
  save();
  const when = new Date(Number(emission.expiration) * 1000).toISOString();
  let sent;
  try {
    sent = await submitStep({ step: record, save }, () => deps.submit(payer, Operation.invokeContractFunction({
      contract: p.blend_pool, function: 'gulp_emissions', args: [] }), { stage: 'blend gulp_emissions', onSubmitting: prepared(record, save), maxFee: BLEND_FEE_CEILING }));
  } catch (error) {
    if (record.transaction === undefined) {
      Object.assign(record, { status: 'refused' });
      save();
      throw new Error(`Blend emission for reserve token ${id} ${emission.status === 'expired' ? 'expired' : 'expires'} at ${when}, `
        + `and gulp_emissions was refused: ${error.message}`);
    }
    throw error;
  }
  const gulped = scValToNative(sent.returnValue);
  requireThat(typeof gulped === 'bigint' && gulped > 0n, 'gulp_emissions returned no new emissions');
  const after = await read();
  Object.assign(record, { status: after.emission.status === 'live' ? 'gulped' : 'gulped_still_not_live', gulped: gulped.toString(),
    expiration_after: after.emission.expiration === undefined ? null : Number(after.emission.expiration) });
  save();
  requireThat(record.status === 'gulped', `Blend emission for reserve token ${id} is still ${after.emission.status} after gulp_emissions`);
  return record;
}

/** Fund the account, swap to USDC and supply it as the owner, then wait before the owner claim. */
export async function openPosition({ run, save }, overrides = {}) {
  const deps = { ...defaults, ...overrides };
  const plan = checkedPlan(run.walkthrough);
  same(plan.account, run.account, 'plan account');
  requireThat(plan.position_journal === undefined, 'a Blend position step is already recorded; use a fresh run');
  requireThat(!plan.invocations?.length, 'the owner claim already ran');
  await checkIdentities(run, deps);
  same(await deps.contractCodeHash(p.router), p.router_code, 'live router code');
  const payer = payerOf(run, deps);
  const journal = { status: 'opening' };
  plan.position_journal = journal;
  save();
  try {
    // 1. The payer sends the swap input to the account (the account spends it, as the swap's `to`).
    journal.funding_transfer = { status: 'started' };
    save();
    await submitStep({ step: journal.funding_transfer, save }, () => deps.submit(payer, Operation.invokeContractFunction({
      contract: p.native, function: 'transfer', args: [A(run.payer), A(run.account), i128(plan.funding.amount_in)] }),
    { stage: 'blend funding transfer',
      onSubmitting: prepared(journal.funding_transfer, save) }));
    journal.funding_transfer.status = 'confirmed';
    save();
    // 2. The owner swaps it to USDC; the account is both payer and recipient of the swap.
    journal.funding_swap = { status: 'started' };
    save();
    const usdcBefore = await usdcBalance(run, payer, deps);
    const swap = await ownerCall({ run, step: journal.funding_swap, invocation: fundingSwapInvocation(plan),
      stage: 'blend funding swap', save }, deps);
    const amounts = scValToNative(swap.returnValue);
    requireThat(Array.isArray(amounts) && amounts.length === 2 && amounts[0] === BigInt(plan.funding.amount_in)
      && typeof amounts[1] === 'bigint' && amounts[1] >= BigInt(plan.funding.minimum_out), 'funding swap output is below the supply amount');
    const usdcAfter = await usdcBalance(run, payer, deps, journal.funding_swap.ledger);
    Object.assign(journal.funding_swap, { returned_amount: amounts[1].toString(), usdc_before: usdcBefore.toString(),
      usdc_after: usdcAfter.toString() });
    save();
    requireThat(usdcAfter - usdcBefore === amounts[1], 'funding swap balance effect differs from its returned amount');
    journal.funding_swap.status = 'confirmed';
    save();
    // 3. The owner supplies exactly the planned amount (request type 0: supply, not collateral).
    journal.supply = { status: 'started', amount: plan.position.amount };
    save();
    const supply = await ownerCall({ run, step: journal.supply, invocation: supplyInvocation(plan), stage: 'blend supply', save }, deps);
    const returned = positionsOf(supply.returnValue);
    const supplied = await usdcBalance(run, payer, deps, journal.supply.ledger);
    const live = await livePositions(run, payer, deps, journal.supply.ledger);
    requireThat(supplyOnly(returned) && supplyOnly(live) && live.supply[0][1] === returned.supply[0][1],
      'supply did not leave exactly one USDC supply position');
    Object.assign(journal.supply, { b_tokens: returned.supply[0][1].toString(), usdc_spent: (usdcAfter - supplied).toString() });
    save();
    requireThat(usdcAfter - supplied === BigInt(plan.position.amount), 'supply balance effect differs from the planned amount');
    journal.supply.status = 'confirmed';
    journal.status = 'open';
    save();
    // 4. Let emissions accrue so the owner's recorded claim is nonzero.
    const target = journal.supply.ledger + plan.owner_wait_ledgers;
    const deadline = deps.now() + (plan.owner_wait_ledgers * 6 + 120) * 1000;
    for (let previous = 0; ;) {
      const ledger = await deps.latestLedger();
      requireThat(positiveLedger(ledger) && ledger >= previous, 'invalid or regressing ledger while waiting');
      previous = ledger;
      if (ledger >= target) { journal.owner_wait = { target_ledger: target, ledger }; save(); break; }
      requireThat(deps.now() < deadline, 'owner accrual wait timed out');
      await deps.delay();
    }
    return journal;
  } catch (error) {
    if (journal.status === 'opening') {
      journal.status = 'incomplete';
      journal.reason ??= 'open_failed';
    }
    save();
    throw error;
  }
}

/**
 * Withdraw the position while the keys exist. Returns `withdrawn`, `no_position` or
 * `not_applicable` when nothing remains, and `incomplete` with a reason when a position may
 * remain or its state is unknown. A prepared withdrawal is never resubmitted.
 */
export async function closePosition({ run, save }, overrides = {}) {
  const deps = { ...defaults, ...overrides };
  const plan = run.walkthrough;
  const journal = plan?.kind === 'blend_claim' ? plan.position_journal : undefined;
  if (journal === undefined) return { status: 'not_applicable' };
  if (journal.status === 'withdrawn' || journal.status === 'no_position') return { status: journal.status };
  const finish = (status, reason) => {
    journal.status = status;
    if (reason) journal.reason = reason; else delete journal.reason;
    save();
    return reason ? { status, reason } : { status };
  };
  let payer, live;
  try {
    checkedPlan(plan);
    payer = payerOf(run, deps);
    live = await livePositions(run, payer, deps);
  } catch {
    return finish('incomplete', 'position_unreadable');
  }
  if (journal.withdrawal?.transaction !== undefined) {
    if (!isEmpty(live)) return finish('incomplete', journal.withdrawal.status === 'confirmed' ? 'position_still_open' : 'withdrawal_unconfirmed');
    journal.withdrawal.readback = 'empty';
    return finish('withdrawn');
  }
  if (isEmpty(live)) {
    // Nothing is open now. A supply that was prepared but never confirmed may still land.
    const supply = journal.supply;
    if (supply?.transaction !== undefined && supply.status !== 'confirmed') return finish('incomplete', 'supply_unconfirmed');
    return finish(supply?.status === 'confirmed' ? 'incomplete' : 'no_position', supply?.status === 'confirmed' ? 'position_missing' : undefined);
  }
  if (!supplyOnly(live)) return finish('incomplete', 'unexpected_position');
  try { await checkIdentities(run, deps); } catch { return finish('incomplete', 'identity_check_failed'); }
  for (;;) {
    if ((journal.failed_withdrawals?.length ?? 0) >= MAX_WITHDRAWALS) return finish('incomplete', 'withdrawal_not_applied');
    journal.status = 'withdrawing';
    journal.withdrawal = { status: 'started' };
    save();
    try {
      const before = await usdcBalance(run, payer, deps);
      const sent = await ownerCall({ run, step: journal.withdrawal, invocation: withdrawInvocation(plan), stage: 'blend withdrawal', save }, deps);
      const after = await usdcBalance(run, payer, deps, journal.withdrawal.ledger);
      journal.withdrawal.usdc_returned = (after - before).toString();
      const returned = positionsOf(sent.returnValue);
      const readback = await livePositions(run, payer, deps, journal.withdrawal.ledger);
      journal.withdrawal.readback = isEmpty(readback) && isEmpty(returned) ? 'empty' : 'still_open';
      journal.withdrawal.status = 'confirmed';
      save();
      break;
    } catch (error) {
      // Only a prepared withdrawal the network rejected, never queued or applied as failed is
      // known to have changed nothing; anything else may still land and is never rebuilt.
      if (journal.withdrawal.transaction === undefined || journal.withdrawal.status !== 'pending' || !notApplied(error)) {
        return finish('incomplete', 'withdrawal_failed');
      }
      (journal.failed_withdrawals ??= []).push({ ...journal.withdrawal, status: 'not_applied' });
      delete journal.withdrawal;
      save();
    }
  }
  return journal.withdrawal.readback === 'empty' ? finish('withdrawn') : finish('incomplete', 'position_still_open');
}

if (isMainModule(import.meta.url)) {
  const [command, ...rest] = process.argv.slice(2);
  const options = rpc.args(rest);
  requireThat(['refresh', 'open', 'close'].includes(command) && options['run-dir'] && Object.keys(options).length === 1,
    'usage: blend-position.mjs refresh|open|close --run-dir DIRECTORY');
  const path = join(options['run-dir'], 'run.json');
  let run;
  try { run = rpc.readJson(path); } catch (error) {
    // A run that failed before setup wrote its journal opened nothing.
    if (command !== 'close' || error?.code !== 'ENOENT') throw error;
    console.error('Blend position cleanup: not_applicable (no run journal).');
    process.exit(0);
  }
  const save = () => rpc.writeJson(path, run);
  if (command === 'refresh') {
    const record = await refreshEmission({ run, save });
    console.log(`Blend emission refresh: ${record.status}${record.transaction ? ` in ${record.transaction}` : ''}.`);
  } else if (command === 'open') {
    const journal = await openPosition({ run, save });
    console.log(`Blend position open: ${journal.supply.amount} USDC base units supplied in ${journal.supply.transaction}.`);
  } else {
    // Cleanup runs before the keys are discarded; it must not hold up the grant cleanup forever.
    setTimeout(() => {
      console.error(`Blend position cleanup passed its ${CLOSE_DEADLINE_MS / 1000}-second deadline; a supply position may `
        + `remain open on ${run.account}. Retain run.json.`);
      process.exit(1);
    }, CLOSE_DEADLINE_MS).unref();
    const result = await closePosition({ run, save });
    console.error(`Blend position cleanup: ${result.status}${result.reason ? ` (${result.reason})` : ''}.`);
    if (result.status === 'incomplete') {
      console.error(`A Blend supply position may remain open on ${run.account}; retain run.json.`);
      process.exitCode = 1;
    }
  }
}
