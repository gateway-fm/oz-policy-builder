// W2 stateful controls. Negative cases are enforcing simulations only, even if unexpectedly
// permitted. Actual successful charges keep their transaction identities and confirmed ledgers.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Address, Operation, authorizeEntry, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { contractCall, entryAddress, i128, policyDenial, signForSmartAccount } from './lib.mjs';
import { subscriptionConfig } from './subscription.mjs';
import * as rpc from './rpc.mjs';

const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const positiveLedger = (n) => Number.isSafeInteger(n) && n > 0 && n <= 0xffff_ffff;
const transferArgs = (run, to, amount) => [new Address(run.account).toScVal(), new Address(to).toScVal(), i128(BigInt(amount))];

/** Check the full recorded auth tree before producing either a delegated or intentionally empty proof. */
export async function simulatedTransfer(run, { token = run.sac, to = run.recipient, amount = run.amount, signer = 'delegate' }, deps = rpc) {
  const payer = deps.loadKey('payer');
  const args = transferArgs(run, to, amount);
  const operation = (auth = []) => Operation.invokeContractFunction({ contract: token, function: 'transfer', args, auth });
  const entries = await deps.recordAuth(payer, operation(), 'subscription control');
  requireThat(entries.length === 1 && entryAddress(entries[0]) === run.account, 'unexpected subscription authorization entries');
  const intended = contractCall(token, 'transfer', args);
  assert.deepEqual(Buffer.from(entries[0].rootInvocation.toXDR()), Buffer.from(intended.toXDR()), 'unexpected subscription authorization tree');
  const until = (await deps.latestLedger()) + 100;
  let auth;
  if (signer === 'none') {
    const accountEntry = await authorizeEntry(entries[0], async () => ({ signatureScVal: xdr.ScVal.scvMap([
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('context_rule_ids'), val: xdr.ScVal.scvVec([xdr.ScVal.scvU32(run.rule_id)]) }),
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('signers'), val: xdr.ScVal.scvMap([]) }),
    ]) }), until, rpc.NETWORK_PASSPHRASE);
    auth = [accountEntry];
  } else {
    requireThat(['delegate', 'payer'].includes(signer), 'unsupported control signer');
    const signed = await signForSmartAccount({ entry: entries[0], expect: intended, signer: deps.loadKey(signer),
      ruleIds: [run.rule_id], validUntilLedger: until, networkPassphrase: rpc.NETWORK_PASSPHRASE });
    auth = [signed.accountEntry, signed.delegateEntry].filter(Boolean);
  }
  return deps.enforceSimulation(payer, operation(auth));
}

const defaults = {
  ...rpc, simulatedTransfer,
  delay: () => new Promise((resolve) => setTimeout(resolve, 5000)), now: () => Date.now(),
  invokePermit: async (dir, run) => {
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('./invoke.mjs', import.meta.url)),
      '--run-dir', dir, '--amount', run.amount, '--to', run.recipient, '--expect', 'permit'], { stdio: 'inherit', timeout: 180_000 });
    if (result.error) throw result.error;
    requireThat(result.status === 0, 'subscription charge did not complete');
  },
};

export async function runSubscriptionControls(dir, overrides = {}) {
  const deps = { ...defaults, ...overrides };
  const path = join(dir, 'run.json');
  let run = deps.readJson(path);
  const config = subscriptionConfig(run);
  requireThat(config && config.installation_readback === 'matched' && run.authority_check?.rechecked_at_ledger,
    'subscription controls require the checked composed installation');
  requireThat(config.controls === undefined, 'subscription controls already started; use a fresh isolated grant');
  requireThat(config.other_token && config.other_token !== run.sac, 'missing independent token control');
  requireThat(!run.invocations?.some((i) => i.signer === 'delegate'), 'grant has already been exercised');
  await deps.assertTestnet();
  const balance = scValToNative(await deps.viewCall({ publicKey: () => run.payer }, config.other_token, 'balance', [new Address(run.account).toScVal()]));
  requireThat(typeof balance === 'bigint' && balance >= BigInt(run.amount), 'wrong-token control requires an actually funded account');
  const journal = { status: 'running', steps: [] };
  run.subscription.controls = journal;
  const save = () => { run.subscription.controls = journal; deps.writeJson(path, run); };
  save();

  async function deny(name, request, acceptable, before = null) {
    const observed = await deps.simulatedTransfer(run, request, deps);
    requireThat(positiveLedger(observed.ledger), 'control lacks an actual simulation ledger');
    const attributed = acceptable.map(([enforcer, code]) => ({ enforcer, code }))
      .find((item) => observed.result === 'deny' && policyDenial(observed.error, run.account, item.enforcer) === item.code);
    const timely = before === null || observed.ledger < before;
    const result = attributed && timely ? 'verified_denial' : timely ? 'unexpected_result' : 'inconclusive_window_elapsed';
    journal.steps.push({ name, result, ledger: observed.ledger, token: request.token ?? run.sac,
      to: request.to ?? run.recipient, amount: request.amount ?? run.amount, signer: request.signer ?? 'delegate',
      enforcer: attributed?.enforcer ?? null, code: attributed?.code ?? null, before_ledger: before });
    save();
    requireThat(result === 'verified_denial', `${name}: ${result}; use a fresh isolated grant`);
  }
  async function charge(name) {
    const previous = run.invocations?.length ?? 0;
    try { await deps.invokePermit(dir, run); }
    finally {
      // If the child journal cannot be re-read, do not overwrite it with stale parent state.
      run = null;
      run = deps.readJson(path);
    }
    const record = run.invocations?.at(-1);
    requireThat(run.invocations?.length === previous + 1 && record.signer === 'delegate' && record.rule === run.rule_id
      && record.amount === run.amount && record.to === run.recipient && record.result === 'permit'
      && /^[0-9a-f]{64}$/.test(record.hash) && positiveLedger(record.ledger), 'charge lacks exact confirmed transaction evidence');
    journal.steps.push({ name, result: 'confirmed_charge', transaction: record.hash, ledger: record.ledger });
    save();
    return record.ledger;
  }
  async function waitUntil(target) {
    requireThat(positiveLedger(target) && target < run.valid_until_ledger, 'subscription window exceeds grant expiry');
    const deadline = deps.now() + (config.period_ledgers * 20 + 120) * 1000;
    let previous = 0;
    for (;;) {
      const ledger = await deps.latestLedger();
      requireThat(positiveLedger(ledger) && ledger >= previous, 'invalid or regressing ledger while waiting');
      previous = ledger;
      if (ledger >= target) {
        journal.steps.push({ name: 'window_wait', result: 'ledger_reached', target_ledger: target, ledger }); save(); return;
      }
      requireThat(deps.now() < deadline, 'subscription ledger wait timed out; run is incomplete');
      await deps.delay();
    }
  }

  try {
    const generated = run.policy;
    const spending = config.policy_address;
    await deny('larger_amount', { amount: (BigInt(run.amount) + 1n).toString() }, [[generated, 6], [spending, 3221]]);
    requireThat(BigInt(run.amount) > 1n, 'split-charge control needs amount > 1');
    await deny('split_charge', { amount: (BigInt(run.amount) / 2n).toString() }, [[generated, 6]]);
    await deny('wrong_recipient', { to: run.payer }, [[generated, 6]]);
    await deny('wrong_token', { token: config.other_token }, [[run.account, 3002]]);
    await deny('wrong_signer', { signer: 'payer' }, [[run.account, 3016]]);
    await deny('zero_signers', { signer: 'none' }, [[generated, 1], [spending, 3223]]);
    const first = await charge('first_charge');
    await deny('early_repeat', {}, [[spending, 3221]], first + config.period_ledgers);
    await waitUntil(first + config.period_ledgers);
    const second = await charge('next_window_charge');
    requireThat(second >= first + config.period_ledgers, 'second charge was confirmed before the next window');
    await waitUntil(second + config.period_ledgers);
    await deny('count_cap', {}, [[generated, 7]]);
    journal.status = 'completed'; save();
  } catch (error) {
    journal.status = 'incomplete'; if (run !== null) save(); throw error;
  }
  return journal;
}

if (isMainModule(import.meta.url)) {
  const options = rpc.args();
  requireThat(options['run-dir'], 'usage: subscription-controls.mjs --run-dir DIRECTORY');
  await runSubscriptionControls(options['run-dir']);
}
