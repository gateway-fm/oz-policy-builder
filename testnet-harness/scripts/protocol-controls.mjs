// W1/W3 stateful controls on an installed protocol bundle. Negative cases are enforcing
// simulations only; the one delegated positive is a confirmed transaction with its output
// balance effect. Expiry is observed after a bounded ledger wait, never inferred from time.
import { isMainModule } from './cli-entry.mjs';
import { revokePermissionBundle } from './bundle-cleanup.mjs';
import { loadBundleFiles } from './bundle-command.mjs';
import { inspectBundleGrant } from './bundle-grant.mjs';
import { checkBundleArtifacts } from './permission-bundle.mjs';
import { invokeProtocol } from './protocol-invoke.mjs';
import * as rpc from './rpc.mjs';
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const positiveLedger = (n) => Number.isSafeInteger(n) && n > 0 && n <= 0xffff_ffff;

// Rule 0 is the root invocation's rule (protocolInputs refuses any other order), so the
// root's generated policy is the first enforcer reached for tuple, signer and count denials.
function negatives(kind, account, root) {
  const tuple = { enforcer: root, code: 6 };
  const signers = [
    ['wrong_signer', { signer: 'payer', expected: { enforcer: account, code: 3016 } }],
    ['zero_signers', { signer: 'none', expected: { enforcer: root, code: 1 } }],
  ];
  if (kind === 'blend_claim') {
    return [['reserve_ids', { control: 'reserve_ids', expected: tuple }],
      ['claim_recipient', { control: 'claim_recipient', expected: tuple }],
      ['pool_function', { control: 'pool_function', expected: tuple }], ...signers];
  }
  return [['input_cap', { control: 'input_cap', expected: tuple }],
    ['output_floor', { control: 'output_floor', expected: tuple }],
    ['exact_deadline', { control: 'deadline', expected: tuple }], ...signers,
    // The child token rule is independently usable; this observes that disclosed authority.
    ['independent_token', { control: 'direct_token', expected: { permit: true } }]];
}

const defaults = {
  ...rpc, invoke: (options) => invokeProtocol(options), cleanup: (input) => revokePermissionBundle(input),
  checkArtifacts: checkBundleArtifacts, inspectGrant: (run, spec, entry) => inspectBundleGrant(run, spec, entry),
  delay: () => new Promise((resolve) => setTimeout(resolve, 5000)), now: () => Date.now(),
};

export async function runProtocolControls(input, overrides = {}) {
  const deps = { ...defaults, ...overrides };
  const { run, spec, artifacts, save } = input;
  const plan = run.walkthrough;
  requireThat(plan?.controls === undefined, 'protocol controls already started; use a fresh isolated grant');
  requireThat(['soroswap_swap', 'blend_claim'].includes(plan.kind), 'unsupported protocol walkthrough');
  const entries = plan.bundle?.entries;
  requireThat(plan.bundle?.status === 'installed' && Array.isArray(entries)
    && entries.length === (plan.kind === 'blend_claim' ? 1 : 2)
    && entries.every((entry, index) => entry.rule_index === index && typeof entry.policy === 'string'
      && Number.isInteger(entry.installation?.rule_id) && entry.installation.rule_id > 0), 'controls require the complete installed bundle');
  requireThat(!plan.invocations?.some((item) => item.signer === 'delegate'), 'grant has already been exercised');
  requireThat(positiveLedger(run.valid_until_ledger), 'missing bounded grant expiry');
  let accrualTarget = null;
  if (plan.kind === 'blend_claim') {
    // Emissions accrue with time; a claim straight after the owner's recorded claim can be zero.
    const owner = plan.owner_transaction?.ledger;
    requireThat(Number.isInteger(plan.accrual_ledgers) && plan.accrual_ledgers >= 1 && plan.accrual_ledgers <= 120
      && positiveLedger(owner), 'Blend controls need an explicit 1..120 ledger accrual wait after the owner claim');
    accrualTarget = owner + plan.accrual_ledgers;
    requireThat(accrualTarget < run.valid_until_ledger, 'accrual wait reaches the grant expiry');
  }
  await deps.checkArtifacts(spec, artifacts, { hashSpec: deps.hashSpec });
  for (const entry of entries) await deps.inspectGrant(run, spec, entry);
  const start = await deps.latestLedger();
  requireThat(positiveLedger(start) && start < run.valid_until_ledger, 'grant is already at or past its expiry ledger');

  const journal = { status: 'running', steps: [] };
  plan.controls = journal;
  save();
  const record = (step) => { journal.steps.push(step); save(); };
  async function call(name, { mode = 'simulate', signer = 'delegate', control = 'baseline', expected }, window) {
    const observed = await deps.invoke({ run, name, mode, signer, control, expected, save });
    const wanted = mode === 'execute' ? 'confirmed' : expected.permit ? 'verified_independent_permission' : 'verified_denial';
    requireThat(observed?.status === wanted && positiveLedger(observed.ledger), `${name}: ${observed?.status ?? 'missing result'}`);
    // A denial seen at the wrong side of expiry is attributed to the wrong rule state.
    const timely = window === 'any' || (window === 'valid' ? observed.ledger <= run.valid_until_ledger
      : observed.ledger > run.valid_until_ledger);
    record({ name, result: timely ? observed.status : 'inconclusive_expiry_window', ledger: observed.ledger,
      ...(observed.transaction ? { transaction: observed.transaction } : {}),
      ...(expected?.code === undefined ? {} : { enforcer: expected.enforcer, code: expected.code }) });
    requireThat(timely, `${name}: observed on the wrong side of the grant expiry; use a fresh isolated grant`);
  }
  async function waitUntil(name, target) {
    const deadline = deps.now() + ((target - start) * 6 + 120) * 1000;
    let previous = 0;
    for (;;) {
      const ledger = await deps.latestLedger();
      requireThat(positiveLedger(ledger) && ledger >= previous, 'invalid or regressing ledger while waiting');
      previous = ledger;
      if (ledger >= target) { record({ name, result: 'ledger_reached', target_ledger: target, ledger }); return; }
      requireThat(deps.now() < deadline, `${name} timed out; run is incomplete`);
      await deps.delay();
    }
  }

  try {
    const root = entries[0].policy;
    for (const [name, options] of negatives(plan.kind, run.account, root)) await call(name, options, 'valid');
    if (accrualTarget !== null) await waitUntil('accrual_wait', accrualTarget);
    await call(plan.kind === 'blend_claim' ? 'delegate_claim' : 'delegate_swap', { mode: 'execute' }, 'valid');
    await call('count_cap', { expected: { enforcer: root, code: 7 } }, 'valid');
    // The account rejects an expired rule before any policy runs, so the spent count cannot mask it.
    await waitUntil('expiry_wait', run.valid_until_ledger + 1);
    await call('expired_rule', { expected: { enforcer: run.account, code: 3002 } }, 'expired');
    const cleanup = await deps.cleanup(input);
    record({ name: 'cleanup', result: cleanup?.status ?? 'missing' });
    requireThat(cleanup?.status === 'removed', 'bundle cleanup is incomplete; inspect the journal');
    await call('post_revocation', { expected: { enforcer: run.account, code: 3000 } }, 'any');
    journal.status = 'completed';
    save();
  } catch (error) {
    journal.status = 'incomplete';
    save();
    throw error;
  }
  return journal;
}

if (isMainModule(import.meta.url)) {
  const options = rpc.args();
  requireThat(options['run-dir'], 'usage: protocol-controls.mjs --run-dir DIRECTORY');
  const result = await runProtocolControls(loadBundleFiles(options['run-dir']));
  console.log(`Protocol controls: ${result.status}.`);
}
