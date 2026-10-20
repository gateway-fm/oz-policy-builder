// Export local observations, not a verdict or a cryptographic attestation. Only explicitly
// selected, typed fields leave the run directory. Raw RPC errors and paths never do.
import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync,
  renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { isMainModule } from './cli-entry.mjs';

const HASH = /^[0-9a-f]{64}$/;
const ADDRESS = /^[CG][A-Z2-7]{55}$/;
const TESTNET = 'Test SDF Network ; September 2015';
const MAX_FILE = 64 * 1024 * 1024;
const fail = () => { throw new Error('invalid or inconsistent evidence record'); };
const object = (v) => v && typeof v === 'object' && !Array.isArray(v) ? v : fail();
const match = (v, pattern) => typeof v === 'string' && pattern.test(v) ? v : fail();
const uint = (v) => Number.isSafeInteger(v) && v >= 0 && v <= 0xffff_ffff ? v : fail();
const choice = (v, values) => values.includes(v) ? v : fail();
const optional = (v, validate) => v === undefined ? null : validate(v);
const hash = (v) => match(v, HASH);
const address = (v) => match(v, ADDRESS);
const amount = (v) => {
  match(v, /^(0|[1-9][0-9]{0,38})$/);
  return BigInt(v) <= (1n << 127n) - 1n ? v : fail();
};
const timestamp = (v) => {
  match(v, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  return Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v ? v : fail();
};

function readFile(path) {
  let fd;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  try {
    // Inspect the opened file, not a pathname that could change before the read. No final
    // symlink is followed, and a FIFO/device is refused without a blocking open.
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_FILE) fail();
    return readFileSync(fd);
  } finally { closeSync(fd); }
}

function provenance(value) {
  if (value === undefined) return { status: 'unavailable' };
  const p = object(value);
  if (p.schema_version !== 1 || typeof p.checkout_dirty !== 'boolean') fail();
  const cli = object(p.cli);
  const mode = choice(cli.mode, ['cargo', 'external']);
  const binary = mode === 'external' ? hash(cli.binary_sha256) : null;
  if (mode === 'cargo' && cli.binary_sha256 !== null) fail();
  const started = timestamp(p.started_at);
  const finished = p.finished_at === null ? null : timestamp(p.finished_at);
  const exit = p.exit_code === null ? null : uint(p.exit_code);
  if ((finished === null) !== (exit === null) || exit > 255 || (finished !== null && finished < started)) fail();
  return {
    status: exit === null ? 'unfinished' : exit === 0 ? 'exited_zero' : 'exited_nonzero',
    started_at: started, finished_at: finished, exit_code: exit,
    checkout_commit: match(p.checkout_commit, /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
    checkout_dirty: p.checkout_dirty,
    node_version: match(p.node_version, /^\d{1,3}\.\d{1,3}\.\d{1,3}$/),
    cli: { mode, binary_sha256: binary },
  };
}

function invocation(value) {
  const v = object(value);
  const result = choice(v.result, ['permit', 'deny']);
  const common = {
    signer: choice(v.signer, ['owner', 'delegate']), rule: uint(v.rule),
    amount: amount(v.amount), to: address(v.to), result,
  };
  if (v.control !== undefined) common.control = choice(v.control, ['post_revocation']);
  if (v.ledger !== undefined) common.ledger = uint(v.ledger);
  if (v.observation !== undefined) choice(v.observation, ['enforcing_simulation']);
  if (result === 'permit') {
    if (v.code !== undefined || v.enforcer !== undefined) fail();
    if (v.observation === 'enforcing_simulation') {
      if (v.hash !== undefined || !common.ledger) fail();
      return { ...common, observation: 'enforcing_simulation', transaction: null };
    }
    return { ...common, observation: 'submitted_transaction', transaction: hash(v.hash) };
  }
  if (v.hash !== undefined) fail(); // simulation denials have no submitted transaction
  return {
    ...common, observation: 'enforcing_simulation', transaction: null,
    enforcer: v.enforcer === null ? null : address(v.enforcer),
    code: v.code === null ? null : uint(v.code),
  };
}

function runRecord(value) {
  if (value === undefined) return null;
  const r = object(value);
  if (r.network !== TESTNET) fail();
  const owner = object(r.owner);
  const ownerKind = choice(owner.kind, ['ed25519', 'passkey']);
  const ownerSummary = ownerKind === 'ed25519'
    ? { kind: ownerKind, address: address(owner.address) }
    : { kind: ownerKind, verifier: address(owner.verifier), verifier_code_hash: hash(owner.verifier_code_hash) };
  const tx = object(r.tx);
  const transactions = {};
  for (const key of ['deploy_verifier', 'deploy_account', 'fund_account', 'add_backup_owner', 'upload_policy', 'create_policy', 'add_context_rule',
    'create_subscription_policy', 'create_subscription_merchant', 'create_control_token', 'mint_control_token']) {
    if (tx[key] !== undefined) transactions[key] = hash(tx[key]);
  }
  const policy = optional(r.policy, address);
  const policyHash = optional(r.policy_wasm_hash, hash);
  const rule = optional(r.rule_id, uint);
  if ((policy === null) !== (policyHash === null) || (rule === null) !== (transactions.add_context_rule === undefined)) fail();
  if (rule !== null && policy === null) fail();
  let authority = { status: 'not_recorded' };
  if (r.authority_check !== undefined) {
    const a = object(r.authority_check);
    if (a.refused !== undefined) {
      if (!Array.isArray(a.refused) || a.refused.length === 0 || rule !== null
        || a.authority_commitment !== undefined || a.rechecked_at_ledger !== undefined) fail();
      authority = { status: 'refused', reason_count: a.refused.length };
    } else {
      const checked = uint(a.checked_at_ledger);
      const rechecked = uint(a.rechecked_at_ledger);
      if (rechecked < checked) fail();
      authority = {
        status: 'rechecked', authority_commitment: hash(a.authority_commitment),
        checked_at_ledger: checked, rechecked_at_ledger: rechecked,
      };
    }
  }
  const invocations = r.invocations === undefined ? [] : r.invocations;
  if (!Array.isArray(invocations) || invocations.length > 1000) fail();
  return {
    network: 'testnet', protocol: uint(r.protocol), account: address(r.account),
    account_code_hash: hash(r.account_code_hash), target: address(r.sac), owner: ownerSummary,
    delegate: address(r.delegate), recipient: address(r.recipient), amount: amount(r.amount),
    valid_until_ledger: optional(r.valid_until_ledger, uint), registry_root: optional(r.registry_root, hash),
    policy, policy_wasm_hash: policyHash, rule_id: rule,
    installation: rule === null ? 'not_recorded' : 'recorded', transactions, authority,
    invocations: invocations.map(invocation),
    ...(r.subscription === undefined ? {} : { subscription: subscriptionRecord(r.subscription, r) }),
  };
}

function subscriptionRecord(value, run) {
  const s = object(value);
  if (s.schema_version !== 1 || !Number.isInteger(s.period_ledgers) || s.period_ledgers < 12 || s.period_ledgers > 120) fail();
  const result = { mode: choice(s.mode, ['short_test_window']), period_ledgers: s.period_ledgers,
    policy_address: address(s.policy_address), policy_code_hash: hash(s.policy_code_hash),
    code_observed_ledger: optional(s.code_observed_ledger, uint), other_token: optional(s.other_token, address),
    control_token_funding: optional(s.control_token_funding, (v) => choice(v, ['matched'])),
    installation_readback: optional(s.installation_readback, (v) => choice(v, ['matched'])) };
  if (s.controls === undefined) return { ...result, controls: { status: 'not_recorded', steps: [] } };
  const controls = object(s.controls);
  const status = choice(controls.status, ['running', 'incomplete', 'completed']);
  if (!Array.isArray(controls.steps) || controls.steps.length > 20) fail();
  const steps = controls.steps.map((value) => {
    const step = object(value);
    const name = choice(step.name, ['larger_amount', 'split_charge', 'wrong_recipient', 'wrong_token', 'wrong_signer',
      'zero_signers', 'early_repeat', 'count_cap', 'first_charge', 'next_window_charge', 'window_wait']);
    const ledger = uint(step.ledger);
    if (!ledger) fail();
    if (name === 'first_charge' || name === 'next_window_charge') {
      const matches = (run.invocations ?? []).filter((i) => i.signer === 'delegate' && i.rule === run.rule_id
        && i.result === 'permit' && i.hash === step.transaction && i.ledger === ledger
        && i.amount === run.amount && i.to === run.recipient);
      if (matches.length !== 1) fail();
      return { name, ledger, result: choice(step.result, ['confirmed_charge']), transaction: hash(step.transaction) };
    }
    if (name === 'window_wait') {
      const target = uint(step.target_ledger);
      if (!target || ledger < target) fail();
      return { name, ledger, target_ledger: target, result: choice(step.result, ['ledger_reached']) };
    }
    const result = choice(step.result, ['verified_denial', 'unexpected_result', 'inconclusive_window_elapsed']);
    const before = step.before_ledger === null ? null : uint(step.before_ledger);
    if (result === 'verified_denial' && (step.code === null || step.enforcer === null || (before !== null && ledger >= before))) fail();
    const expectedCodes = {
      larger_amount: [[run.policy, 6], [s.policy_address, 3221]], split_charge: [[run.policy, 6]], wrong_recipient: [[run.policy, 6]],
      wrong_token: [[run.account, 3002]], wrong_signer: [[run.account, 3016]], zero_signers: [[run.policy, 1], [s.policy_address, 3223]],
      early_repeat: [[s.policy_address, 3221]], count_cap: [[run.policy, 7]],
    };
    if (result === 'verified_denial' && !expectedCodes[name].some(([contract, code]) => step.enforcer === contract && step.code === code)) fail();
    if (step.token !== (name === 'wrong_token' ? s.other_token : run.sac)
      || step.to !== (name === 'wrong_recipient' ? run.payer : run.recipient)
      || step.signer !== (name === 'wrong_signer' ? 'payer' : name === 'zero_signers' ? 'none' : 'delegate')
      || step.amount !== (name === 'larger_amount' ? (BigInt(run.amount) + 1n).toString()
        : name === 'split_charge' ? (BigInt(run.amount) / 2n).toString() : run.amount)) fail();
    return { name, ledger, result, token: address(step.token), to: address(step.to), amount: amount(step.amount),
      signer: choice(step.signer, ['delegate', 'payer', 'none']), before_ledger: before,
      enforcer: step.enforcer === null ? null : address(step.enforcer), code: step.code === null ? null : uint(step.code) };
  });
  if (status === 'completed') {
    if (steps.length !== 12 || steps.some((s) => ['unexpected_result', 'inconclusive_window_elapsed'].includes(s.result))) fail();
    const names = steps.map((s) => s.name);
    if (JSON.stringify(names) !== JSON.stringify(['larger_amount', 'split_charge', 'wrong_recipient', 'wrong_token',
      'wrong_signer', 'zero_signers', 'first_charge', 'early_repeat', 'window_wait', 'next_window_charge', 'window_wait', 'count_cap'])) fail();
    if (steps[7].before_ledger !== steps[6].ledger + s.period_ledgers || steps[7].enforcer !== s.policy_address || steps[7].code !== 3221
      || steps[9].ledger < steps[6].ledger + s.period_ledgers || steps[11].ledger < steps[9].ledger + s.period_ledgers
      || steps[6].transaction === steps[9].transaction) fail();
  }
  return { ...result, controls: { status, steps } };
}

const WALKTHROUGH_STEPS = {
  soroswap_swap: ['input_cap', 'output_floor', 'exact_deadline', 'wrong_signer', 'zero_signers', 'independent_token',
    'delegate_swap', 'count_cap', 'expiry_wait', 'expired_rule', 'cleanup', 'post_revocation'],
  blend_claim: ['reserve_ids', 'claim_recipient', 'pool_function', 'wrong_signer', 'zero_signers', 'accrual_wait',
    'delegate_claim', 'count_cap', 'expiry_wait', 'expired_rule', 'cleanup', 'post_revocation'],
};
const SUBMITTED = ['started', 'pending', 'confirmed_unverified', 'confirmed'];
const SIMULATED = ['started', 'verified_denial', 'unexpected_permit', 'unattributed_denial',
  'verified_independent_permission', 'independent_permission_not_observed'];

/** W1/W3 bundle journal: typed fields only; RPC readbacks, plans and host errors stay local. */
function walkthroughRecord(value, run) {
  if (value === undefined) return { status: 'not_recorded' };
  const w = object(value);
  const kind = choice(w.kind, ['soroswap_swap', 'blend_claim']);
  if (!run || w.account !== run.account) fail();
  const rawInvocations = w.invocations ?? [];
  if (!Array.isArray(rawInvocations) || rawInvocations.length > 100) fail();
  const invocations = rawInvocations.map((item) => {
    const i = object(item);
    const observation = choice(i.observation, ['submitted_transaction', 'enforcing_simulation']);
    const status = choice(i.status, observation === 'submitted_transaction' ? SUBMITTED : SIMULATED);
    const ids = Array.isArray(i.rule_ids) && i.rule_ids.length >= 1 && i.rule_ids.length <= 2 ? i.rule_ids.map(uint) : fail();
    const transaction = observation === 'submitted_transaction' && status !== 'started' ? hash(i.transaction)
      : i.transaction === undefined ? null : fail();
    const denial = status === 'verified_denial';
    if (denial !== (i.code !== undefined) || denial !== (i.enforcer !== undefined)) fail();
    return { name: match(i.name, /^[a-z][a-z0-9_]{0,63}$/),
      control: choice(i.control, ['baseline', 'input_cap', 'output_floor', 'deadline', 'direct_token',
        'reserve_ids', 'claim_recipient', 'pool_function']),
      signer: choice(i.signer, ['owner', 'delegate', 'payer', 'none']), rule_ids: ids, observation, status, transaction,
      ledger: optional(i.ledger, uint), enforcer: denial ? address(i.enforcer) : null, code: denial ? uint(i.code) : null,
      returned_amount: optional(i.returned_amount, amount) };
  });
  let owner = null;
  if (w.owner_transaction !== undefined) {
    const o = object(w.owner_transaction);
    const returned = amount(o.returned_amount);
    if (returned === '0' || BigInt(amount(o.balance_after)) - BigInt(amount(o.balance_before)) !== BigInt(returned)
      || invocations.filter((i) => i.signer === 'owner' && i.status === 'confirmed' && i.transaction === o.hash
        && i.returned_amount === returned).length !== 1) fail();
    owner = { transaction: hash(o.hash), ledger: uint(o.ledger), output_token: address(o.output_token), returned_amount: returned };
  }
  let bundle = null;
  if (w.bundle !== undefined) {
    const b = object(w.bundle);
    if (b.account !== run.account || !Array.isArray(b.entries) || b.entries.length < 1 || b.entries.length > 2) fail();
    bundle = { status: choice(b.status, ['preparing', 'installed', 'incomplete']), spec_hash: hash(b.spec_hash),
      registry_root: hash(b.registry_root),
      cleanup: b.cleanup === undefined ? 'not_attempted'
        : choice(object(b.cleanup).status, ['attempting', 'removed', 'incomplete', 'no_installed_grants']),
      entries: b.entries.map((item, index) => {
        const e = object(item);
        if (e.rule_index !== index) fail();
        const installed = e.installation === undefined ? null : object(e.installation);
        const rule = installed === null || installed.rule_id === null ? null : uint(installed.rule_id);
        if (installed !== null && installed.transaction !== e.tx?.install) fail();
        let removal = null;
        if (e.removal !== undefined) {
          const r = object(e.removal);
          const event = choice(r.event, ['not_verified', 'verified']);
          const readback = choice(r.rule_readback, ['not_checked', 'absent', 'still_present']);
          const cleanup = choice(r.policy_cleanup, ['not_checked', 'not_installed', 'still_installed']);
          if (rule === null || (readback !== 'not_checked' && event !== 'verified')
            || (cleanup !== 'not_checked' && readback !== 'absent')) fail();
          removal = { transaction: hash(r.transaction), ledger: r.ledger === null ? null : uint(r.ledger),
            event, rule_readback: readback, policy_cleanup: cleanup };
        }
        // A prepared but unconfirmed submission may still land; keep its identity visible.
        const pending = e.pending === undefined ? null : { operation: choice(object(e.pending).operation, ['upload', 'create', 'install']),
          transaction: hash(e.pending.transaction) };
        const pendingRemoval = e.pending_removal === undefined ? null : { transaction: hash(object(e.pending_removal).transaction) };
        return { rule_index: index, wasm_hash: hash(e.wasm_hash), policy: optional(e.policy, address), rule_id: rule,
          installation_transaction: installed === null ? null : hash(installed.transaction), pending,
          removal, pending_removal: pendingRemoval };
      }) };
    const done = (e) => e.rule_id === null || (e.removal?.event === 'verified' && e.removal.rule_readback === 'absent'
      && e.removal.policy_cleanup === 'not_installed');
    if (bundle.cleanup === 'removed' && !bundle.entries.every(done)) fail();
  }
  if (w.controls === undefined) return { kind, owner_transaction: owner, invocations, bundle, controls: { status: 'not_recorded', steps: [] } };
  const c = object(w.controls);
  const status = choice(c.status, ['running', 'incomplete', 'completed']);
  if (!Array.isArray(c.steps) || c.steps.length > 20) fail();
  const steps = c.steps.map((item) => {
    const step = object(item);
    const name = choice(step.name, WALKTHROUGH_STEPS[kind]);
    if (name === 'cleanup') return { name, result: choice(step.result, ['removed', 'incomplete', 'no_installed_grants', 'missing']) };
    const ledger = uint(step.ledger);
    if (!ledger) fail();
    if (name === 'accrual_wait' || name === 'expiry_wait') {
      const target = uint(step.target_ledger);
      if (ledger < target) fail();
      return { name, ledger, target_ledger: target, result: choice(step.result, ['ledger_reached']) };
    }
    const result = choice(step.result, ['verified_denial', 'verified_independent_permission', 'confirmed', 'inconclusive_expiry_window']);
    const denial = step.code !== undefined;
    if (denial !== (step.enforcer !== undefined)) fail();
    return { name, ledger, result, transaction: optional(step.transaction, hash),
      enforcer: denial ? address(step.enforcer) : null, code: denial ? uint(step.code) : null };
  });
  if (status === 'completed') {
    const root = bundle?.entries[0]?.policy;
    const valid = run.valid_until_ledger;
    const positive = kind === 'blend_claim' ? 'delegate_claim' : 'delegate_swap';
    const expected = { input_cap: [root, 6], output_floor: [root, 6], exact_deadline: [root, 6], reserve_ids: [root, 6],
      claim_recipient: [root, 6], pool_function: [root, 6], wrong_signer: [run.account, 3016], zero_signers: [root, 1],
      count_cap: [root, 7], expired_rule: [run.account, 3002], post_revocation: [run.account, 3000] };
    if (!bundle || bundle.status !== 'installed' || bundle.cleanup !== 'removed' || valid === null
      || JSON.stringify(steps.map((s) => s.name)) !== JSON.stringify(WALKTHROUGH_STEPS[kind])) fail();
    for (const s of steps) {
      if (s.name === 'cleanup') { if (s.result !== 'removed') fail(); continue; }
      if (s.name === 'expiry_wait' && s.target_ledger !== valid + 1) fail();
      if (s.name.endsWith('_wait')) continue;
      if (s.name === 'expired_rule' ? s.ledger <= valid : s.name !== 'post_revocation' && s.ledger > valid) fail();
      if (s.name === positive) {
        if (s.result !== 'confirmed' || invocations.filter((i) => i.signer === 'delegate' && i.status === 'confirmed'
          && i.transaction === s.transaction && i.ledger === s.ledger).length !== 1) fail();
      } else if (s.name === 'independent_token') {
        if (s.result !== 'verified_independent_permission') fail();
      } else if (s.result !== 'verified_denial' || s.enforcer !== expected[s.name][0] || s.code !== expected[s.name][1]) fail();
    }
  }
  return { kind, owner_transaction: owner, invocations, bundle, controls: { status, steps } };
}

function protocolPipelineRecord(value, run, walkthrough) {
  if (value === undefined) return { status: 'not_recorded' };
  const p = object(value);
  if (p.schema_version !== 1 || !run || p.account !== run.account || walkthrough.status === 'not_recorded'
    || p.kind !== walkthrough.kind || p.recorded_transaction !== walkthrough.owner_transaction?.transaction
    || !Array.isArray(p.artifacts) || p.artifacts.length < 1 || p.artifacts.length > 2) fail();
  const cases = uint(p.reference_cases);
  if (cases === 0) fail();
  return {
    status: 'recorded', kind: p.kind, recorded_transaction: hash(p.recorded_transaction),
    recording_hash: hash(p.recording_hash), acquisition_trust: choice(p.acquisition_trust, ['rpc_reported']),
    synthesis_recording_hash: hash(p.synthesis_recording_hash), synthesis_trust: choice(p.synthesis_trust, ['self_supplied']),
    spec_hash: hash(p.spec_hash), reference_cases: cases, artifact_reproduction: choice(p.artifact_reproduction, ['matched']),
    current_network_preflight: choice(p.current_network_preflight, ['not_checked_here']),
    artifacts: p.artifacts.map((item, index) => {
      const a = object(item);
      if (a.rule_index !== index) fail();
      return { rule_index: index, wasm_hash: hash(a.wasm_hash), normalized_input_hash: hash(a.normalized_input_hash) };
    }),
  };
}

function pipelineRecord(value, run) {
  if (value === undefined) return { status: 'not_recorded' };
  const p = object(value);
  if (p.schema_version !== 1 || !run || p.account !== run.account) fail();
  const ownerTransfers = run.invocations.filter((i) => i.signer === 'owner' && i.rule === 0
    && i.result === 'permit' && i.to === run.recipient && i.amount === run.amount);
  if (ownerTransfers.length !== 1 || ownerTransfers[0].transaction !== p.recorded_transaction) fail();
  const cases = uint(p.reference_cases);
  if (cases === 0) fail();
  const model = p.models_all_policies;
  const gap = p.unmodeled_reviewed_policies;
  if (model !== undefined || gap !== undefined || run.subscription) {
    if (model !== !run.subscription || JSON.stringify(gap) !== JSON.stringify(run.subscription ? ['rule[0]: oz:spending_limit'] : [])) fail();
  }
  return {
    status: 'recorded', recorded_transaction: hash(p.recorded_transaction),
    recording_hash: hash(p.recording_hash), acquisition_trust: choice(p.acquisition_trust, ['rpc_reported']),
    synthesis_recording_hash: hash(p.synthesis_recording_hash), synthesis_trust: choice(p.synthesis_trust, ['self_supplied']),
    spec_hash: hash(p.spec_hash), normalized_input_hash: hash(p.normalized_input_hash), reference_cases: cases,
    artifact_reproduction: choice(p.artifact_reproduction, ['matched']),
    current_network_preflight: choice(p.current_network_preflight, ['not_checked_here']),
    ...(model === undefined ? {} : { models_all_policies: model, unmodeled_reviewed_policies: gap }),
  };
}

function lifecycleRecord(value, run) {
  if (value === undefined) return { status: 'not_recorded', removals: [], configuration_checks: [] };
  const journal = object(value);
  if (!run || !Array.isArray(journal.removals) || journal.removals.length > 100) fail();
  const removals = journal.removals.map((entry) => {
    const r = object(entry);
    const rule = uint(r.rule_id);
    if (rule === 0 || rule !== run.rule_id) fail();
    const event = choice(r.event, ['not_verified', 'verified']);
    const readback = choice(r.rule_readback, ['not_checked', 'absent', 'still_present']);
    const cleanup = choice(r.policy_cleanup, ['not_checked', 'not_installed', 'still_installed']);
    const ledger = r.ledger === null ? null : uint(r.ledger);
    if ((event === 'verified' && !ledger) || (readback !== 'not_checked' && event !== 'verified')
      || (cleanup !== 'not_checked' && readback !== 'absent')) fail();
    const reviewed = r.reviewed_policy_cleanup === undefined ? 'not_checked'
      : choice(r.reviewed_policy_cleanup, ['not_checked', 'not_installed', 'still_installed']);
    if (reviewed !== 'not_checked' && (!run.subscription || readback !== 'absent')) fail();
    return { rule_id: rule, transaction: hash(r.transaction), ledger, event,
      rule_readback: readback, policy_cleanup: cleanup,
      ...(run.subscription ? { reviewed_policy_cleanup: reviewed } : {}) };
  });
  const checks = journal.configuration_checks ?? [];
  if (!Array.isArray(checks) || checks.length > 100) fail();
  let pending;
  if (journal.pending_removal !== undefined) {
    const p = object(journal.pending_removal);
    const rule = uint(p.rule_id);
    if (!rule || rule !== run.rule_id || removals.some((r) => r.rule_id === rule)) fail();
    pending = { rule_id: rule, transaction: hash(p.transaction),
      status: choice(p.status, ['prepared_for_submission']) };
  }
  return {
    status: 'recorded', removals,
    ...(pending ? { pending_removal: pending } : {}),
    configuration_checks: checks.map((entry) => {
      const c = object(entry);
      const configuration = choice(c.configuration, ['matched', 'drift_or_unavailable']);
      if (configuration === 'drift_or_unavailable') {
        if (c.read_ledgers !== null) fail();
        return { configuration, read_ledgers: null };
      }
      const rule = uint(c.rule_id);
      if (rule !== run.rule_id || c.account_code_hash !== run.account_code_hash
        || c.policy_code_hash !== run.policy_wasm_hash) fail();
      if (Object.hasOwn(c, 'ledger')) fail();
      const ledgers = object(c.read_ledgers);
      if (!ledgers.account_code || !ledgers.policy_code || !ledgers.rule) fail();
      let reviewed;
      if (run.subscription) {
        const p = object(c.reviewed_policy);
        if (p.address !== run.subscription.policy_address || p.code_hash !== run.subscription.policy_code_hash) fail();
        reviewed = { address: address(p.address), code_hash: hash(p.code_hash),
          code_ledger: uint(p.code_ledger), configuration_ledger: uint(p.configuration_ledger) };
      }
      return { configuration, observation: choice(c.observation, ['non_atomic']),
        read_ledgers: { account_code: uint(ledgers.account_code), policy_code: uint(ledgers.policy_code), rule: uint(ledgers.rule) }, rule_id: rule,
        account_code_hash: hash(c.account_code_hash), policy_code_hash: hash(c.policy_code_hash),
        ...(reviewed ? { reviewed_policy: reviewed } : {}) };
    }),
  };
}

function failureCleanupRecord(value, run, lifecycle) {
  if (value === undefined) return { status: 'not_recorded' };
  const c = object(value);
  const status = choice(c.status, ['attempting', 'removed', 'incomplete']);
  const rule = uint(c.rule_id);
  if (!run || !rule) fail();
  const record = { status, network: choice(c.network, [TESTNET]), account: address(c.account),
    account_code_hash: hash(c.account_code_hash), rule_id: rule, installation: hash(c.installation),
    policy: address(c.policy), policy_wasm_hash: hash(c.policy_wasm_hash),
    reason: optional(c.reason, (v) => choice(v, ['verified_removal', 'deadline', 'identity_changed',
      'removal_unconfirmed', 'removal_already_recorded'])),
    transaction: optional(c.transaction, hash) };
  if (c.subscription !== null) {
    const s = object(c.subscription);
    if (s.schema_version !== 1) fail();
    record.reviewed_policy = { address: address(s.policy_address), code_hash: hash(s.policy_code_hash),
      mode: choice(s.mode, ['short_test_window']), period_ledgers: uint(s.period_ledgers) };
  }
  if (status === 'removed' && (record.reason !== 'verified_removal' || record.account !== run.account
    || record.account_code_hash !== run.account_code_hash || record.installation !== run.transactions.add_context_rule
    || record.policy !== run.policy || rule !== run.rule_id || record.policy_wasm_hash !== run.policy_wasm_hash
    || (c.subscription === null) !== (run.subscription === undefined)
    || (c.subscription !== null && (record.reviewed_policy.address !== run.subscription?.policy_address
      || record.reviewed_policy.code_hash !== run.subscription?.policy_code_hash
      || record.reviewed_policy.mode !== run.subscription?.mode
      || record.reviewed_policy.period_ledgers !== run.subscription?.period_ledgers))
    || !lifecycle.removals.some((r) => r.rule_id === rule && r.transaction === record.transaction
      && r.event === 'verified' && r.rule_readback === 'absent'))) fail();
  if (status !== 'removed' && record.transaction !== null) fail();
  return record;
}

export function exportEvidence(runDir) {
  if (!lstatSync(runDir).isDirectory()) fail();
  const artifacts = {};
  function artifact(key, path) {
    const bytes = readFile(path);
    if (bytes !== null) artifacts[key] = { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
    return bytes;
  }
  const decode = (bytes) => bytes === null ? undefined : JSON.parse(bytes.toString('utf8'));
  const rawRun = decode(artifact('run', join(runDir, 'run.json')));
  const run = runRecord(rawRun);
  const lifecycle = lifecycleRecord(rawRun?.lifecycle, run);
  const failureCleanup = failureCleanupRecord(rawRun?.failure_cleanup, run, lifecycle);
  const source = provenance(decode(artifact('provenance', join(runDir, 'provenance.json'))));
  const pipeline = pipelineRecord(decode(artifact('pipeline', join(runDir, 'pipeline.json'))), run);
  const walkthrough = walkthroughRecord(rawRun?.walkthrough, run);
  const protocolPipeline = protocolPipelineRecord(
    decode(artifact('protocol_pipeline', join(runDir, 'protocol-pipeline.json'))), run, walkthrough);
  if (run === null && source.status === 'unavailable') fail();
  for (const [key, file] of [['spec', 'spec.json'], ['recording', 'recording.json'], ['import_bundle', 'import-bundle.json'],
    ['synthesis', 'synthesis.json'], ['decisions', 'decisions.json'], ['reference_suite', 'reference-suite.json'],
    ['verification', 'verification.json']]) {
    // Local CLI-selected directory plus a constant basename, not a backend request path.
    // readFile checks a regular O_NOFOLLOW descriptor; only a digest leaves this call.
    // nosemgrep
    artifact(key, join(runDir, file));
  }
  // The operator explicitly selected this local run. No server accepts this path, and the
  // directory is checked below; files use checked descriptors and only typed summaries leave.
  // nosemgrep
  const policyDir = join(runDir, 'policy');
  let policyExists = false;
  try { if (!lstatSync(policyDir).isDirectory()) fail(); policyExists = true; }
  catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (policyExists) {
    artifact('build_manifest', join(policyDir, 'build-manifest.json'));
    const wasms = readdirSync(policyDir).filter((name) => name.endsWith('.wasm'));
    if (wasms.length > 1) fail();
    if (wasms.length === 1) artifact('policy_wasm', join(policyDir, wasms[0]));
  }
  if (run?.policy_wasm_hash && artifacts.policy_wasm && run.policy_wasm_hash !== artifacts.policy_wasm.sha256) fail();
  // A protocol bundle keeps one generated policy per rule under policies/rule-N.
  for (const [index, entry] of (walkthrough.bundle?.entries ?? []).entries()) {
    // Operator-selected local run directory plus constant names, as above.
    // nosemgrep
    const ruleDir = join(runDir, 'policies', `rule-${index}`);
    let names;
    try { if (!lstatSync(ruleDir).isDirectory()) fail(); names = readdirSync(ruleDir); }
    catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    artifact(`build_manifest_rule_${index}`, join(ruleDir, 'build-manifest.json'));
    artifact(`verification_rule_${index}`, join(runDir, `verification-${index}.json`));
    const wasms = names.filter((name) => name.endsWith('.wasm'));
    if (wasms.length > 1) fail();
    if (wasms.length === 1 && artifact(`policy_wasm_rule_${index}`, join(ruleDir, wasms[0])) !== null
      && artifacts[`policy_wasm_rule_${index}`].sha256 !== entry.wasm_hash) fail();
  }
  return {
    schema_version: 1,
    evidence_kind: 'local_harness_record',
    limitations: [
      'Local files can be edited; this summary is not authenticated ledger evidence or a milestone verdict.',
      'Artifact hashes identify exact file bytes, not independent reproduction or canonical spec identity.',
      'A missing install record does not prove that nothing was submitted.',
      'Denials describe enforcing simulations, not failed on-chain transactions.',
      'Passkey runs use an exportable software credential in a virtual authenticator.',
      'Authority trust, when used, is operator-supplied test configuration.',
      'A recorded reproduction result is a local observation; it is not live preflight or a wallet acceptance verdict.',
    ],
    provenance: source, run, pipeline, lifecycle, failure_cleanup: failureCleanup,
    ...(walkthrough.status === 'not_recorded' ? {} : { walkthrough, protocol_pipeline: protocolPipeline }), artifacts,
  };
}

/** Publish a complete summary atomically; replacing a symlink must not write to its target. */
export function writeEvidence(runDir) {
  const report = exportEvidence(runDir);
  const temporary = join(runDir, `.evidence-${randomUUID()}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  let closed = false;
  let published = false;
  try {
    writeFileSync(fd, `${JSON.stringify(report, null, 2)}\n`);
    closeSync(fd);
    closed = true;
    renameSync(temporary, join(runDir, 'evidence.json'));
    published = true;
  } finally {
    try { if (!closed) closeSync(fd); }
    finally { if (!published) rmSync(temporary, { force: true }); }
  }
}

if (isMainModule(import.meta.url)) {
  try {
    const [flag, runDir, mode, ...extra] = process.argv.slice(2);
    if (flag !== '--run-dir' || !runDir || (mode !== undefined && mode !== '--write') || extra.length) fail();
    if (mode === '--write') writeEvidence(resolve(runDir));
    else console.log(JSON.stringify(exportEvidence(resolve(runDir)), null, 2));
  } catch {
    console.error('evidence export failed: expected --run-dir <directory> [--write] with valid, consistent local records');
    process.exitCode = 1;
  }
}
