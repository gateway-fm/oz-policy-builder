// Bounded caller-owned cleanup removes each known grant once, preserving partial/ambiguous results.
// A missing installation ID is never replaced by owner rule 0 or inferred from rule order.
// An attempt that prepared no transaction may be retried; a prepared or sent removal is never
// sent again: its hash is reconciled, and only one that definitively did not land is replaced.
import assert from 'node:assert/strict';
import { Address, Operation, scValToNative, xdr } from '@stellar/stellar-sdk';
import { inspectBundleGrant } from './bundle-grant.mjs';
import { contractCall, entryAddress, signForSmartAccount } from './lib.mjs';
import { removalEvent } from './lifecycle.mjs';
import { ownerSigner } from './owner.mjs';
import { checkBundleArtifacts } from './permission-bundle.mjs';
import * as rpc from './rpc.mjs';
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected cleanup ${field}`);
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const hash = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const absent = (error, account) => error instanceof rpc.SimulationError
  && new RegExp(`contract:${account}, topics:\\[error, Error\\(Contract, #3000\\)\\], data:\\["failing with contract error", 3000\\]`).test(error.error);
// One removal that did not land may be followed by one fresh removal; never a third.
export const MAX_FAILED_REMOVALS = 2;
const completed = (entry) => entry.removal?.event === 'verified' && entry.removal.rule_readback === 'absent'
  && entry.removal.policy_cleanup === 'not_installed';

export async function revokePermissionBundle({ run, spec, artifacts, save }, overrides = {}) {
  const deps = { ...rpc, ownerSigner, removalEvent, inspectGrant: inspectBundleGrant,
    checkArtifacts: checkBundleArtifacts, now: () => Date.now(), ...overrides };
  // As the failure-cleanup child, `deadline` (epoch ms) is just before the parent's kill.
  const remaining = () => (deps.deadline ?? Infinity) - deps.now();
  const identities = await deps.checkArtifacts(spec, artifacts, { hashSpec: deps.hashSpec });
  const bundle = run.walkthrough?.bundle;
  requireThat(bundle && Array.isArray(bundle.entries) && bundle.entries.length === identities.length, 'missing complete bundle journal');
  same(bundle.account, run.account, 'account');
  same(bundle.account_code_hash, run.account_code_hash, 'account code');
  same(run.account_code_hash, rpc.PINNED_ACCOUNT_WASM, 'account pin');
  same(bundle.network, rpc.NETWORK_PASSPHRASE, 'network');
  same(run.network, bundle.network, 'run network');
  same(spec.smart_account.address, run.account, 'spec account');
  same(spec.smart_account.observed_code_hash, run.account_code_hash, 'spec account code');
  same(bundle.spec_hash, identities[0].spec_hash, 'full spec identity');
  same(bundle.registry_root, spec.registry_snapshot, 'registry root');
  same(run.registry_root, bundle.registry_root, 'run registry root');
  const ids = [];
  for (const [index, entry] of bundle.entries.entries()) {
    for (const field of ['rule_index', 'wasm_hash', 'spec_hash']) same(entry[field], identities[index][field], field);
    if (entry.installation) {
      const installed = entry.installation;
      requireThat((installed.rule_id === null || (Number.isInteger(installed.rule_id) && installed.rule_id > 0 && installed.rule_id <= 0xffff_ffff))
        && hash(installed.transaction) && installed.transaction === entry.tx?.install, 'invalid confirmed cleanup installation');
      if (installed.rule_id !== null) ids.push(installed.rule_id);
    }
    if (entry.pending?.operation === 'install') requireThat(hash(entry.pending.transaction), 'invalid pending installation identity');
    if (entry.removal) requireThat(hash(entry.removal.transaction), 'invalid recorded removal identity');
    if (entry.pending_removal) requireThat(hash(entry.pending_removal.transaction), 'invalid pending removal identity');
  }
  requireThat(new Set(ids).size === ids.length, 'duplicate installed rule ID');
  bundle.cleanup = { status: 'attempting' };
  save();
  const payerKey = () => {
    const payer = deps.loadKey('payer');
    same(payer.publicKey(), run.payer, 'fee payer');
    return payer;
  };
  // Confirmed removal: event, then readbacks at or after its ledger. Throws at the failing stage.
  async function verifyRemoval(entry, id, receipt, progress) {
    progress('removal event');
    deps.removalEvent(receipt, { hash: entry.removal.transaction, account: run.account, ruleId: id });
    entry.removal.event = 'verified';
    save();
    const payer = payerKey();
    const floor = entry.removal.ledger ?? 0;
    const read = (contract, fn, args) => rpc.observeAtOrAfter(floor,
      () => deps.viewCallObservation(payer, contract, fn, args), { delay: deps.delay });
    const args = [xdr.ScVal.scvU32(id)];
    progress('rule readback');
    try {
      await read(run.account, 'get_context_rule', args);
      entry.removal.rule_readback = 'still_present';
      save();
      throw new Error('removed bundle rule remains present');
    } catch (error) {
      if (!absent(error, run.account)) throw error;
      entry.removal.rule_readback = 'absent';
      save();
    }
    progress('policy readback');
    const installed = scValToNative((await read(entry.policy, 'is_installed', [xdr.ScVal.scvU32(id),
      new Address(run.account).toScVal()])).value);
    requireThat(typeof installed === 'boolean', 'malformed policy cleanup observation');
    entry.removal.policy_cleanup = installed ? 'still_installed' : 'not_installed';
    entry.cleanup_attempt.status = installed ? 'incomplete' : 'removed';
    save();
  }
  for (const entry of [...bundle.entries].reverse()) {
    if (!entry.installation || entry.installation.rule_id === null || entry.removal) continue;
    const id = entry.installation.rule_id;
    let stage = 'identity checks';
    const progress = (next) => { stage = next; };
    entry.cleanup_attempt = { status: 'attempting', attempts: (entry.cleanup_attempt?.attempts ?? 0) + 1 };
    save();
    try {
      // A prepared removal is never sent again. Its hash decides: landed, it is verified like any
      // confirmed removal; definitively not landed (failed, or unseen after its validity window),
      // it is kept by hash and one fresh removal may follow; otherwise it stays pending.
      if (entry.pending_removal) {
        progress('identity checks');
        await deps.assertTestnet();
        progress('pending removal outcome');
        const prepared = entry.pending_removal;
        const outcome = await deps.transactionOutcome(prepared.transaction, prepared.max_time ?? null,
          { budgetMs: Math.max(0, Math.min(rpc.OUTCOME_POLL_BUDGET_MS, remaining() - rpc.REMOVAL_RESERVE_MS)),
            minLedger: prepared.min_ledger ?? null });
        if (outcome?.status === 'SUCCESS') {
          entry.removal = { transaction: prepared.transaction, ledger: Number.isSafeInteger(outcome.ledger) ? outcome.ledger : null,
            event: 'not_verified', rule_readback: 'not_checked', policy_cleanup: 'not_checked', confirmation: 'reconciled',
            before: prepared.before ?? { configuration: 'mismatch_or_unavailable' } };
          delete entry.pending_removal;
          save();
          await verifyRemoval(entry, id, outcome, progress);
          continue;
        }
        const landed = outcome?.status === 'FAILED' ? 'failed'
          : outcome?.status === 'NOT_FOUND' && outcome.after_window === true && Number.isSafeInteger(prepared.max_time) ? 'expired_unseen' : null;
        if (landed === null) throw new Error('prepared removal has no final outcome yet');
        (entry.failed_removals ??= []).push({ transaction: prepared.transaction, status: landed });
        delete entry.pending_removal;
        save();
        if (entry.failed_removals.length >= MAX_FAILED_REMOVALS) throw new Error('a fresh removal was already tried once');
      }
      // The pinned account assigns rule IDs from a monotonic counter, so the ID from our
      // confirmed install names only that grant. That holds only for the pinned code on the
      // expected network: those checks must pass before signing. A changed or unreadable grant
      // or policy is still removed.
      progress('identity checks');
      requireThat((entry.failed_removals?.length ?? 0) < MAX_FAILED_REMOVALS, 'removals already failed twice; none is prepared again');
      requireThat(remaining() >= rpc.REMOVAL_RESERVE_MS, 'too little time before the cleanup deadline to finish a removal; nothing prepared');
      await deps.assertTestnet();
      same(await deps.contractCodeHash(run.account), run.account_code_hash, 'live account code');
      progress('pre-removal readback');
      let before;
      try { before = await deps.inspectGrant(run, spec, entry, deps); }
      catch { before = { configuration: 'mismatch_or_unavailable' }; }
      const payer = payerKey();
      const args = [xdr.ScVal.scvU32(id)];
      const operation = (auth = []) => Operation.invokeContractFunction({
        contract: run.account, function: 'remove_context_rule', args, auth,
      });
      progress('recording authorization');
      const recorded = await deps.recordAuth(payer, operation(), 'bundle remove_context_rule');
      requireThat(recorded.length === 1 && entryAddress(recorded[0]) === run.account, 'unexpected cleanup authorization entries');
      progress('owner signature');
      const owner = await deps.ownerSigner(run);
      const signed = await signForSmartAccount({ entry: recorded[0], expect: contractCall(run.account, 'remove_context_rule', args),
        signer: owner, ruleIds: [0], validUntilLedger: (await deps.latestLedger()) + 100,
        networkPassphrase: rpc.NETWORK_PASSPHRASE });
      progress('submission');
      const sent = await deps.submit(payer, operation([signed.accountEntry, signed.delegateEntry].filter(Boolean)), {
        stage: `bundle remove rule ${id}`, onSubmitting: (transaction, window = {}) => {
          requireThat(hash(transaction), 'invalid prepared removal identity');
          entry.pending_removal = { transaction, status: 'prepared_for_submission', before,
            ...(Number.isSafeInteger(window.max_time) ? { max_time: window.max_time } : {}),
            ...(Number.isSafeInteger(window.min_ledger) ? { min_ledger: window.min_ledger } : {}) };
          save();
        },
      });
      requireThat(entry.pending_removal?.transaction === sent.hash, 'confirmed removal differs from prepared hash');
      entry.removal = { transaction: sent.hash, ledger: sent.receipt?.ledger ?? null,
        event: 'not_verified', rule_readback: 'not_checked', policy_cleanup: 'not_checked', before };
      delete entry.pending_removal;
      save();
      await verifyRemoval(entry, id, sent.receipt, progress);
    } catch (error) {
      // Preserve the precise journal stage and known hash; the reason goes to stderr (the
      // cleanup log), never into the journal, with this run's secrets redacted.
      console.error(rpc.redactSecrets(`bundle cleanup rule ${id}: ${stage} failed: ${error?.message ?? error}`));
      entry.cleanup_attempt.status = 'incomplete';
      save();
    }
  }
  const unknown = bundle.entries.some((entry) => entry.pending?.operation === 'install' || entry.installation?.rule_id === null);
  const installed = bundle.entries.filter((entry) => entry.installation && entry.installation.rule_id !== null);
  bundle.cleanup = { status: unknown || installed.some((entry) => !completed(entry)) ? 'incomplete'
    : installed.length ? 'removed' : 'no_installed_grants' };
  save();
  return bundle.cleanup;
}
