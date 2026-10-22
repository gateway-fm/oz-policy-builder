// Each rule is installed separately. All original bindings remain in each authority request.
// Every submission hash is journaled before sending; a partial or ambiguous attempt is not retried.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Address, Operation, scValToNative } from '@stellar/stellar-sdk';
import { approveInstall, signedRuleArgs } from './approve-install.mjs';
import { bundleGrantDescription, inspectBundleGrant } from './bundle-grant.mjs';
import { contractCall, entryAddress, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import { checkBundleArtifacts, bundleCheckRequest } from './permission-bundle.mjs';
import { protocolInputs, validateProtocolSynthesis } from './protocol-synthesis.mjs';
import * as rpc from './rpc.mjs';
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected bundle ${field}`);

export async function installPermissionBundle({ run, spec, artifacts, recording, checker, save }, overrides = {}) {
  const deps = { ...rpc, ownerSigner, approveInstall, inspectGrant: inspectBundleGrant, ...overrides };
  requireThat(run.walkthrough?.bundle === undefined, 'a bundle attempt is already recorded; inspect it before retrying');
  requireThat(checker?.runner && checker.trust && typeof checker.confirm === 'function'
    && checker.signedRegistrySnapshot && typeof checker.rpcSource === 'string', 'bundle requires the full authority check');
  const identities = await checkBundleArtifacts(spec, artifacts, { hashSpec: deps.hashSpec });
  validateProtocolSynthesis({ spec, spec_hash: identities[0].spec_hash }, run, protocolInputs(run, recording), run.registry_root);
  await deps.assertTestnet();
  same(await deps.contractCodeHash(run.account), run.account_code_hash, 'live account pin');
  const payer = deps.loadKey('payer');
  same(payer.publicKey(), run.payer, 'fee payer');
  const owner = await deps.ownerSigner(run);
  const journal = run.walkthrough.bundle = {
    status: 'preparing', account: run.account, account_code_hash: run.account_code_hash,
    network: run.network, spec_hash: identities[0].spec_hash, registry_root: spec.registry_snapshot,
    entries: identities.map((identity) => ({ ...identity, tx: {} })),
  };
  save();
  async function send(entry, operation, op, fee = {}) {
    requireThat(entry.pending === undefined, 'a bundle transaction is already pending');
    const sent = await deps.submit(payer, op, { stage: `bundle rule ${entry.rule_index} ${operation}`, ...fee,
      onSubmitting: (transaction) => {
        requireThat(/^[0-9a-f]{64}$/.test(transaction), 'invalid pending transaction identity');
        entry.pending = { operation, transaction, status: 'prepared_for_submission' };
        save();
      } });
    requireThat(entry.pending?.transaction === sent.hash, 'confirmed transaction differs from journaled submission');
    entry.tx[operation] = sent.hash;
    delete entry.pending;
    if (operation === 'install') {
      // The known transaction survives even an unusable return value or failed readback.
      entry.installation = { transaction: sent.hash, ledger: sent.receipt?.ledger ?? null, rule_id: null };
    }
    save();
    return sent;
  }
  try {
    for (const [index, entry] of journal.entries.entries()) {
      // New code's rent and write fee can exceed the ten-XLM upload default (README: Keys).
      const uploaded = await send(entry, 'upload', Operation.uploadContractWasm({ wasm: artifacts[index].wasm }),
        { maxFee: rpc.POLICY_WASM_UPLOAD_FEE });
      same(Buffer.from(scValToNative(uploaded.returnValue)).toString('hex'), entry.wasm_hash, 'uploaded Wasm');
      const created = await send(entry, 'create', Operation.createCustomContract({
        address: new Address(payer.publicKey()), wasmHash: Buffer.from(entry.wasm_hash, 'hex'), salt: randomBytes(32),
      }));
      entry.policy = deps.contractIdOf(created.returnValue);
      save();
      same(await deps.contractCodeHash(entry.policy), entry.wasm_hash, 'deployed code');
    }
    const policies = journal.entries.map((entry) => entry.policy);
    requireThat(new Set(policies).size === policies.length, 'duplicate deployed bundle policy');
    for (const entry of journal.entries) {
      const fromSpec = bundleGrantDescription(run, spec, entry);
      const request = bundleCheckRequest({ spec, artifacts, policies, ruleIndex: entry.rule_index,
        signedRegistrySnapshot: checker.signedRegistrySnapshot, rpcSource: checker.rpcSource });
      // The request binds every rule's policy, so the check answers about all of them; the
      // signed intent itself must still name only this rule's policy (signedRuleArgs).
      const approval = await deps.approveInstall({ ...checker, request, log: deps.log, expect: {
        account: run.account, networkId: spec.network_id, target: fromSpec.context, boundPolicies: policies,
        ruleIndex: entry.rule_index, specHash: entry.spec_hash, registrySnapshotRoot: spec.registry_snapshot,
      } });
      entry.authority = approval.approved ? { ...approval.evidence, status: 'rechecked' } : { status: 'refused' };
      save();
      requireThat(approval.approved === true, 'the harness wallet did not approve the bundle rule');
      const ruleArgs = signedRuleArgs({ approved: approval.args, fromSpec, account: run.account });
      const operation = (auth = []) => Operation.invokeContractFunction({
        contract: run.account, function: 'add_context_rule', args: ruleArgs, auth,
      });
      const recorded = await deps.recordAuth(payer, operation(), 'bundle add_context_rule');
      requireThat(recorded.length === 1 && entryAddress(recorded[0]) === run.account, 'unexpected bundle installation authorization');
      const ledger = await deps.latestLedger();
      requireThat(ledger < fromSpec.validUntil, 'bundle grant expired before signing');
      const signed = await signForSmartAccount({ entry: recorded[0], expect: contractCall(run.account, 'add_context_rule', ruleArgs),
        signer: owner, ruleIds: [0], validUntilLedger: Math.min(ledger + 100, fromSpec.validUntil),
        networkPassphrase: rpc.NETWORK_PASSPHRASE });
      const installed = await send(entry, 'install', operation([signed.accountEntry, signed.delegateEntry].filter(Boolean)));
      const returned = scValToNative(installed.returnValue);
      requireThat(Number.isInteger(returned?.id) && returned.id > 0 && returned.id <= 0xffff_ffff
        && !journal.entries.some((other) => other !== entry && other.installation?.rule_id === returned.id),
      'invalid or duplicate installed bundle rule');
      entry.installation.rule_id = returned.id;
      save();
      entry.readback = await deps.inspectGrant(run, spec, entry, deps);
      save();
    }
    journal.status = 'installed';
    save();
    return journal;
  } catch (error) {
    journal.status = 'incomplete';
    save();
    throw error;
  }
}
