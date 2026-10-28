import assert from 'node:assert/strict';
import test from 'node:test';
import { replacementConsent } from '../shared/replacement.mjs';
import { installable, signInstall, verified } from './install-fixture.mjs';
async function installed() {
  const f = await installable(); await verified(f);
  const assembly = await f.actions.assemble({ reviewId: f.review.reviewId });
  const result = await f.actions.submit({ id: assembly.action.id, signedAuthEntriesXdr: await signInstall(f, assembly) });
  return Object.assign(f, { installation: result.installation });
}
async function removeGrant(f) {
  const preparation = await f.actions['prepare-revoke']({ installationId: f.installation.installationId });
  const { xdr } = await import('@stellar/stellar-sdk');
  const envelope = xdr.TransactionEnvelope.fromXDR(preparation.assembly.envelope_xdr_base64, 'base64');
  const entry = envelope.v1.tx.operations[0].body.invokeHostFunctionOp.auth[0].toXDR('base64');
  const result = await f.actions['confirm-revoke']({ id: preparation.action.id, signedAuthEntriesXdr: await f.signEntry(entry) });
  return Object.assign(f, { removal: result.removal });
}
async function removed() { return removeGrant(await installed()); }
test('replacement needs verified removal, fresh owner/rule reads and explicit budget acknowledgement', async () => {
  const f = await removed();
  assert.equal((await f.actions.status({})).capabilities.replacement, true);
  const prepared = await f.actions['prepare-replacement']({ installationId: f.installation.installationId });
  assert.deepEqual(prepared.display, replacementConsent(f));
  const sent = f.submissions.length;
  await assert.rejects(f.actions['confirm-replacement']({ id: prepared.action.id, consent: 'continue' }), /refused/);
  const result = await f.actions['confirm-replacement']({ id: prepared.action.id, consent: 'previously_used_authority_plus_new_cap' });
  assert.equal(result.replacementReady, true);
  assert.equal(f.submissions.length, sent, 'replacement setup itself signs/submits nothing');
  const status = await f.actions.status({});
  assert.equal(status.capabilities.replacement, false);
  assert.deepEqual(status.replacement, result, 'a lost confirmation can recover the exact action-bound receipt');
  assert.equal(status.capabilities.install, false, 'all old reviews were discarded');
  assert.equal(status.installations[0].removal.status, 'removed', 'history is retained');
  await assert.rejects(f.actions.assemble({ reviewId: f.review.reviewId }), /refused/);
  await assert.rejects(f.actions.review({ deploymentId: f.deployed.deploymentId, wallet: f.f.wallet }), /refused/);
  await assert.rejects(f.actions['prepare-deploy']({ artifactId: f.artifactId }), /refused/, 'old artifact remains spent');
  await assert.rejects(f.actions['confirm-replacement']({ id: prepared.action.id, consent: 'previously_used_authority_plus_new_cap' }), /unavailable/);
});
test('an installed grant cannot overlap its replacement', async () => {
  const f = await installed();
  assert.equal((await f.actions.status({})).capabilities.replacement, false);
  await assert.rejects(f.actions['prepare-replacement']({ installationId: f.installation.installationId }), /refused/);
});
for (const change of ['owner changed', 'rule revived', 'rule revived after preparation', 'removal read lagging']) {
  test(`replacement refuses ${change}`, async () => {
    const f = await removed();
    let prepared;
    if (change === 'rule revived after preparation') prepared = await f.actions['prepare-replacement']({ installationId: f.installation.installationId });
    if (change === 'owner changed') f.network.view = async () => ({ value: f.rule, ledger: f.state.ledger });
    if (change.startsWith('rule revived')) f.state.installed = true;
    if (change === 'removal read lagging') f.network.ruleReadback = async () => ({ status: 'absent', ledger: f.removal.ledger - 1 });
    await assert.rejects(prepared
      ? f.actions['confirm-replacement']({ id: prepared.action.id, consent: 'previously_used_authority_plus_new_cap' })
      : f.actions['prepare-replacement']({ installationId: f.installation.installationId }), /refused/);
    assert.equal((await f.actions.status({})).capabilities.install, false);
  });
}
test('a confirmed but unverified removal never opens replacement', async () => {
  const f = await installed();
  const p = await f.actions['prepare-revoke']({ installationId: f.installation.installationId });
  const { xdr } = await import('@stellar/stellar-sdk');
  const e = xdr.TransactionEnvelope.fromXDR(p.assembly.envelope_xdr_base64, 'base64').v1.tx.operations[0].body.invokeHostFunctionOp.auth[0];
  f.readback = () => ({ status: 'present', xdr: f.rule.toXDR('base64'), ledger: f.state.ledger });
  await assert.rejects(f.actions['confirm-revoke']({ id: p.action.id, signedAuthEntriesXdr: await f.signEntry(e.toXDR('base64')) }), /refused/);
  assert.equal((await f.actions.status({})).capabilities.replacement, false);
});

test('one backend can install a fresh checked grant after revocation and acknowledgement', async () => {
  const f = await removed();
  const preview = await f.actions['prepare-replacement']({ installationId: f.installation.installationId });
  await f.actions['confirm-replacement']({ id: preview.action.id, consent: 'previously_used_authority_plus_new_cap' });
  const newArtifactId = '9'.repeat(64);
  const oldArtifact = f.toolchain.artifact, oldBinding = f.toolchain.bindingRequest, oldAuthority = f.toolchain.authority;
  // The fake toolchain regenerates the same grant content under a new artifact identity. Its
  // fake deployer uses a fixed address; this tests allowance/check sequencing, not live deployment.
  f.toolchain.record = async () => ({ recordId: '8'.repeat(64) });
  f.toolchain.generate = async (input) => {
    assert.equal(input.recordId, '8'.repeat(64)); return { ...f.artifact, artifactId: newArtifactId };
  };
  f.toolchain.artifact = (id) => id === newArtifactId ? oldArtifact(f.artifactId) : oldArtifact(id);
  f.toolchain.bindingRequest = (id, ...args) => oldBinding(id === newArtifactId ? f.artifactId : id, ...args);
  f.toolchain.authority = async (command, request) => command === 'check-policy-call-surface'
    ? { binding_set_hash: f.f.expected.bindingSetHash, spec_hash: f.artifact.specHash } : oldAuthority(command, request);
  f.f.intent.authority.verdict.evidence.enumeration_evidence.next_id = 2;
  const recording = await f.actions.record({ transactionHash: '7'.repeat(64), wallet: f.f.wallet });
  const generated = await f.actions.generate({ recordId: recording.recordId, delegateAddress: f.delegate.address,
    maxCalls: 1, validUntilLedger: f.artifact.spec.rules[0].valid_until.ledger, grantName: f.f.intent.rule_name });
  const deployment = await f.actions['prepare-deploy']({ artifactId: generated.artifactId });
  f.deployed = await f.actions['confirm-deploy']({ id: deployment.action.id });
  f.review = await f.actions.review({ deploymentId: f.deployed.deploymentId, wallet: f.f.wallet });
  assert.equal(f.review.verification.complete, false);
  await assert.rejects(f.actions.assemble({ reviewId: f.review.reviewId }), /refused/, 'old passing report cannot be reused');
  // Preserve the prior signature-expiry guard and acquire a new capture for this check window.
  f.state.ledger = Math.max(f.state.ledger, ...f.obligations.map((o) => o.signatureExpirationLedger + 1));
  const { stubNativeChecks } = await import('./native-actions-fixture.mjs');
  stubNativeChecks(f, f.delegate, f.holder, { maxCalls: 1, captureLedger: f.state.ledger });
  for (const frame of [f.holder.frames.prepared, f.holder.frames.result, f.holder.captured.prepared, f.holder.captured.result]) frame.candidate_context_rule_id = 2;
  f.holder.frames.expected.candidateContextRuleId = 2;
  const checks = await verified(f);
  assert.equal(checks.live.verification.complete, true, JSON.stringify(checks.live.verification.layers));
  const { installedRule, addedEvent } = await import('./install-fixture.mjs');
  const newRule = installedRule(f.f.intent, { ruleId: 2 });
  f.network.ruleReadback = async (_account, ruleId) => ({ status: f.state.installed && ruleId === 2 ? 'present' : 'absent',
    ...(f.state.installed && ruleId === 2 ? { xdr: newRule.toXDR('base64') } : {}), ledger: f.state.ledger });
  f.onSubmit = async (_envelope, stage) => {
    assert.equal(stage, 'install-policy');
    f.state.ledger++; f.state.nextId = 3; f.state.installed = true;
    return { hash: '6'.repeat(64), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: newRule,
      events: [addedEvent(f.f.wallet.contractId, newRule, 2)] };
  };
  const assembly = await f.actions.assemble({ reviewId: f.review.reviewId });
  const result = await f.actions.submit({ id: assembly.action.id, signedAuthEntriesXdr: await signInstall(f, assembly) });
  assert.equal(result.installation.ruleId, 2);
  assert.equal(result.installation.status, 'installed');
  const history = (await f.actions.status({})).installations;
  assert.equal(history.length, 2); assert.equal(history[0].removal.status, 'removed'); assert.equal(history[1].removal, null);
  assert.equal((await f.actions.status({})).capabilities.replacement, false, 'second grant must also be revoked first');
  // After a second removal, only that latest installation may anchor new consent.
  const { removalFor, removedEvent } = await import('./install-fixture.mjs');
  f.installation = result.installation;
  f.network.prepareRemoval = async ({ wallet, ruleId }) => removalFor({ account: wallet.contractId, ruleId,
    payer: f.network.payerAddress, sequence: f.sequence, ledger: f.state.ledger });
  f.onSubmit = async (_envelope, stage) => {
    assert.equal(stage, 'revoke-policy'); f.state.ledger++; f.state.installed = false;
    const { xdr } = await import('@stellar/stellar-sdk');
    return { hash: '5'.repeat(64), ledger: f.state.ledger, trust: 'rpc_reported', returnValue: xdr.ScVal.scvVoid(),
      events: [removedEvent(f.f.wallet.contractId, 2)] };
  };
  await removeGrant(f);
  await assert.rejects(f.actions['prepare-replacement']({ installationId: history[0].installationId }), /refused/);
  const latest = await f.actions['prepare-replacement']({ installationId: result.installation.installationId });
  assert.equal(latest.display.previousRuleId, 2);
});

for (const failure of ['ambiguous', 'confirmed unverified']) test(`replacement remains closed after ${failure} installation, even after any known rule is removed`, async () => {
  const f = await installable(); await verified(f);
  const assembly = await f.actions.assemble({ reviewId: f.review.reviewId });
  const submit = f.network.submitEnvelope;
  f.network.submitEnvelope = async (...args) => {
    if (failure === 'ambiguous') throw new Error('unknown submission outcome');
    const result = await submit(...args);
    // Keep the real event/rule ID, but break verification of the returned rule.
    const { xdr } = await import('@stellar/stellar-sdk');
    return { ...result, returnValue: xdr.ScVal.scvVoid() };
  };
  await assert.rejects(f.actions.submit({ id: assembly.action.id, signedAuthEntriesXdr: await signInstall(f, assembly) }));
  f.network.submitEnvelope = submit;
  const status = await f.actions.status({});
  if (failure === 'confirmed unverified') {
    assert.equal(status.installations[0].status, 'confirmed_unverified');
    f.installation = status.installations[0];
    await removeGrant(f);
  } else assert.equal(status.installations.length, 0);
  assert.equal((await f.actions.status({})).capabilities.replacement, false);
  await assert.rejects(f.actions['prepare-replacement']({ installationId: f.installation?.installationId ?? 'a'.repeat(64) }), /refused/);
});
for (const stage of ['prepare', 'confirm']) for (const change of ['owner behind anchor', 'owner beyond window', 'absence beyond window']) {
  test(`replacement ${stage} rejects ${change} with otherwise unchanged authority`, async () => {
    const f = await removed();
    const p = stage === 'confirm' ? await f.actions['prepare-replacement']({ installationId: f.installation.installationId }) : null;
    if (change === 'owner behind anchor') f.ownerLedgerOffset = -1;
    if (change === 'owner beyond window') f.ownerLedgerOffset = 13;
    if (change === 'absence beyond window') f.readback = () => ({ status: 'absent', ledger: f.state.ledger + 13 });
    await assert.rejects(p
      ? f.actions['confirm-replacement']({ id: p.action.id, consent: 'previously_used_authority_plus_new_cap' })
      : f.actions['prepare-replacement']({ installationId: f.installation.installationId }), /refused/);
    assert.equal((await f.actions.status({})).capabilities.install, false);
  });
}

for (const field of ['attempts', 'display']) test(`confirmation rechecks retained replacement ${field}`, async () => {
  const f = await removed();
  const issue = f.session.issue.bind(f.session);
  // Inject stale trusted-session data to exercise the independent confirmation guard.
  f.session.issue = (kind, value) => issue(kind, kind !== 'replacement' ? value : {
    ...value, ...(field === 'attempts' ? { attempts: value.attempts - 1 }
      : { display: { ...value.display, previousRuleId: 999 } }) });
  const p = await f.actions['prepare-replacement']({ installationId: f.installation.installationId });
  await assert.rejects(f.actions['confirm-replacement']({ id: p.action.id, consent: 'previously_used_authority_plus_new_cap' }), /refused/);
  assert.equal((await f.actions.status({})).capabilities.install, false);
});
