import { createECDH, randomBytes } from 'node:crypto';
import { Address, Asset, Networks, Operation, StrKey, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM, freezeCopy, ownerRule, reviewIntent } from '../shared/approval.mjs';
import { decodeBase64Url } from '../shared/base64url.mjs';
import { MAX_FEE_STROOPS, MAX_UPLOAD_FEE_STROOPS } from './network.mjs';
import { reviewSample, validateSampleAssembly } from '../shared/sample.mjs';
import { validateSignedAuthorization } from '../shared/signature.mjs';
import { DelegateCapabilities, NATIVE_LIMITS, checkDryRunPreparation, nativeJobText, runAccountExecution } from './native-execution.mjs';
import { FRESHNESS_LEDGERS, capturedCall, capturedJobText, checkTargetCapture, runCapturedExecution } from './captured-execution.mjs';

const refuse = () => { throw new Error('wallet action refused; refresh and review again'); };
const HASH = /^[a-f0-9]{64}$/;
const id = () => randomBytes(32).toString('hex');
const get = (map, key) => { if (typeof key !== 'string' || !HASH.test(key) || !map.has(key)) refuse(); return map.get(key); };
const exact = (value, names) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== names.length || names.some((name) => !Object.hasOwn(value, name))) refuse();
};
const receipt = ({ hash, ledger, trust }) => ({ hash, ledger, trust });
function credential(value) {
  if (typeof value.publicKey !== 'string' || !/^04[a-f0-9]{128}$/.test(value.publicKey)) refuse();
  const publicKey = Buffer.from(value.publicKey, 'hex');
  const verifier = createECDH('prime256v1');
  try { verifier.setPublicKey(publicKey); } catch { refuse(); }
  return Buffer.concat([publicKey, decodeBase64Url(value.credentialId)]);
}
function walletIdentity(value) {
  exact(value, ['contractId', 'credentialId', 'publicKey', 'verifier']);
  if (!StrKey.isValidContract(value.contractId) || !StrKey.isValidContract(value.verifier) || value.contractId === value.verifier) refuse();
  credential(value);
  return freezeCopy(value);
}
function freshOwner(value, signer) {
  const fields = value?.type === 'scvMap' ? value.map : [];
  const names = ['context_type', 'id', 'name', 'policies', 'policy_ids', 'signer_ids', 'signers', 'valid_until'];
  if (fields.length !== names.length || fields.some((entry, index) => entry.key.type !== 'scvSymbol'
    || entry.key.sym.toString() !== names[index])) refuse();
  const native = Object.fromEntries(fields.map((entry) => [entry.key.sym.toString(), entry.val]));
  const equal = (a, b) => a.toXDR('base64') === b.toXDR('base64');
  if (native.id.type !== 'scvU32' || native.id.u32 !== 0 || native.name.type !== 'scvString'
    || !equal(native.context_type, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]))
    || !equal(native.policies, xdr.ScVal.scvVec([])) || !equal(native.signers, xdr.ScVal.scvVec([signer]))
    || !equal(native.policy_ids, xdr.ScVal.scvVec([]))
    || !equal(native.signer_ids, xdr.ScVal.scvVec([xdr.ScVal.scvU32(0)]))
    || native.valid_until.type !== 'scvVoid') refuse();
}
function missingVerification(artifact, bindingSetHash, accountLayer, targetLayer) {
  return freezeCopy({ runId: id(), specHash: artifact?.specHash ?? null, wasmHash: artifact?.wasmHash ?? null,
    bindingSetHash: bindingSetHash ?? null, complete: false, layers: [
      { layer: 'reference', status: artifact ? 'passed' : 'unavailable', detail: artifact
        ? 'Constraint-derived reference cases passed; artifact reproduced separately.' : 'No candidate prepared.' },
      accountLayer ?? { layer: 'account_wasm', status: 'unavailable', detail: 'Candidate account execution has not run.' },
      targetLayer ?? { layer: 'captured_target', status: 'unavailable', detail: 'Captured target execution has not run.' },
      { layer: 'live_enforcement', status: 'unavailable', detail: 'Wallet-authorized candidate behavioral preflight has not run.' },
    ] });
}
const accountLayer = (status, detail) => ({ layer: 'account_wasm', status, detail });
const targetLayer = (status, detail) => ({ layer: 'captured_target', status, detail });

/** Closed HTTP operations. Every privileged input comes from retained state or operator configuration. */
export function createWalletActions({ session, toolchain, network, native = null }) {
  const deployments = new Map();
  const attemptedArtifacts = new Set();
  const reviews = new Map();
  const delegates = new DelegateCapabilities();
  let accountCheckRunning = false;
  let accountAttempted = false;
  let sampleAccount = null;
  let sampleSubmitted = false;
  async function sampleOwner() {
    await network.assertTestnet();
    const account = await network.requireInstance(sampleAccount.wallet.contractId, ACCOUNT_WASM);
    const verifier = await network.requireInstance(sampleAccount.wallet.verifier, WEBAUTHN_WASM);
    const observed = await network.view(sampleAccount.wallet.contractId, 'get_context_rule', [xdr.ScVal.scvU32(0)]);
    if (observed.ledger < account.ledger || observed.ledger < verifier.ledger
      || observed.ledger - account.ledger > 12 || observed.ledger - verifier.ledger > 12) refuse();
    const ownerRuleXdr = observed.value.toXDR('base64');
    const approval = reviewSample({ ...sampleAccount, ownerRuleXdr });
    return { ownerRuleXdr, approval, ownerReadLedger: observed.ledger };
  }
  return {
    status: async (input) => {
      exact(input, []);
      return { networkId: NETWORK_ID, network: 'testnet', accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM,
        maxFeeStroops: MAX_FEE_STROOPS, maxUploadFeeStroops: MAX_UPLOAD_FEE_STROOPS, maxValidityLedgers: 120,
        capabilities: { record: true, generate: true, deploy: true, sampleTransfer: true, accountCheck: native !== null,
          install: false, lifecycle: false },
        verification: missingVerification() };
    },
    'prepare-account': async (input) => {
      exact(input, ['credentialId', 'publicKey']);
      credential(input);
      if (accountAttempted) refuse();
      const summary = { credentialId: input.credentialId, publicKey: input.publicKey, accountWasm: ACCOUNT_WASM,
        verifierWasm: WEBAUTHN_WASM, sampleFundingStroops: '10000000', maxFeeStroops: MAX_FEE_STROOPS,
        maxTotalFeeStroops: 3 * MAX_FEE_STROOPS };
      return { action: session.issue('create_account', input), summary };
    },
    'confirm-account': async (input) => {
      exact(input, ['id']);
      return session.consume(input.id, 'create_account', async (selected) => {
        if (accountAttempted) refuse();
        accountAttempted = true;
        await network.assertTestnet();
        await network.requireCode(ACCOUNT_WASM);
        await network.requireCode(WEBAUTHN_WASM);
        await network.fundPayer();
        const verifier = await network.create(WEBAUTHN_WASM, [], 'deploy-verifier');
        const signer = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'), new Address(verifier.contractId).toScVal(),
          xdr.ScVal.scvBytes(credential(selected))]);
        const account = await network.create(ACCOUNT_WASM, [xdr.ScVal.scvVec([signer]), xdr.ScVal.scvMap([])], 'deploy-account');
        const observed = await network.view(account.contractId, 'get_context_rule', [xdr.ScVal.scvU32(0)]);
        if (observed.ledger < account.receipt.ledger || observed.ledger - account.receipt.ledger > 12) refuse();
        freshOwner(observed.value, signer);
        const funded = await network.submitOperation(Operation.invokeContractFunction({
          contract: Asset.native().contractId(Networks.TESTNET), function: 'transfer', args: [
            new Address(network.payerAddress).toScVal(), new Address(account.contractId).toScVal(),
            xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 10_000_000n })),
          ],
        }), 'fund-account');
        const wallet = walletIdentity({ contractId: account.contractId, verifier: verifier.contractId, ...selected });
        const descriptor = freezeCopy({ recipient: network.payerAddress, amountStroops: '1000000',
          ownerRuleXdr: observed.value.toXDR('base64') });
        reviewSample({ wallet, descriptor, ownerRuleXdr: descriptor.ownerRuleXdr });
        sampleAccount = { wallet, descriptor };
        return { wallet, sample: descriptor,
          receipts: [verifier.receipt, account.receipt, funded].map(receipt) };
      });
    },
    record: async (input) => {
      exact(input, ['transactionHash', 'wallet']);
      const wallet = walletIdentity(input.wallet);
      if (!HASH.test(input.transactionHash)) refuse();
      await network.assertTestnet();
      await network.requireInstance(wallet.contractId, ACCOUNT_WASM);
      await network.requireInstance(wallet.verifier, WEBAUTHN_WASM);
      return toolchain.record({ transactionHash: input.transactionHash, accountAddress: wallet.contractId });
    },
    'prepare-sample': async (input) => {
      exact(input, ['wallet']);
      const wallet = walletIdentity(input.wallet);
      if (!sampleAccount || sampleSubmitted
        || ['contractId', 'credentialId', 'publicKey', 'verifier'].some((key) => wallet[key] !== sampleAccount.wallet[key])) refuse();
      session.invalidate('sample');
      const observed = await sampleOwner();
      const prepared = await network.prepareSample({ ...sampleAccount, ...observed });
      validateSampleAssembly({ ...prepared, ...observed });
      return { ...prepared, ownerRuleXdr: observed.ownerRuleXdr,
        action: session.issue('sample', { ...prepared, approval: observed.approval, ownerRuleXdr: observed.ownerRuleXdr }) };
    },
    'submit-sample': async (input) => {
      exact(input, ['id', 'signedAuthEntriesXdr']);
      return session.consume(input.id, 'sample', async (prepared) => {
        if (!sampleAccount || sampleSubmitted) refuse();
        const observed = await sampleOwner();
        if (observed.approval.commitment !== prepared.approval.commitment) refuse();
        const source = await network.sourceCapture();
        const currentLedger = await network.latestLedger();
        if (source.ledger < observed.ownerReadLedger || currentLedger < source.ledger
          || currentLedger - observed.ownerReadLedger > 12 || currentLedger - source.ledger > 12) refuse();
        // Preserve the preview read order and its original freshness window. A fresh
        // owner read additionally checks that this exact credential still owns the account.
        const limits = { ...prepared.limits, sourceSequence: source.sourceSequence, currentLedger };
        const checked = validateSampleAssembly({ ...prepared, ...observed, limits });
        const signed = await validateSignedAuthorization({ approval: observed.approval, checked,
          signedAuthEntriesXdr: input.signedAuthEntriesXdr, origin: 'http://localhost:3000' });
        sampleSubmitted = true;
        session.invalidate('sample');
        const submitted = await network.submitEnvelope(signed.envelopeXdr, 'sample-transfer');
        if (submitted.returnValue.type !== 'scvVoid') refuse();
        return { transactionHash: submitted.hash, receipt: receipt(submitted) };
      });
    },
    generate: async (input) => {
      exact(input, ['recordId', 'delegateAddress', 'validUntilLedger', 'maxCalls', 'grantName']);
      return toolchain.generate({ ...input, currentLedger: await network.latestLedger() });
    },
    'prepare-deploy': async (input) => {
      exact(input, ['artifactId']);
      const { response: artifact } = toolchain.artifact(input.artifactId);
      if (attemptedArtifacts.has(input.artifactId) || attemptedArtifacts.size >= 8) refuse();
      return { action: session.issue('deploy', { artifactId: input.artifactId }), summary: {
        specHash: artifact.specHash, wasmHash: artifact.wasmHash, maxFeeStroops: MAX_FEE_STROOPS,
        maxUploadFeeStroops: MAX_UPLOAD_FEE_STROOPS, maxTotalFeeStroops: MAX_UPLOAD_FEE_STROOPS + MAX_FEE_STROOPS,
      } };
    },
    'confirm-deploy': async (input) => {
      exact(input, ['id']);
      return session.consume(input.id, 'deploy', async ({ artifactId }) => {
        if (attemptedArtifacts.has(artifactId)) refuse();
        attemptedArtifacts.add(artifactId);
        const held = toolchain.artifact(artifactId);
        const artifact = held.response;
        await network.fundPayer();
        const upload = await network.upload(Buffer.from(held.wasmBase64, 'base64'), artifact.wasmHash);
        const deployed = await network.create(artifact.wasmHash, [], 'deploy-policy');
        const deploymentId = id();
        const request = toolchain.bindingRequest(artifactId, deployed.contractId, `wallet-deployment:${deployed.receipt.hash}`);
        const checked = await toolchain.authority('check-policy-call-surface', request);
        if (!HASH.test(checked.binding_set_hash) || checked.spec_hash !== artifact.specHash) refuse();
        const response = freezeCopy({ deploymentId, policyAddress: deployed.contractId, wasmHash: artifact.wasmHash,
          bindingSet: request.binding_set, bindingSetHash: checked.binding_set_hash,
          receipts: [upload, deployed.receipt].map(receipt) });
        deployments.set(deploymentId, { artifactId, request, response });
        return response;
      });
    },
    review: async (input) => {
      exact(input, ['deploymentId', 'wallet']);
      if (reviews.size >= 8) refuse();
      const wallet = walletIdentity(input.wallet);
      const deployment = get(deployments, input.deploymentId);
      const { response: artifact } = toolchain.artifact(deployment.artifactId);
      if (artifact.spec.smart_account.address !== wallet.contractId) refuse();
      const intent = await toolchain.authority('prepare-install-intent', deployment.request);
      const expected = { account: wallet.contractId, target: artifact.spec.rules[0].context.contract,
        networkId: NETWORK_ID, specHash: artifact.specHash, bindingSetHash: deployment.response.bindingSetHash,
        registrySnapshotRoot: artifact.spec.registry_snapshot, boundPolicies: [deployment.response.policyAddress], ruleIndex: 0 };
      const choices = intent.authority.verdict.authority_list.filter((entry) =>
        entry.requirement?.kind === 'all_of' && entry.requirement.signers?.length === 1
        && entry.requirement.signers[0].public_key === wallet.publicKey && entry.requirement.signers[0].verifier === wallet.verifier);
      if (!choices.length || choices.length > 32) refuse();
      let ownerRuleXdr;
      for (const choice of choices) {
        const observed = await network.view(wallet.contractId, 'get_context_rule', [xdr.ScVal.scvU32(choice.rule_id)]);
        if (observed.ledger < intent.authority.verdict.observed_ledger || observed.ledger - intent.authority.verdict.observed_ledger > 12) refuse();
        const raw = observed.value.toXDR('base64');
        try { ownerRule(intent, wallet, raw); ownerRuleXdr = raw; break; } catch { /* another full credential may share the public key */ }
      }
      if (!ownerRuleXdr) refuse();
      const approval = reviewIntent({ intent, expected, wallet, ownerRuleXdr });
      const reviewId = id();
      const verification = missingVerification(artifact, deployment.response.bindingSetHash);
      // The proposed chain ID for local execution; a later installation must read NextId again.
      const enumeration = intent.authority.verdict.evidence?.enumeration_evidence;
      const nextRuleId = enumeration?.method === 'bounded_next_id' && Number.isSafeInteger(enumeration.next_id)
        && enumeration.next_id >= 0 && enumeration.next_id <= 0xffffffff ? enumeration.next_id : null;
      reviews.set(reviewId, { approval, deploymentId: input.deploymentId, verification, nextRuleId });
      return freezeCopy({ reviewId, intent, expected, wallet, ownerRuleXdr, verification });
    },
    // A local automation delegate: the key stays in this process; it never becomes an owner signer.
    'create-delegate': async (input) => {
      exact(input, []);
      if (!native) refuse();
      return delegates.create();
    },
    // Both local execution layers for one reviewed grant, from one CLI preparation (one run hash).
    // `signal` aborts when the HTTP client disconnects: every child process group is killed and
    // nothing is recorded, so the backend's locks are released without accepting partial evidence.
    'check-account': async (input, { signal } = {}) => {
      exact(input, ['reviewId', 'capabilityId']);
      if (!native || accountCheckRunning) refuse();
      const review = get(reviews, input.reviewId);
      const deployment = get(deployments, review.deploymentId);
      const { response: artifact } = toolchain.artifact(deployment.artifactId);
      const rule = artifact.spec.rules[0];
      const signers = rule.authorization?.signers;
      const delegate = signers?.length === 1 ? signers[0].delegated?.address : undefined;
      const signer = delegates.signer(input.capabilityId, delegate);
      const maxCalls = rule.state?.[0]?.call_count_per_installation?.max_calls;
      const target = capturedCall(artifact.spec);
      let layer, captured;
      // An unsupported shape is reported as such whatever else happens to this check.
      if (!target) {
        captured = targetLayer('unsupported', 'Captured execution supports one exact-amount native XLM transfer from the account '
          + 'to a G account; nothing was captured and the worker did not run.');
      }
      if (!Number.isSafeInteger(maxCalls) || maxCalls < 1 || maxCalls > NATIVE_LIMITS.maxCalls) {
        layer = accountLayer('unsupported', `The native worker supports call caps up to ${NATIVE_LIMITS.maxCalls}; it did not run.`);
        captured ??= targetLayer('unsupported', `The native worker supports call caps up to ${NATIVE_LIMITS.maxCalls}; it did not run.`);
      } else if (review.nextRuleId === null) {
        layer = accountLayer('unavailable', 'The reviewed authority evidence did not establish the next context rule ID.');
        captured ??= targetLayer('unavailable', 'The reviewed authority evidence did not establish the next context rule ID.');
      } else {
        accountCheckRunning = true;
        const stopped = () => { if (signal?.aborted) refuse(); };
        try {
          let prepared, source, checked;
          try {
            prepared = await toolchain.prepareDryRun({ artifactId: deployment.artifactId,
              candidate: deployment.request, candidateContextRuleId: review.nextRuleId, signal });
            source = await network.nativeSource(ACCOUNT_WASM);
          } catch {
            // Infrastructure, not the candidate: the CLI preparation or operator RPC read did not complete.
            layer = accountLayer('unavailable', 'CLI preparation or the operator RPC ledger read did not complete; the worker did not run.');
            captured ??= targetLayer('unavailable', 'CLI preparation or the operator RPC ledger read did not complete; the worker did not run.');
          }
          if (!layer) {
            try {
              checked = checkDryRunPreparation(prepared.output, { specHash: artifact.specHash,
                bindingSetHash: deployment.response.bindingSetHash, accountAddress: artifact.spec.smart_account.address,
                delegateAddress: delegate, policyAddress: deployment.response.policyAddress, policyCodeHash: artifact.wasmHash,
                candidateContextRuleId: review.nextRuleId, sourceLedger: source.ledger.sequence });
            } catch {
              layer = accountLayer('failed', 'Preparation evidence, the native worker or its report was refused; no evidence accepted.');
              captured ??= targetLayer('failed', 'The CLI preparation evidence was refused; the worker did not run.');
            }
          }
          if (!layer) {
            try {
              layer = await runAccountExecution({ executable: native.executable, run: native.run, signer, maxCalls, signal,
                jobText: nativeJobText(prepared.request, source.accountWasmBase64, source.ledger), ...checked });
            } catch {
              layer = accountLayer('failed', 'Preparation evidence, the native worker or its report was refused; no evidence accepted.');
            }
          }
          stopped();
          let capture;
          if (!captured) {
            try {
              const envelope = await network.targetEnvelope(target.call);
              const notBefore = await network.latestLedger();
              capture = { notBefore, value: await toolchain.captureTarget(envelope, { signal }) };
            } catch {
              // Includes a simulation the target itself refused: the CLI reports that and an endpoint
              // failure alike, so the backend cannot attribute it to the candidate.
              captured = targetLayer('unavailable', 'capture-target or the operator RPC read did not complete; the worker did not run.');
            }
          }
          const observed = capture?.value?.observed_ledger;
          if (!captured && Number.isSafeInteger(observed)
            && (observed < capture.notBefore || observed - capture.notBefore > FRESHNESS_LEDGERS)) {
            // A lagging or slow endpoint: no current-state evidence was obtained, which says nothing about the candidate.
            captured = targetLayer('unavailable', 'The capture was not from the current ledger window; the worker did not run.');
          }
          if (!captured) {
            try {
              const checkedCapture = checkTargetCapture(capture.value, { call: target.call, accountAddress: target.accountAddress,
                recipient: target.recipient, notBefore: capture.notBefore });
              const validUntil = rule.valid_until?.ledger;
              // A call based on the capture lands at the next ledger or later, where such a grant no longer applies.
              if (Number.isSafeInteger(validUntil) && checkedCapture.observedLedger >= validUntil) {
                captured = targetLayer('unavailable', 'The grant expires at or before the captured ledger; the worker did not run.');
              } else {
                captured = await runCapturedExecution({ executable: native.executable, run: native.run, signer, maxCalls, signal,
                  jobText: capturedJobText(prepared.request, source.accountWasmBase64, checkedCapture),
                  expected: { runHash: checked.expected.runHash, accountAddress: target.accountAddress, delegateAddress: delegate,
                    policyAddress: deployment.response.policyAddress, policyCodeHash: artifact.wasmHash,
                    candidateContextRuleId: review.nextRuleId, observedLedger: checkedCapture.observedLedger,
                    captureHash: checkedCapture.captureHash, recipient: target.recipient, amount: target.amount } });
              }
            } catch {
              captured = targetLayer('failed', 'The capture, the native worker or its report was refused; no evidence accepted.');
            }
          }
          stopped();
        } finally { accountCheckRunning = false; }
      }
      const verification = missingVerification(artifact, deployment.response.bindingSetHash, layer, captured);
      reviews.set(input.reviewId, { ...review, verification });
      return freezeCopy({ reviewId: input.reviewId, verification });
    },
    // These handlers cannot be enabled by caller-supplied evidence. They will be
    // connected only to the actual wallet-owned execution and lifecycle backends.
    assemble: async () => { refuse(); },
    submit: async () => { refuse(); },
  };
}
