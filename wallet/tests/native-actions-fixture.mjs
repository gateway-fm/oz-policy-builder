import assert from 'node:assert/strict';
import { Account, Keypair } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID } from '../shared/approval.mjs';
import { captureHash, targetEnvelopeXdr } from '../server/captured-execution.mjs';
import { deploymentFixture } from './actions-fixture.mjs';
import { CASE_IDS, RECIPIENT, captureFixture, capturedFrames, capturedSignRequest } from './captured-execution-fixture.mjs';
import { nativeFixture, signRequest } from './native-execution-fixture.mjs';

export const LEDGER = { protocol_version: 29, sequence: 1000, timestamp: '1760000000', base_reserve: 5000000,
  min_temp_entry_ttl: 720, min_persistent_entry_ttl: 120960, max_entry_ttl: 3110400 };
export const CAPTURE_LEDGER = 5294840;
const clone = (value) => structuredClone(value);
const transfer = () => ({ fn: 'transfer', args: [
  { i: 0, c: { eq_address: { value: 'SELF' } }, prov: 'observed_exact' },
  { i: 1, c: { eq_address: { value: RECIPIENT } }, prov: 'observed_exact' },
  { i: 2, c: { eq_i128: { value: '1000000' } }, prov: 'observed_exact' }], justified_by: ['recordings[0]/auth[0]/root'] });

/**
 * A deployed, reviewed native-transfer grant whose delegate is a backend-created capability.
 * The CLI preparation, capture and worker are faked unless `native` names a real executable.
 */
export async function reviewed({ maxCalls = 2, runFails = false, intentChange = () => {}, prepareFails = false, sourceFails = false,
  allowedCalls = [transfer()], captureChange = () => {}, capturedChange = () => {}, capturedPreparedChange = () => {},
  captureFails = false, envelopeFails = false, capturedRunFails = false, notBefore = CAPTURE_LEDGER - 2, native: realNative } = {}) {
  const runs = [];
  const prepares = [];
  const captures = [];
  let frames, captured, capture;
  const native = realNative ?? { executable: '/fixed/ozpb-execution-runtime', run: async (executable, jobText, options) => {
    runs.push({ executable, jobText, prepareOnly: options.prepareOnly === true, captured: options.captured === true });
    if (options.captured) {
      if (capturedRunFails) throw new Error('native process refused; no execution evidence accepted');
      const prepared = clone(captured.prepared);
      capturedPreparedChange(prepared);
      options.validatePrepared(prepared);
      if (options.prepareOnly) return prepared;
      for (const [caseId, requestId, nonce] of [[CASE_IDS[0], '1', 1001n], [CASE_IDS[1], '2', 1002n]]) {
        const request = capturedSignRequest(captured.prepared, { caseId, requestId, nonce });
        const answer = options.sign(request);
        assert.ok(Keypair.fromPublicKey(captured.prepared.binding.delegate_address).verify(
          Buffer.from(request.digest_hex, 'hex'), Buffer.from(answer.signature_hex, 'hex')));
      }
      const result = clone(captured.result);
      capturedChange(result);
      return options.validateResult(result);
    }
    if (runFails) throw new Error('native process refused; no execution evidence accepted');
    options.validatePrepared(structuredClone(frames.prepared));
    if (options.prepareOnly) return structuredClone(frames.prepared);
    const answer = options.sign(signRequest(frames.prepared));
    assert.ok(Keypair.fromPublicKey(frames.prepared.binding.delegate_address).verify(
      Buffer.from(signRequest(frames.prepared).digest_hex, 'hex'), Buffer.from(answer.signature_hex, 'hex')));
    return options.validateResult(structuredClone(frames.result));
  } };
  const f = deploymentFixture(() => {}, { native });
  const delegate = await f.actions['create-delegate']({});
  f.artifact.spec.rules[0].authorization = { signers: [{ delegated: { address: delegate.address } }] };
  f.artifact.spec.rules[0].state = [{ call_count_per_installation: { max_calls: maxCalls } }];
  if (allowedCalls) f.artifact.spec.rules[0].allowed_calls = allowedCalls;
  const preview = await f.actions['prepare-deploy']({ artifactId: f.artifactId });
  const deployed = await f.actions['confirm-deploy']({ id: preview.action.id });
  intentChange(f.f.intent.authority.verdict.evidence);
  const review = await f.actions.review({ deploymentId: deployed.deploymentId, wallet: f.f.wallet });
  frames = nativeFixture({ maxCalls, accountAddress: f.f.wallet.contractId, delegateAddress: delegate.address,
    policyAddress: f.policy, policyCodeHash: f.artifact.wasmHash, candidateContextRuleId: 1 });
  capture = captureFixture({ account: f.f.wallet.contractId, observedLedger: CAPTURE_LEDGER });
  captureChange(capture, { account: f.f.wallet.contractId });
  captured = capturedFrames({ capture, captureHash: captureHash(capture), account: f.f.wallet.contractId, delegate: delegate.address,
    policyAddress: f.policy, policyCodeHash: f.artifact.wasmHash, candidateContextRuleId: 1, maxCalls,
    runHash: frames.expected.runHash });
  f.toolchain.prepareDryRun = async (input) => {
    prepares.push(input);
    if (prepareFails) throw new Error('wallet pipeline refused; refresh and review again');
    return { request: { candidate: input.candidate, run_nonce: 'e'.repeat(64) }, output: {
      schema: 'ozpb:dry-run:v1', run_hash: frames.expected.runHash, binding: { spec_hash: f.artifact.specHash,
        binding_set_hash: f.f.expected.bindingSetHash, registry_snapshot_root: 'c'.repeat(64), account_address: f.f.wallet.contractId,
        account_code_hash: ACCOUNT_WASM, network_id: NETWORK_ID, rule_index: 0, candidate_context_rule_id: input.candidateContextRuleId,
        suite_hash: frames.expected.suiteHash, policy_code_hashes: { [f.policy]: f.artifact.wasmHash } },
      artifact_verification: { matches: true }, reference_report: { total: 3, disagreements: 0,
        outcomes: frames.reference.outcomes, expected_classes: { 0: frames.reference.requiredClasses } },
      layers: [{ id: 'reference', status: 'passed', cases: 3 }, { id: 'account_wasm', status: 'unavailable' },
        { id: 'captured_target', status: 'unavailable' }, { id: 'live_enforcement', status: 'unavailable' }],
      complete: false, disclaimer: 'x' } };
  };
  f.network.nativeSource = async (hash) => { assert.equal(hash, ACCOUNT_WASM);
    if (sourceFails) throw new Error('wallet network operation refused; inspect the local journal before retrying');
    return { ledger: LEDGER, accountWasmBase64: 'AGFzbQEAAAA=' }; };
  const envelopes = [];
  f.network.latestLedger = async () => notBefore;
  f.network.targetEnvelope = async (call) => {
    if (envelopeFails) throw new Error('wallet network operation refused; inspect the local journal before retrying');
    // A real unsigned envelope from a throwaway source, so a test can search every output for it.
    envelopes.push(targetEnvelopeXdr(new Account(Keypair.random().publicKey(), '41'), call));
    return envelopes.at(-1);
  };
  f.toolchain.captureTarget = async (envelope, options) => {
    captures.push({ envelope, signal: options?.signal });
    assert.equal(envelope, envelopes.at(-1), 'the capture receives exactly the envelope the backend built');
    if (captureFails) throw new Error('wallet pipeline refused; refresh and review again');
    return clone(capture);
  };
  return { ...f, delegate, deployed, review, runs, prepares, captures, envelopes, native, capture, captured };
}
