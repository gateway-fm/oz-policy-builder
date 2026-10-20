// Validate the real recording and every synthesized protocol capability before building/installing.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Address, Networks, scValToNative } from '@stellar/stellar-sdk';
import { PINNED_ACCOUNT_WASM } from './rpc.mjs';
import { PROTOCOL_TARGETS, protocolInvocation } from './protocol-calls.mjs';
const NETWORK_ID = createHash('sha256').update(Networks.TESTNET).digest('hex');
const TEMPLATE = 'policy-templates/scope@1';
const SCHEMA = '15fbc6fa21090cba820dc97afbf9a0b2f4402016646dae87a2ec8a3839d17e61';
const same = (a, b, name) => assert.deepEqual(a, b, `unexpected protocol ${name}`);
const requireThat = (condition, name) => { if (!condition) throw new Error(`invalid protocol ${name}`); };
const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const ledger = (value) => Number.isInteger(value) && value > 0 && value <= 0xffff_ffff;
const addressOf = (value) => Address.fromScAddress(value).toString();
function summary(value) {
  if (value.type === 'scvAddress') return { address: scValToNative(value) };
  if (value.type === 'scvI128') return { i128: scValToNative(value).toString() };
  if (value.type === 'scvU64') return { u64: Number(scValToNative(value)) };
  return { other: { xdr_base64: Buffer.from(value.toXDR()).toString('base64') } };
}
function normalized(node) {
  const call = node?.call?.contract;
  requireThat(call && Array.isArray(call.args) && Array.isArray(node.sub_invocations), 'recorded tree');
  return { call: { contract: { ...call, args: call.args.map((arg) => {
    if (arg?.i128 === undefined) return arg;
    requireThat(Object.keys(arg).length === 1 && (typeof arg.i128 === 'bigint' || typeof arg.i128 === 'string'
      || Number.isSafeInteger(arg.i128)) && /^-?(0|[1-9][0-9]*)$/.test(String(arg.i128)), 'recorded i128');
    return { i128: String(arg.i128) };
  }) } }, sub_invocations: node.sub_invocations.map(normalized) };
}
function tree(root) {
  const call = root.function.contractFn;
  return { call: { contract: { contract: addressOf(call.contractAddress), fn_name: call.functionName.toString(),
    args: call.args.map(summary) } }, sub_invocations: root.subInvocations.map(tree) };
}

/**
 * Sort calls into the CLI's rule order (by contract address) and require the root invocation
 * to come first. Signatures list rule IDs in authorization-context order, root first; any
 * other rule order would misattribute every per-rule control.
 */
export function orderRootFirst(calls) {
  calls.sort((a, b) => a.contract < b.contract ? -1 : a.contract > b.contract ? 1 : 0);
  requireThat(calls.length >= 1 && !calls[0].path.includes('/sub['), 'root invocation rule order');
  return calls;
}

export function protocolInputs(run, recording) {
  same(run.network, Networks.TESTNET, 'network');
  same(run.account_code_hash, PINNED_ACCOUNT_WASM, 'account pin');
  same(run.walkthrough?.account, run.account, 'plan account');
  const plan = run.walkthrough;
  const horizon = plan.grant_duration_ledgers ?? 1000;
  requireThat(Number.isInteger(horizon) && horizon >= 30 && horizon <= 1000, 'grant horizon');
  const root = protocolInvocation(plan);
  const bundle = recording.bundle;
  same(bundle?.network_id, NETWORK_ID, 'recording network');
  same(bundle.execution, 'executed_success', 'recording execution');
  same(recording.trust, 'rpc_reported', 'acquisition trust');
  requireThat(hash(recording.recording_hash) && ledger(bundle.ledger) && bundle.ledger <= 0xffff_ffff - 1000, 'recording identity/ledger');
  const selected = bundle.authorizations?.map((auth, index) => ({ auth, index })).filter(({ auth }) => auth.authorizer === run.account);
  requireThat(selected?.length === 1, 'selected authorization count');
  same(normalized(selected[0].auth.root), tree(root), 'entire invocation tree');
  const observe = (contract, code) => {
    const seen = bundle.contract_executables?.[contract];
    requireThat(ledger(seen?.observed_ledger) && seen.observed_ledger >= bundle.ledger, 'executable observation ledger');
    same(seen.executable, code ? { wasm: { code_hash: code } } : 'stellar_asset', 'observed executable');
    return seen;
  };
  observe(run.account, run.account_code_hash);
  const calls = [];
  function walk(node, path) {
    const c = node.function.contractFn;
    const contract = addressOf(c.contractAddress);
    const code = contract === PROTOCOL_TARGETS.blend_pool ? PROTOCOL_TARGETS.blend_code
      : contract === PROTOCOL_TARGETS.router ? PROTOCOL_TARGETS.router_code : null;
    calls.push({ contract, fn: c.functionName.toString(), args: c.args, path, code, observation: observe(contract, code) });
    node.subInvocations.forEach((child, i) => walk(child, `${path}/sub[${i}]`));
  }
  walk(root, `recordings[0]/auth[${selected[0].index}]`);
  orderRootFirst(calls);
  const widen = (contract, fn_name, arg_index, bound, intent) => ({ contract, fn_name, arg_index, bound, intent, blast_radius: 'medium' });
  const widenings = plan.kind === 'soroswap_swap' ? [
    widen(PROTOCOL_TARGETS.router, 'swap_exact_tokens_for_tokens', 0, { le_i128: { max: plan.amount_in } }, 'Bound this swap input at the recorded amount'),
    widen(PROTOCOL_TARGETS.router, 'swap_exact_tokens_for_tokens', 1, { ge_i128: { min: plan.minimum_out } }, 'Use the explicitly selected absolute output floor'),
    widen(PROTOCOL_TARGETS.native, 'transfer', 2, { le_i128: { max: plan.amount_in } }, 'Permit the bounded token transfer to the exact pair as an independent capability'),
  ] : [];
  return { calls, account: { address: run.account, observed_code_hash: run.account_code_hash,
    registry_resolution: 'resolved by the toolkit from the signed snapshot' }, decisions: {
    grant_name: plan.kind === 'blend_claim' ? 'blend-claim' : 'soroswap-swap', delegate_signers: [{ delegated: { address: run.delegate } }],
    predicate: 'any_of', valid_until_ledger: bundle.ledger + horizon, no_expiry_acknowledged: false, max_calls: 1,
    widenings, spending_limit: null,
  } };
}

export function validateProtocolSynthesis(output, run, inputs, registryRoot) {
  requireThat(hash(output.spec_hash), 'canonical spec hash');
  if (output.questions !== undefined) same(output.questions, [], 'unanswered questions');
  const spec = output.spec;
  same(spec?.schema, 'policy-spec/v1', 'schema');
  same(spec.name, inputs.decisions.grant_name, 'grant name');
  same(spec.network_id, NETWORK_ID, 'spec network');
  same(spec.smart_account?.address, run.account, 'spec account');
  same(spec.smart_account?.observed_code_hash, run.account_code_hash, 'spec account code');
  requireThat(hash(registryRoot), 'configured registry root');
  same(spec.registry_snapshot, registryRoot, 'registry root');
  same(spec.rules?.length, inputs.calls.length, 'complete rule count');
  inputs.calls.forEach((call, index) => {
    const rule = spec.rules[index];
    same(rule.context, { type: 'CallContract', contract: call.contract, target_code_hash: call.code ? {
      hash: call.code, observed_ledger: call.observation.observed_ledger, role: 'evidence_only', on_drift: 'warn',
    } : null }, 'rule target and code observation');
    same(rule.valid_until, { ledger: inputs.decisions.valid_until_ledger, approx_time: null }, 'bounded expiry');
    same(rule.authorization, { kind: 'any_of', strict_signer_set: true, signers: inputs.decisions.delegate_signers }, 'signers');
    const args = call.args.map((value, i) => {
      const w = inputs.decisions.widenings.find((w) => w.contract === call.contract && w.fn_name === call.fn && w.arg_index === i);
      if (w) return { i, c: w.bound, prov: { user_widened: { intent: w.intent, blast_radius: w.blast_radius } } };
      const c = value.type === 'scvAddress' ? { eq_address: { value: scValToNative(value) === run.account ? 'SELF' : scValToNative(value) } }
        : value.type === 'scvI128' ? { eq_i128: { value: scValToNative(value).toString() } }
          : { eq_scval: { xdr_base64: Buffer.from(value.toXDR()).toString('base64') } };
      return { i, c, prov: 'observed_exact' };
    });
    same(rule.allowed_calls, [{ fn: call.fn, args, justified_by: [call.path] }], 'allowed tuple');
    same(rule.state, [{ call_count_per_installation: { max_calls: 1 } }], 'per-capability call count');
    same(rule.policies, [{ generated: { kind: 'gen:scope+count', template_family: TEMPLATE, capability_schema: SCHEMA } }], 'generated capability');
  });
  requireThat(spec.evidence?.recordings?.length === 1 && hash(spec.evidence.recordings[0].hash), 'synthesis recording identity');
  same(spec.evidence.recordings[0].trust, 'self_supplied', 'synthesis trust');
  return spec;
}
