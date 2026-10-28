// The pure half of the derived-denial replay: which cases of a spec's emitted suite a live call
// can carry, how each is realized on the recorded call, and which enforcer should refuse it. No
// network, no keys, no clock. `derived-denials.mjs` runs it against the network after
// installation; `evidence.mjs` runs it again over the retained files, so an exported journal must
// be exactly what this plan says the run replayed.
import { createHash } from 'node:crypto';
import { Address, Asset, Networks, StrKey, nativeToScVal, scValToNative, xdr } from '@stellar/stellar-sdk';
import { contractCall, i128 } from './lib.mjs';
import { PROTOCOL_TARGETS, protocolInvocation } from './protocol-calls.mjs';

const NATIVE_SAC = Asset.native().contractId(Networks.TESTNET);

export const MIN_DERIVED_DENIALS = 5;
export const CASES_FORMAT = 'ozpb-reference-suite-cases/v1';
/** Classes whose mutation is in the call or the signer set, which a live delegate controls. */
export const LIVE_CLASSES = Object.freeze({
  arg_equality: 'argument', numeric_boundary: 'argument', different_address_arg: 'argument',
  different_function: 'function', different_contract: 'contract',
  zero_signers: 'signer', wrong_signer: 'signer', signer_boundary: 'signer',
});
/** Classes evaluated offline only (layer 1), and why the live network cannot carry them. */
export const OFFLINE_CLASSES = Object.freeze({
  time_boundary: 'ledger_time',
  call_count_boundary: 'installation_state', missing_state: 'installation_state', strict_set_mutation: 'installation_state',
  arg_arity: 'host_rejects_before_authorization', type_confusion: 'host_rejects_before_authorization',
});
export const OFFLINE_REASONS = Object.freeze(['ledger_time', 'installation_state', 'host_rejects_before_authorization',
  'authorizer_replaced', 'no_live_stand_in', 'signer_key_not_held', 'repeated_signer_unrepresentable']);
/**
 * The argument each pinned target function asks to authorize, read from its source: the SAC's and
 * Blend's `from.require_auth()`, Soroswap's `to.require_auth()`. An unlisted pair is refused.
 */
export const AUTHORIZER = Object.freeze({
  [`${NATIVE_SAC}:transfer`]: 0,
  [`${PROTOCOL_TARGETS.blend_pool}:claim`]: 0,
  [`${PROTOCOL_TARGETS.router}:swap_exact_tokens_for_tokens`]: 3,
});
export const REALIZATIONS = Object.freeze(['mutation_on_recorded_call', 'live_stand_in']);
export const SELECTION = 'every deny case of a live-realizable class that the recorded call can carry, in suite order';
export const STAND_INS = Object.freeze(['blend_pool_submit', 'w2_control_token']);

const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const A = (address) => new Address(address).toScVal();
const hex = (v) => Buffer.from(v.toXDR()).toString('hex');
const sameArg = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const addressOf = (call) => Address.fromScAddress(call.contractAddress).toString();

/** sha256 over the format line, the spec hash and the compact JSON of `cases` (crates/harness `suite_hash`). */
export function suiteHash(specHash, cases) {
  return createHash('sha256').update(`${CASES_FORMAT}\n${specHash}\n${JSON.stringify(cases)}`).digest('hex');
}

/**
 * The emitted cases, once they are shown to be this installed spec's complete suite: the format,
 * the spec hash the installed artifacts were built from, a suite hash that recomputes over exactly
 * this list, and the same labels, classes and expectations the pre-install reference report
 * evaluated (and agreed with) in the same order.
 */
export function verifySuite(emitted, { specHash, reference }) {
  requireThat(emitted?.format === CASES_FORMAT, 'unexpected reference-suite cases format');
  requireThat(emitted.spec_hash === specHash, 'emitted cases name another spec than the installed spec');
  requireThat(Array.isArray(emitted.cases) && emitted.cases.length > 0 && emitted.total === emitted.cases.length,
    'emitted case count is inconsistent');
  requireThat(suiteHash(emitted.spec_hash, emitted.cases) === emitted.suite_hash, 'cases do not recompute to their suite hash');
  emitted.cases.forEach((c, index) => requireThat(c.index === index && c.id === `case-${index}`, 'emitted case ids are out of order'));
  const outcomes = reference?.report?.outcomes;
  requireThat(reference?.report?.spec_hash === specHash && Array.isArray(outcomes) && outcomes.length === emitted.total
    && outcomes.every((o, i) => o.label === emitted.cases[i].label && o.class === emitted.cases[i].class
      && o.rule_index === emitted.cases[i].rule_index && o.agree === true
      && o.expected === (emitted.cases[i].expect_permit ? 'permit' : 'deny')),
  'emitted cases differ from the suite the pre-install reference report evaluated');
  return emitted.cases;
}

/**
 * The W2 composition's addresses. The live runner has already required the full checked
 * configuration (`subscription.mjs`); this only refuses what the plan itself would misuse.
 */
function w2Config(run) {
  const config = run.subscription;
  if (config === undefined) return null;
  requireThat(config && StrKey.isValidContract(config.policy_address ?? '') && run.sac === NATIVE_SAC
    && ![run.account, run.sac, run.policy].includes(config.policy_address), 'invalid subscription composition');
  return config;
}

export function preorder(node, out = []) {
  out.push(node);
  node.subInvocations.forEach((child) => preorder(child, out));
  return out;
}

/**
 * Each installed rule's recorded call (the call the grant was synthesized from), its authorization
 * tree and rule ID, and the policies installed with it.
 */
export function liveRules(run, spec) {
  requireThat(Array.isArray(spec?.rules) && spec.rules.length >= 1, 'spec has no rules');
  requireThat(spec.smart_account?.address === run.account, 'spec names another account');
  const shape = (rule, index, node, ruleId, policies) => {
    const call = node.function.contractFn;
    requireThat(addressOf(call) === rule.context.contract, 'recorded call and rule target differ');
    requireThat(Number.isInteger(ruleId) && ruleId > 0 && ruleId <= 0xffff_ffff, 'missing installed rule ID');
    const fn = call.functionName.toString();
    const authorizer = AUTHORIZER[`${rule.context.contract}:${fn}`];
    requireThat(Number.isInteger(authorizer), `no pinned authorizing argument for ${fn} on ${rule.context.contract}`);
    return { rule_index: index, contract: rule.context.contract, fn, args: call.args, node, rule_id: ruleId, authorizer,
      policies, allowed_fns: rule.allowed_calls.map((c) => c.fn), allowed_calls: rule.allowed_calls, authorization: rule.authorization };
  };
  if (run.walkthrough !== undefined) {
    const plan = run.walkthrough;
    requireThat(['blend_claim', 'soroswap_swap'].includes(plan?.kind), 'unsupported protocol walkthrough');
    const entries = plan.bundle?.entries;
    requireThat(plan.bundle?.status === 'installed' && Array.isArray(entries) && entries.length === spec.rules.length,
      'derived denials require the complete installed bundle');
    const nodes = preorder(protocolInvocation(plan));
    const rules = spec.rules.map((rule, index) => {
      const entry = entries[index];
      requireThat(entry?.rule_index === index && StrKey.isValidContract(entry.policy ?? ''), 'incomplete bundle entry');
      const matching = nodes.filter((node) => addressOf(node.function.contractFn) === rule.context.contract);
      requireThat(matching.length === 1, 'each rule must match exactly one recorded call');
      return shape(rule, index, matching[0], entry.installation?.rule_id, [{ address: entry.policy, kind: 'generated' }]);
    });
    requireThat(new Set(rules.map((r) => r.rule_id)).size === rules.length, 'duplicate installed rule IDs');
    return rules;
  }
  const config = w2Config(run);
  requireThat(config && spec.rules.length === 1, 'derived denials run on the W1, W2 or W3 walkthrough');
  requireThat(StrKey.isValidContract(run.policy ?? ''), 'missing installed generated policy');
  const node = contractCall(run.sac, 'transfer', [A(run.account), A(run.recipient), i128(BigInt(run.amount))]);
  return [shape(spec.rules[0], 0, node, run.rule_id, [{ address: run.policy, kind: 'generated' },
    { address: config.policy_address, kind: 'spending_limit' }])];
}

/**
 * Live equivalents for the suite's network-absent names, each already observed by a walkthrough
 * control: W1's other pool function (`submit`, FunctionNotAllowed) and W2's funded control token
 * (the same transfer on another contract, UnvalidatedContext). Nothing else is substituted.
 */
export function liveStandIns(run, rule) {
  if (run.walkthrough?.kind === 'blend_claim' && rule.contract === PROTOCOL_TARGETS.blend_pool) {
    return { different_function: { name: 'blend_pool_submit', fn: 'submit',
      args: [A(run.account), A(run.account), A(run.account), xdr.ScVal.scvVec([])] } };
  }
  const config = run.walkthrough === undefined ? w2Config(run) : null;
  if (config && StrKey.isValidContract(config.other_token ?? '') && config.other_token !== rule.contract && rule.contract === run.sac) {
    return { different_contract: { name: 'w2_control_token', contract: config.other_token } };
  }
  return {};
}

function encodeArg(arg) {
  const keys = Object.keys(arg ?? {});
  requireThat(keys.length === 1, 'malformed emitted argument');
  if (keys[0] === 'address') return A(arg.address);
  if (keys[0] === 'i128') {
    requireThat(typeof arg.i128 === 'string' && /^-?(0|[1-9][0-9]{0,38})$/.test(arg.i128), 'malformed emitted i128');
    return nativeToScVal(BigInt(arg.i128), { type: 'i128' });
  }
  requireThat(keys[0] === 'scval_xdr' && typeof arg.scval_xdr === 'string', 'malformed emitted argument');
  return xdr.ScVal.fromXDR(arg.scval_xdr, 'base64');
}

const signerAddress = (signer) => (signer && Object.keys(signer).length === 1 && signer.delegated
  && typeof signer.delegated.address === 'string' ? signer.delegated.address : null);

/** The signer set a case authenticates, in terms of keys this run holds. */
function realizeSigners(context, delegate) {
  const live = new Set(context.rule_live_signers.map(signerAddress));
  const addresses = context.authenticated_signers.map(signerAddress);
  if (addresses.some((a) => a === null)) return { offline: 'signer_key_not_held' };
  if (new Set(addresses).size !== addresses.length) return { offline: 'repeated_signer_unrepresentable' };
  const unrecognized = addresses.filter((a) => !live.has(a));
  // The account refuses an unrecognized Delegated signer when it reaches it, before authenticating
  // it, so it needs no proof; a rule signer other than this run's delegate would need a key the run
  // does not hold.
  if (addresses.some((a) => live.has(a) && a !== delegate)) return { offline: 'signer_key_not_held' };
  if (unrecognized.some((a) => !StrKey.isValidEd25519PublicKey(a))) return { offline: 'signer_key_not_held' };
  return { delegate: addresses.includes(delegate), unrecognized };
}

const sameContext = (a, b) => sameArg({ ...a, authenticated_signers: null }, { ...b, authenticated_signers: null });

function realizeDenial(c, rule, base, standIns, account, delegate) {
  if (!sameContext(c.context, base.context)) return { offline: 'installation_state' };
  const signers = realizeSigners(c.context, delegate);
  if (signers.offline) return signers;
  let contract = rule.contract, fn = rule.fn, args = null, standIn = null;
  if (c.invocation.contract !== base.invocation.contract) {
    const s = standIns.different_contract;
    if (!s) return { offline: 'no_live_stand_in' };
    contract = s.contract; standIn = s.name;
  }
  if (c.invocation.fn_name !== base.invocation.fn_name) {
    const s = standIns.different_function;
    if (!s) return { offline: 'no_live_stand_in' };
    fn = s.fn; args = s.args; standIn = s.name;
  }
  if (args === null) {
    if (c.invocation.args.length !== rule.args.length) return { offline: 'host_rejects_before_authorization' };
    const authorizer = rule.authorizer;
    requireThat(rule.args[authorizer]?.type === 'scvAddress' && Address.fromScVal(rule.args[authorizer]).toString() === account,
      'the pinned authorizing argument does not name the account');
    args = [];
    for (const [i, arg] of c.invocation.args.entries()) {
      // A position this mutation left alone keeps the recorded value: it satisfies the same
      // constraint, and it has the type the target decodes (the suite's wildcard stand-in may not).
      if (sameArg(arg, base.invocation.args[i])) { args.push(rule.args[i]); continue; }
      const value = encodeArg(arg);
      if (value.type !== rule.args[i].type) return { offline: 'host_rejects_before_authorization' };
      if (i === authorizer && hex(value) !== hex(rule.args[i])) return { offline: 'authorizer_replaced' };
      args.push(value);
    }
  }
  const realization = standIn ? 'live_stand_in' : 'mutation_on_recorded_call';
  // A mutation of the recorded call keeps the recorded children, as the delegate would sign the
  // whole tree; a stand-in is a different call and is authorized alone.
  const tree = contractCall(contract, fn, args);
  if (!standIn) tree.subInvocations = rule.node.subInvocations;
  return { id: c.id, index: c.index, rule_index: c.rule_index, class: c.class, family: LIVE_CLASSES[c.class], label: c.label,
    expect_permit: false, realization, stand_in: standIn, contract, fn, args, tree, signers };
}

/** One rule ID per authorization context, in the account's (pre-order) context order. */
function ruleIdsFor(tree, rules, fallback) {
  return preorder(tree).map((node, position) => {
    const contract = addressOf(node.function.contractFn);
    const owner = rules.filter((r) => r.contract === contract);
    if (position === 0 && owner.length === 0) return fallback.rule_id;
    requireThat(owner.length === 1, 'a recorded context has no installed rule');
    return owner[0].rule_id;
  });
}

const constraintKind = (c) => (typeof c === 'string' ? c : Object.keys(c ?? {})[0]);

/**
 * Mutations are applied to the recorded call, so it must be the call the suite's original
 * describes: equal at every exact position and within every bound. Otherwise a replayed denial
 * could be refused for a difference the suite never made.
 */
function requireRecordedOriginal(c, rule) {
  const constraints = [...rule.allowed_calls[0].args].sort((a, b) => a.i - b.i);
  requireThat(c.invocation.contract === rule.contract && c.invocation.fn_name === rule.fn
    && c.invocation.args.length === rule.args.length && constraints.length === rule.args.length,
  'recorded call differs from the suite original');
  c.invocation.args.forEach((arg, i) => {
    const constraint = constraints[i].c, kind = constraintKind(constraint), live = rule.args[i];
    const ok = kind === 'any_value' ? true
      : kind === 'le_i128' ? live.type === 'scvI128' && scValToNative(live) <= BigInt(constraint.le_i128.max)
        : kind === 'ge_i128' ? live.type === 'scvI128' && scValToNative(live) >= BigInt(constraint.ge_i128.min)
          : hex(encodeArg(arg)) === hex(live);
    requireThat(ok, `recorded call differs from the suite original at arg[${i}]`);
  });
}

/**
 * Select and realize the live cases. Pure: no network. Refuses fewer than the minimum number of
 * realizable denials before anything is simulated.
 */
export function planDerivedDenials({ cases, rules, account, delegate, standIns = () => ({}) }) {
  const byRule = new Map(rules.map((rule) => [rule.rule_index, rule]));
  const bases = new Map();
  for (const c of cases) if (c.class === 'original') bases.set(c.rule_index, [...(bases.get(c.rule_index) ?? []), c]);
  // Mutations are applied to the recorded call, and the run records one call per rule. A rule
  // with several allowed tuples (the only kind with cross-product cases) is therefore refused.
  requireThat(rules.every((rule) => (bases.get(rule.rule_index) ?? []).length === 1),
    'each rule must have exactly one allowed tuple: the run recorded one call per rule');
  const originals = [], denials = [], offline = new Map();
  let permitsNotReplayed = 0;
  const skip = (c, reason) => {
    const key = `${c.rule_index}|${c.class}|${reason}`;
    const entry = offline.get(key) ?? { rule_index: c.rule_index, class: c.class, reason, cases: 0, ids: [] };
    entry.cases++; entry.ids.push(c.id); offline.set(key, entry);
  };
  for (const c of cases) {
    const rule = byRule.get(c.rule_index);
    requireThat(rule, 'a suite case names a rule this run did not install');
    if (c.class === 'original') {
      requireThat(c.expect_permit === true, 'an original case must permit');
      requireRecordedOriginal(c, rule);
      originals.push({ id: c.id, index: c.index, rule_index: c.rule_index, class: c.class, family: 'original', label: c.label,
        expect_permit: true, realization: 'recorded_call', stand_in: null, contract: rule.contract, fn: rule.fn, args: rule.args,
        tree: rule.node, rule_ids: ruleIdsFor(rule.node, rules, rule), signers: { delegate: true, unrecognized: [] } });
      continue;
    }
    if (c.expect_permit) { permitsNotReplayed++; continue; }
    if (!LIVE_CLASSES[c.class]) {
      requireThat(OFFLINE_CLASSES[c.class], `unclassified mutation class ${c.class}`);
      skip(c, OFFLINE_CLASSES[c.class]);
      continue;
    }
    const realized = realizeDenial(c, rule, bases.get(c.rule_index)[0], standIns(rule), account, delegate);
    // A stand-in contract is signed for the case's own rule, which is what the account refuses.
    if (realized.offline) skip(c, realized.offline);
    else denials.push({ ...realized, rule_ids: realized.stand_in ? [rule.rule_id] : ruleIdsFor(realized.tree, rules, rule) });
  }
  requireThat(denials.length >= MIN_DERIVED_DENIALS,
    `derived denials refused: this suite has ${denials.length} live-realizable deny cases; at least ${MIN_DERIVED_DENIALS} are required`);
  return { originals, denials, offline: [...offline.values()], permits_not_replayed: permitsNotReplayed };
}

/** Signers the generated policy's predicate needs (`kind` is `any_of`, `all_of` or `{ threshold: { n } }`). */
function requiredSigners(authorization) {
  const kind = authorization?.kind;
  if (kind === 'any_of' || kind === 'any_of_current_rule_signers') return 1;
  if (kind === 'all_of') return authorization.signers.length;
  requireThat(Number.isInteger(kind?.threshold?.n) && kind.threshold.n >= 1, 'unmodeled signer predicate');
  return kind.threshold.n;
}

/**
 * The first refusal the installed rule should produce for a realized case, or `{ permit: true }`.
 * `order` is the live rule's policy order. Mirrors stellar-accounts 0.7.2 `do_check_auth`
 * (context type, then unrecognized signers, then each policy in order), the generated policy's
 * check order (ZeroSigners 1, PredicateUnsatisfied 2, FunctionNotAllowed 5, NoTupleMatched 6) and
 * the reviewed spending limit's (NotAllowed 3223, LessThanZero 3226, SpendingLimitExceeded 3221).
 */
export function predictEnforcer(item, rule, order, account) {
  if (item.class === 'different_contract') return { enforcer: account, code: 3002 };
  if (item.signers.unrecognized.length) return { enforcer: account, code: 3016 };
  const signed = item.signers.delegate;
  for (const policy of order) {
    if (policy.kind === 'generated') {
      if (!signed) return { enforcer: policy.address, code: 1 };
      if (requiredSigners(rule.authorization) > 1) return { enforcer: policy.address, code: 2 };
      if (!rule.allowed_fns.includes(item.fn)) return { enforcer: policy.address, code: 5 };
      if (!item.expect_permit) return { enforcer: policy.address, code: 6 };
      continue;
    }
    requireThat(policy.kind === 'spending_limit', 'unmodeled installed policy');
    if (!signed || item.fn !== 'transfer' || item.args[2]?.type !== 'scvI128') return { enforcer: policy.address, code: 3223 };
    const amount = scValToNative(item.args[2]);
    if (amount < 0n) return { enforcer: policy.address, code: 3226 };
    if (policy.spent + amount > policy.limit) return { enforcer: policy.address, code: 3221 };
  }
  return { permit: true };
}
