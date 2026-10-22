// Live derived denials: this spec's own layer-1 suite, replayed against the installed rule as
// enforcing simulations right after installation. Post-install and state-dependent: each result
// is the endpoint's answer at its reported ledger. Nothing is ever submitted.
//
// What is replayed is chosen by rule, not by name: every deny case of the suite whose mutation a
// live call can carry. The suite is emitted here from the installed spec (`ozpb reference-suite
// --emit-cases`); its suite hash is a checksum over that list, not a signature, so the binding is
// that this script ran the CLI itself, and a reviewer can re-run it on the retained spec.
// A case the network cannot carry is listed as offline with the reason, never dropped silently:
//
//   - a different ledger, call count, policy state or rule signer set (time, count, missing-state
//     and strict-set classes) needs state the live installation does not have;
//   - an arity change or a value of another type is refused by the target's argument decoding
//     before the account is ever asked to authorize, so no enforcer can be attributed;
//   - replacing the authorizing argument (the transfer or claim `from`, the swap `to`; pinned per
//     target function in AUTHORIZER) moves the authorization off the account, so its policies are
//     never asked either;
//   - the suite's different-contract address and absent function name exist nowhere on the
//     network. Where a walkthrough control has already shown a live equivalent, that stand-in is
//     used and labeled; otherwise the case stays offline.
//
// Each realized case must be refused by the enforcer its class predicts — the account before any
// policy for a foreign contract (UnvalidatedContext, 3002) or an unrecognized signer
// (UnauthorizedSigner, 3016), otherwise the first policy in the live rule's own order that
// refuses it — attributed by contract id in the host's diagnostic events. A permit, or a denial
// from any other contract or code, fails the run.
//
// The account checks payload signers one at a time in map key order, refusing an unrecognized one
// before authenticating it. The suite's unrecognized signer is the all-zero ed25519 key, which
// sorts before any real delegate, so "authorized set plus an unrecognized signer" stops at the
// same account check as "unrecognized signer" alone: two suite cases, one live check. The
// delegate's proof is still supplied, so the case stays correct if the order ever differs.
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Address, Operation, StrKey, authorizeEntry, authorizeInvocation, nativeToScVal, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { authDigest, checkAuthInvocation, contractCall, delegatedSignersPayload, i128, policyDenial } from './lib.mjs';
import { PROTOCOL_TARGETS, protocolInvocation } from './protocol-calls.mjs';
import { parseJsonExact } from './raw-json.mjs';
import { subscriptionConfig } from './subscription.mjs';
import * as rpc from './rpc.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const MIN_DERIVED_DENIALS = 5;
export const CASES_FORMAT = 'ozpb-reference-suite-cases/v1';
/** Classes whose mutation is in the call or the signer set, which a live delegate controls. */
export const LIVE_CLASSES = Object.freeze({
  arg_equality: 'argument', numeric_boundary: 'argument', different_address_arg: 'argument',
  tuple_cross_product: 'cross_product', different_function: 'function', different_contract: 'contract',
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
  [`${rpc.NATIVE_SAC}:transfer`]: 0,
  [`${PROTOCOL_TARGETS.blend_pool}:claim`]: 0,
  [`${PROTOCOL_TARGETS.router}:swap_exact_tokens_for_tokens`]: 3,
});
export const REALIZATIONS = Object.freeze(['mutation_on_recorded_call', 'literal_tuple', 'live_stand_in']);
export const STAND_INS = Object.freeze(['blend_pool_submit', 'w2_control_token']);
const LABELS = Object.freeze({ post_install: true, state_dependent: true, simulation_only: true, submitted: false });
// A signed original is a live authorization of the real call until it expires, and the RPC endpoint
// sees it; it lasts only long enough to be simulated.
const AUTH_LIFETIME_LEDGERS = 5;

const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const A = (address) => new Address(address).toScVal();
const hex = (v) => Buffer.from(v.toXDR()).toString('hex');
const sameArg = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const addressOf = (call) => Address.fromScAddress(call.contractAddress).toString();
const positiveLedger = (n) => Number.isSafeInteger(n) && n > 0 && n <= 0xffff_ffff;

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

function preorder(node, out = []) {
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
  const config = subscriptionConfig(run);
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
  const config = run.walkthrough === undefined ? subscriptionConfig(run) : null;
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

function realizeDenial(c, rule, bases, standIns, account, delegate) {
  const base = bases.length === 1 ? bases[0] : null;
  const reference = base ?? bases[0];
  if (!reference || !sameContext(c.context, reference.context)) return { offline: 'installation_state' };
  const signers = realizeSigners(c.context, delegate);
  if (signers.offline) return signers;
  let contract = rule.contract, fn = rule.fn, args = null, standIn = null;
  if (c.invocation.contract !== reference.invocation.contract) {
    const s = standIns.different_contract;
    if (!s) return { offline: 'no_live_stand_in' };
    contract = s.contract; standIn = s.name;
  }
  if (c.invocation.fn_name !== reference.invocation.fn_name) {
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
      if (base && sameArg(arg, base.invocation.args[i])) { args.push(rule.args[i]); continue; }
      const value = encodeArg(arg);
      if (value.type !== rule.args[i].type) return { offline: 'host_rejects_before_authorization' };
      if (i === authorizer && hex(value) !== hex(rule.args[i])) return { offline: 'authorizer_replaced' };
      args.push(value);
    }
  }
  const realization = standIn ? 'live_stand_in' : base ? 'mutation_on_recorded_call' : 'literal_tuple';
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
      // The run recorded one call per rule; that call is this rule's original when it has one tuple.
      if ((bases.get(c.rule_index) ?? []).length === 1) {
        requireRecordedOriginal(c, rule);
        const ids = ruleIdsFor(rule.node, rules, rule);
        originals.push({ id: c.id, index: c.index, rule_index: c.rule_index, class: c.class, family: 'original', label: c.label,
          expect_permit: true, realization: 'recorded_call', stand_in: null, contract: rule.contract, fn: rule.fn, args: rule.args,
          tree: rule.node, rule_ids: ids, signers: { delegate: true, unrecognized: [] } });
      } else permitsNotReplayed++;
      continue;
    }
    if (c.expect_permit) { permitsNotReplayed++; continue; }
    if (!LIVE_CLASSES[c.class]) {
      requireThat(OFFLINE_CLASSES[c.class], `unclassified mutation class ${c.class}`);
      skip(c, OFFLINE_CLASSES[c.class]);
      continue;
    }
    const realized = realizeDenial(c, rule, bases.get(c.rule_index) ?? [], standIns(rule), account, delegate);
    // A stand-in contract is signed for the case's own rule, which is what the account refuses.
    if (realized.offline) skip(c, realized.offline);
    else denials.push({ ...realized, rule_ids: realized.stand_in ? [rule.rule_id] : ruleIdsFor(realized.tree, rules, rule) });
  }
  requireThat(rules.every((rule) => originals.some((o) => o.rule_index === rule.rule_index)),
    'every installed rule needs its recorded original');
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

/** Which of the candidate contracts raised the account's authentication failure, if any. */
function observedDenial(error, account, candidates) {
  for (const contract of candidates) {
    const code = policyDenial(error, account, contract);
    if (code !== null) return { enforcer: contract, code };
  }
  return { enforcer: null, code: null };
}

async function authorize({ account, tree, ruleIds, delegateKey, unrecognized, until }) {
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(account).toScAddress(), nonce: randomBytes(8).readBigInt64BE(),
      signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid() })),
    rootInvocation: tree,
  });
  let delegateEntry = null;
  const accountEntry = await authorizeEntry(entry, async (_preimage, payload) => {
    const digest = authDigest(payload, ruleIds);
    if (delegateKey) {
      delegateEntry = await authorizeInvocation({ signer: delegateKey, validUntilLedgerSeq: until,
        invocation: checkAuthInvocation(account, digest), networkPassphrase: rpc.NETWORK_PASSPHRASE, authV2: false });
    }
    return { signatureScVal: delegatedSignersPayload([...(delegateKey ? [delegateKey.publicKey()] : []), ...unrecognized], ruleIds) };
  }, until, rpc.NETWORK_PASSPHRASE);
  return [accountEntry, delegateEntry].filter(Boolean);
}

function readLivePolicies(value) {
  const field = value?.map?.filter((entry) => entry.key.type === 'scvSymbol' && entry.key.sym.toString() === 'policies');
  requireThat(field?.length === 1 && field[0].val.type === 'scvVec', 'live rule has no policy list');
  return field[0].val.vec.map((policy) => Address.fromScVal(policy).toString());
}

function cliRunner(dir, env) {
  const command = env.OZPB_BIN ? [env.OZPB_BIN.includes('/') ? resolve(env.OZPB_BIN) : env.OZPB_BIN]
    : ['cargo', 'run', '--locked', '-q', '-p', 'ozpb-cli', '--'];
  return (args) => {
    const result = spawnSync(command[0], [...command.slice(1), ...args], {
      cwd: ROOT, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024,
    });
    if (result.stderr) writeFileSync(join(dir, 'derived-cases.log'), result.stderr, { flag: 'wx', mode: 0o600 });
    if (result.error) throw result.error;
    requireThat(result.status === 0, 'reference-suite --emit-cases failed; see the local run log');
    return result.stdout;
  };
}

/** Run the derived-denial suite for the installed grant in `dir`; returns the completed journal. */
export async function runDerivedDenials(runDirectory, overrides = {}) {
  // The run directory `run.sh` created, or one its operator names on the command line; inside it
  // only fixed names are read or written.
  // nosec
  const dir = resolve(runDirectory);
  requireThat(lstatSync(dir).isDirectory(), 'run directory must be a directory');
  const deps = { ...rpc, standIns: null, runCli: null, ...overrides };
  const path = join(dir, 'run.json');
  const run = deps.readJson(path);
  requireThat(run.derived_denials === undefined, 'derived denials already started; use a fresh isolated grant');
  requireThat(run.network === rpc.NETWORK_PASSPHRASE && run.account_code_hash === rpc.PINNED_ACCOUNT_WASM, 'unexpected network or account pin');
  const protocol = run.walkthrough !== undefined;
  // Before any delegated call: the replay describes the grant as installed, not as exercised.
  requireThat(protocol ? run.walkthrough.controls === undefined && !run.walkthrough.invocations?.some((i) => i.signer === 'delegate')
    : run.subscription?.controls === undefined && !run.invocations?.some((i) => i.signer === 'delegate'),
  'derived denials run after installation and before any delegated call');
  if (!protocol) {
    requireThat(run.subscription?.installation_readback === 'matched' && positiveLedger(run.authority_check?.rechecked_at_ledger),
      'derived denials require the checked composed installation');
  }
  const specPath = join(dir, 'spec.json');
  requireThat(resolve(run.spec ?? '') === specPath, 'run does not name its own spec');
  const spec = parseJsonExact(readFileSync(specPath, 'utf8'));
  const pipeline = parseJsonExact(readFileSync(join(dir, protocol ? 'protocol-pipeline.json' : 'pipeline.json'), 'utf8'));
  const specHash = pipeline.spec_hash;
  requireThat(/^[0-9a-f]{64}$/.test(specHash ?? '') && (!protocol || run.walkthrough.bundle?.spec_hash === specHash),
    'installed spec identity is missing');
  const reference = parseJsonExact(readFileSync(join(dir, 'reference-suite.json'), 'utf8'));
  const text = (deps.runCli ?? cliRunner(dir, process.env))(['reference-suite', '--spec', specPath, '--emit-cases']);
  const emitted = parseJsonExact(text);
  const cases = verifySuite(emitted, { specHash, reference });
  const rules = liveRules(run, spec);
  const plan = planDerivedDenials({ cases, rules, account: run.account, delegate: run.delegate,
    standIns: deps.standIns ?? ((rule) => liveStandIns(run, rule)) });
  // Kept beside the journal it was replayed from, and only once a replay starts: a refusal above
  // leaves nothing that reads as an attempted replay.
  writeFileSync(join(dir, 'derived-cases.json'), text, { flag: 'wx', mode: 0o600 });

  const journal = { schema_version: 1, status: 'running', labels: { ...LABELS },
    suite: { spec_hash: emitted.spec_hash, suite_hash: emitted.suite_hash, total: emitted.total, minimum_denials: MIN_DERIVED_DENIALS },
    selection: 'every deny case of a live-realizable class that the recorded call can carry, in suite order',
    offline: plan.offline.map(({ rule_index, class: cls, reason, cases: n }) => ({ rule_index, class: cls, reason, cases: n })),
    permits_not_replayed: plan.permits_not_replayed, policy_order: [], originals: [], cases: [] };
  run.derived_denials = journal;
  const save = () => { run.derived_denials = journal; deps.writeJson(path, run); };
  save();
  try {
    await deps.assertTestnet();
    requireThat(await deps.contractCodeHash(run.account) === run.account_code_hash, 'live account code differs from its pin');
    const source = { publicKey: () => run.payer };
    const orders = new Map();
    for (const rule of rules) {
      const live = await deps.viewCallObservation(source, run.account, 'get_context_rule', [xdr.ScVal.scvU32(rule.rule_id)]);
      const order = readLivePolicies(live.value);
      requireThat(order.length === rule.policies.length && rule.policies.every((p) => order.includes(p.address)),
        'live rule policies differ from the installed composition');
      const policies = [];
      for (const address of order) {
        const policy = { ...rule.policies.find((p) => p.address === address) };
        const pinned = policy.kind === 'spending_limit' ? run.subscription.policy_code_hash
          : protocol ? run.walkthrough.bundle.entries[rule.rule_index].wasm_hash : run.policy_wasm_hash;
        requireThat(await deps.contractCodeHash(address) === pinned, 'live policy code differs from the installed artifact');
        if (policy.kind === 'spending_limit') {
          const data = scValToNative((await deps.viewCallObservation(source, address, 'get_spending_limit_data',
            [xdr.ScVal.scvU32(rule.rule_id), A(run.account)])).value);
          requireThat(typeof data.spending_limit === 'bigint' && data.spending_limit === BigInt(run.amount)
            && data.cached_total_spent === 0n && Array.isArray(data.spending_history) && data.spending_history.length === 0,
          'spending policy is not in its unexercised installed state');
          Object.assign(policy, { limit: data.spending_limit, spent: 0n });
        }
        policies.push(policy);
      }
      orders.set(rule.rule_index, policies);
      journal.policy_order.push(...order.filter((a) => !journal.policy_order.includes(a)));
    }
    save();
    const delegateKey = deps.loadKey('delegate');
    requireThat(delegateKey.publicKey() === run.delegate, 'delegate key differs from the installed signer');
    const candidates = [run.account, ...new Set(rules.flatMap((rule) => rule.policies.map((p) => p.address)))];

    const simulate = async (item) => {
      const until = (await deps.latestLedger()) + AUTH_LIFETIME_LEDGERS;
      const auth = await authorize({ account: run.account, tree: item.tree, ruleIds: item.rule_ids,
        delegateKey: item.signers.delegate ? delegateKey : null, unrecognized: item.signers.unrecognized, until });
      const operation = Operation.invokeContractFunction({ contract: item.contract, function: item.fn, args: item.args, auth });
      const observed = await deps.enforceSimulation(source, operation);
      requireThat(positiveLedger(observed.ledger), 'missing enforcing-simulation ledger');
      return observed;
    };
    for (const item of plan.originals) {
      const record = { id: item.id, rule_index: item.rule_index, status: 'started' };
      journal.originals.push(record); save();
      requireThat(predictEnforcer(item, rules[item.rule_index], orders.get(item.rule_index), run.account).permit,
        `${item.id}: the recorded original is not predicted to permit`);
      const observed = await simulate(item);
      Object.assign(record, { ledger: observed.ledger, status: observed.result === 'permit' ? 'permitted' : 'unexpected_denial' });
      save();
      requireThat(record.status === 'permitted', `${item.id}: ${record.status}; the recorded original must permit`);
    }
    for (const item of plan.denials) {
      const expected = predictEnforcer(item, rules[item.rule_index], orders.get(item.rule_index), run.account);
      requireThat(!expected.permit, `${item.id}: no enforcer is predicted to refuse it`);
      const record = { id: item.id, rule_index: item.rule_index, class: item.class, family: item.family, label: item.label,
        realization: item.realization, stand_in: item.stand_in, expected, status: 'started' };
      journal.cases.push(record); save();
      const observed = await simulate(item);
      const seen = observed.result === 'deny' ? observedDenial(observed.error, run.account, candidates) : { enforcer: null, code: null };
      const attributed = observed.result === 'deny' && seen.enforcer === expected.enforcer && seen.code === expected.code;
      Object.assign(record, { ledger: observed.ledger, observed: { result: observed.result, ...seen },
        status: attributed ? 'verified_denial' : observed.result === 'permit' ? 'unexpected_permit' : 'unattributed_denial' });
      save();
      requireThat(attributed, `${item.id}: ${record.status}; nothing was submitted`);
    }
    journal.status = 'completed';
    save();
  } catch (error) {
    journal.status = 'incomplete';
    save();
    throw error;
  }
  return journal;
}

export function summarize(journal) {
  const lines = [`Derived denials (post-install, state-dependent enforcing simulations; nothing submitted): ${journal.status}`,
    `  suite ${journal.suite.suite_hash} of spec ${journal.suite.spec_hash}: ${journal.suite.total} cases`];
  for (const o of journal.originals) lines.push(`  ${o.id} rule[${o.rule_index}] original: ${o.status} at ${o.ledger}`);
  for (const c of journal.cases) {
    lines.push(`  ${c.id} rule[${c.rule_index}] ${c.class}${c.stand_in ? ` (stand-in ${c.stand_in})` : ''}: `
      + `${c.observed?.enforcer ?? '-'} #${c.observed?.code ?? '-'} (expected ${c.expected.enforcer} #${c.expected.code}) at ${c.ledger}`);
  }
  const by = {};
  for (const c of journal.cases) by[`${c.expected.enforcer} #${c.expected.code}`] = (by[`${c.expected.enforcer} #${c.expected.code}`] ?? 0) + 1;
  lines.push(`  denials by expected enforcer: ${Object.entries(by).map(([k, n]) => `${k} x${n}`).join('; ')}`);
  lines.push(`  offline, not replayed live: ${journal.offline.map((o) => `rule[${o.rule_index}] ${o.class} x${o.cases} (${o.reason})`).join('; ')}`);
  return lines.join('\n');
}

if (isMainModule(import.meta.url)) {
  const options = rpc.args();
  requireThat(options['run-dir'] && Object.keys(options).length === 1, 'usage: derived-denials.mjs --run-dir DIRECTORY');
  console.log(summarize(await runDerivedDenials(options['run-dir'])));
}
