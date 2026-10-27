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
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Address, Operation, authorizeEntry, authorizeInvocation, scValToNative, xdr } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import { MIN_DERIVED_DENIALS, SELECTION, liveRules, liveStandIns, planDerivedDenials, predictEnforcer, verifySuite } from './derived-plan.mjs';
import { authDigest, checkAuthInvocation, delegatedSignersPayload, policyDenial } from './lib.mjs';
import { parseJsonExact } from './raw-json.mjs';
import * as rpc from './rpc.mjs';

export {
  AUTHORIZER, CASES_FORMAT, LIVE_CLASSES, MIN_DERIVED_DENIALS, OFFLINE_CLASSES, OFFLINE_REASONS, REALIZATIONS, SELECTION, STAND_INS,
  liveRules, liveStandIns, planDerivedDenials, predictEnforcer, suiteHash, verifySuite,
} from './derived-plan.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const LABELS = Object.freeze({ post_install: true, state_dependent: true, simulation_only: true, submitted: false });
// A signed original is a live authorization of the real call until it expires, and the RPC endpoint
// sees it; it lasts only long enough to be simulated.
const AUTH_LIFETIME_LEDGERS = 5;
const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const A = (address) => new Address(address).toScVal();
const positiveLedger = (n) => Number.isSafeInteger(n) && n > 0 && n <= 0xffff_ffff;
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

export function cliRunner(dir, env) {
  const command = env.OZPB_BIN ? [env.OZPB_BIN.includes('/') ? resolve(env.OZPB_BIN) : env.OZPB_BIN]
    : ['cargo', 'run', '--locked', '-q', '-p', 'ozpb-cli', '--'];
  return (args) => {
    const result = spawnSync(command[0], [...command.slice(1), ...args], {
      cwd: ROOT, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024,
    });
    // Kept only for a failure, and replaced by a later attempt's: a refused plan may be retried.
    if (result.error || result.status !== 0) writeFileSync(join(dir, 'derived-cases.log'), result.stderr ?? '', { mode: 0o600 });
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
    selection: SELECTION,
    offline: plan.offline.map(({ rule_index, class: cls, reason, cases: n, ids }) => ({ rule_index, class: cls, reason, cases: n, ids })),
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
