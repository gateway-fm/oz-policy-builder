// The real CLI pipeline for the harness's one exact transfer. No keys, signatures or submissions.
// Recording is an RPC read; synthesis revalidates supplied JSON and lowers its trust to
// self_supplied. Saved reports retain those different evidence boundaries.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainModule } from './cli-entry.mjs';
import { parseJsonExact } from './raw-json.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const NETWORK = 'Test SDF Network ; September 2015';
const NETWORK_ID = createHash('sha256').update(NETWORK).digest('hex');
const HASH = /^[0-9a-f]{64}$/;
const TEMPLATE = 'policy-templates/scope@1';
const HORIZON = 17_280;
const fail = (message) => { throw new Error(message); };
const requireThat = (condition, message) => { if (!condition) fail(message); };
const isHash = (value) => typeof value === 'string' && HASH.test(value) && !/^0+$/.test(value);
const same = (actual, expected, field) => assert.deepEqual(actual, expected, `unexpected ${field}`);
const read = (path) => parseJsonExact(readFileSync(path, 'utf8'));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });

function recordingInputs(run, recording) {
  const bundle = recording.bundle;
  same(bundle?.network_id, NETWORK_ID, 'recording network');
  same(bundle.execution, 'executed_success', 'recording execution');
  same(recording.trust, 'rpc_reported', 'acquisition trust');
  requireThat(isHash(recording.recording_hash), 'recording has no identity');
  requireThat(Number.isInteger(bundle.ledger) && bundle.ledger > 0 && bundle.ledger <= 0xffff_ffff - HORIZON,
    'recording ledger cannot support the bounded grant lifetime');
  const observation = bundle.contract_executables?.[run.account];
  same(observation?.executable?.wasm?.code_hash, run.account_code_hash, 'observed account code');
  requireThat(Number.isInteger(observation.observed_ledger) && observation.observed_ledger >= bundle.ledger
    && observation.observed_ledger <= 0xffff_ffff, 'invalid executable observation ledger');
  const selected = bundle.authorizations?.map((auth, index) => ({ auth, index }))
    .filter(({ auth }) => auth.authorizer === run.account);
  requireThat(selected?.length === 1, 'recording must contain exactly one authorization by this account');
  const { auth, index } = selected[0];
  same(auth.root?.sub_invocations, [], 'recorded sub-invocations');
  const call = auth.root?.call?.contract;
  same(call?.contract, run.sac, 'recorded target');
  same(call.fn_name, 'transfer', 'recorded function');
  same(call.args?.length, 3, 'recorded argument count');
  same(call.args[0], { address: run.account }, 'recorded source');
  same(call.args[1], { address: run.recipient }, 'recorded recipient');
  requireThat(Object.keys(call.args[2]).length === 1 && call.args[2].i128 !== undefined, 'recorded amount is not i128');
  same(String(call.args[2].i128), run.amount, 'recorded amount');
  return {
    account: { address: run.account, observed_code_hash: run.account_code_hash,
      registry_resolution: 'resolved by the toolkit from the signed snapshot' },
    decisions: { grant_name: 'native-sub', delegate_signers: [{ delegated: { address: run.delegate } }],
      predicate: 'any_of', valid_until_ledger: bundle.ledger + HORIZON, no_expiry_acknowledged: false,
      max_calls: 1, widenings: [], spending_limit: null },
    justification: `recordings[0]/auth[${index}]`,
  };
}

function validateSynthesis(output, run, inputs, expectedRegistryRoot) {
  requireThat(isHash(output.spec_hash), 'synthesis has no canonical spec hash');
  if (output.questions !== undefined) same(output.questions, [], 'unanswered synthesis questions');
  requireThat(Array.isArray(output.rationale) && output.rationale.every((s) => typeof s === 'string'), 'missing synthesis rationale');
  const spec = output.spec;
  same(spec?.schema, 'policy-spec/v1', 'spec schema');
  same(spec.name, inputs.decisions.grant_name, 'grant name');
  same(spec.network_id, NETWORK_ID, 'spec network');
  same(spec.smart_account?.address, run.account, 'spec account');
  same(spec.smart_account?.observed_code_hash, run.account_code_hash, 'spec account code');
  requireThat(isHash(spec.registry_snapshot), 'spec has no resolved registry root');
  if (expectedRegistryRoot) same(spec.registry_snapshot, expectedRegistryRoot, 'configured registry root');
  same(spec.rules?.length, 1, 'rule count');
  const rule = spec.rules[0];
  same(rule.context, { type: 'CallContract', contract: run.sac, target_code_hash: null }, 'rule target');
  same(rule.valid_until?.ledger, inputs.decisions.valid_until_ledger, 'rule expiry');
  same(rule.authorization, { kind: 'any_of', strict_signer_set: true, signers: inputs.decisions.delegate_signers }, 'rule signers');
  same(rule.allowed_calls, [{ fn: 'transfer', args: [
    { i: 0, c: { eq_address: { value: 'SELF' } }, prov: 'observed_exact' },
    { i: 1, c: { eq_address: { value: run.recipient } }, prov: 'observed_exact' },
    { i: 2, c: { eq_i128: { value: run.amount } }, prov: 'observed_exact' },
  ], justified_by: [inputs.justification] }], 'allowed tuple');
  same(rule.state, [{ call_count_per_installation: { max_calls: 1 } }], 'call cap');
  requireThat(rule.policies?.length === 1 && Object.keys(rule.policies[0]).length === 1
    && rule.policies[0].generated?.kind === 'gen:scope+count'
    && rule.policies[0].generated.template_family === TEMPLATE
    && isHash(rule.policies[0].generated.capability_schema), 'expected exactly the generated scope+count policy');
  requireThat(spec.evidence?.recordings?.length === 1 && isHash(spec.evidence.recordings[0].hash), 'missing synthesis evidence');
  same(spec.evidence.recordings[0].trust, 'self_supplied', 'synthesis evidence trust');
  return spec;
}

export function runSynthesisFlow(runDirectory, env = process.env) {
  const dir = resolve(runDirectory);
  requireThat(lstatSync(dir).isDirectory(), 'run directory must be a directory');
  // A retry must start a new run. Refuse even a dangling symlink; no previous positive report
  // may survive beside outputs from a failed attempt.
  const outputs = ['recording.json', 'account.json', 'decisions.json', 'synthesis.json', 'spec.json',
    'reference-suite.json', 'verification.json', 'pipeline.json', 'policy'];
  for (const name of outputs) {
    try { lstatSync(join(dir, name)); fail(`pipeline output already exists: ${name}`); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const runPath = join(dir, 'run.json');
  const run = read(runPath);
  same(run.network, NETWORK, 'run network');
  requireThat(run.delegate !== run.owner?.address && run.delegate !== run.account, 'delegate must differ from the owner and account');
  requireThat(typeof run.amount === 'string' && /^[1-9][0-9]*$/.test(run.amount) && BigInt(run.amount) <= (1n << 127n) - 1n,
    'run amount must be a positive i128 decimal');
  const permits = run.invocations?.filter((i) => i.signer === 'owner' && i.rule === 0 && i.result === 'permit'
    && i.to === run.recipient && i.amount === run.amount && isHash(i.hash));
  requireThat(permits?.length === 1, 'run needs exactly one recorded owner transfer');
  const trust = [env.OZPB_SIGNED_REGISTRY_SNAPSHOT, env.OZPB_REGISTRY_ROOTS_FILE, env.OZPB_REGISTRY_MIN_VERSION];
  requireThat(trust.every(Boolean) || trust.every((v) => !v), 'configure all three registry trust inputs, or none');
  const [snapshot, roots, minimum] = trust.every(Boolean) ? [resolve(trust[0]), resolve(trust[1]), trust[2]]
    : [join(ROOT, 'docs/examples/registry.signed.json'), join(ROOT, 'docs/examples/registry-roots.json'), '3'];
  requireThat(/^[1-9][0-9]*$/.test(minimum), 'registry minimum version must be a positive integer');
  requireThat(existsSync(snapshot) && existsSync(roots), 'registry trust files are missing');
  // Resolve caller-selected paths before launching under ROOT; bare names retain PATH lookup.
  const command = env.OZPB_BIN ? [env.OZPB_BIN.includes('/') ? resolve(env.OZPB_BIN) : env.OZPB_BIN]
    : ['cargo', 'run', '--locked', '-q', '-p', 'ozpb-cli', '--'];
  function cli(stage, args, filename, parser = parseJsonExact) {
    const result = spawnSync(command[0], [...command.slice(1), stage, ...args], {
      cwd: ROOT, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024,
    });
    if (result.stderr) writeFileSync(join(dir, `${stage}.log`), result.stderr, { flag: 'wx', mode: 0o600 });
    if (result.error) throw result.error;
    requireThat(result.status === 0, `${stage} failed; see the local run log`);
    if (!filename) return;
    // Keep CLI bytes intact, especially u64 nonces and signed registry data.
    writeFileSync(join(dir, filename), result.stdout, { flag: 'wx', mode: 0o600 });
    return parser(result.stdout);
  }
  // Large integer fields are inspected losslessly but never serialized back into the bundle.
  // The real CLI reads its own unmodified output, including all raw XDR and numeric literals.
  const record = cli('record', ['--tx-hash', permits[0].hash, '--rpc-url', env.OZPB_RPC_URL || 'https://soroban-testnet.stellar.org',
    '--network', NETWORK], 'recording.json', (text) => JSON.parse(text, (_key, value, context) =>
    typeof value === 'number' && !Number.isSafeInteger(value) && /^-?\d+$/.test(context?.source ?? '') ? BigInt(context.source) : value));
  const inputs = recordingInputs(run, record);
  save(join(dir, 'account.json'), inputs.account);
  save(join(dir, 'decisions.json'), inputs.decisions);
  const synthesis = cli('synthesize', ['--bundle', join(dir, 'recording.json'), '--selected-authorizer', run.account,
    '--account', join(dir, 'account.json'), '--signed-registry', snapshot, '--registry-roots', roots,
    '--registry-min-version', minimum, '--decisions', join(dir, 'decisions.json'), '--template-family', TEMPLATE], 'synthesis.json');
  const spec = validateSynthesis(synthesis, run, inputs, env.OZPB_REGISTRY_SNAPSHOT_ROOT);
  save(join(dir, 'spec.json'), spec);
  const reference = cli('reference-suite', ['--spec', join(dir, 'spec.json')], 'reference-suite.json');
  same(reference.report?.spec_hash, synthesis.spec_hash, 'reference spec hash');
  same(reference.all_agree, true, 'reference verdict');
  same(reference.disagreements, 0, 'reference disagreements');
  same(reference.missing_classes, [], 'reference missing classes');
  same(reference.unmodeled_reviewed_policies, [], 'reference unmodeled policies');
  requireThat(Number.isSafeInteger(reference.total) && reference.total > 0, 'reference suite has no cases');
  const policy = join(dir, 'policy');
  cli('generate', ['--spec', join(dir, 'spec.json'), '--rule', '0', '--out', policy]);
  const wasms = readdirSync(policy).filter((name) => name.endsWith('.wasm'));
  requireThat(wasms.length === 1, 'expected exactly one generated Wasm');
  const wasm = join(policy, wasms[0]);
  const manifestPath = join(policy, 'build-manifest.json');
  const manifest = read(manifestPath);
  same(manifest.spec_hash, synthesis.spec_hash, 'manifest spec hash');
  same(manifest.registry_snapshot, spec.registry_snapshot, 'manifest registry root');
  same(manifest.rule_index, 0, 'manifest rule');
  same(manifest.wasm_hash, createHash('sha256').update(readFileSync(wasm)).digest('hex'), 'manifest Wasm hash');
  const verified = cli('verify', ['--spec', join(dir, 'spec.json'), '--rule', '0', '--generated-dir', policy,
    '--wasm', wasm, '--manifest', manifestPath], 'verification.json');
  same(verified.matches, true, 'artifact reproduction verdict');
  same(verified.spec_conformance, 'conforms (validated PolicySpec v1)', 'spec conformance');
  same(verified.source_reproduction, 'reproduced: generated non-lock files are byte-identical', 'source reproduction');
  same(verified.wasm_reproduction, 'reproduced: Wasm and BuildManifest are identical', 'Wasm reproduction');
  requireThat(/^pass: [1-9][0-9]* constraint-derived cases all agree$/.test(verified.offline_behavioral_conformance), 'incomplete behavioral conformance');
  same(verified.models_all_policies, true, 'behavioral scope');
  same(verified.unmodeled_reviewed_policies, [], 'unmodeled verification policies');
  requireThat(isHash(manifest.normalized_input_hash), 'manifest lacks normalized input identity');
  same(verified.normalized_input_hash, manifest.normalized_input_hash, 'verification input identity');
  same(verified.current_network_preflight, 'not_checked_here: state-dependent (wallet/live)', 'verification evidence boundary');
  Object.assign(run, { spec: join(dir, 'spec.json'), valid_until_ledger: inputs.decisions.valid_until_ledger,
    registry_root: spec.registry_snapshot });
  writeFileSync(runPath, JSON.stringify(run, null, 2) + '\n');
  save(join(dir, 'pipeline.json'), {
    schema_version: 1, account: run.account, recorded_transaction: permits[0].hash,
    recording_hash: record.recording_hash, acquisition_trust: 'rpc_reported',
    synthesis_recording_hash: spec.evidence.recordings[0].hash, synthesis_trust: 'self_supplied',
    spec_hash: synthesis.spec_hash, normalized_input_hash: verified.normalized_input_hash,
    reference_cases: reference.total, artifact_reproduction: 'matched', current_network_preflight: 'not_checked_here',
  });
  return wasm;
}

if (isMainModule(import.meta.url)) {
  const args = process.argv.slice(2);
  requireThat(args.length === 2 && args[0] === '--run-dir', 'usage: synthesis-flow.mjs --run-dir DIRECTORY');
  const wasm = runSynthesisFlow(args[1]);
  console.log(`recorded, synthesized and reproduced policy: ${wasm}`);
}
