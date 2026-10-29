// Real record/synthesis/reference/build/reproduction pipeline for the closed protocol plans.
// It neither signs nor submits; every rule is generated from the same complete synthesized spec.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isMainModule } from './cli-entry.mjs';
import { parseJsonExact } from './raw-json.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { adapterDisclosure, protocolInputs, validateProtocolSynthesis } from './protocol-synthesis.mjs';
import { writeJson } from './rpc.mjs';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const NETWORK = 'Test SDF Network ; September 2015';
const BLND = 'CB22KRA3YZVCNCQI64JQ5WE7UY2VAV7WFLK6A2JN3HEX56T2EDAFO7QF';
const requireThat = (condition, text) => { if (!condition) throw new Error(text); };
const same = (a, b, field) => assert.deepEqual(a, b, `unexpected protocol ${field}`);
const hash = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const decimal = (v) => typeof v === 'string' && /^(0|[1-9][0-9]{0,38})$/.test(v) && BigInt(v) <= (1n << 127n) - 1n;
const read = (path) => parseJsonExact(readFileSync(path, 'utf8'));
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });

export function runProtocolFlow(runDirectory, env = process.env) {
  // `runDirectory` is the run directory `run.sh` created, or one its operator names on the command
  // line; no server or remote request reaches this script. It must be a directory; inside it,
  // only fixed names and the CLI's own output under `policies/` are read or written.
  // nosec
  const dir = resolve(runDirectory);
  requireThat(lstatSync(dir).isDirectory(), 'run directory must be a directory');
  for (const name of ['recording.json', 'account.json', 'decisions.json', 'synthesis.json', 'spec.json',
    'reference-suite.json', 'protocol-pipeline.json', 'policies']) {
    try { lstatSync(join(dir, name)); throw new Error(`protocol output already exists: ${name}`); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const run = read(join(dir, 'run.json'));
  same(run.network, NETWORK, 'run network');
  const owner = run.walkthrough?.owner_transaction;
  requireThat(owner && hash(owner.hash) && Number.isInteger(owner.ledger) && owner.ledger > 0
    && decimal(owner.balance_before) && decimal(owner.balance_after) && decimal(owner.returned_amount)
    && BigInt(owner.returned_amount) > 0n && BigInt(owner.balance_after) - BigInt(owner.balance_before) === BigInt(owner.returned_amount),
  'protocol recording requires a confirmed nonzero owner output and matched balance effect');
  const expectedToken = run.walkthrough.kind === 'blend_claim' ? BLND : PROTOCOL_TARGETS.swap_output;
  same(owner.output_token, expectedToken, 'owner output token');
  const trust = [env.OZPB_SIGNED_REGISTRY_SNAPSHOT, env.OZPB_REGISTRY_ROOTS_FILE, env.OZPB_REGISTRY_MIN_VERSION];
  requireThat(trust.every(Boolean) || trust.every((v) => !v), 'configure all three registry trust inputs or none');
  const [snapshot, roots, minimum] = trust.every(Boolean) ? [resolve(trust[0]), resolve(trust[1]), trust[2]]
    : [join(ROOT, 'docs/examples/registry.signed.json'), join(ROOT, 'docs/examples/registry-roots.json'), '4'];
  requireThat(/^[1-9][0-9]*$/.test(minimum) && existsSync(snapshot) && existsSync(roots), 'invalid registry trust configuration');
  requireThat(hash(env.OZPB_REGISTRY_SNAPSHOT_ROOT), 'protocol flow requires the explicit resolved registry root');
  const command = env.OZPB_BIN ? [env.OZPB_BIN.includes('/') ? resolve(env.OZPB_BIN) : env.OZPB_BIN]
    : ['cargo', 'run', '--locked', '-q', '-p', 'ozpb-cli', '--'];
  function cli(stage, args, filename, tag = stage, parser = parseJsonExact) {
    const result = spawnSync(command[0], [...command.slice(1), stage, ...args], {
      cwd: ROOT, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024,
    });
    if (result.stderr) writeFileSync(join(dir, `${tag}.log`), result.stderr, { flag: 'wx', mode: 0o600 });
    if (result.error) throw result.error;
    requireThat(result.status === 0, `${stage} failed; see the local run log`);
    if (!filename) return;
    writeFileSync(join(dir, filename), result.stdout, { flag: 'wx', mode: 0o600 });
    return parser(result.stdout);
  }
  const recording = cli('record', ['--tx-hash', owner.hash, '--rpc-url', env.OZPB_RPC_URL || 'https://soroban-testnet.stellar.org',
    '--network', NETWORK], 'recording.json', 'record', (text) => JSON.parse(text, (_k, v, context) =>
    typeof v === 'number' && !Number.isSafeInteger(v) && /^-?\d+$/.test(context?.source ?? '') ? BigInt(context.source) : v));
  same(recording.bundle?.ledger, owner.ledger, 'confirmed recording ledger');
  const inputs = protocolInputs(run, recording);
  save(join(dir, 'account.json'), inputs.account);
  save(join(dir, 'decisions.json'), inputs.decisions);
  const synthesis = cli('synthesize', ['--bundle', join(dir, 'recording.json'), '--selected-authorizer', run.account,
    '--account', join(dir, 'account.json'), '--signed-registry', snapshot, '--registry-roots', roots,
    '--registry-min-version', minimum, '--decisions', join(dir, 'decisions.json'), '--template-family', 'policy-templates/scope@1'], 'synthesis.json');
  const spec = validateProtocolSynthesis(synthesis, run, inputs, env.OZPB_REGISTRY_SNAPSHOT_ROOT);
  // The adapter the router rule relies on, and what it leaves open. Whoever holds a root key can
  // sign the binding, so a registry the public development key can sign is labeled a development
  // assertion, whichever files the operator pointed at; any other root is the operator's.
  const disclosure = adapterDisclosure(spec);
  requireThat((disclosure.adapter !== null) === (run.walkthrough.kind === 'soroswap_swap'), 'unexpected adapter identity');
  const developmentKeys = Object.values(read(join(ROOT, 'docs/examples/registry-roots.json')).keys);
  const configuredKeys = Object.values(read(roots).keys ?? {}).map((key) => String(key).toLowerCase());
  const registryLabel = configuredKeys.some((key) => developmentKeys.includes(key)) ? 'development_root' : 'operator_root';
  const specPath = join(dir, 'spec.json'); save(specPath, spec);
  const reference = cli('reference-suite', ['--spec', specPath], 'reference-suite.json');
  same(reference.report?.spec_hash, synthesis.spec_hash, 'reference spec hash');
  same(reference.all_agree, true, 'reference verdict'); same(reference.disagreements, 0, 'reference disagreements');
  same(reference.missing_classes, [], 'reference coverage'); same(reference.unmodeled_reviewed_policies, [], 'reference modeled policies');
  requireThat(Number.isSafeInteger(reference.total) && reference.total > 0, 'missing protocol reference cases');
  mkdirSync(join(dir, 'policies'));
  const artifacts = [];
  for (let index = 0; index < spec.rules.length; index++) {
    const out = join(dir, 'policies', `rule-${index}`);
    cli('generate', ['--spec', specPath, '--rule', String(index), '--out', out], undefined, `generate-${index}`);
    const wasms = readdirSync(out).filter((name) => name.endsWith('.wasm'));
    requireThat(wasms.length === 1, 'expected exactly one Wasm per rule');
    const wasm = join(out, wasms[0]); const manifestPath = join(out, 'build-manifest.json'); const manifest = read(manifestPath);
    same(manifest.rule_index, index, 'manifest rule index'); same(manifest.spec_hash, synthesis.spec_hash, 'manifest full spec identity');
    same(manifest.registry_snapshot, spec.registry_snapshot, 'manifest registry root');
    same(manifest.wasm_hash, createHash('sha256').update(readFileSync(wasm)).digest('hex'), 'manifest Wasm hash');
    const verified = cli('verify', ['--spec', specPath, '--rule', String(index), '--generated-dir', out,
      '--wasm', wasm, '--manifest', manifestPath], `verification-${index}.json`, `verify-${index}`);
    same(verified.matches, true, 'artifact reproduction'); same(verified.models_all_policies, true, 'modeled policies');
    same(verified.unmodeled_reviewed_policies, [], 'unmodeled policies');
    same(verified.spec_conformance, 'conforms (validated PolicySpec v1)', 'spec conformance');
    same(verified.source_reproduction, 'reproduced: generated non-lock files are byte-identical', 'source reproduction');
    same(verified.wasm_reproduction, 'reproduced: Wasm and BuildManifest are identical', 'Wasm reproduction');
    requireThat(/^pass: [1-9][0-9]* constraint-derived cases all agree$/.test(verified.offline_behavioral_conformance), 'incomplete behavioral conformance');
    requireThat(hash(manifest.normalized_input_hash), 'missing normalized input identity');
    same(verified.normalized_input_hash, manifest.normalized_input_hash, 'verification input');
    same(verified.current_network_preflight, 'not_checked_here: state-dependent (wallet/live)', 'verification boundary');
    artifacts.push({ rule_index: index, directory: out, wasm, manifest: manifestPath, wasm_hash: manifest.wasm_hash,
      normalized_input_hash: manifest.normalized_input_hash });
  }
  Object.assign(run, { spec: specPath, registry_root: spec.registry_snapshot, valid_until_ledger: inputs.decisions.valid_until_ledger });
  run.walkthrough.artifacts = artifacts;
  writeJson(join(dir, 'run.json'), run);
  save(join(dir, 'protocol-pipeline.json'), { schema_version: 1, account: run.account, kind: run.walkthrough.kind,
    recorded_transaction: owner.hash, recording_hash: recording.recording_hash, acquisition_trust: 'rpc_reported',
    synthesis_recording_hash: spec.evidence.recordings[0].hash, synthesis_trust: 'self_supplied', spec_hash: synthesis.spec_hash,
    reference_cases: reference.total, artifact_reproduction: 'matched', current_network_preflight: 'not_checked_here',
    adapter: disclosure.adapter && { ...disclosure.adapter, registry_root: spec.registry_snapshot, registry: registryLabel },
    high_blast_radius: disclosure.high_blast_radius,
    ...(run.walkthrough.kind === 'soroswap_swap' ? { deadline_unix: String(run.walkthrough.deadline) } : {}),
    artifacts: artifacts.map(({ rule_index, wasm_hash, normalized_input_hash }) => ({ rule_index, wasm_hash, normalized_input_hash })) });
  return artifacts;
}
if (isMainModule(import.meta.url)) {
  const args = process.argv.slice(2);
  requireThat(args.length === 2 && args[0] === '--run-dir', 'usage: protocol-flow.mjs --run-dir DIRECTORY');
  console.log(`Reproduced ${runProtocolFlow(args[1]).length} independent protocol capabilities.`);
}
