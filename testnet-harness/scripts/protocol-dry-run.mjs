// Offline account-Wasm evidence for each generated W1/W3 capability, before any installation.
// Synthetic policy addresses and proposed rule IDs are local execution identities, not ledger claims.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StrKey } from '@stellar/stellar-sdk';
import { WalletNetwork } from '../../wallet/server/network.mjs';
import { loadBundleFiles } from './bundle-command.mjs';
import { isMainModule } from './cli-entry.mjs';
import { bundleCheckRequest, checkBundleArtifacts } from './permission-bundle.mjs';
import { RawJson, parseJsonExact, requestText } from './raw-json.mjs';
import { PINNED_ACCOUNT_WASM, RPC_URL, loadKey } from './rpc.mjs';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const FILES = ['Cargo.toml', 'rust-toolchain.toml', 'rustfmt.toml', 'src/lib.rs', 'src/contract.rs'];
const requireThat = (ok, message) => { if (!ok) throw new Error(message); };
const hash = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const save = (path, bytes) => writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });

/** Independently recompute the acceptance counts and bind the report to the exact request. */
export function checkProtocolDryRun(report, request, specHash) {
  const candidate = request.candidate, binding = report?.binding;
  requireThat(report?.schema === 'ozpb:dry-run:v1' && hash(report.run_hash) && report.complete === false
    && report.artifact_verification?.matches === true, 'invalid account-Wasm report');
  assert.deepEqual({ spec_hash: binding?.spec_hash, account_address: binding?.account_address,
    account_code_hash: binding?.account_code_hash, network_id: binding?.network_id,
    registry_snapshot_root: binding?.registry_snapshot_root, rule_index: binding?.rule_index,
    candidate_context_rule_id: binding?.candidate_context_rule_id }, {
    spec_hash: specHash, account_address: candidate.account_address, account_code_hash: PINNED_ACCOUNT_WASM,
    network_id: candidate.network_id, registry_snapshot_root: candidate.spec.registry_snapshot,
    rule_index: candidate.rule_index, candidate_context_rule_id: request.candidate_context_rule_id,
  }, 'account-Wasm report candidate changed');
  const codes = Object.fromEntries(candidate.binding_set.bindings.map((b) => [b.contract_address, b.observed_wasm_hash]));
  assert.deepEqual(binding.policy_code_hashes, codes, 'account-Wasm report policy bindings changed');
  requireThat(hash(binding.suite_hash) && hash(binding.binding_set_hash), 'missing report binding hashes');
  requireThat(Array.isArray(report.layers) && report.layers.length === 4
    && report.layers.every((l, i) => l.id === ['reference', 'account_wasm', 'captured_target', 'live_enforcement'][i]),
  'invalid report layers');
  const [reference, account, captured, live] = report.layers;
  const execution = account.execution, selected = candidate.binding_set.bindings.find((b) => b.rule_index === candidate.rule_index);
  requireThat(reference.status === 'passed' && account.status === 'passed' && captured.status === 'unavailable'
    && live.status === 'unavailable' && report.layers.every((l) => l.writes_committed === false)
    && execution?.run_hash === report.run_hash && execution.suite_hash === binding.suite_hash
    && execution.policy_address === selected.contract_address && execution.policy_code_hash === selected.observed_wasm_hash
    && execution.source_network_id === candidate.network_id && hash(execution.execution_network_id)
    && execution.execution_network_id !== candidate.network_id && Array.isArray(execution.cases)
    && account.cases === execution.cases.length, 'account-Wasm execution was not bound or passed');
  const cases = execution.cases;
  requireThat(cases.length > 0 && cases.every((c) => c.agree === true && typeof c.expected_permit === 'boolean'
    && c.permitted === c.expected_permit && (c.permitted || (c.state_unchanged === true
      && ['account', 'policy'].includes(c.refused_by) && Number.isSafeInteger(c.refusal_code)))), 'invalid executed case outcomes');
  const original = cases.some((c) => c.class === 'original' && c.expected_permit && c.permitted);
  const denied = cases.filter((c) => !c.expected_permit && !c.permitted).length;
  assert.deepEqual(report.acceptance, { required_reverted_denials: 5, original_permitted: original,
    executed_layers: [{ layer: 'account_wasm', status: 'passed', original_permitted: original, reverted_denials: denied }],
    meets_minimum: original && denied >= 5 }, 'account-Wasm acceptance differs from executed outcomes');
  requireThat(report.acceptance.meets_minimum, 'account-Wasm report misses original permit or five reverted denials');
  return { rule_index: candidate.rule_index, run_hash: report.run_hash, suite_hash: binding.suite_hash,
    policy_address: selected.contract_address, policy_code_hash: selected.observed_wasm_hash,
    original_permitted: true, reverted_denials: denied, complete: false };
}

export async function runProtocolDryRuns(directory, env = process.env, overrides = {}) {
  const { dir, run, spec, artifacts } = loadBundleFiles(directory);
  requireThat(run.network === 'Test SDF Network ; September 2015' && run.account_code_hash === PINNED_ACCOUNT_WASM
    && ['blend_claim', 'soroswap_swap'].includes(run.walkthrough?.kind) && run.walkthrough.bundle === undefined,
  'offline protocol reports require a fresh W1/W3 testnet candidate');
  // Refuse repeated attempts, including a previous partial execution.
  for (const name of ['account-dry-runs.json', ...spec.rules.flatMap((_r, i) => [`account-dry-run-${i}.json`, `account-dry-run-${i}.failed.json`])]) {
    try { lstatSync(join(dir, name)); throw new Error('account-Wasm report already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const required = (name) => { requireThat(env[name], `protocol dry-run requires ${name}`); return env[name]; };
  const binary = required('OZPB_BIN'), worker = resolve(required('OZPB_NATIVE_WORKER'));
  const roots = resolve(required('OZPB_REGISTRY_ROOTS_FILE')), minimum = required('OZPB_REGISTRY_MIN_VERSION');
  const sources = resolve(required('OZPB_RPC_SOURCES_FILE'));
  const snapshot = new RawJson(readFileSync(resolve(required('OZPB_SIGNED_REGISTRY_SNAPSHOT')), 'utf8'));
  const deps = { checkArtifacts: checkBundleArtifacts, loadKey, execute: spawnSync,
    nativeSource: () => new WalletNetwork({ rpcUrl: env.OZPB_RPC_URL || RPC_URL }).nativeSource(PINNED_ACCOUNT_WASM), ...overrides };
  const identities = await deps.checkArtifacts(spec, artifacts);
  const delegate = deps.loadKey('delegate');
  requireThat(delegate.publicKey() === run.delegate, 'offline delegate differs from run');
  const policies = artifacts.map((artifact, i) => StrKey.encodeContract(createHash('sha256')
    .update(`ozpb:walkthrough:offline-policy:v1:${run.account}:${i}:${artifact.manifest.wasm_hash}`).digest()));
  const temporary = mkdtempSync(join(dirname(resolve(required('OZPB_HARNESS_SECRETS'))), 'ozpb-protocol-dry-run-'));
  const reports = [];
  try {
    const source = await deps.nativeSource();
    save(join(temporary, 'delegate.key'), delegate.secret() + '\n');
    save(join(temporary, 'account.wasm'), Buffer.from(source.accountWasmBase64, 'base64'));
    save(join(temporary, 'ledger.json'), requestText(source.ledger));
    for (const [index, artifact] of artifacts.entries()) {
      // Operator-selected local run directory plus constant names (FILES); this harness CLI
      // has no remote caller, and the bytes only go to the local dry-run as claimed sources.
      // nosemgrep
      const generated = join(dir, 'policies', `rule-${index}`);
      const request = { candidate: bundleCheckRequest({ spec, artifacts, policies, ruleIndex: index,
        signedRegistrySnapshot: snapshot, rpcSource: env.OZPB_RPC_SOURCE || 'testnet' }),
      artifact: { spec, rule_index: index,
        claimed_generated_files: Object.fromEntries(FILES.map((name) => [name, readFileSync(join(generated, name), 'utf8')])),
        claimed_wasm_base64: artifact.wasm.toString('base64'), claimed_build_manifest: artifact.manifest },
      candidate_context_rule_id: index + 1, run_nonce: randomBytes(32).toString('hex') };
      const requestPath = join(temporary, `request-${index}.json`);
      save(requestPath, requestText(request));
      const buildFlags = [['--stellar-binary', env.OZPB_STELLAR_BINARY], ['--build-cache-dir', env.OZPB_BUILD_CACHE_DIR],
        ['--build-jobs', env.OZPB_BUILD_JOBS], ['--build-timeout-secs', env.OZPB_BUILD_TIMEOUT_SECS]]
        .flatMap(([flag, value]) => value ? [flag, String(value)] : []);
      let result;
      try {
        result = deps.execute(binary.includes('/') ? resolve(binary) : binary, ['dry-run', '--request', requestPath,
        '--registry-roots', roots, '--registry-min-version', minimum, '--rpc-sources', sources,
        '--native-worker', worker, '--delegate-key-file', join(temporary, 'delegate.key'),
        '--account-wasm', join(temporary, 'account.wasm'), '--source-ledger', join(temporary, 'ledger.json'), ...buildFlags],
      { cwd: ROOT, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024 });
        // CLI stdout is its machine report, never the seed; stderr is never retained.
        requireThat(!result.error && result.status === 0, 'account-Wasm CLI failed');
        const report = parseJsonExact(result.stdout);
        const summary = checkProtocolDryRun(report, request, identities[index].spec_hash);
        requireThat(report.layers[1].execution.source_ledger === source.ledger.sequence
          && report.layers[1].execution.delegate_address === delegate.publicKey(), 'account-Wasm source or delegate changed');
        save(join(dir, `account-dry-run-${index}.json`), result.stdout);
        reports.push(summary);
      } catch {
        // Failed/local reports are confidential diagnostics, not exported passing evidence.
        const stdout = typeof result?.stdout === 'string' && Buffer.byteLength(result.stdout) <= 64 * 1024 * 1024
          ? result.stdout : '';
        save(join(dir, `account-dry-run-${index}.failed.json`), stdout || JSON.stringify({
          status: 'failed_without_report', exit_status: result?.status ?? null, installation_attempted: false }));
        throw new Error(`account-Wasm dry-run failed; no installation attempted; inspect account-dry-run-${index}.failed.json locally`);
      }
    }
    const summary = { schema_version: 1, account: run.account, spec_hash: identities[0].spec_hash,
      execution: 'offline_synthetic_policy_addresses_and_proposed_rule_ids', source_ledger: source.ledger.sequence, reports };
    save(join(dir, 'account-dry-runs.json'), requestText(summary));
    return summary;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
if (isMainModule(import.meta.url)) {
  const args = process.argv.slice(2);
  requireThat(args.length === 2 && args[0] === '--run-dir', 'usage: protocol-dry-run.mjs --run-dir DIRECTORY');
  console.log(`Account-Wasm permit/deny bar met for ${(await runProtocolDryRuns(args[1])).reports.length} independent rules.`);
}
