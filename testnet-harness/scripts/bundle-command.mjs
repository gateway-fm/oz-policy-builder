// Explicit local CLI entrypoints for the closed protocol bundle; no remote request interface.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { isMainModule } from './cli-entry.mjs';
import { cliCheckRunner } from './check-runner.mjs';
import { revokePermissionBundle } from './bundle-cleanup.mjs';
import { installPermissionBundle } from './bundle-install.mjs';
import { inspectBundleGrant } from './bundle-grant.mjs';
import { RawJson, parseJsonExact } from './raw-json.mjs';
import { walletTrust } from './wallet-decision.mjs';
import { args, redactSecrets, writeJson } from './rpc.mjs';
import { childDeadline } from './failure-cleanup.mjs';
const requireThat = (ok, text) => { if (!ok) throw new Error(text); };

export function loadBundleFiles(directory, expectedRunHash) {
  const dir = resolve(directory), runPath = join(dir, 'run.json');
  // `directory` is the run directory `run.sh` created, or one its operator names on the command
  // line; no server or remote request reaches this script. The basename is fixed to that
  // run's own journal, whose digest can pin a cleanup child to the exact snapshot.
  // nosec
  const bytes = readFileSync(runPath);
  if (expectedRunHash !== undefined) requireThat(/^[0-9a-f]{64}$/.test(expectedRunHash)
    && createHash('sha256').update(bytes).digest('hex') === expectedRunHash, 'protocol cleanup run snapshot changed');
  const run = parseJsonExact(bytes.toString('utf8'));
  const spec = parseJsonExact(readFileSync(join(dir, 'spec.json'), 'utf8'));
  requireThat(resolve(run.spec) === join(dir, 'spec.json') && Array.isArray(run.walkthrough?.artifacts)
    && run.walkthrough.artifacts.length === spec.rules.length, 'missing protocol artifact inventory');
  const artifacts = spec.rules.map((_rule, index) => {
    const artifactDir = join(dir, 'policies', `rule-${index}`);
    const names = readdirSync(artifactDir).filter((name) => name.endsWith('.wasm'));
    requireThat(names.length === 1, 'expected exactly one indexed protocol Wasm');
    const wasm = join(artifactDir, names[0]), manifestPath = join(artifactDir, 'build-manifest.json');
    const inventory = run.walkthrough.artifacts[index];
    requireThat(inventory.rule_index === index && resolve(inventory.directory) === artifactDir
      && resolve(inventory.wasm) === wasm && resolve(inventory.manifest) === manifestPath, 'changed protocol artifact inventory');
    const manifest = parseJsonExact(readFileSync(manifestPath, 'utf8'));
    requireThat(inventory.wasm_hash === manifest.wasm_hash
      && inventory.normalized_input_hash === manifest.normalized_input_hash, 'changed protocol artifact identity');
    return { wasm: readFileSync(wasm), manifest };
  });
  return { dir, run, spec, artifacts, save: () => writeJson(runPath, run) };
}

export function protocolChecker(run, options, env = process.env) {
  requireThat(options.confirm === 'operator', 'protocol installation requires explicit --confirm operator');
  const required = (name) => {
    requireThat(typeof env[name] === 'string' && env[name].length > 0, `protocol installation requires ${name}`);
    return env[name];
  };
  const binary = required('OZPB_BIN');
  const runner = cliCheckRunner({ command: [binary.includes('/') ? resolve(binary) : binary],
    registryRoots: resolve(required('OZPB_REGISTRY_ROOTS_FILE')),
    registryMinVersion: required('OZPB_REGISTRY_MIN_VERSION'),
    rpcSources: resolve(required('OZPB_RPC_SOURCES_FILE')),
    build: { stellarBinary: env.OZPB_STELLAR_BINARY, cacheDir: env.OZPB_BUILD_CACHE_DIR,
      jobs: env.OZPB_BUILD_JOBS, timeoutSecs: env.OZPB_BUILD_TIMEOUT_SECS } });
  const snapshot = new RawJson(readFileSync(resolve(required('OZPB_SIGNED_REGISTRY_SNAPSHOT')), 'utf8'));
  const own = run.owner.kind === 'passkey' ? [{ scheme: 'webauthn_p256', public_key: run.owner.public_key }]
    : [{ classic_account: run.owner.address }];
  return { runner, trust: walletTrust({ own, operator: [] }), signedRegistrySnapshot: snapshot,
    rpcSource: env.OZPB_RPC_SOURCE ?? 'testnet', confirm: async () => {
      console.error('Explicit operator mode approves this test grant without a human prompt.');
      return true;
    } };
}

export async function bundleCommand(command, directory, options = {}) {
  requireThat(['install', 'inspect', 'cleanup'].includes(command), 'bundle command is install, inspect or cleanup');
  const input = loadBundleFiles(directory, options['expected-run-sha256']);
  if (command === 'install') {
    const checker = protocolChecker(input.run, options);
    const recording = JSON.parse(readFileSync(join(input.dir, 'recording.json'), 'utf8'), (_key, value, context) =>
      typeof value === 'number' && !Number.isSafeInteger(value) && /^-?\d+$/.test(context?.source ?? '') ? BigInt(context.source) : value);
    return installPermissionBundle({ ...input, checker, recording });
  }
  if (command === 'cleanup') return revokePermissionBundle(input, options.deadline === undefined ? {} : { deadline: options.deadline });
  requireThat(input.run.walkthrough.bundle?.status === 'installed', 'no complete protocol bundle to inspect');
  return Promise.all(input.run.walkthrough.bundle.entries.map((entry) => inspectBundleGrant(input.run, input.spec, entry)));
}

/** The command line. As the failure-cleanup child, cleanup stops itself before the parent's kill. */
export async function bundleMain(argv, { run = bundleCommand, now = () => Date.now() } = {}) {
  const [command, ...rest] = argv;
  const options = args(rest);
  requireThat(options['run-dir'], 'usage: bundle-command.mjs install|inspect|cleanup --run-dir DIRECTORY');
  if (command === 'cleanup') options.deadline = childDeadline(now());
  return run(command, options['run-dir'], options);
}

if (isMainModule(import.meta.url)) {
  let result;
  try { result = await bundleMain(process.argv.slice(2)); } catch (error) {
    if (process.argv[2] !== 'cleanup') throw error;
    // The cleanup child's output is kept in cleanup-child.log: a message, no stack, no secrets.
    console.error(redactSecrets(`bundle cleanup failed: ${error?.message ?? error}`));
    process.exit(1);
  }
  console.log(JSON.stringify(result));
  if (process.argv[2] === 'cleanup' && result.status === 'incomplete') process.exitCode = 1;
}
