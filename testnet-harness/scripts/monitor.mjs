// A one-shot observation of this installed grant and its code pins. No daemon, signatures,
// submissions or claim that this checks the account's complete authority surface.
import { join } from 'node:path';
import { isMainModule } from './cli-entry.mjs';
import { inspectInstalledGrant } from './lifecycle.mjs';
import * as rpc from './rpc.mjs';

export async function monitorGrant(dir, overrides = {}) {
  const deps = { ...rpc, ...overrides };
  // Local CLI operator selects --run-dir; this is not a server request or a remote input.
  // nosec
  const path = join(dir, 'run.json');
  const run = deps.readJson(path);
  const spec = deps.readJson(join(dir, 'spec.json'));
  if (run.lifecycle !== undefined && (!run.lifecycle || !Array.isArray(run.lifecycle.removals)
    || !Array.isArray(run.lifecycle.configuration_checks ?? []))) throw new Error('malformed lifecycle journal');
  run.lifecycle ??= { removals: [] };
  const checks = run.lifecycle.configuration_checks ?? [];
  try {
    const observed = await inspectInstalledGrant(run, spec, deps);
    run.lifecycle.configuration_checks = [...checks, observed];
    deps.writeJson(path, run);
    return observed;
  } catch (error) {
    run.lifecycle.configuration_checks = [...checks, { configuration: 'drift_or_unavailable', read_ledgers: null }];
    deps.writeJson(path, run);
    throw error;
  }
}

if (isMainModule(import.meta.url)) {
  const opts = rpc.args();
  if (!opts['run-dir']) throw new Error('usage: monitor.mjs --run-dir DIRECTORY');
  const observed = await monitorGrant(opts['run-dir']);
  console.log(`grant ${observed.rule_id} configuration and code pins matched in non-atomic reads: ${JSON.stringify(observed.read_ledgers)}`);
}
