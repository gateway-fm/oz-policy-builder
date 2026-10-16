// Run bookkeeping only: no keys, endpoint URLs, environment dump, or tool output is saved.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { delimiter, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const FILE = 'provenance.json';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function startRun(runDir, env = process.env) {
  // A fresh directory prevents old install IDs or outcomes becoming this attempt's evidence.
  if (readdirSync(runDir).length) throw new Error('run directory must be empty');
  const git = (...args) => execFileSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  let cli = { mode: 'cargo', binary_sha256: null };
  if (env.OZPB_BIN) {
    const candidates = env.OZPB_BIN.includes('/') ? [resolve(env.OZPB_BIN)]
      : (env.PATH ?? '').split(delimiter).map((dir) => resolve(dir, env.OZPB_BIN));
    const binary = candidates.find((path) => {
      try { return statSync(path).isFile() && (statSync(path).mode & 0o111); } catch { return false; }
    });
    if (!binary) throw new Error('configured CLI is not executable');
    cli = { mode: 'external', binary_sha256: sha256(readFileSync(binary)) };
  }
  const record = {
    schema_version: 1,
    started_at: new Date().toISOString(),
    finished_at: null,
    exit_code: null,
    checkout_commit: git('rev-parse', 'HEAD'),
    checkout_dirty: git('status', '--porcelain', '--untracked-files=normal') !== '',
    node_version: process.versions.node,
    cli,
  };
  writeFileSync(join(runDir, FILE), `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return record;
}

export function finishRun(runDir, exitCode) {
  if (!Number.isInteger(exitCode) || exitCode < 0 || exitCode > 255) throw new Error('invalid exit code');
  const path = join(runDir, FILE);
  const record = JSON.parse(readFileSync(path, 'utf8'));
  if (record.schema_version !== 1 || record.finished_at !== null || record.exit_code !== null) {
    throw new Error('run provenance is not an unfinished run');
  }
  record.finished_at = new Date().toISOString();
  record.exit_code = exitCode;
  writeFileSync(path, `${JSON.stringify(record, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [action, runDir, code, ...extra] = process.argv.slice(2);
    if (!runDir || extra.length) throw new Error('usage');
    if (action === 'start' && code === undefined) startRun(runDir);
    else if (action === 'finish' && /^(0|[1-9][0-9]{0,2})$/.test(code)) finishRun(runDir, Number(code));
    else throw new Error('usage');
  } catch {
    // Filesystem and subprocess errors can include local paths or operator configuration.
    console.error('run provenance failed; use start <empty-run-dir> or finish <run-dir> <exit-code>');
    process.exitCode = 1;
  }
}
