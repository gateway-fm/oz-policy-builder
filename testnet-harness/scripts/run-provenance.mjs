// Run bookkeeping only: no keys, endpoint URLs, environment dump, or tool output is saved.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  accessSync, closeSync, constants, fstatSync, ftruncateSync, openSync, readFileSync, readdirSync,
  realpathSync, statSync, writeFileSync, writeSync,
} from 'node:fs';
import { delimiter, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeEvidence } from './evidence.mjs';
import { isMainModule } from './cli-entry.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const FILE = 'provenance.json';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function withFile(path, flags, maxBytes, action) {
  const fd = openSync(path, flags | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes) throw new Error('expected a bounded regular file');
    return action(fd);
  } finally { closeSync(fd); }
}

export function startRun(runDir, env = process.env) {
  // A fresh directory prevents old install IDs or outcomes becoming this attempt's evidence.
  if (readdirSync(runDir).length) throw new Error('run directory must be empty');
  const git = (...args) => execFileSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  let cli = { mode: 'cargo', binary_sha256: null };
  if (env.OZPB_BIN) {
    const candidates = env.OZPB_BIN.includes('/') ? [resolve(env.OZPB_BIN)]
      : (env.PATH ?? '').split(delimiter).map((dir) => resolve(dir, env.OZPB_BIN));
    const binary = candidates.find((path) => {
      try {
        if (!statSync(path).isFile()) return false;
        accessSync(path, constants.X_OK);
        return true;
      } catch { return false; }
    });
    if (!binary) throw new Error('configured CLI is not executable');
    // An operator-selected executable can be a symlink (as in a package-manager bin dir).
    // Resolve it explicitly, then hash the same regular-file descriptor we checked.
    cli = { mode: 'external', binary_sha256: withFile(realpathSync(binary), constants.O_RDONLY,
      256 * 1024 * 1024, (fd) => sha256(readFileSync(fd))) };
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

function updateRun(runDir, change) {
  const path = join(runDir, FILE);
  withFile(path, constants.O_RDWR, 64 * 1024, (fd) => {
    const record = JSON.parse(readFileSync(fd, 'utf8'));
    if (record?.schema_version !== 1) throw new Error('invalid run provenance');
    change(record);
    const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`);
    let written = 0;
    while (written < bytes.length) {
      const count = writeSync(fd, bytes, written, bytes.length - written, written);
      if (count === 0) throw new Error('provenance write made no progress');
      written += count;
    }
    ftruncateSync(fd, bytes.length);
  });
}

export function finishRun(runDir, exitCode) {
  if (!Number.isInteger(exitCode) || exitCode < 0 || exitCode > 255) throw new Error('invalid exit code');
  updateRun(runDir, (record) => {
    if (record.finished_at !== null || record.exit_code !== null) {
      throw new Error('run provenance is not an unfinished run');
    }
    record.finished_at = new Date().toISOString();
    record.exit_code = exitCode;
  });
}

export function finalizeRun(runDir, exitCode) {
  finishRun(runDir, exitCode);
  try { writeEvidence(runDir); }
  catch (error) {
    // Export failure changes a successful wrapper exit to failure. Keep that in provenance
    // as well; an original failure keeps its own code even if reporting fails too.
    updateRun(runDir, (record) => { record.exit_code = exitCode || 1; });
    throw error;
  }
  return exitCode;
}

if (isMainModule(import.meta.url)) {
  let failureCode = 1;
  try {
    const [action, runDir, code, ...extra] = process.argv.slice(2);
    if (!runDir || extra.length) throw new Error('usage');
    if (action === 'start' && code === undefined) startRun(runDir);
    else if (['finish', 'finalize'].includes(action) && /^(0|[1-9][0-9]{0,2})$/.test(code) && Number(code) <= 255) {
      if (action === 'finalize') {
        failureCode = Number(code) || 1;
        process.exitCode = finalizeRun(runDir, Number(code));
      } else finishRun(runDir, Number(code));
    }
    else throw new Error('usage');
  } catch {
    // Filesystem and subprocess errors can include local paths or operator configuration.
    console.error('run bookkeeping failed; use start <empty-run-dir> or finish/finalize <run-dir> <exit-code>');
    process.exitCode = failureCode;
  }
}
