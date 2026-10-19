// The seam between the harness and the authority check: run `ozpb check-policy-call-surface` or
// `ozpb prepare-install-intent` and return its JSON answer, or throw a `ToolError`.
//
// The wallet recomputes the check itself, against the RPC source the operator configured; it
// never accepts an answer handed to it. So the runner takes the operator's registry roots, the
// anti-rollback floor and the RPC source file, and the request names only a source.
//
// Exit status, per the CLI: the check exits 0 for any answer, refused or not; the intent exits 1
// when anything is refused or unresolved, and prints JSON only on success. Either way a non-zero
// exit is not an answer: it becomes a `ToolError`, which the wallet treats as a refusal. The code
// is read only from the first line, `Error: E_CODE: message` (anyhow over the tool's error), and
// each following `  - …` line is one finding. Anything else on a non-zero exit (an unreadable or
// unparsable file, a usage error, a crash) is `E_TOOL_FAILED`.
//
// The check rebuilds the generated policy to recognize it, offline, so it needs the same
// stellar-cli and a warm build cache as the `ozpb generate` run: `build` passes them through.
//
// Authority-runner tests use fixtures. Installer identity tests run this tree's real CLI.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { requestText } from './raw-json.mjs';

export class ToolError extends Error {
  constructor(code, message, details = []) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

/** The error a non-zero exit stands for, from its stderr. */
export function toolErrorFrom(stderr, status) {
  const lines = stderr.split('\n');
  const head = /^Error: (E_[A-Z0-9_]+): (.*)$/.exec(lines[0] ?? '');
  if (!head) return new ToolError('E_TOOL_FAILED', `exit ${status}: ${lines.slice(0, 6).join(' | ').trim()}`);
  const details = lines.slice(1).filter((l) => l.startsWith('  - ')).map((l) => l.slice(4));
  return new ToolError(head[1], `${head[1]}: ${head[2]}`, details);
}

function run(argv, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
}

/** Validate and hash the already-read spec with Rust's canonical implementation. The existing
 * reference-suite report carries that hash; its behavioral results are not an install verdict.
 * A private copy keeps the CLI and installer on the same input if the original file changes.
 */
export async function cliSpecHash(spec) {
  const command = process.env.OZPB_BIN
    ? [process.env.OZPB_BIN]
    : ['cargo', 'run', '--locked', '-q', '--manifest-path',
      fileURLToPath(new URL('../../Cargo.toml', import.meta.url)), '-p', 'ozpb-cli', '--'];
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-spec-'));
  try {
    const path = join(dir, 'spec.json');
    writeFileSync(path, requestText(spec), { mode: 0o600 });
    const { status, stdout, stderr } = await run([...command, 'reference-suite', '--spec', path]);
    if (status !== 0) throw toolErrorFrom(stderr, status);
    let hash;
    try { hash = JSON.parse(stdout).report?.spec_hash; } catch { /* rejected below */ }
    if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) {
      throw new ToolError('E_TOOL_OUTPUT', 'reference-suite printed no canonical spec hash');
    }
    return hash;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * `command`: the argv prefix that runs `ozpb`, e.g. `['target/debug/ozpb']` or
 * `['cargo', 'run', '-q', '-p', 'ozpb-cli', '--']`.
 */
export function cliCheckRunner({ command, registryRoots, registryMinVersion, rpcSources, build = {}, env = {} }) {
  if (!command?.length) throw new Error('the check runner needs the ozpb command');
  const buildFlags = [
    ['--stellar-binary', build.stellarBinary], ['--build-cache-dir', build.cacheDir],
    ['--build-jobs', build.jobs], ['--build-timeout-secs', build.timeoutSecs],
  ].flatMap(([flag, value]) => (value === undefined || value === null || value === '' ? [] : [flag, String(value)]));
  async function call(subcommand, request) {
    // The request goes by file, in a private directory removed afterwards.
    const dir = mkdtempSync(join(tmpdir(), 'ozpb-check-'));
    try {
      const path = join(dir, 'request.json');
      writeFileSync(path, requestText(request), { mode: 0o600 });
      const { status, stdout, stderr } = await run([
        ...command, subcommand, '--request', path, '--registry-roots', registryRoots,
        '--registry-min-version', String(registryMinVersion), '--rpc-sources', rpcSources, ...buildFlags,
      ], env);
      if (status !== 0) throw toolErrorFrom(stderr, status);
      try {
        return JSON.parse(stdout);
      } catch {
        throw new ToolError('E_TOOL_OUTPUT', `${subcommand} printed no JSON answer`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  return {
    checkPolicyCallSurface: (request) => call('check-policy-call-surface', request),
    prepareInstallIntent: (request) => call('prepare-install-intent', request),
  };
}
