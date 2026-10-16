// Export local observations, not a verdict or a cryptographic attestation. Only explicitly
// selected, typed fields leave the run directory. Raw RPC errors and paths never do.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HASH = /^[0-9a-f]{64}$/;
const ADDRESS = /^[CG][A-Z2-7]{55}$/;
const TESTNET = 'Test SDF Network ; September 2015';
const MAX_FILE = 64 * 1024 * 1024;
const fail = () => { throw new Error('invalid or inconsistent evidence record'); };
const object = (v) => v && typeof v === 'object' && !Array.isArray(v) ? v : fail();
const match = (v, pattern) => typeof v === 'string' && pattern.test(v) ? v : fail();
const uint = (v) => Number.isSafeInteger(v) && v >= 0 && v <= 0xffff_ffff ? v : fail();
const choice = (v, values) => values.includes(v) ? v : fail();
const optional = (v, validate) => v === undefined ? null : validate(v);
const hash = (v) => match(v, HASH);
const address = (v) => match(v, ADDRESS);
const amount = (v) => {
  match(v, /^(0|[1-9][0-9]{0,38})$/);
  return BigInt(v) <= (1n << 127n) - 1n ? v : fail();
};
const timestamp = (v) => {
  match(v, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  return Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v ? v : fail();
};

function readFile(path) {
  let stat;
  try { stat = lstatSync(path); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  if (!stat.isFile() || stat.size > MAX_FILE) fail(); // includes symlinks
  return readFileSync(path);
}

function provenance(value) {
  if (value === null) return { status: 'unavailable' };
  const p = object(value);
  if (p.schema_version !== 1 || typeof p.checkout_dirty !== 'boolean') fail();
  const cli = object(p.cli);
  const mode = choice(cli.mode, ['cargo', 'external']);
  const binary = mode === 'external' ? hash(cli.binary_sha256) : null;
  if (mode === 'cargo' && cli.binary_sha256 !== null) fail();
  const started = timestamp(p.started_at);
  const finished = p.finished_at === null ? null : timestamp(p.finished_at);
  const exit = p.exit_code === null ? null : uint(p.exit_code);
  if ((finished === null) !== (exit === null) || exit > 255 || (finished !== null && finished < started)) fail();
  return {
    status: exit === null ? 'unfinished' : exit === 0 ? 'exited_zero' : 'exited_nonzero',
    started_at: started, finished_at: finished, exit_code: exit,
    checkout_commit: match(p.checkout_commit, /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/),
    checkout_dirty: p.checkout_dirty,
    node_version: match(p.node_version, /^\d{1,3}\.\d{1,3}\.\d{1,3}$/),
    cli: { mode, binary_sha256: binary },
  };
}

function invocation(value) {
  const v = object(value);
  const result = choice(v.result, ['permit', 'deny']);
  const common = {
    signer: choice(v.signer, ['owner', 'delegate']), rule: uint(v.rule),
    amount: amount(v.amount), to: address(v.to), result,
  };
  if (result === 'permit') {
    if (v.code !== undefined || v.enforcer !== undefined) fail();
    return { ...common, observation: 'submitted_transaction', transaction: hash(v.hash) };
  }
  if (v.hash !== undefined) fail(); // simulation denials have no submitted transaction
  return {
    ...common, observation: 'enforcing_simulation', transaction: null,
    enforcer: v.enforcer === null ? null : address(v.enforcer),
    code: v.code === null ? null : uint(v.code),
  };
}

function runRecord(value) {
  if (value === null) return null;
  const r = object(value);
  if (r.network !== TESTNET) fail();
  const owner = object(r.owner);
  const ownerKind = choice(owner.kind, ['ed25519', 'passkey']);
  const ownerSummary = ownerKind === 'ed25519'
    ? { kind: ownerKind, address: address(owner.address) }
    : { kind: ownerKind, verifier: address(owner.verifier), verifier_code_hash: hash(owner.verifier_code_hash) };
  const tx = object(r.tx);
  const transactions = {};
  for (const key of ['deploy_verifier', 'deploy_account', 'fund_account', 'add_backup_owner', 'upload_policy', 'create_policy', 'add_context_rule']) {
    if (tx[key] !== undefined) transactions[key] = hash(tx[key]);
  }
  const policy = optional(r.policy, address);
  const policyHash = optional(r.policy_wasm_hash, hash);
  const rule = optional(r.rule_id, uint);
  if ((policy === null) !== (policyHash === null) || (rule === null) !== (transactions.add_context_rule === undefined)) fail();
  if (rule !== null && policy === null) fail();
  let authority = { status: 'not_recorded' };
  if (r.authority_check !== undefined) {
    const a = object(r.authority_check);
    if (a.refused !== undefined) {
      if (!Array.isArray(a.refused) || a.refused.length === 0 || rule !== null
        || a.authority_commitment !== undefined || a.rechecked_at_ledger !== undefined) fail();
      authority = { status: 'refused', reason_count: a.refused.length };
    } else {
      const checked = uint(a.checked_at_ledger);
      const rechecked = uint(a.rechecked_at_ledger);
      if (rechecked < checked) fail();
      authority = {
        status: 'rechecked', authority_commitment: hash(a.authority_commitment),
        checked_at_ledger: checked, rechecked_at_ledger: rechecked,
      };
    }
  }
  const invocations = r.invocations ?? [];
  if (!Array.isArray(invocations) || invocations.length > 1000) fail();
  return {
    network: 'testnet', protocol: uint(r.protocol), account: address(r.account),
    account_code_hash: hash(r.account_code_hash), target: address(r.sac), owner: ownerSummary,
    delegate: address(r.delegate), recipient: address(r.recipient), amount: amount(r.amount),
    valid_until_ledger: optional(r.valid_until_ledger, uint), registry_root: optional(r.registry_root, hash),
    policy, policy_wasm_hash: policyHash, rule_id: rule,
    installation: rule === null ? 'not_recorded' : 'recorded', transactions, authority,
    invocations: invocations.map(invocation),
  };
}

export function exportEvidence(runDir) {
  if (!lstatSync(runDir).isDirectory()) fail();
  const artifacts = {};
  function artifact(key, path) {
    const bytes = readFile(path);
    if (bytes !== null) artifacts[key] = { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
    return bytes;
  }
  const decode = (bytes) => bytes === null ? null : JSON.parse(bytes.toString('utf8'));
  const run = runRecord(decode(artifact('run', join(runDir, 'run.json'))));
  const source = provenance(decode(artifact('provenance', join(runDir, 'provenance.json'))));
  if (run === null && source.status === 'unavailable') fail();
  for (const [key, file] of [['spec', 'spec.json'], ['recording', 'recording.json'], ['import_bundle', 'import-bundle.json']]) {
    artifact(key, join(runDir, file));
  }
  const policyDir = join(runDir, 'policy');
  let policyExists = false;
  try { if (!lstatSync(policyDir).isDirectory()) fail(); policyExists = true; }
  catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (policyExists) {
    artifact('build_manifest', join(policyDir, 'build-manifest.json'));
    const wasms = readdirSync(policyDir).filter((name) => name.endsWith('.wasm'));
    if (wasms.length > 1) fail();
    if (wasms.length === 1) artifact('policy_wasm', join(policyDir, wasms[0]));
  }
  if (run?.policy_wasm_hash && artifacts.policy_wasm && run.policy_wasm_hash !== artifacts.policy_wasm.sha256) fail();
  return {
    schema_version: 1,
    evidence_kind: 'local_harness_record',
    limitations: [
      'Local files can be edited; this summary is not authenticated ledger evidence or a milestone verdict.',
      'Artifact hashes identify exact file bytes, not independent reproduction or canonical spec identity.',
      'A missing install record does not prove that nothing was submitted.',
      'Denials describe enforcing simulations, not failed on-chain transactions.',
      'Passkey runs use an exportable software credential in a virtual authenticator.',
      'Authority trust, when used, is operator-supplied test configuration.',
    ],
    provenance: source, run, artifacts,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [flag, runDir, ...extra] = process.argv.slice(2);
    if (flag !== '--run-dir' || !runDir || extra.length) fail();
    console.log(JSON.stringify(exportEvidence(resolve(runDir)), null, 2));
  } catch {
    console.error('evidence export failed: expected --run-dir with valid, consistent local records');
    process.exitCode = 1;
  }
}
