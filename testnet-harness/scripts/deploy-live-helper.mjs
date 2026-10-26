// Deploy the atomic live-enforcement helper on testnet, recognize it by its reviewed hash, and probe
// it once each way with a freshly synthesized candidate policy on a throwaway account.
//
//   npm ci --prefix testnet-harness/scripts
//   OZPB_BIN=<built ozpb> node testnet-harness/scripts/deploy-live-helper.mjs [--evidence <out.json>]
//
// Testnet only: the passphrase is pinned and an RPC serving any other network is refused before
// anything is built, funded, signed or sent. In order:
//
//   1. builds `contracts/atomic-live-helper` with `stellar contract build --locked` and refuses
//      unless the Wasm's SHA-256 is `EXPECTED_HELPER_HASH`, the reviewed hash the real-Wasm host
//      tests assert (`execution-runtime/tests/atomic_helper.rs`);
//   2. runs the harness's own setup (`setup.mjs`: Friendbot keys, the pinned OpenZeppelin account
//      with an ed25519 owner), a real owner transfer of 1,000,000 stroops under rule 0
//      (`invoke.mjs`), and the record → synthesize → generate → verify chain
//      (`synthesis-flow.mjs`), so the candidate is a generated policy with a call cap of one for
//      exactly that transfer by a separate delegate;
//   3. uploads and deploys the candidate policy and the helper, each refused unless the network
//      stores the reviewed bytes and the deployed instance reads back with the reviewed code hash;
//   4. builds the four authorization entries itself — the owner's for the account's
//      `add_context_rule` under rule 0, the delegate's for the asset's `transfer` under the
//      candidate rule, each with its signer's `__check_auth` entry, signatures expiring 12
//      ledgers out — and runs one enforce-mode simulation of `install_and_transfer` per case:
//      the recorded 1,000,000 stroops (`target:original:0`) must succeed with exactly that amount
//      moved, the candidate rule returned and the candidate's counter used once; one stroop more
//      (`target:argument-denial:0`) must fail with the policy's `NoTupleMatched` (#6) raised by
//      the policy contract inside the account's authentication. A helper refusal (7001–7009) or
//      an account error is a failed case, never a denial. Nothing is submitted for either case;
//   5. once every case signature has expired, reads back that the account's native balance is
//      what it was before the cases and that the candidate policy reports no installation;
//   6. only if all of that holds, writes public addresses, hashes, ledgers and outcomes to
//      `docs/evidence/atomic-live-helper-testnet-<date>.json` (or `--evidence`), refusing to
//      overwrite. The throwaway keys are deleted on success, failure and SIGINT/SIGTERM/SIGHUP.
//
// The signatures are real: each case's set is a submittable installation and transfer until it
// expires (docs/ATOMIC-LIVE-HELPER.md). They are sent to the testnet RPC endpoint inside the
// simulation request and to nothing else; this script never prints or stores them, and step 5
// checks that nobody submitted them. This is a harness probe with automation keys;
// `live_enforcement` stays unavailable.
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Address, Networks, Operation, StrKey, TransactionBuilder, scValToNative, xdr } from '@stellar/stellar-sdk';

import { checkArtifact } from './artifact.mjs';
import { isMainModule } from './cli-entry.mjs';
import { addContextRuleArgs, contractCall, i128, policyDenial, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import { parseJsonExact } from './raw-json.mjs';
import * as rpc from './rpc.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const HERE = fileURLToPath(new URL('.', import.meta.url));
export const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';
if (Networks.TESTNET !== TESTNET_PASSPHRASE || rpc.NETWORK_PASSPHRASE !== TESTNET_PASSPHRASE) {
  throw new Error('the harness network is not testnet');
}
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hostLine = (text) => String(text).split('\n')[0];

/** The sample permit, and the helper's bound: the permit plus its one-stroop adjacent denial. */
export const PERMIT_AMOUNT = 1_000_000n;
export const MAX_HELPER_AMOUNT = PERMIT_AMOUNT + 1n;
/** Rule 0, the owner's Default rule, authorizes the installation. */
const OWNER_RULE = 0;
/** A fresh pinned account holds only rule 0, so the candidate is allocated rule 1. */
const EXPECTED_RULE_ID = 1;
/** How long each case's signatures stay valid: long enough for one simulation, no longer. */
const SIGNATURE_LEDGERS = 12;
/** `HelperError` in contracts/atomic-live-helper/src/lib.rs. */
export const HELPER_ERROR_CODES = Array.from({ length: 9 }, (_, i) => 7001 + i);
const POLICY_NO_TUPLE_MATCHED = 6;

export function expectedHelperHash(source) {
  const found = [...source.matchAll(/const EXPECTED_HELPER_HASH: &str =\s*"([0-9a-f]{64})";/g)];
  if (found.length === 0) throw new Error('EXPECTED_HELPER_HASH not found in execution-runtime/tests/atomic_helper.rs');
  if (found.length !== 1) throw new Error('expected exactly one EXPECTED_HELPER_HASH');
  return found[0][1];
}
/** The reviewed helper Wasm: the hash the real-Wasm host tests assert, read from them. */
export const EXPECTED_HELPER_HASH = expectedHelperHash(
  readFileSync(new URL('../../execution-runtime/tests/atomic_helper.rs', import.meta.url), 'utf8'));

/** Refuse an RPC serving anything but testnet. */
export async function requireTestnet(getNetwork = () => rpc.server.getNetwork()) {
  const net = await getNetwork();
  if (net?.passphrase !== TESTNET_PASSPHRASE) {
    throw new Error(`${rpc.RPC_ORIGIN} serves "${net?.passphrase}", not testnet; refusing`);
  }
  return net;
}

/** The ID of the contract `deployer` creates with `salt`, derived here rather than taken from RPC. */
export function contractIdFor(deployer, salt, networkPassphrase = TESTNET_PASSPHRASE) {
  const preimage = xdr.HashIdPreimage.envelopeTypeContractId(new xdr.HashIdPreimageContractId({
    networkId: createHash('sha256').update(networkPassphrase).digest(),
    contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(new xdr.ContractIdPreimageFromAddress({
      address: new Address(deployer).toScAddress(), salt: Buffer.from(salt),
    })),
  }));
  return StrKey.encodeContract(createHash('sha256').update(preimage.toXDR()).digest());
}

/**
 * Upload `wasm` and deploy one instance, only if its hash is `expectedHash`, the network stores
 * exactly those bytes, the created ID is the one derived locally from the payer and salt, and the
 * instance reads back running them. `deps`: `getNetwork`, `submit` and `contractCodeObservation`,
 * as in rpc.mjs.
 */
export async function deployReviewedWasm({ wasm, expectedHash, label, payer, deps }) {
  await requireTestnet(deps.getNetwork);
  const built = sha256(wasm);
  if (built !== expectedHash) throw new Error(`${label} Wasm ${built} is not the reviewed ${expectedHash}; refusing to deploy it`);
  const upload = await deps.submit(payer, Operation.uploadContractWasm({ wasm }), { stage: `upload ${label} Wasm` });
  const stored = Buffer.from(scValToNative(upload.returnValue)).toString('hex');
  if (stored !== built) throw new Error(`network stored ${stored}, local ${label} Wasm is ${built}`);
  const salt = randomBytes(32);
  const create = await deps.submit(payer, Operation.createCustomContract({
    address: new Address(payer.publicKey()), wasmHash: Buffer.from(built, 'hex'), salt,
  }), { stage: `create ${label}` });
  const contract = contractIdFor(payer.publicKey(), salt);
  const reported = rpc.contractIdOf(create.returnValue);
  if (reported !== contract) throw new Error(`creating the ${label}: RPC reported ${reported}, not ${contract}`);
  const observed = await deps.contractCodeObservation(contract);
  if (observed.value !== built) throw new Error(`deployed ${label} ${contract} runs ${observed.value}, not the reviewed ${built}`);
  return { contract, code_hash: observed.value, readback_ledger: observed.ledger, upload_tx: upload.hash, create_tx: create.hash };
}

function helperAmount(amount) {
  const value = BigInt(amount);
  if (value < 1n || value > MAX_HELPER_AMOUNT) throw new Error(`the helper executes only 1..=${MAX_HELPER_AMOUNT} stroops, not ${value}`);
  return value;
}

/**
 * The helper's `Candidate` struct: a map keyed by field-name symbols in symbol order.
 * `{ account, policy, policyHash, delegate, expectedRuleId, name, validUntil, recipient, amount }`.
 */
export function candidateScVal(c) {
  const policyHash = Buffer.from(c.policyHash, 'hex');
  if (policyHash.length !== 32) throw new Error('the policy hash must be 32 bytes');
  const fields = {
    account: new Address(c.account).toScVal(),
    amount: i128(helperAmount(c.amount)),
    delegate: new Address(c.delegate).toScVal(),
    expected_rule_id: xdr.ScVal.scvU32(c.expectedRuleId),
    name: xdr.ScVal.scvString(c.name),
    policy: new Address(c.policy).toScVal(),
    policy_hash: xdr.ScVal.scvBytes(policyHash),
    recipient: new Address(c.recipient).toScVal(),
    valid_until: xdr.ScVal.scvU32(c.validUntil),
  };
  return xdr.ScVal.scvMap(Object.keys(fields).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
    .map((key) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val: fields[key] })));
}

/**
 * The four entries one case needs, built here rather than taken from a recording simulation:
 * the account's entry for `add_context_rule` exactly as the helper calls it, under rule 0, with
 * the owner's `__check_auth` entry; then the account's entry for the asset's
 * `transfer(account, recipient, amount)`, with no sub-invocations, under the candidate rule only,
 * with the delegate's. Account entries carry address-bound (V2) credentials.
 */
export async function buildCaseAuthorizations({ candidate, sac, owner, delegate, validUntilLedger, networkPassphrase }) {
  if (networkPassphrase !== TESTNET_PASSPHRASE) throw new Error('case authorizations are signed for testnet only');
  const amount = helperAmount(candidate.amount);
  if (delegate.publicKey() !== candidate.delegate) throw new Error('the delegate key is not the candidate\'s delegate');
  const install = contractCall(candidate.account, 'add_context_rule', addContextRuleArgs({
    context: sac, name: candidate.name, validUntil: candidate.validUntil,
    signers: [{ kind: 'delegated', address: candidate.delegate }],
    policies: [{ address: candidate.policy, install_params: { kind: 'generated' } }],
  }));
  const transfer = contractCall(sac, 'transfer',
    [new Address(candidate.account).toScVal(), new Address(candidate.recipient).toScVal(), i128(amount)]);
  const unsigned = (root) => new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(new xdr.SorobanAddressCredentials({
      address: new Address(candidate.account).toScAddress(), nonce: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()),
      signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid(),
    })),
    rootInvocation: root,
  });
  const sign = (root, signer, ruleIds) => signForSmartAccount({
    entry: unsigned(root), expect: root, signer, ruleIds, validUntilLedger, networkPassphrase,
  });
  const installed = await sign(install, owner, [OWNER_RULE]);
  const transferred = await sign(transfer, delegate, [candidate.expectedRuleId]);
  return [installed.accountEntry, installed.delegateEntry, transferred.accountEntry, transferred.delegateEntry];
}

/**
 * A failed simulation as a policy denial, or not. It is a denial only when the policy contract
 * itself raised the code inside the account's failed authentication (`policyDenial`), and no
 * helper refusal was raised: a 7001–7009 from the helper settles nothing about the policy, and
 * neither does an account's own error. With `expected.code`, any other policy code fails the case.
 */
export function evaluateDenial(sim, { account, policy, helper }, expected = {}) {
  if (typeof sim?.error !== 'string') return { result: 'failed', reason: 'the simulation did not fail' };
  const text = sim.error;
  const host = hostLine(text);
  const raisedByHelper = [...text.matchAll(new RegExp(`contract:${helper}, topics:\\[error, Error\\(Contract, #(\\d+)\\)\\]`, 'g'))]
    .map((m) => Number(m[1]));
  const helperCode = raisedByHelper.find((code) => HELPER_ERROR_CODES.includes(code));
  if (helperCode !== undefined) return { result: 'failed', reason: 'helper_refusal', code: helperCode, host };
  const code = policyDenial(text, account, policy);
  if (code === null) return { result: 'failed', reason: 'not_a_policy_denial', host };
  if (expected.code !== undefined && code !== expected.code) {
    return { result: 'failed', reason: `policy code ${code}, expected ${expected.code}`, code, host };
  }
  return { result: 'deny', enforcer: policy, code, host };
}

const keyHex = (key) => Buffer.from(key.toXDR()).toString('hex');
const contractDataKey = (contract, key) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
  contract: new Address(contract).toScAddress(), key, durability: xdr.ContractDataDurability.persistent,
}));
const symbolVec = (name, ...rest) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name), ...rest]);
/** Balance-carrying entries: classic accounts and trustlines, and any contract's `Balance(_)` entry. */
function isBalanceKey(key) {
  if (key.type === 'account' || key.type === 'trustline') return true;
  const k = key.type === 'contractData' ? key.contractData.key : null;
  return k?.type === 'scvVec' && k.vec?.[0]?.type === 'scvSymbol' && k.vec[0].sym.toString() === 'Balance';
}

/**
 * A successful simulation as the permit case, or not: the helper returned the candidate rule; the
 * only balance changes are the account's native balance down by exactly `amount` and the
 * recipient's up by exactly `amount`; the account stored that rule in this invocation; and the
 * candidate policy's installation for it was created in this invocation with its call counter
 * used exactly once (install starts it at 0).
 */
export function evaluatePermit(sim, { sac, account, recipient, policy, amount, ruleId, maxCalls }) {
  if (!sim || typeof sim.error === 'string') return { result: 'failed', reason: 'simulation failed', host: hostLine(sim?.error) };
  const fail = (reason) => ({ result: 'failed', reason });
  const returned = scValToNative(sim.result?.retval ?? xdr.ScVal.scvVoid())?.id;
  if (returned !== ruleId) return fail(`the helper returned rule ${returned}, expected ${ruleId}`);
  const changes = new Map();
  for (const change of sim.stateChanges ?? []) {
    const k = keyHex(change.key);
    if (changes.has(k)) return fail('a ledger entry changed twice');
    changes.set(k, change);
  }
  const senderKey = keyHex(contractDataKey(sac, symbolVec('Balance', new Address(account).toScVal())));
  const recipientKey = keyHex(xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: new Address(recipient).toScAddress().accountId })));
  for (const [k, change] of changes) {
    if (isBalanceKey(change.key) && k !== senderKey && k !== recipientKey) return fail(`unexpected balance change ${k}`);
  }
  const delta = (change, read) => (change?.after ? read(change.after) : 0n) - (change?.before ? read(change.before) : 0n);
  const sent = delta(changes.get(senderKey), (e) => BigInt(scValToNative(e.data.contractData.val).amount));
  if (sent !== -BigInt(amount)) return fail(`account balance changed by ${sent}, expected ${-BigInt(amount)}`);
  const received = delta(changes.get(recipientKey), (e) => BigInt(e.data.account.balance));
  if (received !== BigInt(amount)) return fail(`recipient balance changed by ${received}, expected ${amount}`);
  // stellar-accounts 0.7.2 keeps each rule in persistent `ContextRuleData(id)`.
  const stored = changes.get(keyHex(contractDataKey(account, symbolVec('ContextRuleData', xdr.ScVal.scvU32(ruleId)))));
  if (!stored || stored.before !== null || !stored.after) return fail(`the account did not store rule ${ruleId} in this simulation`);
  const policyEntry = (name) => changes.get(keyHex(contractDataKey(policy,
    symbolVec(name, new Address(account).toScVal(), xdr.ScVal.scvU32(ruleId)))));
  const installed = policyEntry('Installed');
  if (!installed || installed.before !== null || scValToNative(installed.after?.data.contractData.val ?? xdr.ScVal.scvVoid()) !== true) {
    return fail(`no fresh installation marker of the candidate policy for rule ${ruleId}`);
  }
  const counter = policyEntry('CallCount');
  const used = counter?.after ? scValToNative(counter.after.data.contractData.val) : null;
  if (!counter || counter.before !== null || used !== 1) {
    return fail(`the candidate counter for rule ${ruleId} was not created and used exactly once (used ${used})`);
  }
  return {
    result: 'permit', returned_rule_id: returned,
    balance_changes: { account: sent.toString(), recipient: received.toString() },
    candidate_counter: { rule_id: ruleId, used_before: 0, used_after: used, remaining_after: maxCalls - used, installed_in_simulation: true },
  };
}

/**
 * Once every case signature has expired at `lastExpiry`: the case signatures can no longer move or
 * install anything, so the account's balance must equal its value before the cases and the
 * candidate must report no installation, each read at a ledger after `lastExpiry`.
 */
export function postExpiryReadback({ lastExpiry, balanceBefore, balanceAfter, installedAfter }) {
  const record = {
    after_signature_expiration_ledger: lastExpiry,
    account_balance_before_cases: { amount: String(balanceBefore.value), ledger: balanceBefore.ledger },
    account_balance_after_expiry: { amount: String(balanceAfter.value), ledger: balanceAfter.ledger },
    candidate_is_installed_after_expiry: { value: installedAfter.value, ledger: installedAfter.ledger },
  };
  const untouched = balanceAfter.ledger > lastExpiry && installedAfter.ledger > lastExpiry
    && balanceAfter.value === balanceBefore.value && installedAfter.value === false;
  return { record, untouched };
}

/** Evidence is written only for a permit, a policy denial with `NoTupleMatched`, and an untouched account. */
export function requireProbeOutcomes({ permit, denial, untouched }) {
  if (permit.result !== 'permit' || denial.result !== 'deny' || denial.code !== POLICY_NO_TUPLE_MATCHED || !untouched) {
    throw new Error(`probe failed: permit case ${permit.result}, denial case ${denial.result}, `
      + `post-expiry state ${untouched ? 'unchanged' : 'CHANGED'}; no evidence written`);
  }
}

/** Checked before the run starts, so a long live run cannot end at an existing file. */
export function refuseExistingEvidence(path) {
  if (existsSync(path)) throw new Error(`${path} already exists; refusing to overwrite evidence`);
}

/** Written exclusively: an existing file is never replaced, even if it appeared during the run. */
export function writeEvidence(path, report) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
}

/** Exit statuses for the signals that delete the throwaway keys before the process exits. */
const KEY_SIGNALS = { SIGINT: 2, SIGTERM: 15, SIGHUP: 1 };

/**
 * Run `work(secretsFile)` with a fresh private directory for the throwaway keys, named to the
 * harness steps by `OZPB_HARNESS_SECRETS`. The directory is deleted when `work` settles, either
 * way, and on SIGINT, SIGTERM or SIGHUP before the process exits with the signal's status.
 */
export async function withThrowawayKeys(work, { proc = process } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-live-helper-'));
  const remove = () => rmSync(dir, { recursive: true, force: true });
  let cancelled = false;
  let active = null;
  // Each step owns a process group, including any CLI/build descendants. Keep the event loop
  // available while it runs so cancellation can stop all of them before removing their keys.
  const runStep = async (script, args) => {
    if (cancelled) throw new Error('helper run cancelled');
    if (active) throw new Error('helper steps must run sequentially');
    const child = spawn(process.execPath, [resolve(HERE, script), ...args], {
      cwd: ROOT, detached: true, stdio: 'inherit',
      env: { ...process.env, OZPB_HARNESS_SECRETS: secrets },
    });
    const closed = new Promise((done) => {
      let error;
      child.once('error', (e) => { error = e; });
      child.once('close', (status) => done({ status, error }));
    });
    active = { child, closed };
    const result = await closed;
    active = null;
    if (cancelled) throw new Error('helper run cancelled');
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`${script} failed (exit ${result.status})`);
  };
  const onSignal = (signal) => {
    if (cancelled) return;
    cancelled = true;
    const finish = () => { remove(); proc.exit(128 + KEY_SIGNALS[signal]); };
    if (!active) { finish(); return; }
    // No grace period for a signing child: cancellation must not permit another transaction.
    try { if (Number.isInteger(active.child.pid)) process.kill(-active.child.pid, 'SIGKILL'); }
    catch (e) { if (e.code !== 'ESRCH') throw e; }
    // A kill request is not a reaped child. Do not delete its key directory or exit yet.
    active.closed.then(finish);
  };
  for (const signal of Object.keys(KEY_SIGNALS)) proc.on(signal, onSignal);
  const secrets = join(dir, 'keys.json');
  proc.env.OZPB_HARNESS_SECRETS = secrets;
  try {
    return await work(secrets, runStep);
  } finally {
    remove();
    delete proc.env.OZPB_HARNESS_SECRETS;
    for (const signal of Object.keys(KEY_SIGNALS)) proc.removeListener(signal, onSignal);
  }
}

// --- the live run ---------------------------------------------------------------------------------

/** Enforce-mode simulation of `operation` with its supplied authorization. Never signed or sent. */
async function simulateEnforce(payer, operation) {
  const source = await rpc.server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: TESTNET_PASSPHRASE })
    .addOperation(operation).setTimeout(60).build();
  try {
    return await rpc.server.simulateTransaction(tx, undefined, 'enforce');
  } catch (e) {
    // A transport error carries the request, and with it the signed entries; keep only its message.
    throw new Error(`simulation request failed: ${String(e?.message ?? e).split('\n')[0]}`);
  }
}

/** Wait, polling RPC, until the latest ledger is past `ledger`. */
async function waitPast(ledger, { timeoutMs = 300_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const latest = await rpc.latestLedger();
    if (latest > ledger) return latest;
    if (Date.now() > deadline) throw new Error(`ledger ${ledger} did not pass within ${timeoutMs / 1000} s`);
    await new Promise((done) => setTimeout(done, 5000));
  }
}

/** Until which ledger the instance and the code entries of `contract` stay live, as RPC reports. */
async function liveUntil(contract, wasmHash) {
  const instance = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
    contract: new Address(contract).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(),
    durability: xdr.ContractDataDurability.persistent,
  }));
  const code = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(wasmHash, 'hex') }));
  const { entries } = await rpc.server.getLedgerEntries(instance, code);
  const of = (key) => entries.find((e) => keyHex(e.key) === keyHex(key))?.liveUntilLedgerSeq ?? null;
  return { instance_live_until_ledger: of(instance), code_live_until_ledger: of(code) };
}


const STELLAR = process.env.OZPB_STELLAR_BINARY || 'stellar';

function buildHelper(outDir) {
  const result = spawnSync(STELLAR, ['contract', 'build', '--locked',
    '--manifest-path', join(ROOT, 'contracts/atomic-live-helper/Cargo.toml'),
    '--package', 'ozpb-atomic-live-helper', '--out-dir', outDir], { cwd: ROOT, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`stellar contract build failed (exit ${result.status})`);
  return readFileSync(join(outDir, 'ozpb_atomic_live_helper.wasm'));
}

const tool = (command, args) => execFileSync(command, args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

async function main() {
  const opts = rpc.args();
  for (const key of Object.keys(opts)) if (key !== 'evidence') throw new Error(`unknown option --${key}`);
  const startedAt = new Date();
  const date = startedAt.toISOString().slice(0, 10);
  const evidencePath = resolve(opts.evidence ?? join(ROOT, `docs/evidence/atomic-live-helper-testnet-${date}.json`));
  refuseExistingEvidence(evidencePath);
  // Every step resolves the CLI the same way, whatever directory each runs it from.
  if (process.env.OZPB_BIN?.includes('/')) process.env.OZPB_BIN = resolve(process.env.OZPB_BIN);
  const net = await requireTestnet();
  rpc.log(`network   ${net.passphrase} (protocol ${net.protocolVersion}) via ${rpc.RPC_ORIGIN}`);
  const provenance = {
    checkout_commit: tool('git', ['rev-parse', 'HEAD']),
    checkout_dirty: tool('git', ['status', '--porcelain']).length > 0,
    script_sha256: sha256(readFileSync(fileURLToPath(import.meta.url))),
    node_version: process.versions.node,
    stellar_cli: tool(STELLAR, ['--version']).split('\n')[0],
    rustc: tool('rustc', ['--version']),
    started_at: startedAt.toISOString(),
  };

  const runDir = join(HERE, '..', 'runs', `live-helper-${startedAt.toISOString().replace(/[-:]|\.\d+/g, '')}-${process.pid}`);
  mkdirSync(join(runDir, 'helper'), { recursive: true });
  const helperWasm = buildHelper(join(runDir, 'helper'));
  if (sha256(helperWasm) !== EXPECTED_HELPER_HASH) {
    throw new Error(`built helper ${sha256(helperWasm)} is not the reviewed ${EXPECTED_HELPER_HASH}; refusing to deploy it`);
  }
  rpc.log(`helper    built ${EXPECTED_HELPER_HASH} = EXPECTED_HELPER_HASH`);
  // Generation builds offline from the committed generated-contract lockfile; fetch those exact
  // dependencies now, so a cold cache fails before anything is funded or signed.
  const fetched = spawnSync('cargo', ['fetch', '--locked'], { cwd: join(ROOT, 'contracts/golden-transfer-policy'), stdio: 'inherit' });
  if (fetched.error || fetched.status !== 0) throw new Error('cargo fetch --locked for the generated policy failed');

  const report = await withThrowawayKeys(async (secrets, runStep) => {
    await runStep('setup.mjs', ['--run-dir', runDir, '--owner', 'ed25519', '--amount', String(PERMIT_AMOUNT)]);
    let run = rpc.readJson(join(runDir, 'run.json'));
    await runStep('invoke.mjs', ['--run-dir', runDir, '--signer', 'owner', '--rule', '0', '--amount', run.amount,
      '--to', run.recipient, '--expect', 'permit', '--bundle', join(runDir, 'import-bundle.json')]);
    await runStep('synthesis-flow.mjs', ['--run-dir', runDir]);
    run = rpc.readJson(join(runDir, 'run.json'));
    const spec = parseJsonExact(readFileSync(run.spec, 'utf8'));
    const policyDir = join(runDir, 'policy');
    const manifest = parseJsonExact(readFileSync(join(policyDir, 'build-manifest.json'), 'utf8'));
    const policyWasm = readFileSync(join(policyDir, readdirWasm(policyDir)));
    const policyHash = await checkArtifact(spec, policyWasm, manifest);
    const rule = spec.rules[0];
    const maxCalls = rule.state?.[0]?.call_count_per_installation?.max_calls;
    if (!Number.isInteger(maxCalls) || maxCalls < 1) throw new Error('the candidate has no call cap; the helper cannot observe it');
    const pipeline = rpc.readJson(join(runDir, 'pipeline.json'));
    const justifying = run.invocations.find((i) => i.signer === 'owner' && i.rule === 0 && i.result === 'permit');

    const payer = rpc.loadKey('payer');
    const owner = await ownerSigner(run);
    const delegate = rpc.loadKey('delegate');
    const deps = { getNetwork: () => rpc.server.getNetwork(), submit: rpc.submit, contractCodeObservation: rpc.contractCodeObservation };
    const policy = await deployReviewedWasm({ wasm: policyWasm, expectedHash: policyHash, label: 'candidate policy', payer, deps });
    rpc.log(`policy    ${policy.contract}  code ${policy.code_hash} read back at ledger ${policy.readback_ledger}`);
    const helper = await deployReviewedWasm({ wasm: helperWasm, expectedHash: EXPECTED_HELPER_HASH, label: 'helper', payer, deps });
    rpc.log(`helper    ${helper.contract}  code ${helper.code_hash} read back at ledger ${helper.readback_ledger}`);

    const candidate = {
      account: run.account, policy: policy.contract, policyHash, delegate: run.delegate, expectedRuleId: EXPECTED_RULE_ID,
      name: spec.name, validUntil: rule.valid_until.ledger, recipient: run.recipient,
    };
    const view = async (contract, fn, args) => {
      const observed = await rpc.viewCallObservation(payer, contract, fn, args);
      return { value: scValToNative(observed.value), ledger: observed.ledger };
    };
    const balance = () => view(run.sac, 'balance', [new Address(run.account).toScVal()]);
    const balanceBefore = await balance();
    const probe = async (name, amount, evaluate) => {
      await requireTestnet();
      const validUntilLedger = (await rpc.latestLedger()) + SIGNATURE_LEDGERS;
      const auth = await buildCaseAuthorizations({ candidate: { ...candidate, amount }, sac: run.sac, owner, delegate,
        validUntilLedger, networkPassphrase: TESTNET_PASSPHRASE });
      const sim = await simulateEnforce(payer, Operation.invokeContractFunction({
        contract: helper.contract, function: 'install_and_transfer', args: [candidateScVal({ ...candidate, amount })], auth,
      }));
      const outcome = evaluate(sim);
      rpc.log(`case      ${name} ${amount}: ${outcome.result}${outcome.code ? ` #${outcome.code}` : ''}${outcome.reason ? ` (${outcome.reason})` : ''}`);
      if (outcome.host) rpc.log(`          ${outcome.host}`);
      // On an unexpected outcome, show only the diagnostic error events: contract IDs and codes,
      // never call arguments, which carry the authorization payloads.
      if (outcome.result === 'failed' && typeof sim.error === 'string') {
        for (const line of sim.error.split('\n').filter((l) => /topics:\[error, Error\(/.test(l))) {
          rpc.log(`          ${line.trim().replace(/, data:.*$/, '')}`);
        }
      }
      return { case: name, amount: amount.toString(), expected_rule_id: EXPECTED_RULE_ID,
        signature_expiration_ledger: validUntilLedger, simulation_ledger: sim.latestLedger, submitted: false, ...outcome };
    };
    const permit = await probe('target:original:0', PERMIT_AMOUNT, (sim) => evaluatePermit(sim, {
      sac: run.sac, account: run.account, recipient: run.recipient, policy: policy.contract,
      amount: PERMIT_AMOUNT, ruleId: EXPECTED_RULE_ID, maxCalls,
    }));
    const denial = await probe('target:argument-denial:0', PERMIT_AMOUNT + 1n, (sim) => evaluateDenial(sim,
      { account: run.account, policy: policy.contract, helper: helper.contract }, { code: POLICY_NO_TUPLE_MATCHED }));
    if (denial.result === 'deny') denial.attribution = 'NoTupleMatched raised by the candidate policy contract id inside the account\'s failed authentication, nested under the helper';

    // The signed entries went to the RPC inside the simulations and were valid until they
    // expired. Once they have, nothing they authorize can happen any more: read back that nothing did.
    const lastExpiry = Math.max(permit.signature_expiration_ledger, denial.signature_expiration_ledger);
    rpc.log(`waiting   for ledger ${lastExpiry} to pass, after which no case signature is valid`);
    await waitPast(lastExpiry);
    const balanceAfter = await balance();
    const installedAfter = await view(policy.contract, 'is_installed', [xdr.ScVal.scvU32(EXPECTED_RULE_ID), new Address(run.account).toScVal()]);
    const { record: postExpiry, untouched } = postExpiryReadback({ lastExpiry, balanceBefore, balanceAfter, installedAfter });
    rpc.log(`readback  account balance ${balanceAfter.value} (was ${balanceBefore.value}), candidate installed: ${installedAfter.value}`);

    const record = {
      schema_version: 1,
      evidence_kind: 'atomic_live_helper_testnet_probe',
      live_enforcement: 'unavailable',
      live_enforcement_reason: 'the wallet-side preparation, consent, signing and result validation are not built; this is a harness probe with automation keys',
      limitations: [
        'Enforce-mode simulations only: this script submitted neither case; post_expiry_readback shows the account balance unchanged and the candidate not installed once every case signature had expired.',
        'Owner and delegate are throwaway automation keys held by this script and deleted after the run; no wallet, consent screen or human approval was involved.',
        'State-dependent: each outcome describes testnet state at its simulation ledger.',
        'Each case was signed with real authorizations of the installation and the transfer, valid until its signature_expiration_ledger. They went to the testnet RPC endpoint inside the simulation request; this script never printed or stored them.',
        'The authorizations were built by this script, the transfer entry with no sub-invocations and context_rule_ids [1]; the helper alone cannot tell which rule checked the executed transfer.',
        'The account entries carry address-bound (V2) credentials; the owner\'s and delegate\'s __check_auth entries carry classic address credentials, as the rest of the harness signs them, where the host tests sign all four as V2.',
        'A testnet reset removes these contracts; docs/ATOMIC-LIVE-HELPER.md says how to redeploy.',
      ],
      provenance: { ...provenance, finished_at: new Date().toISOString() },
      network: TESTNET_PASSPHRASE,
      network_id: sha256(Buffer.from(TESTNET_PASSPHRASE)),
      protocol: net.protocolVersion,
      rpc: rpc.RPC_ORIGIN,
      helper: { ...helper, ...await liveUntil(helper.contract, helper.code_hash),
        expected_code_hash: EXPECTED_HELPER_HASH, expected_from: 'execution-runtime/tests/atomic_helper.rs EXPECTED_HELPER_HASH' },
      account: { contract: run.account, code_hash: run.account_code_hash, deploy_tx: run.tx.deploy_account },
      owner: run.owner.address,
      delegate: run.delegate,
      recipient: run.recipient,
      asset: run.sac,
      candidate_policy: { ...policy, spec_hash: pipeline.spec_hash, name: spec.name, max_calls: maxCalls,
        valid_until_ledger: rule.valid_until.ledger, justifying_transfer_tx: justifying?.hash ?? null,
        recording_hash: pipeline.recording_hash, artifact_reproduction: pipeline.artifact_reproduction },
      cases: [permit, denial],
      post_expiry_readback: postExpiry,
    };
    // The same public record stays in the (gitignored) run directory whatever the outcome.
    rpc.writeJson(join(runDir, 'live-helper.json'), record);
    requireProbeOutcomes({ permit, denial, untouched });
    return record;
  });
  report.throwaway_keys_deleted = true;
  writeEvidence(evidencePath, report);
  rpc.log(`evidence  ${evidencePath}`);
}

function readdirWasm(dir) {
  const wasms = readdirSync(dir).filter((name) => name.endsWith('.wasm'));
  if (wasms.length !== 1) throw new Error(`expected one generated Wasm in ${dir}, found ${wasms.length}`);
  return wasms[0];
}

if (isMainModule(import.meta.url)) await main();
