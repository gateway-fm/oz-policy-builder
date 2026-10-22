// Network side of the harness: one RPC client, Friendbot, and a submit loop that refuses to sign
// what simulation rejected. Everything here talks to the live network; nothing here holds a key
// longer than the call that signs with it.
import { randomBytes } from 'node:crypto';
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import {
  Account, Address, Asset, Keypair, Networks, Operation, StrKey, TransactionBuilder, rpc, scValToNative, xdr,
} from '@stellar/stellar-sdk';

export const NETWORK_PASSPHRASE = Networks.TESTNET;
export const RPC_URL = process.env.OZPB_RPC_URL ?? 'https://soroban-testnet.stellar.org';
export const server = new rpc.Server(RPC_URL);
/** What is printed and stored about the endpoint: its origin, never a path, query or credential. */
export const RPC_ORIGIN = new URL(RPC_URL).origin;

/** The pinned OpenZeppelin account example, `ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM`. */
export const PINNED_ACCOUNT_WASM = 'a12747ff6c139dc14fc2fd30d200d6bbb5da7b5d59812c047ce1f9cad226b289';

/**
 * OpenZeppelin's WebAuthn verifier example (`examples/multisig-smart-account/webauthn-verifier`),
 * built from the same tag, commit and toolchain as the pins in `ozpb_domain::pinned_upstream`.
 * Recognized by the version-3 development registry. The README says how to reproduce it.
 */
export const PINNED_WEBAUTHN_VERIFIER_WASM = 'e63a030d0f1a1481e36059a4837c433083b33e704c1f9625b7314795b6d72b76'; // gitleaks:allow -- public WebAuthn Wasm SHA-256

/** The native-XLM Stellar Asset Contract: derived, never deployed. */
export const NATIVE_SAC = Asset.native().contractId(NETWORK_PASSPHRASE);

export const log = (...a) => console.log(...a);

/** A simulation the network rejected. `.error` is the host's text, diagnostic events included. */
export class SimulationError extends Error {
  constructor(stage, error) {
    super(`${stage} simulation failed: ${String(error).split('\n')[0]}`);
    this.stage = stage;
    this.error = String(error);
  }
}

/**
 * Refuse to talk to anything but testnet. The keys are throwaway, but the scripts sign whatever
 * the RPC asks them to, and an endpoint pointed at another network by a stray variable should
 * fail here rather than at a signature.
 */
export async function assertTestnet() {
  const net = await server.getNetwork();
  if (net.passphrase !== NETWORK_PASSPHRASE) {
    throw new Error(`${RPC_ORIGIN} serves "${net.passphrase}", not testnet`);
  }
  return net;
}

export async function fund(address) {
  const net = await server.getNetwork();
  const base = net.friendbotUrl ?? 'https://friendbot.stellar.org/';
  const res = await fetch(`${base}?addr=${encodeURIComponent(address)}`);
  if (!res.ok) throw new Error(`friendbot refused ${address}: HTTP ${res.status}`);
}

export async function latestLedger() {
  return (await server.getLatestLedger()).sequence;
}

/** The latest ledger and the close time (Unix seconds) the RPC reports for it. */
export async function latestLedgerClose() {
  const latest = await server.getLatestLedger();
  const closeTime = Number(latest.closeTime);
  if (!Number.isSafeInteger(closeTime) || closeTime <= 0) throw new Error('RPC latest ledger lacks a valid close time');
  return { ledger: readLedger(latest.sequence), close_time: closeTime };
}

/** Default total transaction fee, including Soroban resources: one testnet XLM. */
export const MAX_TRANSACTION_FEE = 10_000_000n;
/** The most any call other than a Wasm upload may name: ten testnet XLM. */
export const MAX_NAMED_CALL_FEE = 100_000_000n;
/** A Wasm upload that names no ceiling keeps the earlier fixed one: ten testnet XLM. */
export const DEFAULT_WASM_UPLOAD_FEE = 100_000_000n;
/** The most a Wasm upload may name: twenty testnet XLM. Only an upload may name above ten. */
export const MAX_NAMED_UPLOAD_FEE = 200_000_000n;
/**
 * What the W1, W2 and W3 installers name for a generated policy's upload: fifteen testnet XLM.
 * On 22 October 2026 a 21,814-byte generated policy's upload assembled at 101,220,139 stroops,
 * above the ten-XLM default; new code's write fee and rent follow the network's prices.
 */
export const POLICY_WASM_UPLOAD_FEE = 150_000_000n;

/** Exactly one Wasm upload: the only transaction class that may name more than ten XLM. */
function isWasmUpload(operations) {
  return operations.length === 1
    && operations[0].body?.invokeHostFunctionOp?.hostFunction.type === 'hostFunctionTypeUploadContractWasm';
}

/** Explicit source-payer authorization for exactly this operation, never an RPC-supplied tree. */
function withSourceAuthorization(operation, payer) {
  const invoke = operation.body?.invokeHostFunctionOp;
  if (!invoke || invoke.auth.length !== 0) return operation;
  const func = invoke.hostFunction;
  const preimage = (func.createContract ?? func.createContractV2)?.contractIdPreimage;
  if (preimage?.type === 'contractIdPreimageFromAddress'
    && Address.fromScAddress(preimage.fromAddress.address).toString() !== payer) {
    throw new Error('submission refused: contract creation source differs from fee payer');
  }
  let root;
  switch (func.type) {
    case 'hostFunctionTypeInvokeContract':
      root = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(func.invokeContract);
      break;
    case 'hostFunctionTypeCreateContract':
      root = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(func.createContract);
      break;
    case 'hostFunctionTypeCreateContractV2':
      root = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractV2HostFn(func.createContractV2);
      break;
    case 'hostFunctionTypeUploadContractWasm':
      return operation;
    default:
      throw new Error('submission refused: unsupported host function');
  }
  if (operation.sourceAccount !== null) throw new Error('submission refused: explicit operation source');
  return Operation.invokeHostFunction({ func, auth: [new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({ function: root, subInvocations: [] }),
  })] });
}

/** Assembly may add resource data and a bounded fee, never change the call we will sign. */
function checkAssembly(assembled, expectedEnvelope, maximumFee = MAX_TRANSACTION_FEE) {
  try {
    const expected = xdr.TransactionEnvelope.fromXDR(expectedEnvelope);
    // Re-derived from the intended envelope, never the assembled one: above ten XLM only for an upload.
    if (maximumFee > (isWasmUpload(expected.v1.tx.operations) ? MAX_NAMED_UPLOAD_FEE : MAX_NAMED_CALL_FEE)) throw new Error();
    const envelope = assembled.toEnvelope();
    if (assembled.networkPassphrase !== NETWORK_PASSPHRASE || envelope.type !== 'envelopeTypeTx'
      || envelope.v1.signatures.length !== 0) throw new Error();
    const wire = envelope.v1.tx;
    if (!Number.isSafeInteger(wire.fee) || wire.fee < 100 || BigInt(wire.fee) > maximumFee) throw new Error();
    if (wire.ext.type === 'sorobanData') {
      const resourceFee = wire.ext.sorobanData.resourceFee;
      if (typeof resourceFee !== 'bigint' || resourceFee < 0n || resourceFee > BigInt(wire.fee)) throw new Error();
    } else if (wire.ext.type !== 'v0') throw new Error();
    // Decode a separate copy: the SDK's envelope shares objects with its transaction.
    const normalized = xdr.TransactionEnvelope.fromXDR(envelope.toXDR());
    normalized.v1.tx.fee = expected.v1.tx.fee;
    normalized.v1.tx.ext = expected.v1.tx.ext;
    if (!Buffer.from(normalized.toXDR()).equals(expectedEnvelope)) throw new Error();
  } catch {
    throw new Error('submission refused: assembled transaction differs or exceeds the fee ceiling');
  }
}

/**
 * Simulate, assemble, sign with the fee payer, submit and wait. An operation that already carries
 * signed auth entries (attached after a recording simulation) is simulated in enforcing mode with
 * them; one without gets an explicit fee-payer entry for this exact host function only.
 * Assembly may change only resources and a bounded total fee; it cannot add authorization.
 *
 * A failed simulation throws `SimulationError` before the transaction is signed or sent, which is
 * what makes a denial observable without spending a fee: the enforcing simulation runs
 * `__check_auth` and the installed policies exactly as the network would.
 */
export async function submit(payer, operation, { stage = 'submit', onSubmitting, maxFee } = {}) {
  // A caller whose call is known to cost more than one XLM in resources (rent for new entries)
  // names its own ceiling, at most ten XLM. A Wasm upload, classified from this operation and
  // never from anything the RPC returns, defaults to ten XLM and may name up to twenty.
  const upload = isWasmUpload([operation]);
  const ceiling = maxFee === undefined ? (upload ? DEFAULT_WASM_UPLOAD_FEE : MAX_TRANSACTION_FEE) : maxFee;
  if (typeof ceiling !== 'bigint' || ceiling < MAX_TRANSACTION_FEE
    || ceiling > (upload ? MAX_NAMED_UPLOAD_FEE : MAX_NAMED_CALL_FEE)) {
    throw new Error('submission refused: invalid fee ceiling');
  }
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '1000000', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(withSourceAuthorization(operation, payer.publicKey())).setTimeout(SUBMIT_TIMEOUT_SECONDS).build();
  if (tx.source !== payer.publicKey()) throw new Error('submission refused: RPC returned another fee payer');
  const expectedEnvelope = Buffer.from(tx.toEnvelope().toXDR());
  const sim = await server.simulateTransaction(tx, undefined, 'enforce');
  if (rpc.Api.isSimulationError(sim)) throw new SimulationError(stage, sim.error);
  const assembled = rpc.assembleTransaction(tx, sim).build();
  checkAssembly(assembled, expectedEnvelope, ceiling);
  assembled.sign(payer);
  const expectedHash = Buffer.from(assembled.hash()).toString('hex');
  const maxTime = Number(tx.timeBounds.maxTime);
  const minLedger = ledgerOf(sim.latestLedger);
  // Persist a removal identity before the first network write. A failed checkpoint prevents send;
  // a later transport/confirmation failure keeps the identity available for reconciliation. The
  // end of the validity window says when an unseen transaction can no longer land.
  if (onSubmitting) await onSubmitting(expectedHash, { max_time: maxTime, ...(minLedger === null ? {} : { min_ledger: minLedger }) });
  log(`transaction prepared ${expectedHash}; expires ${tx.timeBounds.maxTime}`);
  const sent = await server.sendTransaction(assembled);
  const status = ['PENDING', 'DUPLICATE', 'TRY_AGAIN_LATER', 'ERROR'].includes(sent.status) ? sent.status : 'UNKNOWN';
  log(`transaction send ${expectedHash}; status ${status}`);
  if (sent.status === 'ERROR') {
    throw new Error(`${stage}: sendTransaction ERROR ${sent.errorResult?.toXDR?.('base64') ?? ''}`);
  }
  if (sent.hash !== expectedHash) throw new Error(`${stage}: RPC returned another transaction identity`);
  if (!['PENDING', 'DUPLICATE'].includes(sent.status)) {
    throw new Error(`${stage}: transaction ${expectedHash} was not accepted (${status}); no automatic retry`);
  }
  const done = await transactionOutcome(sent.hash, maxTime, { minLedger });
  if (done.status !== 'SUCCESS') {
    throw new Error(`${stage}: transaction ${sent.hash} ended ${done.status}`);
  }
  if (done.txHash !== expectedHash) throw new Error(`${stage}: confirmed transaction identity differs`);
  return { hash: sent.hash, returnValue: done.returnValue, receipt: done };
}

const POLL_INTERVAL_MS = 2000;
/** Every submitted transaction is valid for this many seconds after it is built (`setTimeout`). */
export const SUBMIT_TIMEOUT_SECONDS = 120;
/** How long one outcome query may poll locally. Ledger close times, not this, decide outcomes. */
export const OUTCOME_POLL_BUDGET_MS = 180_000;
/**
 * Time a cleanup keeps in hand before it prepares a removal: one submission's outcome polling,
 * two bounded readbacks (10 reads, 2 s apart, each) and slack for recording and signing.
 */
export const REMOVAL_RESERVE_MS = OUTCOME_POLL_BUDGET_MS + 40_000 + 20_000;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The outcome of one submitted transaction. SUCCESS and FAILED are returned at once. Otherwise
 * it polls within a local budget; transport errors are retried, not outcomes. `NOT_FOUND` with
 * `after_window: true` means the endpoint has closed a ledger after the window (`maxTime`, Unix
 * seconds) so the transaction can no longer land, and still retains the ledgers from the window's
 * start, so it would have seen it. Only ledger close times decide that; the local clock only
 * bounds polling. Without a known window, one read is made and `NOT_FOUND` proves nothing.
 */
const closeTimeOf = (v) => typeof v === 'string'
  ? (/^[1-9][0-9]{0,15}$/.test(v) && Number.isSafeInteger(Number(v)) ? Number(v) : null)
  : Number.isSafeInteger(v) && v > 0 ? v : null;
const ledgerOf = (v) => Number.isSafeInteger(v) && v > 0 ? v : null;

export async function transactionOutcome(hash, maxTime, { now = () => Date.now(), delay = pause,
  budgetMs = OUTCOME_POLL_BUDGET_MS, minLedger = null } = {}) {
  const known = Number.isSafeInteger(maxTime) && maxTime > 0;
  const stopAt = now() + (known ? budgetMs : 0);
  for (;;) {
    let response = null;
    try { response = await server.getTransaction(hash); } catch { response = null; }
    if (response?.status === 'SUCCESS' || response?.status === 'FAILED') return response;
    if (known && response?.status === 'NOT_FOUND') {
      // Only well-formed, ordered close times can show that a ledger closed after the window.
      const latest = closeTimeOf(response.latestLedgerCloseTime), oldest = closeTimeOf(response.oldestLedgerCloseTime);
      if (latest !== null && oldest !== null && latest >= oldest && latest > maxTime) {
        // The endpoint must still retain the window's start: by close time, and, when the
        // prepare-time simulation ledger is known, by ledger number too.
        const prepared = ledgerOf(minLedger), retainedFrom = ledgerOf(response.oldestLedger);
        const retains = oldest <= maxTime - SUBMIT_TIMEOUT_SECONDS
          && (prepared === null || (retainedFrom !== null && retainedFrom <= prepared));
        return { status: 'NOT_FOUND', after_window: retains };
      }
    }
    if (!known || now() >= stopAt) return { status: response?.status === 'NOT_FOUND' ? 'NOT_FOUND' : 'UNKNOWN', after_window: false };
    await delay(POLL_INTERVAL_MS);
  }
}

/**
 * A read accepted only when the endpoint reports a ledger at or after `minimum` (a confirmed
 * transaction's ledger), so a lagging endpoint cannot answer for the state before it. Reads below
 * it, and transport errors, are retried a bounded number of times. A simulation error carrying a
 * ledger at or after `minimum` is that read's answer and is rethrown.
 */
export async function observeAtOrAfter(minimum, read, { delay = pause, attempts = 10 } = {}) {
  for (let attempt = 1; ; attempt++) {
    let result, failure, ledger;
    try { result = await read(); ledger = result?.ledger; } catch (error) { failure = error; ledger = error?.ledger; }
    if (Number.isSafeInteger(ledger) && ledger >= minimum) {
      if (failure) throw failure;
      return result;
    }
    if (attempt >= attempts) throw new Error(`readback endpoint did not reach the confirmed ledger ${minimum}`);
    await delay(POLL_INTERVAL_MS);
  }
}

/** Run a recording simulation and return the auth entries the network says the call needs. */
export async function recordAuth(payer, operation, stage) {
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(operation).setTimeout(120).build();
  const sim = await server.simulateTransaction(tx, undefined, 'record');
  if (rpc.Api.isSimulationError(sim)) throw new SimulationError(`${stage} (recording)`, sim.error);
  return sim.result?.auth ?? [];
}

/** Enforce supplied authorization without signing or submitting the fee transaction. */
export async function enforceSimulation(payer, operation) {
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(operation).setTimeout(60).build();
  const simulated = await server.simulateTransaction(tx, undefined, 'enforce');
  const ledger = readLedger(simulated.latestLedger);
  return rpc.Api.isSimulationError(simulated)
    ? { result: 'deny', ledger, error: String(simulated.error) }
    : { result: 'permit', ledger };
}

/** Simulate a read-only call and return its value as an ScVal. Nothing is signed or sent. */
export async function viewCall(payer, contract, fn, fnArgs = []) {
  return (await viewCallObservation(payer, contract, fn, fnArgs)).value;
}

const readLedger = (ledger) => {
  if (!Number.isSafeInteger(ledger) || ledger < 1 || ledger > 0xffff_ffff) throw new Error('RPC read lacks a valid ledger');
  return ledger;
};

/** Retain this simulation's own ledger; separate reads do not form an atomic snapshot. */
export async function viewCallObservation(payer, contract, fn, fnArgs = []) {
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(Operation.invokeContractFunction({ contract, function: fn, args: fnArgs }))
    .setTimeout(60).build();
  const sim = await server.simulateTransaction(tx);
  // The ledger an error answered at lets a caller require it to follow a confirmed write.
  if (rpc.Api.isSimulationError(sim)) throw Object.assign(new SimulationError(fn, sim.error), { ledger: sim.latestLedger });
  return { value: sim.result.retval, ledger: readLedger(sim.latestLedger) };
}

// A syntactically valid source that need not exist: simulation reads no account entry for it.
const READ_ONLY_SOURCE = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

/** A read-only call simulated without any harness account or key; nothing is signed or sent. */
export async function readOnlyView(contract, fn, fnArgs = []) {
  const tx = new TransactionBuilder(new Account(READ_ONLY_SOURCE, '0'), { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(Operation.invokeContractFunction({ contract, function: fn, args: fnArgs }))
    .setTimeout(60).build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw Object.assign(new SimulationError(fn, sim.error), { ledger: sim.latestLedger });
  return { value: sim.result.retval, ledger: readLedger(sim.latestLedger) };
}

/** The wasm hash a contract instance runs, as the network reports it. */
export async function contractCodeHash(contractId) {
  return (await contractCodeObservation(contractId)).value;
}

/** Retain the ledger reported by this instance-entry read. */
export async function contractCodeObservation(contractId) {
  const { value, ledger } = await contractInstanceObservation(contractId);
  return { value, ledger };
}

/** The instance's code hash and its instance storage entries, from one checked entry read. */
export async function contractInstanceObservation(contractId) {
  const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
    contract: new Address(contractId).toScAddress(),
    key: xdr.ScVal.scvLedgerKeyContractInstance(),
    durability: xdr.ContractDataDurability.persistent,
  }));
  const { entries, latestLedger } = await server.getLedgerEntries(key);
  if (entries.length !== 1) throw new Error(`no instance entry for ${contractId}`);
  const ledger = readLedger(latestLedger);
  const entry = entries[0];
  const sameXdr = (actual, expected) => actual?.toXDR && Buffer.from(actual.toXDR()).equals(Buffer.from(expected.toXDR()));
  const data = entry.val.contractData;
  if (!sameXdr(entry.key, key) || entry.val.type !== 'contractData'
    || !data || !sameXdr(data.contract, key.contractData.contract) || !sameXdr(data.key, key.contractData.key)
    || data.durability?.name !== 'persistent' || data.val?.type !== 'scvContractInstance') {
    throw new Error(`RPC returned another instance entry for ${contractId}`);
  }
  if (readLedger(entry.lastModifiedLedgerSeq) > ledger || readLedger(entry.liveUntilLedgerSeq) < ledger) {
    throw new Error(`RPC returned expired or inconsistent instance metadata for ${contractId}`);
  }
  const exec = data.val.instance.executable;
  if (exec.type !== 'contractExecutableWasm') throw new Error(`${contractId} is not a wasm contract (${exec.type})`);
  return { value: Buffer.from(exec.wasmHash.value ?? exec.wasmHash).toString('hex'), ledger,
    storage: data.val.instance.storage ?? [] };
}

export const contractIdOf = (scv) => {
  const id = scValToNative(scv);
  if (!StrKey.isValidContract(id)) throw new Error(`expected a contract address, got ${id}`);
  return id;
};

// --- run state ---------------------------------------------------------------------------------
//
// Two files, and the split is the point. `run.json` holds public addresses and transaction hashes
// and lives in the run directory, which is meant to be read. The secrets — the seeds, and with a
// passkey owner the virtual authenticator's exported credential — live in the file
// `OZPB_HARNESS_SECRETS` names, which `run.sh` puts in a temp directory it deletes on exit; they
// are never printed.

export function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * Replace a journal atomically: a new temporary file in the same directory, written and synced,
 * then renamed over the path, so a process killed mid-write leaves either the old or the new
 * journal, never a truncated one.
 */
const journalIo = { openSync, writeSync, fsyncSync, closeSync, renameSync, rmSync };
export function writeJson(path, value, io = journalIo) {
  const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  const fd = io.openSync(temporary, 'wx');
  try {
    try {
      // A short write (a full disk) must not leave a truncated journal to be renamed into place.
      for (let written = 0; written < bytes.length;) {
        const count = io.writeSync(fd, bytes, written, bytes.length - written, written);
        if (!(count > 0)) throw new Error('journal write made no progress');
        written += count;
      }
      io.fsyncSync(fd);
    } finally { io.closeSync(fd); }
    io.renameSync(temporary, path);
  } catch (error) {
    io.rmSync(temporary, { force: true });
    throw error;
  }
}

export function secretsPath() {
  const path = process.env.OZPB_HARNESS_SECRETS;
  if (!path) throw new Error('OZPB_HARNESS_SECRETS must name the secrets file (run.sh sets it)');
  return path;
}

export function writeSecrets(secrets) {
  // `wx`: never overwrite an existing file, so a stray path cannot clobber someone's keys.
  writeFileSync(secretsPath(), JSON.stringify(secrets), { mode: 0o600, flag: 'wx' });
}

function readSecrets() {
  try {
    return JSON.parse(readFileSync(secretsPath(), 'utf8'));
  } catch {
    // Deliberately not the parser's message: it can quote the file's contents, which are seeds.
    throw new Error('the secrets file is unreadable or not JSON');
  }
}

/**
 * Replace one entry of the secrets file this run created (`writeSecrets` made it). Used to keep a
 * passkey's advancing sign count. Written beside it and renamed over it, so an interrupted write
 * cannot lose the seeds the file also holds.
 */
export function updateSecret(name, value) {
  const secrets = readSecrets();
  if (!(name in secrets)) throw new Error(`no ${name} entry in the secrets file to update`);
  secrets[name] = value;
  const path = secretsPath();
  const next = `${path}.next`;
  try {
    writeFileSync(next, JSON.stringify(secrets), { mode: 0o600, flag: 'wx' });
    renameSync(next, path);
  } catch (e) {
    rmSync(next, { force: true });
    throw e;
  }
}

/** A secret entry as stored, for the ones that are not seeds. */
export function loadSecret(name) {
  const secrets = readSecrets();
  if (!secrets[name]) throw new Error(`no ${name} entry in the secrets file`);
  return secrets[name];
}

export function loadKey(name) {
  return Keypair.fromSecret(loadSecret(name));
}

/**
 * Diagnostic text with this run's secrets removed: every string value of the secrets file (seeds
 * and passkey credential fields), and anything shaped like a Stellar seed. Used for cleanup
 * output that is written to a file; addresses and transaction hashes are kept.
 */
export function redactSecrets(text) {
  let out = String(text);
  const values = [];
  const collect = (v) => {
    if (typeof v === 'string' && v.length >= 16) values.push(v);
    else if (v && typeof v === 'object') Object.values(v).forEach(collect);
  };
  try { collect(JSON.parse(readFileSync(secretsPath(), 'utf8'))); } catch { /* no readable secrets file: patterns only */ }
  for (const value of values.sort((a, b) => b.length - a.length)) out = out.split(value).join('<redacted>');
  return out.replace(/\bS[A-Z2-7]{55}\b/g, '<redacted seed>');
}

/** Parse `--name value` pairs; positional arguments are not used, and a value may not be a flag. */
export function args(argv = process.argv.slice(2)) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const [flag, value] = [argv[i], argv[i + 1]];
    if (!flag.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`bad arguments near ${flag}`);
    }
    out[flag.slice(2)] = value;
  }
  return out;
}
