// Network side of the harness: one RPC client, Friendbot, and a submit loop that refuses to sign
// what simulation rejected. Everything here talks to the live network; nothing here holds a key
// longer than the call that signs with it.
import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import {
  Address, Asset, Keypair, Networks, Operation, StrKey, TransactionBuilder, rpc, scValToNative, xdr,
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

/** Fixed total transaction fee, including Soroban resources: one testnet XLM. */
export const MAX_TRANSACTION_FEE = 10_000_000n;
/** Uploading newly generated code has a larger fixed ceiling: ten testnet XLM. */
export const MAX_WASM_UPLOAD_FEE = 100_000_000n;

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
function checkAssembly(assembled, expectedEnvelope) {
  try {
    const expected = xdr.TransactionEnvelope.fromXDR(expectedEnvelope);
    const intended = expected.v1.tx.operations;
    const maximumFee = intended.length === 1
      && intended[0].body.invokeHostFunctionOp?.hostFunction.type === 'hostFunctionTypeUploadContractWasm'
      ? MAX_WASM_UPLOAD_FEE : MAX_TRANSACTION_FEE;
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
export async function submit(payer, operation, { stage = 'submit' } = {}) {
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '1000000', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(withSourceAuthorization(operation, payer.publicKey())).setTimeout(120).build();
  if (tx.source !== payer.publicKey()) throw new Error('submission refused: RPC returned another fee payer');
  const expectedEnvelope = Buffer.from(tx.toEnvelope().toXDR());
  const sim = await server.simulateTransaction(tx, undefined, 'enforce');
  if (rpc.Api.isSimulationError(sim)) throw new SimulationError(stage, sim.error);
  const assembled = rpc.assembleTransaction(tx, sim).build();
  checkAssembly(assembled, expectedEnvelope);
  assembled.sign(payer);
  const sent = await server.sendTransaction(assembled);
  if (sent.status === 'ERROR') {
    throw new Error(`${stage}: sendTransaction ERROR ${sent.errorResult?.toXDR?.('base64') ?? ''}`);
  }
  const expectedHash = Buffer.from(assembled.hash()).toString('hex');
  if (sent.hash !== expectedHash) throw new Error(`${stage}: RPC returned another transaction identity`);
  const done = await server.pollTransaction(sent.hash, { attempts: 30, sleepStrategy: () => 2000 });
  if (done.status !== 'SUCCESS') {
    throw new Error(`${stage}: transaction ${sent.hash} ended ${done.status}`);
  }
  if (done.txHash !== expectedHash) throw new Error(`${stage}: confirmed transaction identity differs`);
  return { hash: sent.hash, returnValue: done.returnValue, receipt: done };
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
  if (rpc.Api.isSimulationError(sim)) throw new SimulationError(fn, sim.error);
  return { value: sim.result.retval, ledger: readLedger(sim.latestLedger) };
}

/** The wasm hash a contract instance runs, as the network reports it. */
export async function contractCodeHash(contractId) {
  return (await contractCodeObservation(contractId)).value;
}

/** Retain the ledger reported by this instance-entry read. */
export async function contractCodeObservation(contractId) {
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
  return { value: Buffer.from(exec.wasmHash.value ?? exec.wasmHash).toString('hex'), ledger };
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

export function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
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
