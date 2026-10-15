// Network side of the harness: one RPC client, Friendbot, and a submit loop that refuses to sign
// what simulation rejected. Everything here talks to the live network; nothing here holds a key
// longer than the call that signs with it.
import { readFileSync, writeFileSync } from 'node:fs';
import {
  Address, Asset, Keypair, Networks, StrKey, TransactionBuilder, rpc, scValToNative, xdr,
} from '@stellar/stellar-sdk';

export const NETWORK_PASSPHRASE = Networks.TESTNET;
export const RPC_URL = process.env.OZPB_RPC_URL ?? 'https://soroban-testnet.stellar.org';
export const server = new rpc.Server(RPC_URL);
/** What is printed and stored about the endpoint: its origin, never a path, query or credential. */
export const RPC_ORIGIN = new URL(RPC_URL).origin;

/** The pinned OpenZeppelin account example, `ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM`. */
export const PINNED_ACCOUNT_WASM = 'a12747ff6c139dc14fc2fd30d200d6bbb5da7b5d59812c047ce1f9cad226b289';

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

/**
 * Simulate, assemble, sign with the fee payer, submit and wait. An operation that already carries
 * signed auth entries (attached after a recording simulation) is simulated in enforcing mode with
 * them; one without uses the simulation's own source-account authorization.
 *
 * A failed simulation throws `SimulationError` before the transaction is signed or sent, which is
 * what makes a denial observable without spending a fee: the enforcing simulation runs
 * `__check_auth` and the installed policies exactly as the network would.
 */
export async function submit(payer, operation, { stage = 'submit' } = {}) {
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '1000000', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(operation).setTimeout(120).build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new SimulationError(stage, sim.error);
  const assembled = rpc.assembleTransaction(tx, sim).build();
  assembled.sign(payer);
  const sent = await server.sendTransaction(assembled);
  if (sent.status === 'ERROR') {
    throw new Error(`${stage}: sendTransaction ERROR ${sent.errorResult?.toXDR?.('base64') ?? ''}`);
  }
  const done = await server.pollTransaction(sent.hash, { attempts: 30, sleepStrategy: () => 2000 });
  if (done.status !== 'SUCCESS') {
    throw new Error(`${stage}: transaction ${sent.hash} ended ${done.status}`);
  }
  return { hash: sent.hash, returnValue: done.returnValue };
}

/** Run a recording simulation and return the auth entries the network says the call needs. */
export async function recordAuth(payer, operation, stage) {
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(operation).setTimeout(120).build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new SimulationError(`${stage} (recording)`, sim.error);
  return sim.result?.auth ?? [];
}

/** The wasm hash a contract instance runs, as the network reports it. */
export async function contractCodeHash(contractId) {
  const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
    contract: new Address(contractId).toScAddress(),
    key: xdr.ScVal.scvLedgerKeyContractInstance(),
    durability: xdr.ContractDataDurability.persistent,
  }));
  const { entries } = await server.getLedgerEntries(key);
  if (entries.length !== 1) throw new Error(`no instance entry for ${contractId}`);
  const exec = entries[0].val.contractData.val.instance.executable;
  if (exec.type !== 'contractExecutableWasm') throw new Error(`${contractId} is not a wasm contract (${exec.type})`);
  return Buffer.from(exec.wasmHash.value ?? exec.wasmHash).toString('hex');
}

export const contractIdOf = (scv) => {
  const id = scValToNative(scv);
  if (!StrKey.isValidContract(id)) throw new Error(`expected a contract address, got ${id}`);
  return id;
};

// --- run state ---------------------------------------------------------------------------------
//
// Two files, and the split is the point. `run.json` holds public addresses and transaction hashes
// and lives in the run directory, which is meant to be read. The secret seeds live in the file
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

export function loadKey(name) {
  let secrets;
  try {
    secrets = JSON.parse(readFileSync(secretsPath(), 'utf8'));
  } catch {
    // Deliberately not the parser's message: it can quote the file's contents, which are seeds.
    throw new Error('the secrets file is unreadable or not JSON');
  }
  if (!secrets[name]) throw new Error(`no ${name} key in the secrets file`);
  return Keypair.fromSecret(secrets[name]);
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
