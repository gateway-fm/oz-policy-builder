import { accessSync, closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { isAbsolute, normalize } from 'node:path';
import { Keypair, StrKey, hash } from '@stellar/stellar-sdk';
import { RawJson, parseJsonExact } from './raw-json.mjs';
import { walletNetwork } from '../shared/networks.mjs';
import { FeePayer, loadDelegateKey, loadFeePayerKey } from './fee-payer.mjs';
import { MAX_FEE_STROOPS, MAX_UPLOAD_FEE_STROOPS } from './network.mjs';

const REQUIRED = ['executable', 'workRoot', 'rpcUrl', 'registrySnapshotPath', 'registryRootsPath', 'registryMinimumVersion'];
const OPTIONAL = ['network', 'registryPublishedPath', 'feePayerKeyPath', 'delegateKeyPath', 'maxFeeStroops', 'maxUploadFeeStroops', 'sessionSpendCapStroops', 'pinnedWasmDir', 'stellarBinary', 'cargoHome', 'rustupHome', 'buildCacheDir', 'buildJobs', 'buildTimeoutSecs', 'nativeExecutable', 'liveHelper'];
const refused = () => { throw new Error('invalid wallet operator configuration'); };
/** Fields only a mainnet configuration takes: its funding model, its caps and its pinned-code directory. */
const MAINNET_ONLY = ['feePayerKeyPath', 'delegateKeyPath', 'maxFeeStroops', 'maxUploadFeeStroops', 'sessionSpendCapStroops', 'pinnedWasmDir'];
/**
 * Mainnet's fee caps: per transaction (a policy Wasm upload has its own, since mainnet's state-size
 * rent makes a policy upload cost tens of XLM) and for the whole session. The defaults are
 * conservative; the upload and session caps are the operator's settings, set from the simulated
 * costs the wallet shows (docs/MAINNET-INSTALL.md), up to the ceilings below. The upload cap never
 * exceeds the session cap.
 */
export const MAINNET_FEE_DEFAULTS = Object.freeze({ maxFeeStroops: 10_000_000, maxUploadFeeStroops: 120_000_000,
  sessionSpendCapStroops: 150_000_000 });
const MAINNET_FEE_CEILINGS = Object.freeze({ maxFeeStroops: MAX_FEE_STROOPS, maxUploadFeeStroops: 500_000_000,
  sessionSpendCapStroops: 500_000_000 });
/**
 * The development registry's root key, derived as the registry crate derives it
 * (`dev_signing_key`: the Ed25519 key whose seed is SHA-256 of a public label). Anyone can sign with
 * it, so a mainnet session refuses a root policy that names it.
 */
export const DEVELOPMENT_REGISTRY_ROOT = Buffer.from(Keypair.fromRawEd25519Seed(Buffer.from(hash(Buffer.from('ozpb-dev-registry-root-key-v1'))))
  .rawPublicKey()).toString('hex');
/**
 * Mainnet trusts only the operator's production registry: a root policy (threshold and keys) that
 * does not name the development root, with the persisted checkpoint the CLI rejects rollback and
 * equivocation against, at or above the configured floor. Refused at startup with the reason.
 */
function mainnetRegistryTrust(rootsText, minimumVersion) {
  const refusedTrust = (detail) => { throw Object.assign(new Error('registry trust refused'), { startup: detail }); };
  const roots = parseJsonExact(rootsText);
  const keys = roots?.keys && typeof roots.keys === 'object' && !Array.isArray(roots.keys) ? Object.values(roots.keys) : [];
  if (!Number.isSafeInteger(roots?.threshold) || roots.threshold < 1 || !keys.length || keys.some((key) => typeof key !== 'string')) {
    refusedTrust('The registry root policy must name a threshold and at least one key.');
  }
  if (keys.some((key) => key.toLowerCase() === DEVELOPMENT_REGISTRY_ROOT)) {
    refusedTrust('On mainnet the development registry root is refused: anyone can sign with it. Configure the operator\'s '
      + 'production root policy, signed snapshot and checkpoint.');
  }
  const checkpoint = roots.checkpoint;
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) {
    refusedTrust('On mainnet the registry root policy must carry the persisted checkpoint (`checkpoint`).');
  }
  // The CLI writes u64 fields as canonical decimal strings (older files as JSON integers): read both, as BigInt.
  const u64 = (value) => {
    const text = typeof value === 'string' ? value : Number.isSafeInteger(value) && value >= 0 ? String(value) : null;
    if (text === null || !/^(0|[1-9][0-9]{0,19})$/.test(text) || BigInt(text) > 0xffffffffffffffffn) return null;
    return BigInt(text);
  };
  const version = u64(checkpoint.version);
  if (version === null || u64(checkpoint.log_index) === null || typeof checkpoint.root !== 'string' || !/^[0-9a-f]{64}$/.test(checkpoint.root)) {
    refusedTrust('The persisted registry checkpoint must carry its version, log_index and root.');
  }
  if (version < BigInt(minimumVersion)) {
    refusedTrust('The persisted registry checkpoint is older than the configured minimum version.');
  }
}
const integer = (value, max) => Number.isSafeInteger(value) && value >= 1 && value <= max;

function pathInfo(path) {
  if (typeof path !== 'string' || path.length > 4096 || !isAbsolute(path) || normalize(path) !== path
    || realpathSync(path) !== path || typeof process.getuid !== 'function') refused();
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || ![0, process.getuid()].includes(stat.uid) || (stat.mode & 0o022)) refused();
  return stat;
}

function file(path, maximum) {
  const stat = pathInfo(path);
  if (!stat.isFile() || stat.size > maximum) refused();
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.ino !== stat.ino || opened.dev !== stat.dev || opened.size > maximum) refused();
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > maximum) refused();
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length));
  } finally { closeSync(fd); }
}

function executable(path) {
  if (!pathInfo(path).isFile()) refused();
  accessSync(path, constants.X_OK);
  return path;
}

function directory(path, privateOnly = false) {
  const stat = pathInfo(path);
  if (!stat.isDirectory() || privateOnly && (stat.uid !== process.getuid() || (stat.mode & 0o077))) refused();
  accessSync(path, constants.R_OK | constants.X_OK | (privateOnly ? constants.W_OK : 0));
  return path;
}

/** Fixed operator configuration; no request can replace paths, trust roots, or build environment. */
export function loadWalletConfig(path) {
  try {
    const value = parseJsonExact(file(path, 16 * 1024));
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || REQUIRED.some((name) => !Object.hasOwn(value, name))
      || Object.keys(value).some((name) => !REQUIRED.includes(name) && !OPTIONAL.includes(name))
      || !integer(value.registryMinimumVersion, Number.MAX_SAFE_INTEGER)) refused();
    // The session's network, chosen once here: `testnet` (the default) or `mainnet`, nothing else.
    const network = walletNetwork(Object.hasOwn(value, 'network') ? value.network : 'testnet');
    const mainnet = network.name === 'mainnet';
    if (!mainnet && MAINNET_ONLY.some((name) => Object.hasOwn(value, name))) refused();
    // The registry floor is the operator's own registry's version (at least 1): the mainnet registry is
    // its own chain from version 1, not the development registry's (whose floor is 6).
    if (mainnet && !Object.hasOwn(value, 'feePayerKeyPath')) refused();
    const fees = mainnet ? Object.fromEntries(Object.entries(MAINNET_FEE_DEFAULTS).map(([name, fallback]) => {
      const chosen = Object.hasOwn(value, name) ? value[name] : fallback;
      if (!Number.isSafeInteger(chosen) || chosen < 100 || chosen > MAINNET_FEE_CEILINGS[name]) refused();
      return [name, chosen];
    })) : { maxFeeStroops: MAX_FEE_STROOPS, maxUploadFeeStroops: MAX_UPLOAD_FEE_STROOPS, sessionSpendCapStroops: null };
    if (mainnet && (fees.maxFeeStroops > fees.sessionSpendCapStroops || fees.maxUploadFeeStroops > fees.sessionSpendCapStroops)) refused();
    // Mainnet: the operator's own key, which it funds; testnet: a disposable key Friendbot funds.
    const feePayer = mainnet ? loadFeePayerKey(value.feePayerKeyPath) : FeePayer.disposable();
    const pinnedWasmDir = Object.hasOwn(value, 'pinnedWasmDir') ? directory(value.pinnedWasmDir) : null;
    // The operator's published registry log (a directory of signed versions, or its head file), for `registry monitor`.
    let registryPublishedPath = null;
    if (Object.hasOwn(value, 'registryPublishedPath')) {
      const stat = pathInfo(value.registryPublishedPath);
      if (!stat.isDirectory() && !stat.isFile()) refused();
      registryPublishedPath = value.registryPublishedPath;
    }
    // Mainnet: the grant's delegate is the agent's key. Only this optional file gives the wallet a key it may
    // sign with as a delegate (for the checks that need its signatures and the one use of the grant).
    const delegateKey = Object.hasOwn(value, 'delegateKeyPath') ? loadDelegateKey(value.delegateKeyPath) : null;
    if (delegateKey && delegateKey.address === feePayer.address) {
      throw Object.assign(new Error('delegate key refused'), { startup: 'The delegate key must not be the fee payer\'s key: the fee '
        + 'payer is never a signer on an account.' });
    }
    const url = new URL(value.rpcUrl);
    if (typeof value.rpcUrl !== 'string' || value.rpcUrl.length > 2048 || url.protocol !== 'https:'
      || url.username || url.password || url.search || url.hash) refused();
    const registrySnapshot = file(value.registrySnapshotPath, 2 * 1024 * 1024);
    const registryRoots = file(value.registryRootsPath, 256 * 1024);
    new RawJson(registrySnapshot); new RawJson(registryRoots);
    if (mainnet) mainnetRegistryTrust(registryRoots, value.registryMinimumVersion);
    const buildEnvironment = { CARGO_NET_OFFLINE: 'true' };
    if (Object.hasOwn(value, 'stellarBinary')) buildEnvironment.OZPB_STELLAR_BINARY = executable(value.stellarBinary);
    if (Object.hasOwn(value, 'cargoHome')) buildEnvironment.CARGO_HOME = directory(value.cargoHome);
    if (Object.hasOwn(value, 'rustupHome')) buildEnvironment.RUSTUP_HOME = directory(value.rustupHome);
    if (Object.hasOwn(value, 'buildCacheDir')) buildEnvironment.OZPB_BUILD_CACHE_DIR = directory(value.buildCacheDir, true);
    for (const [field, env, maximum] of [['buildJobs', 'OZPB_BUILD_JOBS', 32], ['buildTimeoutSecs', 'OZPB_BUILD_TIMEOUT_SECS', 900]]) {
      if (Object.hasOwn(value, field)) {
        if (!integer(value[field], maximum)) refused();
        buildEnvironment[env] = String(value[field]);
      }
    }
    // The native worker is optional; without it the account-Wasm layer stays unavailable.
    const nativeExecutable = Object.hasOwn(value, 'nativeExecutable') ? executable(value.nativeExecutable) : null;
    // The deployed atomic live helper's contract ID; without it the live-enforcement layer is unavailable.
    // Its code is read back and matched to the reviewed hash before every use, never trusted from here.
    if (Object.hasOwn(value, 'liveHelper') && (typeof value.liveHelper !== 'string' || !StrKey.isValidContract(value.liveHelper))) refused();
    const liveHelper = Object.hasOwn(value, 'liveHelper') ? value.liveHelper : null;
    return Object.freeze({ network, feePayer, delegateKey, fees: Object.freeze(fees), pinnedWasmDir, registryPublishedPath, executable: executable(value.executable), workRoot: directory(value.workRoot, true),
      rpcUrl: url.href, registrySnapshot, registryRoots, registryMinimumVersion: value.registryMinimumVersion,
      buildEnvironment: Object.freeze(buildEnvironment), nativeExecutable, liveHelper });
  } catch (error) {
    // A fee payer key refusal says why, never with the file's content.
    if (typeof error?.startup === 'string') throw error;
    refused();
  }
}
