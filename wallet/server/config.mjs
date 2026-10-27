import { accessSync, closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { isAbsolute, normalize } from 'node:path';
import { StrKey } from '@stellar/stellar-sdk';
import { RawJson, parseJsonExact } from './raw-json.mjs';

const REQUIRED = ['executable', 'workRoot', 'rpcUrl', 'registrySnapshotPath', 'registryRootsPath', 'registryMinimumVersion'];
const OPTIONAL = ['stellarBinary', 'cargoHome', 'rustupHome', 'buildCacheDir', 'buildJobs', 'buildTimeoutSecs', 'nativeExecutable', 'liveHelper'];
const refused = () => { throw new Error('invalid wallet operator configuration'); };
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
    const url = new URL(value.rpcUrl);
    if (typeof value.rpcUrl !== 'string' || value.rpcUrl.length > 2048 || url.protocol !== 'https:'
      || url.username || url.password || url.search || url.hash) refused();
    const registrySnapshot = file(value.registrySnapshotPath, 2 * 1024 * 1024);
    const registryRoots = file(value.registryRootsPath, 256 * 1024);
    new RawJson(registrySnapshot); new RawJson(registryRoots);
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
    return Object.freeze({ executable: executable(value.executable), workRoot: directory(value.workRoot, true),
      rpcUrl: url.href, registrySnapshot, registryRoots, registryMinimumVersion: value.registryMinimumVersion,
      buildEnvironment: Object.freeze(buildEnvironment), nativeExecutable, liveHelper });
  } catch { refused(); }
}
