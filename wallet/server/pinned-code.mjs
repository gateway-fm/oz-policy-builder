// Pinned code the wallet needs on its network and never uploads by itself: the recognized account
// Wasm, the WebAuthn verifier Wasm and the atomic live helper. On mainnet a missing one is refused
// with the exact upload command and, when the operator has placed the reproduced Wasm in
// `pinnedWasmDir`, its simulated cost. The generated policy is different: its upload is part of the
// deployment the owner confirms, with its own simulated cost.
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { join } from 'node:path';

const HASH = /^[0-9a-f]{64}$/;
const MAX_WASM_BYTES = 2 * 1024 * 1024;

/** `<dir>/<hash>.wasm` when it is a regular file of at most 2 MiB whose SHA-256 is `hash`; otherwise null. */
export function readPinnedWasm(dir, hash) {
  if (typeof dir !== 'string' || !HASH.test(hash)) return null;
  const path = join(dir, `${hash}.wasm`);
  let fd;
  try {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_WASM_BYTES) return null;
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (opened.ino !== stat.ino || opened.size > MAX_WASM_BYTES) return null;
    const buffer = Buffer.alloc(opened.size);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    const wasm = buffer.subarray(0, length);
    return createHash('sha256').update(wasm).digest('hex') === hash ? wasm : null;
  } catch { return null; } finally { if (fd !== undefined) closeSync(fd); }
}

/**
 * The network arguments of a `stellar` command the owner runs. Testnet is built into stellar-cli; mainnet
 * is not (`--network mainnet` fails, asking for an RPC provider), so the owner names an endpoint. That
 * stays a placeholder, never the operator's `rpcUrl`: it may embed an API key, and this text reaches the
 * browser.
 */
export function stellarNetworkArgs(network) {
  return network.name === 'testnet' ? '--network testnet'
    : `--rpc-url <your ${network.name} RPC endpoint> --network-passphrase '${network.passphrase}'`;
}

/** The exact command the owner runs to upload one pinned Wasm, and where the wallet expects the file. */
export function uploadInstruction(network, dir, hash) {
  const wasmPath = `${dir ?? '<pinnedWasmDir>'}/${hash}.wasm`;
  return Object.freeze({ wasmPath,
    command: `stellar contract upload --wasm ${wasmPath} ${stellarNetworkArgs(network)} --source <your funded ${network.name} key>` });
}
