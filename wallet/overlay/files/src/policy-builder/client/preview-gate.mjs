// Which build `vite preview` serves, as the build itself recorded it. Only a production build made
// for mainnet may reach the mainnet backend, and the shell that later runs `vite preview` cannot
// change what a build was made for: the build writes its network beside its client output, and the
// preview proxy forwards only when that record says exactly `mainnet`. Used by vite.config.ts only.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildNetwork } from './build-guard.mjs';

export const BUILD_MARKER = 'ozpb-build-network.txt';

/**
 * A Vite plugin: each build writes the network it was made for (build-guard's `buildNetwork`, from the
 * build's resolved env, which is what its `import.meta.env` is made from) into the client output.
 */
export function buildNetworkMarker() {
  let network = 'testnet';
  return {
    name: 'ozpb-build-network-marker',
    apply: 'build',
    configResolved(config) { network = buildNetwork(config.env); },
    generateBundle() {
      if (this.environment && this.environment.name !== 'client') return;
      this.emitFile({ type: 'asset', fileName: BUILD_MARKER, source: network });
    },
  };
}

/** The network the build in `outDir` was made for: `mainnet` only when its record says exactly that. */
export function builtNetwork(outDir) {
  try { return readFileSync(join(outDir, BUILD_MARKER), 'utf8') === 'mainnet' ? 'mainnet' : 'testnet'; } catch { return 'testnet'; }
}
