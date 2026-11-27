import type { Plugin } from 'vite';
export const BUILD_MARKER: 'ozpb-build-network.txt';
export function buildNetworkMarker(): Plugin;
export function builtNetwork(outDir: string): 'testnet' | 'mainnet';
