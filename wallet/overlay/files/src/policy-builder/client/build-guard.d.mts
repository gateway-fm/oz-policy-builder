export type BuildEnv = { readonly VITE_OZPB_NETWORK?: string; readonly DEV?: boolean; readonly PROD?: boolean };
export function buildNetwork(env: BuildEnv | undefined): 'testnet' | 'mainnet';
export function sessionAllowed(network: string, env: BuildEnv | undefined): boolean;
export function sessionRefusal(network: string, env: BuildEnv | undefined): string | null;
export function upstreamAllowed(env: BuildEnv | undefined): boolean;
export const UPSTREAM_DISABLED: string;
export function assertUpstreamEnabled(env: BuildEnv | undefined): void;
