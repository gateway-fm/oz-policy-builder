export interface WalletNetworkProfile {
  readonly name: 'testnet' | 'mainnet';
  readonly passphrase: string;
  readonly networkId: string;
  readonly nativeAsset: string;
  readonly unit: string;
  readonly explorer: string;
  readonly friendbot: string | null;
}
export const PROTOCOL_VERSION: 30;
export const WALLET_NETWORKS: Readonly<{ testnet: WalletNetworkProfile; mainnet: WalletNetworkProfile }>;
export function walletNetwork(name: string): WalletNetworkProfile;
export function networkById(networkId: string): WalletNetworkProfile;
export function stroopsText(stroops: string | number, network: WalletNetworkProfile): string;
