export interface WalletIdentity {
  readonly contractId: string;
  readonly credentialId: string;
  readonly publicKey: string;
  readonly verifier: string;
}
export interface Approval {
  readonly wallet: WalletIdentity;
  readonly ownerRuleId: number;
  readonly ownerRuleXdr: string;
  readonly commitment: string;
  readonly observedLedger: number;
  readonly intent: Readonly<Record<string, unknown>>;
  readonly expected: Readonly<Record<string, unknown>>;
  readonly authorities: readonly unknown[];
  readonly approval_state: 'reviewed_not_signed';
  readonly trust_basis: 'wallet_owned_passkey_identity';
}
export const NETWORK_ID: string;
export const ACCOUNT_WASM: string;
export const WEBAUTHN_WASM: string;
export function freezeCopy<T>(value: T): Readonly<T>;
export function ownerRule(intent: unknown, wallet: WalletIdentity, raw: string): number;
export function reviewIntent(input: unknown): Approval;
