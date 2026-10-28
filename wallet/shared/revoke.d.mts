import type { xdr } from '#wallet-stellar-sdk';
import type { WalletIdentity } from './approval.mjs';
import type { CheckedAssembly } from './assembly.mjs';
export interface RemovalApproval {
  readonly wallet: WalletIdentity;
  readonly ownerRuleId: number;
  readonly ownerRuleXdr: string;
  readonly commitment: string;
  readonly configurationChange?: { readonly recordedRuleXdr: string; readonly observedRuleXdr: string };
  readonly installation: { readonly account: string; readonly ruleId: number; readonly transactionHash: string };
}
export const REMOVAL_MAX_FEE_STROOPS: 10000000;
export function removalCall(account: string, ruleId: number): xdr.InvokeContractArgs;
export function reviewRemoval(input: unknown): RemovalApproval;
export function validateRemovalAssembly(input: unknown): CheckedAssembly;
export function revokeConsent(input: unknown): Readonly<Record<string, unknown>>;

export function removalConfigurationChange(change: unknown, ruleId: number): Readonly<Record<string, unknown>>;
