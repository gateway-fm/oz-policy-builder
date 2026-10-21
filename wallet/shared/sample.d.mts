import type { xdr } from '#wallet-stellar-sdk';
import type { WalletIdentity } from './approval.mjs';
import type { CheckedAssembly } from './assembly.mjs';
export interface SampleDescriptor {
  readonly recipient: string;
  readonly amountStroops: '1000000';
  readonly ownerRuleXdr: string;
}
export interface SampleApproval {
  readonly wallet: WalletIdentity;
  readonly descriptor: SampleDescriptor;
  readonly ownerRuleXdr: string;
  readonly ownerRuleId: 0;
  readonly commitment: string;
}
export const SAMPLE_AMOUNT_STROOPS: '1000000';
export const SAMPLE_MAX_FEE_STROOPS: 10000000;
export function sampleCall(input: {wallet: WalletIdentity; recipient: string}): xdr.InvokeContractArgs;
export function reviewSample(input: unknown): SampleApproval;
export function validateSampleAssembly(input: unknown): CheckedAssembly;
