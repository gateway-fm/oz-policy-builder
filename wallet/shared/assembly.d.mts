import type { xdr } from '@stellar/stellar-sdk';
export interface CheckedAssembly {
  readonly envelopeXdr: string;
  readonly authEntriesXdr: readonly string[];
  readonly expirationLedger: number;
  readonly ownerRuleId: number;
  readonly feeStroops: number;
  readonly minLedger: number;
  readonly maxLedger: number;
  readonly authorityCommitment: string;
}
export function signerScVal(signer: unknown): xdr.ScVal;
export function installCall(intent: unknown): xdr.InvokeContractArgs;
export function decodeEnvelope(raw: string): xdr.TransactionEnvelope;
export function validateAssembly(input: unknown): CheckedAssembly;
