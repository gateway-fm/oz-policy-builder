import type { Approval } from './approval.mjs';
import type { LiveCase } from './live-enforcement.mjs';
export const LIVE_HELPER_WASM: string;
export const LIVE_SIGNATURE_LEDGERS: number;
export const LIVE_CONSENT_MIN_LEDGERS: number;
export const LIVE_RUN_MIN_LEDGERS: number;
export const LIVE_MAX_PERMIT_STROOPS: bigint;
export const LIVE_CASES: readonly ['target:original:0', 'target:argument-denial:0'];
export const LIVE_LABELS: readonly string[];
export type LiveGrant =
  | { readonly supported: true; readonly account: string; readonly delegate: string; readonly recipient: string;
    readonly amount: string; readonly maxCalls: number }
  | { readonly supported: false; readonly reason: string };
export interface ConsentDisplay {
  readonly schema: 'ozpb-live-consent/v1';
  readonly network: 'testnet';
  readonly network_id: string;
  readonly current_ledger: number;
  readonly signature_expiration_ledger: number;
  readonly owner_signs: Readonly<Record<string, unknown>>;
  readonly cases: readonly Readonly<Record<string, unknown>>[];
  readonly warning: string;
  readonly labels: readonly string[];
  readonly delegate: { readonly address: string; readonly key: string };
}
export interface LiveOwnerChecked {
  readonly authEntriesXdr: readonly [string];
  readonly ownerRuleId: number;
  readonly expirationLedger: number;
  readonly authorityCommitment: string;
}
export function liveGrant(spec: unknown): LiveGrant;
export function liveShape(input: { spec: unknown; intent: unknown; wallet: unknown }): LiveGrant;
export function liveCases(input: {
  approval: Approval; spec: unknown; helper: string; policyCodeHash: string; expectedRuleId: number; signatureExpirationLedger: number;
}): readonly [LiveCase, LiveCase];
export function consentDisplay(cases: readonly LiveCase[], options: { currentLedger: number }): ConsentDisplay;
export function statementHash(display: ConsentDisplay): string;
export function checkLiveOwnerEntry(input: { approval: Approval; cases: readonly LiveCase[]; ownerEntryXdr: string }): LiveOwnerChecked;
