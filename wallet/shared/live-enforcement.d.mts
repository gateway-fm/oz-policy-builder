import type { xdr } from '@stellar/stellar-sdk';
export type LiveSigner =
  | { readonly kind: 'delegated'; readonly address: string }
  | { readonly kind: 'external'; readonly verifier: string; readonly key_hex: string };
export interface LiveCase {
  readonly network_id: string;
  readonly helper: string;
  readonly account: string;
  /** The testnet native asset contract, derived, never supplied. */
  readonly asset: string;
  readonly policy: string;
  readonly policy_code_hash: string;
  readonly delegate: string;
  readonly recipient: string;
  readonly amount: string;
  readonly expected_rule_id: number;
  readonly owner_rule_id: number;
  readonly owner_signer: LiveSigner;
  readonly rule_name: string;
  readonly valid_until_ledger: number;
  readonly signature_expiration_ledger: number;
}
interface Ledgers {
  readonly amount: string;
  readonly envelope_xdr_sha256: string;
  readonly simulation_ledger: number;
  readonly signature_expiration_ledger: number;
}
export interface PermitVerdict extends Ledgers {
  readonly outcome: 'permit';
  readonly reason: 'candidate_permitted';
  readonly enforcer: string;
  readonly returned_rule_id: number;
  readonly balance_changes: { readonly account: string; readonly recipient: string };
  readonly candidate_counter: {
    readonly rule_id: number;
    readonly used_before: 0;
    readonly used_after: 1;
    readonly installed_in_simulation: true;
  };
}
export interface DenyVerdict extends Ledgers {
  readonly outcome: 'deny';
  readonly reason: 'policy_denied';
  readonly enforcer: string;
  readonly code: 6;
  readonly host: string;
}
export type FailureReason =
  | 'intent' | 'not_the_helper_call' | 'credentials' | 'expiry' | 'sub_invocations' | 'auth_payload'
  | 'owner_signers' | 'owner_entry_scope' | 'owner_rule_ids' | 'owner_entry_count'
  | 'transfer_signers' | 'transfer_root' | 'transfer_rule_ids' | 'transfer_entry_count'
  | 'unexpected_signer' | 'signer_entry' | 'simulation' | 'ledger_changes' | 'balance_delta'
  | 'rule_not_stored' | 'account_bookkeeping' | 'install_marker' | 'counter_not_dropped'
  | 'nonces' | 'unbound_response' | 'unexpected_ledger_change' | 'returned_rule' | 'helper_refusal' | 'not_a_policy_denial'
  | 'policy_code' | 'malformed';
export interface FailedVerdict {
  readonly outcome: 'failed';
  readonly reason: FailureReason;
  readonly detail: string;
  readonly code?: number;
  readonly host?: string;
}
export type LiveVerdict = PermitVerdict | DenyVerdict | FailedVerdict;
/** The RPC's raw `simulateTransaction` result: XDR stays base64; the SDK's parsed form is refused. */
export interface RawLiveSimulation {
  readonly latestLedger: number;
  readonly error?: string;
  readonly transactionData?: string;
  /** Base64 `DiagnosticEvent`s, which the RPC returns for a failed simulation too. */
  readonly events?: readonly string[];
  readonly results?: readonly { readonly xdr: string; readonly auth?: readonly string[] }[];
  readonly stateChanges?: readonly {
    readonly type: number | 'created' | 'updated' | 'deleted';
    readonly key: string;
    readonly before: string | null;
    readonly after: string | null;
  }[];
  readonly restorePreamble?: unknown;
}
export const HELPER_ERROR_CODES: readonly number[];
export const POLICY_NO_TUPLE_MATCHED: 6;
export function liveCase(intent: unknown): LiveCase;
export function helperCall(intent: unknown): xdr.InvokeContractArgs;
export function transferCall(intent: unknown): xdr.InvokeContractArgs;
export function validateLiveCase(input: { intent: unknown; envelopeXdr: string; simulation: RawLiveSimulation }): LiveVerdict;
