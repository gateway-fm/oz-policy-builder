// The wallet-facing install surface, typed: what `prepare_install_intent` and
// `assemble_install_transaction` take and return, over MCP or as the JSON `ozpb
// prepare-install-intent` and `ozpb assemble-install-transaction` print. Types only, with no
// runtime module: `import type { ... } from './install-wire.mjs'`.
//
// Written by hand from the JSON Schemas in docs/wire-contract.json, and held to them by
// wallet/tests/install-wire.test.mjs: every name below is a schema definition (or one of the four
// roots), and its fields, which of them are required, and their types must match. A schema
// change for either tool fails that test until this file follows it.
//
// The types describe shape only. Everything here is advisory input to the wallet, which decodes
// and checks it against its own RPC before showing the user anything (docs/EXTENDING.md).
// Integers are JSON numbers within u32 (`rule_index` and the indexes within usize).

/** `prepare_install_intent` takes exactly the authority check's request. */
export type PrepareInstallIntentInput = CheckPolicyCallSurfaceInput;

export interface AssembleInstallTransactionInput {
  /** Re-run as given: the tool never accepts a caller's intent or verdict. */
  readonly intent_request: CheckPolicyCallSurfaceInput;
  /** Classic G-address paying the fee and sequence. */
  readonly fee_payer: string;
  readonly max_fee_stroops: number;
  /** 1..=120 ledgers from the sequence read. */
  readonly validity_ledgers: number;
}

export interface AssembleInstallTransactionOutput {
  readonly intent: PrepareInstallIntentOutput;
  readonly envelope_xdr_base64: string;
  /** SHA-256 of the envelope bytes, not the network transaction hash. */
  readonly envelope_xdr_sha256: string;
  readonly network_id: string;
  readonly fee_payer: string;
  /** Decimal; the envelope uses this plus one. */
  readonly source_sequence: string;
  readonly fee_stroops: number;
  readonly sequence_read_ledger: number;
  readonly simulation_ledger: number;
  readonly min_ledger: number;
  /** Exclusive. */
  readonly max_ledger: number;
  readonly restoration: InstallAssemblyRestoration;
  readonly simulation_auth_mode: string;
  readonly evidence_trust: string;
  readonly state_dependent: boolean;
  readonly writes_committed: boolean;
  readonly wallet_requirements: readonly string[];
}

export interface CheckPolicyCallSurfaceInput {
  /** The PolicySpec. */
  readonly spec: unknown;
  readonly rule_index: number;
  readonly binding_set: PolicyBindingSet;
  readonly signed_registry_snapshot: unknown;
  readonly account_address: string;
  readonly network_id: string;
  /** A source the operator configured, by name. */
  readonly rpc_source: string;
}

export interface PrepareInstallIntentOutput {
  readonly operation: InstallOperation;
  readonly account_contract: string;
  readonly context_contract: string;
  readonly rule_name: string;
  /** `null`: the grant does not expire. */
  readonly valid_until_ledger: number | null;
  readonly delegate_signers: readonly PolicySignerKey[];
  readonly policies: readonly InstallPolicy[];
  readonly next_steps: readonly string[];
  readonly authority: CheckPolicyCallSurfaceOutput;
}

export interface CheckPolicyCallSurfaceOutput {
  readonly spec_hash: string;
  readonly binding_set_hash: string;
  readonly registry_snapshot_root: string;
  readonly verdict: PolicyCallSurfaceVerdict;
  readonly summary: string;
}

export type InstallAssemblyRestoration =
  | 'none' | 'separate_transaction_reassemble_required' | 'automatic_within_invocation';

export type InstallOperation = 'add_context_rule';

export interface InstallPolicy {
  readonly policy_index: number;
  readonly address: string;
  readonly install_params: InstallPolicyParams;
}

export type InstallPolicyParams =
  | { readonly kind: 'generated' }
  | { readonly kind: 'spending_limit'; readonly spending_limit: string; readonly period_ledgers: number };

export interface PolicyBindingSet {
  readonly schema: string;
  readonly spec_hash: string;
  readonly network_id: string;
  readonly bindings: readonly PolicyBinding[];
}

export interface PolicyBinding {
  readonly rule_index: number;
  readonly policy_index: number;
  readonly contract_address: string;
  readonly observed_wasm_hash: string;
  readonly recognition: PolicyRecognition;
  readonly resolution_reference: string;
}

export type PolicyRecognition =
  | { readonly kind: 'reviewed_registry' }
  | { readonly kind: 'verified_generated_manifest'; readonly build_manifest: unknown };

/** Advisory: the wallet recomputes it and accepts only with no refusal and nothing unresolved. */
export interface PolicyCallSurfaceVerdict {
  readonly observed_ledger: number;
  readonly network_id: string;
  readonly account_address: string;
  readonly account_code_hash: string;
  readonly spec_hash: string;
  readonly binding_set_hash: string;
  readonly bound_policy_addresses: readonly string[];
  readonly grant: PolicyGrant;
  readonly scope: PolicyAuthorityScope;
  readonly authority_list: readonly PolicyAuthorityEntry[];
  readonly refusals: readonly PolicySurfaceFinding[];
  readonly unresolved: readonly PolicySurfaceFinding[];
  readonly coverage_exclusions: readonly PolicyExcludedRule[];
  readonly notes: PolicyAuthorityNotes;
  readonly authority_state: PolicyAuthorityState;
  readonly evidence: PolicyAuthorityEvidence;
  readonly authority_commitment: string;
}

export interface PolicyGrant {
  readonly rule_index: number;
  readonly target: string;
  readonly stateful: boolean;
  readonly signers: readonly PolicySignerKey[];
  readonly name: string;
  readonly valid_until: number | null;
  readonly policies: readonly PolicyGrantPolicy[];
}

export interface PolicyGrantPolicy {
  readonly address: string;
  readonly install_params: InstallPolicyParams;
}

export type PolicySignerKey =
  | { readonly kind: 'delegated'; readonly address: string }
  | { readonly kind: 'external'; readonly verifier: string; readonly key_hex: string };

export interface PolicyAuthorityScope {
  readonly targets: readonly string[];
  readonly account: string;
  readonly bound_policies: readonly string[];
}

export interface PolicyAuthorityEntry {
  readonly rule_id: number;
  readonly reach: PolicyReach;
  readonly valid_until: number | null;
  readonly requirement: PolicyRequirement;
}

export type PolicyReach =
  | { readonly kind: 'any_call' }
  | { readonly kind: 'account_calls' }
  | { readonly kind: 'policy'; readonly address: string }
  | { readonly kind: 'target'; readonly address: string };

export type PolicyRequirement =
  | { readonly kind: 'all_of'; readonly signers: readonly PolicyIdentity[] }
  | { readonly kind: 'any_of'; readonly signers: readonly PolicyIdentity[]; readonly policies: readonly string[] };

/** One marked `aliases_restricted_key` is never an owner. */
export type PolicyIdentity =
  | { readonly kind: 'classic_account'; readonly address: string; readonly ed25519_public_key: string;
    readonly aliases_restricted_key: boolean }
  | { readonly kind: 'external'; readonly verifier: string; readonly verifier_code_hash: string;
    readonly scheme: PolicyKeyScheme; readonly public_key: string; readonly aliases_restricted_key: boolean };

export type PolicyKeyScheme = 'ed25519' | 'webauthn_p256';

export interface PolicySurfaceFinding {
  readonly code: ErrorCode;
  /** `null` when the finding is about the new rule itself. */
  readonly rule_id: number | null;
  readonly unsupported?: PolicyUnsupportedReason | null;
  readonly reason: string;
  readonly remediation: string;
}

export type PolicyUnsupportedReason =
  | 'policy_guarded' | 'contract_signer' | 'external_signer' | 'unrecognized_signer' | 'classic_multisig'
  | 'classic_account_missing' | 'malformed_key' | 'empty_rule';

export interface PolicyExcludedRule {
  readonly rule_id: number;
  readonly context: PolicyRuleContext;
  readonly policy_addresses: readonly string[];
}

export type PolicyRuleContext =
  | 'default'
  | { readonly call_contract: { readonly address: string } }
  | { readonly create_contract: { readonly wasm_hash: string } };

export interface PolicyAuthorityNotes {
  readonly restricted_key_rules: readonly PolicyRestrictedKeyRule[];
  readonly target_rules: readonly PolicyAuthorityEntry[];
  readonly expired_rules: readonly PolicyExpiredRule[];
}

export interface PolicyRestrictedKeyRule {
  readonly rule_id: number;
  readonly context: PolicyRuleContext;
  readonly valid_until: number | null;
  readonly usable_alone: boolean;
  readonly policy_addresses: readonly string[];
}

export interface PolicyExpiredRule {
  readonly rule_id: number;
  readonly context: PolicyRuleContext;
  readonly valid_until: number;
}

export interface PolicyAuthorityState {
  readonly ordered_state_digest: string;
  readonly classic_accounts: Readonly<Record<string, PolicyClassicAccount>>;
  readonly verifiers: Readonly<Record<string, PolicyVerifierObservation>>;
}

export type PolicyClassicAccount =
  | { readonly state: 'not_found' }
  | { readonly state: 'found'; readonly master_weight: number; readonly low_threshold: number;
    readonly medium_threshold: number; readonly high_threshold: number; readonly signers: readonly PolicyClassicSigner[] };

export interface PolicyClassicSigner {
  readonly key: string;
  readonly weight: number;
}

export interface PolicyVerifierObservation {
  readonly code_hash: string;
  /** `null` when the code is not a recognized owner verifier. */
  readonly scheme: PolicyKeyScheme | null;
}

export interface PolicyAuthorityEvidence {
  readonly enumeration_evidence: PolicyRuleEnumerationEvidence;
  readonly source: string;
  readonly evidence_trust: string;
  readonly raw_ordered_entry_digest: string;
  readonly rpc_batches: number;
  readonly attempts: number;
}

export type PolicyRuleEnumerationEvidence =
  | { readonly method: 'onchain_list'; readonly active_count: number; readonly rule_ids: readonly number[];
    readonly signer_ids: readonly number[]; readonly policy_ids: readonly number[] }
  | { readonly method: 'bounded_next_id'; readonly next_id: number; readonly active_count: number;
    readonly rule_ids: readonly number[]; readonly signer_ids: readonly number[]; readonly policy_ids: readonly number[] };

/**
 * The stable codes (docs/VERSIONING.md). A later minor release may add one: treat a code this
 * union does not name as a failure, as for any code.
 */
export type ErrorCode =
  | 'E_TX_NOT_FOUND' | 'E_RETENTION_EXPIRED' | 'E_ENVELOPE_PARSE' | 'E_UNSUPPORTED_ENVELOPE'
  | 'E_NO_SOROBAN_OP' | 'E_OPERATION_SELECTION' | 'E_TX_FAILED' | 'E_UNSUPPORTED_META_VERSION'
  | 'E_META_PARSE' | 'E_RESULT_MISMATCH' | 'E_UNSUPPORTED_ADDRESS' | 'E_AUTH_PARSE'
  | 'E_IMPORT_PARSE' | 'E_RESOURCE_LIMIT' | 'E_NO_EVIDENCE' | 'E_EVIDENCE_TRUST'
  | 'E_EVIDENCE_INCOHERENT' | 'E_NETWORK_MISMATCH' | 'E_AUTHORIZER_NOT_FOUND'
  | 'E_UNSUPPORTED_PATTERN' | 'E_AMBIGUOUS_ARG_SEMANTICS' | 'E_UNREGISTERED_POLICY'
  | 'E_NEEDS_DECISION' | 'E_SPEC_INVALID' | 'E_CODEGEN' | 'E_BUILD_FAILED' | 'E_BUILD_TIMEOUT'
  | 'E_BUILD_RESOURCE_LIMIT' | 'E_BUILD_UNAVAILABLE' | 'E_BUILD_BUSY' | 'E_CANCELLED'
  | 'E_REGISTRY_SIGNATURE' | 'E_REGISTRY_ROLLBACK' | 'E_REGISTRY_NETWORK' | 'E_REGISTRY_EXPIRED'
  | 'E_REGISTRY_VALIDITY' | 'E_REGISTRY_TRANSPARENCY' | 'E_REGISTRY_REVOKED'
  | 'E_INCOMPATIBLE_ACCOUNT' | 'E_UNREGISTERED_VERIFIER' | 'E_TARGET_ADAPTER_UNSUPPORTED'
  | 'E_UNREGISTERED_TEMPLATE' | 'E_REGISTRY_EMPTY' | 'E_REGISTRY_ROOT_POLICY'
  | 'E_POLICY_BINDING_INVALID' | 'E_ACCOUNT_RULE_ENUMERATION_UNSUPPORTED'
  | 'E_INCOMPLETE_ACCOUNT_STATE' | 'E_UNSAFE_CALL_SURFACE' | 'E_UNSAFE_MANAGEMENT_SURFACE'
  | 'E_UNSUPPORTED_AUTHORITY' | 'E_DELEGATE_HAS_AUTHORITY' | 'E_DELEGATE_GRANT_OVERLAP'
  | 'E_SCAN_BUDGET_EXCEEDED' | 'E_TARGET_CODE_CHANGED' | 'E_TARGET_REFUSED' | 'E_TARGET_ARCHIVED'
  | 'E_WALLET_UNAVAILABLE' | 'E_WALLET_PAIRING_REQUIRED' | 'E_WALLET_BUSY' | 'E_WALLET_DRAFT_PENDING'
  | 'E_WALLET_PROPOSAL_REFUSED' | 'E_PUBLISH_PATH' | 'E_PUBLISH_WASM_MISMATCH'
  | 'E_PUBLISH_MANIFEST_MISMATCH' | 'E_PUBLISH_INDEX_MISMATCH' | 'E_PUBLISH_CONFLICT' | 'E_RPC'
  | 'E_INTERNAL';
