//! MCP wire contract (architecture §4.6, §4.11).
//!
//! This crate IS the interface: the MCP server's `Parameters<T>`/`Json<T>` types come
//! from here, so the generated JSON Schemas and the implementation cannot drift. Every
//! tool has structured input and output; every failure is a stable machine-readable
//! code. No domain logic lives here.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable machine-readable error codes surfaced to agents (architecture §4.6). Kept in
/// one place so the whole toolkit shares one vocabulary; new codes are appended, never
/// renumbered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum ErrorCode {
    // recorder
    ETxNotFound,
    ERetentionExpired,
    EEnvelopeParse,
    EUnsupportedEnvelope,
    ENoSorobanOp,
    EOperationSelection,
    ETxFailed,
    EUnsupportedMetaVersion,
    EMetaParse,
    EUnsupportedAddress,
    EAuthParse,
    EImportParse,
    EResourceLimit,
    // synthesizer
    ENoEvidence,
    EEvidenceTrust,
    ENetworkMismatch,
    EAuthorizerNotFound,
    EUnsupportedPattern,
    EAmbiguousArgSemantics,
    EUnregisteredPolicy,
    ENeedsDecision,
    // spec / codegen
    ESpecInvalid,
    ECodegen,
    EBuildFailed,
    EBuildTimeout,
    EBuildResourceLimit,
    /// The builder could not be started or configured at all — a misconfigured
    /// `stellar` binary path, an unusable build cache, a rejected operator setting.
    /// Distinct from `EBuildFailed` so an operator fault is never reported to an agent
    /// as "your spec does not compile".
    EBuildUnavailable,
    // registry
    ERegistrySignature,
    ERegistryRollback,
    ERegistryNetwork,
    ERegistryExpired,
    ERegistryValidity,
    ERegistryTransparency,
    ERegistryRevoked,
    EIncompatibleAccount,
    EUnregisteredVerifier,
    EUnregisteredTemplate,
    ERegistryEmpty,
    // policy recognition / authority surface
    EPolicyBindingInvalid,
    EAccountRuleEnumerationUnsupported,
    EIncompleteAccountState,
    EAdminRuleUnsafe,
    EUnsafeCallSurface,
    EUnsafeManagementSurface,
    EScanBudgetExceeded,
    // rpc / transport
    ERpc,
    // catch-all internal
    EInternal,
}

/// Uniform structured error returned by every tool on failure.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    /// Present when a tool fails with several findings (e.g. spec validation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ToolError {
            code,
            message: message.into(),
            details: vec![],
        }
    }
    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)?;
        for d in &self.details {
            write!(f, "\n  - {d}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ToolError {}

// ---------------------------------------------------------------------------------------
// Tool inputs/outputs. Domain artifacts (RecordingBundle, PolicySpec, …) are carried as
// JSON values so this wire crate stays free of domain dependencies; the server
// (de)serializes them against the real types.
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecordTransactionInput {
    /// Network passphrase (e.g. "Test SDF Network ; September 2015").
    pub network_passphrase: String,
    /// Transaction hash (64 hex chars).
    pub tx_hash: String,
    /// RPC endpoint URL. On the hosted service this must be an allowlisted endpoint.
    pub rpc_url: String,
    #[serde(default)]
    pub operation_index: Option<u32>,
    #[serde(default)]
    pub allow_failed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecordSimulationInput {
    pub network_passphrase: String,
    /// Unsigned transaction envelope, base64 XDR. Confidential input (§6.5).
    pub envelope_xdr_base64: String,
    pub rpc_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecordOutput {
    /// The RecordingBundle as JSON.
    pub bundle: serde_json::Value,
    /// Full recording hash (hex).
    pub recording_hash: String,
    pub trust: String,
    /// Human-readable notes (e.g. unattributed events).
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SynthesizeInput {
    /// One or more RecordingBundles as JSON.
    pub bundles: Vec<serde_json::Value>,
    /// The selected smart-account authorizer (strkey).
    pub selected_authorizer: String,
    /// The account compatibility record as JSON (SmartAccountRecord).
    pub account: serde_json::Value,
    /// Signed capability-registry snapshot. Its signature, network, validity window, and
    /// rollback version are verified against the server/CLI-configured trusted root; the
    /// request cannot select its own trust root.
    pub signed_registry_snapshot: serde_json::Value,
    /// The user decisions (UserDecisions) as JSON.
    pub decisions: serde_json::Value,
    /// Reviewed spending-limit wasm hash (hex), if composing it.
    #[serde(default)]
    pub spending_limit_capability: Option<String>,
    pub template_family: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SynthesizeOutput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    /// Canonical spec hash (hex).
    pub spec_hash: String,
    /// Per-constraint reasoning for display.
    pub rationale: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EvaluateSpecInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    /// The evaluation context (EvalContext) as JSON.
    pub context: serde_json::Value,
    /// The candidate invocation (Invocation) as JSON.
    pub invocation: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EvaluateSpecOutput {
    /// "permit", "deny", or "indeterminate". The last verdict is fail-closed: at least one
    /// composed reviewed policy is outside the Phase 1 evaluator's model.
    pub verdict: String,
    /// Present on deny or indeterminate: the machine-readable reason. The wire name is retained
    /// for compatibility even though an indeterminate reason is not a denial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GenerateCodeInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    pub rule_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GenerateCodeOutput {
    pub crate_name: String,
    /// Relative path → file contents (Cargo.toml, src/lib.rs).
    pub files: std::collections::BTreeMap<String, String>,
    /// Pre-build normalized codegen input hash (hex). NOT the wasm hash (§4.10).
    pub normalized_input_hash: String,
    /// Pinned build inputs recorded for the BuildManifest.
    pub soroban_sdk_version: String,
    pub stellar_accounts_version: String,
    /// Built Wasm bytes. This is base64 to keep the JSON/MCP artifact self-contained.
    pub wasm_base64: String,
    pub wasm_hash: String,
    /// BuildManifest binding the spec/codegen/source/lock/toolchain/Wasm artifact chain.
    pub build_manifest: serde_json::Value,
    pub build_manifest_hash: String,
}

// --- import_recording ------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImportRecordingInput {
    pub network_passphrase: String,
    /// Raw transaction envelope, base64 XDR.
    pub envelope_xdr_base64: String,
    #[serde(default)]
    pub result_meta_xdr_base64: Option<String>,
    #[serde(default)]
    pub ledger: Option<u32>,
    #[serde(default)]
    pub created_at_unix: Option<i64>,
    /// Unverified supplier claim that the transaction succeeded.
    pub successful: bool,
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::no_build_settings_on_the_wire;

    #[test]
    fn error_codes_round_trip() {
        for code in [
            ErrorCode::ETxNotFound,
            ErrorCode::ENeedsDecision,
            ErrorCode::EInternal,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back);
        }
    }

    #[test]
    fn tool_error_displays_with_details() {
        let e = ToolError::new(ErrorCode::ESpecInvalid, "spec invalid")
            .with_details(vec!["rule 0: no signers".into()]);
        let s = format!("{e}");
        assert!(s.contains("ESpecInvalid"));
        assert!(s.contains("rule 0"));
    }

    #[test]
    fn the_wire_contract_carries_no_build_configuration() {
        no_build_settings_on_the_wire(
            "GenerateCodeInput",
            schemars::schema_for!(GenerateCodeInput),
        );
    }

    #[test]
    fn dtos_have_schemas() {
        // schemars must be able to generate a schema for every input type (this is what
        // the MCP server exposes; if it panics, the wire contract is broken).
        let _ = schemars::schema_for!(RecordTransactionInput);
        let _ = schemars::schema_for!(SynthesizeInput);
        let _ = schemars::schema_for!(EvaluateSpecInput);
        let _ = schemars::schema_for!(GenerateCodeInput);
        let _ = schemars::schema_for!(GenerateCodeOutput);
    }
}
