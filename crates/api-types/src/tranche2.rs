//! Wire types for the operations delivered after the MVP milestone.
//!
//! These sit in their own module so the milestone boundary is a **file** boundary: a delivery
//! that does not include dry-run, verification, authority-surface checking or install-intent
//! preparation drops this file and the `mod`/`pub use` lines that name it, and needs no edit
//! inside a shared file. Surgery on a shared file is the kind of change that goes quietly wrong
//! and cannot be repeated reliably at the next milestone.
//!
//! What groups them is not the milestone number but what they need: every operation here either
//! models a policy's runtime behaviour or reads on-chain authority state, while the MVP surface
//! only records, synthesizes and generates.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// --- dry_run ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DryRunOutput {
    /// The labeled permit/deny evidence report (layer 1) as JSON.
    pub report: serde_json::Value,
    pub total: usize,
    pub disagreements: usize,
    /// True iff the original permits and every derived deny-case denies.
    pub all_agree: bool,
    /// Composed **reviewed** policies (e.g. `oz:spending_limit`) that layer 1 does NOT
    /// model, as `"rule[<i>]: <kind>"`. When non-empty, `all_agree` covers only the
    /// scope+count semantics — the listed policies are enforced on-chain but their stateful
    /// caps/windows are outside this report. Never read `all_agree` as coverage of these.
    pub unmodeled_reviewed_policies: Vec<String>,
    /// Boundary classes actually exercised, as `"<class>: <count>"`. `all_agree` is silent
    /// about coverage, so this is what says how wide the evidence is.
    pub coverage: Vec<String>,
    /// Classes a rule's shape requires but the suite did not exercise, as
    /// `"rule[<i>]: <class>"`. Checked per rule, so one rule's coverage cannot vouch for
    /// another's gap. Non-empty means the evidence is narrower than `all_agree` implies — a
    /// gate failure, not a warning.
    pub missing_classes: Vec<String>,
    /// Classes exercised but never shown to *deny*, as `"rule[<i>]: <class>"`. Usually a
    /// degenerate bound rather than a gap — a cap of `i128::MAX` cannot be exceeded — so this
    /// is reported, not gated. It means the grant is effectively unbounded on that axis.
    pub permit_only_classes: Vec<String>,
}

// --- verify ----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    pub rule_index: usize,
    /// The generated source to check against regeneration: relative path → contents, for every
    /// Rust file of the crate (`src/lib.rs`, `src/contract.rs`).
    ///
    /// A map rather than one string, and every file compared rather than the root alone. Emission
    /// produces a crate root and a contract module; a single-file field would have held the
    /// header, and a hand edit anywhere in the contract would have been reported as reproduced —
    /// the one answer this operation must never give wrongly. Missing and unexpected paths are
    /// mismatches too, so a custom-source crate cannot pass by adding a module.
    pub claimed_sources: std::collections::BTreeMap<String, String>,
    /// Built artifact to reproduce. Omission is reported as not verified, never success.
    #[serde(default)]
    pub claimed_wasm_base64: Option<String>,
    /// BuildManifest supplied with the artifact. Omission is reported separately.
    #[serde(default)]
    pub claimed_build_manifest: Option<serde_json::Value>,
}

/// Each dimension is reported separately — never collapsed into one "pure" boolean
/// (architecture §6.3). Live preflight remains state-dependent and separate.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VerifyOutput {
    pub spec_conformance: String,
    pub source_reproduction: String,
    pub offline_behavioral_conformance: String,
    pub wasm_reproduction: String,
    pub current_network_preflight: String,
    pub normalized_input_hash: String,
    /// Whether layer 1 models **every** policy composed into this rule. Its own dimension,
    /// deliberately not folded into `matches`: "the reproductions agree" and "the evidence
    /// covers every composed policy" are different claims, and collapsing them would let a
    /// green `matches` imply coverage the report does not have.
    pub models_all_policies: bool,
    /// The composed reviewed policies layer 1 does not model, as `"rule[<i>]: <kind>"`.
    /// Non-empty means those policies are enforced only on-chain.
    pub unmodeled_reviewed_policies: Vec<String>,
    pub matches: bool,
}

// --- check_against_policy --------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckAgainstPolicyInput {
    /// PolicySpec and exact installed instance bindings. Recognition is verified by the
    /// toolkit; there is deliberately no caller-supplied `recognized` boolean.
    pub spec: serde_json::Value,
    pub binding_set: PolicyBindingSet,
    pub signed_registry_snapshot: serde_json::Value,
    pub rule_index: usize,
    pub context: serde_json::Value,
    pub invocation: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgainstPolicyOutput {
    /// "permit" | "deny" | "unsupported".
    pub prediction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// State-dependence note: this is a prediction at the supplied context, not a durable
    /// verdict (§4.6).
    pub note: String,
}

// --- policy binding + call-surface check ----------------------------------------------

pub const POLICY_BINDING_SET_SCHEMA: &str = "policy-binding-set/v1";

/// Exact deployed instances corresponding positionally to every PolicyRef in a spec.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBindingSet {
    pub schema: String,
    pub spec_hash: String,
    pub network_id: String,
    pub bindings: Vec<PolicyBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBinding {
    pub rule_index: usize,
    pub policy_index: usize,
    pub contract_address: String,
    pub observed_wasm_hash: String,
    pub recognition: PolicyRecognition,
    /// Deployment transaction hash or immutable registry reference used to resolve this
    /// exact instance. Informational evidence; recognition is verified independently.
    pub resolution_reference: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyRecognition {
    ReviewedRegistry,
    VerifiedGeneratedManifest { build_manifest: serde_json::Value },
}

/// Pure evaluation of an already-acquired coherent account-state snapshot. The acquisition
/// shell is responsible for obtaining these ledger entries from one ledger; caller booleans
/// are not accepted as recognition evidence.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckPolicyCallSurfaceInput {
    pub spec: serde_json::Value,
    pub binding_set: PolicyBindingSet,
    pub signed_registry_snapshot: serde_json::Value,
    pub account_state: serde_json::Value,
    pub account_address: String,
    pub account_code_hash: String,
    pub admin_rule_id: u32,
    pub observed_ledger: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CheckPolicyCallSurfaceOutput {
    pub binding_set_hash: String,
    pub verdict: serde_json::Value,
}

// --- prepare_install_intent ------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareInstallIntentInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
    pub rule_index: usize,
    /// Exact, recognition-verified deployed policy instances.
    pub binding_set: PolicyBindingSet,
    /// A Safe verdict produced for this exact binding set, account, and code hash.
    pub call_surface_verdict: serde_json::Value,
}

/// The pure install intent: the `add_context_rule` operation shape and parameters. It is
/// NOT a signed or even assembled transaction — assembling one needs current sequence,
/// fees, ledger bounds and restoration preambles (an RPC-backed, wallet-owned step), and
/// the call-surface check must pass first. Signing is always wallet-owned (§6.2).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrepareInstallIntentOutput {
    pub operation: String,
    pub target_contract: String,
    pub rule_name: String,
    pub valid_until_ledger: Option<u32>,
    pub delegate_signers: Vec<String>,
    pub policy_addresses: Vec<String>,
    pub next_steps: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::no_build_settings_on_the_wire;

    #[test]
    fn the_wire_contract_carries_no_build_configuration() {
        for (dto, schema) in [
            ("VerifyInput", schemars::schema_for!(VerifyInput)),
            (
                "CheckAgainstPolicyInput",
                schemars::schema_for!(CheckAgainstPolicyInput),
            ),
            (
                "CheckPolicyCallSurfaceInput",
                schemars::schema_for!(CheckPolicyCallSurfaceInput),
            ),
        ] {
            no_build_settings_on_the_wire(dto, schema);
        }
    }

    #[test]
    fn every_post_mvp_dto_has_a_schema() {
        let _ = schemars::schema_for!(DryRunInput);
        let _ = schemars::schema_for!(DryRunOutput);
        let _ = schemars::schema_for!(VerifyInput);
        let _ = schemars::schema_for!(VerifyOutput);
        let _ = schemars::schema_for!(CheckAgainstPolicyInput);
        let _ = schemars::schema_for!(CheckAgainstPolicyOutput);
        let _ = schemars::schema_for!(PolicyBindingSet);
        let _ = schemars::schema_for!(PolicyBinding);
        let _ = schemars::schema_for!(PolicyRecognition);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceInput);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceOutput);
        let _ = schemars::schema_for!(PrepareInstallIntentInput);
        let _ = schemars::schema_for!(PrepareInstallIntentOutput);
    }
}
