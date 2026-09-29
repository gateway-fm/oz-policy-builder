//! Wire types for reference evaluation, verification, live policy checks, and install intent.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// --- reference_suite (layer 1 of the future four-layer dry_run) --------------------------

/// Layer-1 reference evaluation only. The full `dry_run` operation also needs contract
/// integration, a disposable environment, and live preflight (§4.5); this type does not
/// claim those layers or expose mutation modes.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReferenceSuiteInput {
    /// The PolicySpec as JSON.
    pub spec: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReferenceSuiteOutput {
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
    /// Every generated file except `Cargo.lock`, as relative path → contents. This is
    /// exactly the set hashed into `source_hash`: it includes `Cargo.toml`,
    /// `rust-toolchain.toml`, `rustfmt.toml`, `src/lib.rs`, and `src/contract.rs`.
    ///
    /// The implementation must compare the complete key set as well as contents. A missing
    /// manifest/toolchain file or an extra source module is a mismatch, not reproduction.
    pub claimed_generated_files: std::collections::BTreeMap<String, String>,
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
    /// Smart account whose installed rule and policy state will be read.
    pub account_address: String,
    /// Must match the spec and binding set; the server selects a configured endpoint.
    pub network_id: String,
    /// Name of a configured RPC source, never an arbitrary client URL.
    pub rpc_source: String,
    /// Candidate signer identities for this authorization. The server reads live rule
    /// signers, verifier code, counters and ledger state from the selected network.
    pub candidate_signers: Vec<PolicyCheckSigner>,
    /// Proposed invocation, not an observation of installed policy state.
    pub invocation: serde_json::Value,
}

/// Signer identities proposed for a policy check. The current verifier implementation
/// hash is an observation, so an external signer cannot supply it here.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyCheckSigner {
    Delegated { address: String },
    External { verifier: String, key_hex: String },
}

/// A live permit/deny prediction must carry the observations on which it depends. If the
/// ledger state was not acquired, the only honest result is `Unsupported` (§4.6).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "prediction", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckAgainstPolicyOutput {
    Permit {
        evidence: PolicyCheckEvidence,
    },
    Deny {
        deny_reason: String,
        evidence: PolicyCheckEvidence,
    },
    Unsupported {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckEvidence {
    /// Ledger at which every storage and configuration entry below was read.
    pub observed_ledger: u32,
    pub ledger_hash: String,
    /// Exact XDR key/value pairs and TTLs used to evaluate installed policy state.
    pub storage_reads: Vec<PolicyStateRead>,
    /// Exact XDR key/value pairs and TTLs used to resolve policy configuration.
    pub configuration_reads: Vec<PolicyStateRead>,
    pub restoration: PolicyStateRestoration,
    /// State may change immediately after this observation. A new live check is needed
    /// immediately before a transaction is signed; this is not a validity interval.
    pub recheck_before_signing: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyStateRead {
    pub contract_address: String,
    pub key_xdr_base64: String,
    /// `None` records an absent entry; absence can itself decide a prediction.
    pub value_xdr_base64: Option<String>,
    pub live_until_ledger: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStateRestoration {
    NotRequired,
    Restored,
    Required,
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

/// Network-read operation. The trusted acquisition shell resolves `rpc_source` from configured
/// endpoints for `network_id`, validates both against the spec and binding set, and acquires
/// the account code, rule state, policy code, admin-rule identity and ledger anchor itself.
/// Clients cannot supply those observations or choose which rule is exempted as admin.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckPolicyCallSurfaceInput {
    pub spec: serde_json::Value,
    pub binding_set: PolicyBindingSet,
    pub signed_registry_snapshot: serde_json::Value,
    pub account_address: String,
    pub network_id: String,
    /// Name of a configured RPC source, not an arbitrary client-provided URL.
    pub rpc_source: String,
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
    /// The complete check artifact. Preparation must compare both its outer hash and the
    /// inner verdict's binding-set hash, account and code identity with this input.
    pub call_surface_check: CheckPolicyCallSurfaceOutput,
}

/// The pure install intent: the `add_context_rule` operation shape and parameters. It is
/// NOT a signed or even assembled transaction — assembling one needs current sequence,
/// fees, ledger bounds and restoration preambles (an RPC-backed, wallet-owned step), and
/// the call-surface check must pass first. Signing is always wallet-owned (§6.2).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrepareInstallIntentOutput {
    pub operation: String,
    /// The smart-account contract on which `add_context_rule` is invoked.
    pub account_contract: String,
    /// The contract named by the new rule's `CallContract` context.
    pub context_contract: String,
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
        let _ = schemars::schema_for!(ReferenceSuiteInput);
        let _ = schemars::schema_for!(ReferenceSuiteOutput);
        let _ = schemars::schema_for!(VerifyInput);
        let _ = schemars::schema_for!(VerifyOutput);
        let _ = schemars::schema_for!(CheckAgainstPolicyInput);
        let _ = schemars::schema_for!(PolicyCheckSigner);
        let _ = schemars::schema_for!(CheckAgainstPolicyOutput);
        let _ = schemars::schema_for!(PolicyCheckEvidence);
        let _ = schemars::schema_for!(PolicyStateRead);
        let _ = schemars::schema_for!(PolicyStateRestoration);
        let _ = schemars::schema_for!(PolicyBindingSet);
        let _ = schemars::schema_for!(PolicyBinding);
        let _ = schemars::schema_for!(PolicyRecognition);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceInput);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceOutput);
        let _ = schemars::schema_for!(PrepareInstallIntentInput);
        let _ = schemars::schema_for!(PrepareInstallIntentOutput);
    }

    #[test]
    fn a_policy_prediction_cannot_claim_permit_without_observation_evidence() {
        let missing = serde_json::json!({"prediction": "permit"});
        assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(missing).is_err());

        let unavailable = serde_json::json!({
            "prediction": "unsupported",
            "reason": "no coherent ledger snapshot"
        });
        assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(unavailable).is_ok());
    }

    #[test]
    fn callers_cannot_supply_live_account_observations() {
        let mut request = serde_json::json!({
            "spec": {},
            "binding_set": {
                "schema": POLICY_BINDING_SET_SCHEMA,
                "spec_hash": "spec",
                "network_id": "network",
                "bindings": []
            },
            "signed_registry_snapshot": {},
            "account_address": "CACCOUNT",
            "network_id": "network",
            "rpc_source": "configured-testnet"
        });
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceInput>(request.clone()).is_ok());
        for field in [
            "account_state",
            "account_code_hash",
            "admin_rule_id",
            "observed_ledger",
        ] {
            request[field] = serde_json::json!(0);
            let error = serde_json::from_value::<CheckPolicyCallSurfaceInput>(request.clone())
                .expect_err("caller-supplied authority observations must be refused");
            assert!(error.to_string().contains("unknown field"));
            request.as_object_mut().unwrap().remove(field);
        }
    }

    #[test]
    fn policy_check_request_cannot_supply_evaluator_state() {
        let mut request = serde_json::json!({
            "spec": {},
            "binding_set": {
                "schema": POLICY_BINDING_SET_SCHEMA,
                "spec_hash": "spec",
                "network_id": "network",
                "bindings": []
            },
            "signed_registry_snapshot": {},
            "rule_index": 0,
            "account_address": "CACCOUNT",
            "network_id": "network",
            "rpc_source": "configured-testnet",
            "candidate_signers": [],
            "invocation": {}
        });
        assert!(serde_json::from_value::<CheckAgainstPolicyInput>(request.clone()).is_ok());
        for field in [
            "context",
            "smart_account",
            "current_ledger",
            "rule_live_signers",
            "call_count_so_far",
            "authenticated_signers",
        ] {
            request[field] = serde_json::json!(0);
            let error = serde_json::from_value::<CheckAgainstPolicyInput>(request.clone())
                .expect_err("caller-supplied evaluator state must be refused");
            assert!(error.to_string().contains("unknown field"));
            request.as_object_mut().unwrap().remove(field);
        }
        assert!(
            serde_json::from_value::<PolicyCheckSigner>(serde_json::json!({
                "external": {
                    "verifier": "CVERIFIER",
                    "key_hex": "01",
                    "verifier_code_hash": "forged"
                }
            }))
            .is_err()
        );
    }
}
