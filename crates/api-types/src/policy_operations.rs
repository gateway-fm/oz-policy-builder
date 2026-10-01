//! Wire types for reference evaluation, verification, live policy checks, and install intent.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Require a nullable wire field to be present: omission must not deserialize as an
/// explicit `null` value. `#[schemars(required)]` keeps the JSON Schema aligned.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

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
    /// Index of the policy rule in `spec`; this is not an on-chain rule ID.
    pub rule_index: usize,
    /// On-chain context-rule ID selected for this check, not a claim about its state.
    /// The server must read the rule at the observation ledger, verify its context,
    /// validity and policy addresses against the selected spec rule and binding set,
    /// then evaluate its live signers under the spec's authorization semantics. A missing
    /// or mismatched rule cannot produce a permit. Never infer this ID from `rule_index`.
    pub installed_context_rule_id: u32,
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

impl CheckAgainstPolicyInput {
    /// Hash the complete typed request, including the spec, bindings, signed snapshot,
    /// account, network, both rule selectors, signer list, and invocation. The trusted
    /// server records this hash in every permit/deny result after validating the input.
    pub fn request_hash(&self) -> Result<ozpb_domain::Hash32, ozpb_domain::DomainError> {
        ozpb_domain::canonical_hash(ozpb_domain::domains::POLICY_CHECK_REQUEST, self)
    }
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
    /// Request identities. A consumer must compare these to the original request and
    /// independently verify the trusted server's response before relying on a prediction.
    pub account_address: String,
    pub network_id: String,
    pub rule_index: usize,
    /// The on-chain rule whose signer set and policy state were read. The wallet must
    /// select this same rule when authorizing the eventual transaction.
    pub installed_context_rule_id: u32,
    /// Hash of the validated PolicySpec and exact PolicyBindingSet used for this check.
    pub spec_hash: String,
    pub binding_set_hash: String,
    /// Root of the verified registry snapshot used to recognize policy implementations.
    pub registry_snapshot_root: String,
    /// Domain-separated canonical hash of the full [`CheckAgainstPolicyInput`], including
    /// the invocation and ordered candidate-signer identities. The server computes this
    /// via [`CheckAgainstPolicyInput::request_hash`]; it never accepts a caller claim.
    pub request_hash: String,
    /// Ledger at which every storage and configuration entry below was read.
    pub observed_ledger: u32,
    pub ledger_hash: String,
    /// Exact XDR key/value pairs and TTLs used to evaluate installed policy state.
    pub storage_reads: Vec<PolicyStateRead>,
    /// Exact XDR key/value pairs and TTLs used to resolve the selected account rule,
    /// its signers and policies, and the policies' own configuration.
    pub configuration_reads: Vec<PolicyStateRead>,
    pub restoration: PolicyStateRestoration,
    /// State may change immediately after this observation. A new live check is needed
    /// immediately before a transaction is signed; this is not a validity interval.
    pub recheck_before_signing: RecheckBeforeSigning,
}

impl PolicyCheckEvidence {
    /// Check that this evidence belongs to the exact request the caller submitted.
    /// Artifact hashes and live observations still require validation by the trusted server.
    pub fn matches_request(
        &self,
        request: &CheckAgainstPolicyInput,
    ) -> Result<bool, ozpb_domain::DomainError> {
        Ok(self.account_address == request.account_address
            && self.network_id == request.network_id
            && self.rule_index == request.rule_index
            && self.installed_context_rule_id == request.installed_context_rule_id
            && self.request_hash == request.request_hash()?.to_hex())
    }
}

/// A prediction always requires a fresh live check immediately before signing.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecheckBeforeSigning {
    Required,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyStateRead {
    pub contract_address: String,
    pub key_xdr_base64: String,
    /// A checked absence or the exact value and TTL observed at the ledger anchor.
    pub observation: PolicyStateObservation,
}

/// A missing key is a real observation, not a missing field. A present entry always
/// carries both the XDR value and its TTL, so incomplete evidence cannot claim either.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyStateObservation {
    Absent,
    Present {
        value_xdr_base64: String,
        live_until_ledger: u32,
    },
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
#[serde(deny_unknown_fields)]
pub struct CheckPolicyCallSurfaceOutput {
    pub spec_hash: String,
    pub binding_set_hash: String,
    /// Root of the verified signed snapshot used to recognize account and policy code.
    pub registry_snapshot_root: String,
    pub verdict: PolicyCallSurfaceVerdict,
}

/// A complete authority-surface observation at one ledger. The trusted reader must
/// reconcile the enumeration and its transitive closure before constructing this value;
/// the preparer must compare the identities and require a safe result.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyCallSurfaceVerdict {
    pub observed_ledger: u32,
    pub network_id: String,
    pub account_address: String,
    pub account_code_hash: String,
    pub binding_set_hash: String,
    pub bound_policy_addresses: Vec<String>,
    /// Canonical hash of the ordered account rules and transitive storage entries.
    pub ordered_state_digest: String,
    pub enumeration_evidence: PolicyRuleEnumerationEvidence,
    pub dominance_evidence: PolicyDominanceEvidence,
    pub result: PolicyCallSurfaceResult,
}

/// Only complete enumeration strategies can produce a verdict. The reader must verify
/// the active count and resolve every rule's transitive signer and policy references.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyRuleEnumerationEvidence {
    OnchainList {
        active_count: u32,
        rule_ids: Vec<u32>,
        signer_ids: Vec<u32>,
        policy_ids: Vec<u32>,
    },
    BoundedNextId {
        next_id: u32,
        active_count: u32,
        rule_ids: Vec<u32>,
        signer_ids: Vec<u32>,
        policy_ids: Vec<u32>,
    },
}

/// The designated administrator and the rules and methods considered on both surfaces.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDominanceEvidence {
    pub designated_admin_rule_id: u32,
    pub admin_rule_fingerprint: String,
    pub assessed_rule_ids: Vec<u32>,
    pub protected_methods: Vec<PolicyProtectedMethod>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyProtectedMethod {
    pub surface: PolicyProtectedSurface,
    pub contract_address: String,
    pub function: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProtectedSurface {
    DirectPolicy,
    AccountManagement,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyCallSurfaceResult {
    Safe,
    Unsafe { findings: Vec<PolicySurfaceFinding> },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicySurfaceFinding {
    pub surface: PolicyProtectedSurface,
    pub offending_rule_id: u32,
    pub code: String,
    pub reason: String,
    pub remediation: String,
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
    /// The complete check artifact. Preparation must compare its outer spec/binding
    /// hashes and registry root, plus the verdict's inner binding hash, network,
    /// account/code identity and safe result against this input.
    pub call_surface_check: CheckPolicyCallSurfaceOutput,
}

/// The pure install intent: the `add_context_rule` operation shape and parameters. It is
/// NOT a signed or even assembled transaction — assembling one needs current sequence,
/// fees, ledger bounds and restoration preambles (an RPC-backed, wallet-owned step), and
/// the call-surface check must pass first. Signing is always wallet-owned (§6.2).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareInstallIntentOutput {
    pub operation: InstallOperation,
    /// The smart-account contract on which `add_context_rule` is invoked.
    pub account_contract: String,
    /// The contract named by the new rule's `CallContract` context.
    pub context_contract: String,
    pub rule_name: String,
    /// Explicit `null` means no expiration; omission must not silently grant one.
    #[serde(deserialize_with = "required_nullable")]
    #[schemars(required)]
    pub valid_until_ledger: Option<u32>,
    /// The account's typed signer arguments for `add_context_rule`.
    pub delegate_signers: Vec<InstallSigner>,
    /// One entry per policy in the selected spec rule. The preparer must match each
    /// index and address to the binding set, match the install parameters to the spec,
    /// and reject missing or duplicate indexes and addresses before returning an intent.
    pub policies: Vec<InstallPolicy>,
    pub next_steps: Vec<String>,
}

/// The only account operation represented by a prepared install intent.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstallOperation {
    AddContextRule,
}

/// Signer arguments accepted by the account. An external signer needs both its verifier
/// address and key bytes; the verifier's expected code hash remains in the PolicySpec for
/// the pre-install recognition check and is not an `add_context_rule` argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InstallSigner {
    Delegated { address: String },
    External { verifier: String, key_hex: String },
}

/// One address and its value in the account's `Map<Address, Val>` policy argument.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstallPolicy {
    /// Position in the selected PolicySpec rule and its PolicyBindingSet.
    pub policy_index: usize,
    /// The exact deployed address from that binding.
    pub address: String,
    pub install_params: InstallPolicyParams,
}

/// Account-install arguments for the policy kinds this toolkit composes. The assembler
/// encodes `Generated` as the generated policy's ignored `u32` value `0`. The spending
/// limit fields encode `SpendingLimitAccountParams` from the reviewed account library.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstallPolicyParams {
    Generated,
    SpendingLimit {
        /// Canonical decimal i128 from the spec's reviewed `limit` parameter.
        spending_limit: String,
        period_ledgers: u32,
    },
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
    fn every_policy_operations_dto_has_a_schema() {
        let _ = schemars::schema_for!(ReferenceSuiteInput);
        let _ = schemars::schema_for!(ReferenceSuiteOutput);
        let _ = schemars::schema_for!(VerifyInput);
        let _ = schemars::schema_for!(VerifyOutput);
        let _ = schemars::schema_for!(CheckAgainstPolicyInput);
        let _ = schemars::schema_for!(PolicyCheckSigner);
        let _ = schemars::schema_for!(CheckAgainstPolicyOutput);
        let _ = schemars::schema_for!(PolicyCheckEvidence);
        let _ = schemars::schema_for!(RecheckBeforeSigning);
        let _ = schemars::schema_for!(PolicyStateRead);
        let _ = schemars::schema_for!(PolicyStateObservation);
        let _ = schemars::schema_for!(PolicyStateRestoration);
        let _ = schemars::schema_for!(PolicyBindingSet);
        let _ = schemars::schema_for!(PolicyBinding);
        let _ = schemars::schema_for!(PolicyRecognition);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceInput);
        let _ = schemars::schema_for!(CheckPolicyCallSurfaceOutput);
        let _ = schemars::schema_for!(PolicyCallSurfaceVerdict);
        let _ = schemars::schema_for!(PolicyRuleEnumerationEvidence);
        let _ = schemars::schema_for!(PolicyDominanceEvidence);
        let _ = schemars::schema_for!(PolicyProtectedMethod);
        let _ = schemars::schema_for!(PolicyProtectedSurface);
        let _ = schemars::schema_for!(PolicyCallSurfaceResult);
        let _ = schemars::schema_for!(PolicySurfaceFinding);
        let _ = schemars::schema_for!(PrepareInstallIntentInput);
        let _ = schemars::schema_for!(PrepareInstallIntentOutput);
        let _ = schemars::schema_for!(InstallOperation);
        let _ = schemars::schema_for!(InstallSigner);
        let _ = schemars::schema_for!(InstallPolicy);
        let _ = schemars::schema_for!(InstallPolicyParams);
    }

    #[test]
    fn a_policy_prediction_cannot_claim_permit_without_observation_evidence() {
        let missing = serde_json::json!({"prediction": "permit"});
        assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(missing).is_err());

        let mut evidence_without_rule = serde_json::json!({
            "prediction": "permit",
            "evidence": {
                "account_address": "CACCOUNT",
                "network_id": "network",
                "rule_index": 0,
                "spec_hash": "spec-hash",
                "binding_set_hash": "binding-hash",
                "registry_snapshot_root": "registry-root",
                "request_hash": "request-hash",
                "observed_ledger": 100,
                "ledger_hash": "ledger-hash",
                "storage_reads": [],
                "configuration_reads": [],
                "restoration": "not_required",
                "recheck_before_signing": "required"
            }
        });
        assert!(
            serde_json::from_value::<CheckAgainstPolicyOutput>(evidence_without_rule.clone())
                .is_err()
        );
        evidence_without_rule["evidence"]["installed_context_rule_id"] = serde_json::json!(42);
        assert!(
            serde_json::from_value::<CheckAgainstPolicyOutput>(evidence_without_rule.clone())
                .is_ok()
        );
        for invalid in [serde_json::json!(false), serde_json::json!(true)] {
            let mut unsafe_evidence = evidence_without_rule.clone();
            unsafe_evidence["evidence"]["recheck_before_signing"] = invalid;
            assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(unsafe_evidence).is_err());
        }
        for field in [
            "account_address",
            "network_id",
            "rule_index",
            "spec_hash",
            "binding_set_hash",
            "registry_snapshot_root",
            "request_hash",
        ] {
            let mut detached = evidence_without_rule.clone();
            detached["evidence"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<CheckAgainstPolicyOutput>(detached).is_err());
        }

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
    fn call_surface_artifact_requires_typed_observation_and_evidence() {
        let complete = serde_json::json!({
            "spec_hash": "spec",
            "binding_set_hash": "binding",
            "registry_snapshot_root": "registry",
            "verdict": {
                "observed_ledger": 100,
                "network_id": "network",
                "account_address": "CACCOUNT",
                "account_code_hash": "code",
                "binding_set_hash": "binding",
                "bound_policy_addresses": ["CPOLICY"],
                "ordered_state_digest": "state-digest",
                "enumeration_evidence": {
                    "method": "bounded_next_id",
                    "next_id": 2,
                    "active_count": 1,
                    "rule_ids": [1],
                    "signer_ids": [0],
                    "policy_ids": [0]
                },
                "dominance_evidence": {
                    "designated_admin_rule_id": 1,
                    "admin_rule_fingerprint": "admin-fingerprint",
                    "assessed_rule_ids": [1],
                    "protected_methods": [
                        {"surface": "direct_policy", "contract_address": "CPOLICY", "function": "install"},
                        {"surface": "account_management", "contract_address": "CACCOUNT", "function": "add_context_rule"}
                    ]
                },
                "result": "safe"
            }
        });
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(complete.clone()).is_ok());
        for field in [
            "spec_hash",
            "binding_set_hash",
            "registry_snapshot_root",
            "verdict",
        ] {
            let mut incomplete = complete.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(incomplete).is_err());
        }
        for field in [
            "observed_ledger",
            "network_id",
            "account_address",
            "account_code_hash",
            "binding_set_hash",
            "ordered_state_digest",
            "enumeration_evidence",
            "dominance_evidence",
            "result",
        ] {
            let mut incomplete = complete.clone();
            incomplete["verdict"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(incomplete).is_err());
        }
        let mut null_verdict = complete.clone();
        null_verdict["verdict"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(null_verdict).is_err());
        let mut unsupported_scan = complete.clone();
        unsupported_scan["verdict"]["enumeration_evidence"]["method"] = serde_json::json!("none");
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(unsupported_scan).is_err());
        let mut incomplete_scan = complete.clone();
        incomplete_scan["verdict"]["enumeration_evidence"]
            .as_object_mut()
            .unwrap()
            .remove("active_count");
        assert!(serde_json::from_value::<CheckPolicyCallSurfaceOutput>(incomplete_scan).is_err());
        let mut incomplete_dominance = complete;
        incomplete_dominance["verdict"]["dominance_evidence"]
            .as_object_mut()
            .unwrap()
            .remove("protected_methods");
        assert!(
            serde_json::from_value::<CheckPolicyCallSurfaceOutput>(incomplete_dominance).is_err()
        );
    }

    fn policy_check_request_wire() -> serde_json::Value {
        serde_json::json!({
            "spec": {},
            "binding_set": {
                "schema": POLICY_BINDING_SET_SCHEMA,
                "spec_hash": "spec",
                "network_id": "network",
                "bindings": []
            },
            "signed_registry_snapshot": {},
            "rule_index": 0,
            "installed_context_rule_id": 42,
            "account_address": "CACCOUNT",
            "network_id": "network",
            "rpc_source": "configured-testnet",
            "candidate_signers": [],
            "invocation": {}
        })
    }

    #[test]
    fn policy_check_request_cannot_supply_evaluator_state() {
        let mut request = policy_check_request_wire();
        assert!(serde_json::from_value::<CheckAgainstPolicyInput>(request.clone()).is_ok());
        let mut without_installed_id = request.clone();
        without_installed_id
            .as_object_mut()
            .unwrap()
            .remove("installed_context_rule_id");
        assert!(serde_json::from_value::<CheckAgainstPolicyInput>(without_installed_id).is_err());
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

    #[test]
    fn policy_check_evidence_binds_the_complete_request() {
        let request = policy_check_request_wire();
        let baseline: CheckAgainstPolicyInput = serde_json::from_value(request.clone()).unwrap();
        let baseline_hash = baseline.request_hash().unwrap();
        assert_eq!(baseline_hash, baseline.request_hash().unwrap());
        let evidence: PolicyCheckEvidence = serde_json::from_value(serde_json::json!({
            "account_address": baseline.account_address,
            "network_id": baseline.network_id,
            "rule_index": baseline.rule_index,
            "installed_context_rule_id": baseline.installed_context_rule_id,
            "spec_hash": "spec-hash",
            "binding_set_hash": "binding-hash",
            "registry_snapshot_root": "registry-root",
            "request_hash": baseline_hash.to_hex(),
            "observed_ledger": 100,
            "ledger_hash": "ledger-hash",
            "storage_reads": [],
            "configuration_reads": [],
            "restoration": "not_required",
            "recheck_before_signing": "required"
        }))
        .unwrap();
        assert!(evidence.matches_request(&baseline).unwrap());
        for (field, value) in [
            ("account_address", serde_json::json!("COTHER")),
            ("network_id", serde_json::json!("other-network")),
            ("rpc_source", serde_json::json!("other-configured-source")),
            ("rule_index", serde_json::json!(1)),
            ("installed_context_rule_id", serde_json::json!(43)),
            ("spec", serde_json::json!({"changed": true})),
            (
                "binding_set",
                serde_json::json!({
                    "schema": POLICY_BINDING_SET_SCHEMA,
                    "spec_hash": "other-spec",
                    "network_id": "network",
                    "bindings": []
                }),
            ),
            (
                "signed_registry_snapshot",
                serde_json::json!({"changed": true}),
            ),
            (
                "candidate_signers",
                serde_json::json!([{"delegated": {"address": "CDELEGATE"}}]),
            ),
            ("invocation", serde_json::json!({"changed": true})),
        ] {
            let mut changed = request.clone();
            changed[field] = value;
            let changed: CheckAgainstPolicyInput = serde_json::from_value(changed).unwrap();
            assert_ne!(changed.request_hash().unwrap(), baseline_hash, "{field}");
            assert!(!evidence.matches_request(&changed).unwrap(), "{field}");
        }
    }

    #[test]
    fn install_intent_preserves_typed_operation_arguments() {
        let intent = PrepareInstallIntentOutput {
            operation: InstallOperation::AddContextRule,
            account_contract: "CACCOUNT".into(),
            context_contract: "CCONTEXT".into(),
            rule_name: "limited".into(),
            valid_until_ledger: Some(1234),
            delegate_signers: vec![
                InstallSigner::Delegated {
                    address: "CDELEGATE".into(),
                },
                InstallSigner::External {
                    verifier: "CVERIFIER".into(),
                    key_hex: "0123".into(),
                },
            ],
            policies: vec![
                InstallPolicy {
                    policy_index: 0,
                    address: "CSPENDING".into(),
                    install_params: InstallPolicyParams::SpendingLimit {
                        spending_limit: "500000000".into(),
                        period_ledgers: 120_960,
                    },
                },
                InstallPolicy {
                    policy_index: 1,
                    address: "CGENERATED".into(),
                    install_params: InstallPolicyParams::Generated,
                },
            ],
            next_steps: vec![],
        };

        let wire = serde_json::to_value(&intent).unwrap();
        assert_eq!(wire["operation"], "add_context_rule");
        assert_eq!(
            wire["delegate_signers"],
            serde_json::json!([
                {"delegated": {"address": "CDELEGATE"}},
                {"external": {"verifier": "CVERIFIER", "key_hex": "0123"}}
            ])
        );
        let decoded: PrepareInstallIntentOutput = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(decoded.delegate_signers, intent.delegate_signers);
        let mut wrong_operation = wire.clone();
        wrong_operation["operation"] = serde_json::json!("remove_context_rule");
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(wrong_operation).is_err());
        assert_eq!(
            wire["policies"],
            serde_json::json!([
                {
                    "policy_index": 0,
                    "address": "CSPENDING",
                    "install_params": {
                        "kind": "spending_limit",
                        "spending_limit": "500000000",
                        "period_ledgers": 120960
                    }
                },
                {
                    "policy_index": 1,
                    "address": "CGENERATED",
                    "install_params": {"kind": "generated"}
                }
            ])
        );

        let mut flattened = wire;
        flattened["delegate_signers"] = serde_json::json!(["CDELEGATE", "external:CVERIFIER:0123"]);
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(flattened).is_err());
    }

    #[test]
    fn install_intent_rejects_address_only_policy_entries() {
        let base = serde_json::json!({
            "operation": "add_context_rule",
            "account_contract": "CACCOUNT",
            "context_contract": "CCONTEXT",
            "rule_name": "limited",
            "valid_until_ledger": 1234,
            "delegate_signers": [],
            "policies": [{"policy_index": 0, "address": "CSPENDING"}],
            "next_steps": []
        });
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(base.clone()).is_err());

        let mut missing_period = base.clone();
        missing_period["policies"][0]["install_params"] = serde_json::json!({
            "kind": "spending_limit",
            "spending_limit": "500000000"
        });
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(missing_period).is_err());

        let mut addresses_only = base;
        addresses_only.as_object_mut().unwrap().remove("policies");
        addresses_only["policy_addresses"] = serde_json::json!(["CSPENDING"]);
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(addresses_only).is_err());
    }

    #[test]
    fn state_reads_and_no_expiration_require_explicit_evidence() {
        let absent = serde_json::json!({
            "contract_address": "CPOLICY",
            "key_xdr_base64": "key",
            "observation": "absent"
        });
        assert!(serde_json::from_value::<PolicyStateRead>(absent.clone()).is_ok());
        let mut false_absence = absent.clone();
        false_absence["observation"] = serde_json::json!({"absent": {"value_xdr_base64": "value"}});
        assert!(serde_json::from_value::<PolicyStateRead>(false_absence).is_err());
        let mut missing_observation = absent;
        missing_observation
            .as_object_mut()
            .unwrap()
            .remove("observation");
        assert!(serde_json::from_value::<PolicyStateRead>(missing_observation).is_err());

        let present = serde_json::json!({
            "contract_address": "CPOLICY",
            "key_xdr_base64": "key",
            "observation": {
                "present": {
                    "value_xdr_base64": "value",
                    "live_until_ledger": 1234
                }
            }
        });
        assert!(serde_json::from_value::<PolicyStateRead>(present.clone()).is_ok());
        for field in ["value_xdr_base64", "live_until_ledger"] {
            let mut missing = present.clone();
            missing["observation"]["present"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(serde_json::from_value::<PolicyStateRead>(missing).is_err());
        }
        let mut missing_ttl = present;
        missing_ttl["observation"]["present"]["live_until_ledger"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<PolicyStateRead>(missing_ttl).is_err());
        let mut extra_evidence = serde_json::json!({
            "contract_address": "CPOLICY",
            "key_xdr_base64": "key",
            "observation": {
                "present": {
                    "value_xdr_base64": "value",
                    "live_until_ledger": 1234,
                    "source": "caller_supplied"
                }
            }
        });
        assert!(serde_json::from_value::<PolicyStateRead>(extra_evidence.clone()).is_err());
        extra_evidence["observation"]["present"]
            .as_object_mut()
            .unwrap()
            .remove("source");
        assert!(serde_json::from_value::<PolicyStateRead>(extra_evidence).is_ok());

        let intent = serde_json::json!({
            "operation": "add_context_rule",
            "account_contract": "CACCOUNT",
            "context_contract": "CCONTEXT",
            "rule_name": "limited",
            "valid_until_ledger": null,
            "delegate_signers": [],
            "policies": [],
            "next_steps": []
        });
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(intent.clone()).is_ok());
        let mut missing_expiration = intent;
        missing_expiration
            .as_object_mut()
            .unwrap()
            .remove("valid_until_ledger");
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(missing_expiration).is_err());

        for (schema, fields) in [
            (
                serde_json::to_value(schemars::schema_for!(PolicyStateRead)).unwrap(),
                &["observation"][..],
            ),
            (
                serde_json::to_value(schemars::schema_for!(PrepareInstallIntentOutput)).unwrap(),
                &["valid_until_ledger"][..],
            ),
        ] {
            let required = schema["required"].as_array().unwrap();
            for field in fields {
                assert!(required.contains(&serde_json::json!(field)));
            }
        }
    }
}
