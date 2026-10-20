//! Bound evidence for a candidate grant. Missing execution is never a passed layer.

use crate::{CheckPolicyCallSurfaceInput, VerifyInput, VerifyOutput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunInput {
    /// Exact candidate identities and operator RPC source name. This is input to
    /// recognition, not a caller-provided authority verdict or ledger observation.
    pub candidate: CheckPolicyCallSurfaceInput,
    /// Claimed source, Wasm and manifest for exactly the candidate's spec and rule.
    pub artifact: VerifyInput,
    /// Proposed chain ID, independent of the spec index. A later live execution
    /// must read and check the actual NextId; this field is not proof of that ID.
    pub candidate_context_rule_id: u32,
    /// Canonical lowercase 32-byte hex nonce to distinguish otherwise identical runs.
    pub run_nonce: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DryRunLayerId {
    Reference,
    AccountWasm,
    CapturedTarget,
    LiveEnforcement,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DryRunLayerStatus {
    Passed,
    Failed,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunLayer {
    pub id: DryRunLayerId,
    pub status: DryRunLayerStatus,
    /// Stable explanation of the actual evidence or missing prerequisite.
    pub reason: String,
    pub cases: usize,
    pub state_dependent: bool,
    /// Local committed state must be distinguished from live network writes in
    /// execution evidence. No current coordinator layer commits either.
    pub writes_committed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunBinding {
    pub spec_hash: String,
    pub binding_set_hash: String,
    pub registry_snapshot_root: String,
    pub account_address: String,
    /// Registry-recognized spec identity, not a live code observation.
    pub account_code_hash: String,
    pub network_id: String,
    pub rule_index: usize,
    pub candidate_context_rule_id: u32,
    pub suite_hash: String,
    /// Exact contract-address → reproduced/recognized Wasm hash for every binding.
    /// This is not proof of the current contents of those deployed addresses.
    pub policy_code_hashes: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DryRunOutput {
    pub schema: String,
    /// Canonical hash of the full typed request, including artifact claims and nonce.
    pub run_hash: String,
    pub binding: DryRunBinding,
    pub artifact_verification: VerifyOutput,
    /// Selected-rule reference evidence only, with explicit model gaps.
    pub reference_report: serde_json::Value,
    /// Always the four named layers in their declared order.
    pub layers: Vec<DryRunLayer>,
    /// False until every required runtime layer is actually executed and checked.
    /// This is never an account-safety or transaction-authorization verdict.
    pub complete: bool,
    pub disclaimer: String,
}
