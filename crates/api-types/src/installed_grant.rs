//! Read-only modeled-authority monitoring, separate from install preparation.
use crate::{CheckPolicyCallSurfaceInput, CheckPolicyCallSurfaceOutput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Identity derived by the wallet from its event-verified, retained ContextRule XDR. The
/// current scan must match these IDs as well as the spec's resolved signers and policies.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstalledGrantRule {
    pub id: u32,
    pub name: String,
    pub context_contract: String,
    pub valid_until: Option<u32>,
    pub signer_ids: Vec<u32>,
    pub policy_ids: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckInstalledGrantInput {
    pub candidate: CheckPolicyCallSurfaceInput,
    pub installed_rule: InstalledGrantRule,
}

/// This result cannot prepare an installation. Its nested verdict describes a counterfactual
/// authority model with exactly the recorded last-installed rule removed. The actual scan's
/// digest and acquisition evidence remain distinct. Compare the projected commitment to the
/// recorded preinstallation one; never silently learn a new baseline from this observation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckInstalledGrantOutput {
    pub schema: String,
    pub installed_rule_id: u32,
    pub status: String,
    pub reason: Option<String>,
    pub projection: String,
    pub observed_ledger: u32,
    pub actual_account_state_digest: String,
    pub actual_raw_entry_digest: String,
    pub projected_authority: Option<CheckPolicyCallSurfaceOutput>,
}
