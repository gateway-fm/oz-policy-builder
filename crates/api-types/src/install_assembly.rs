//! Wallet-owned installation: advisory unsigned transaction assembly only.

use crate::{PrepareInstallIntentInput, PrepareInstallIntentOutput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssembleInstallTransactionInput {
    /// Re-run this authority check. A caller-supplied intent or verdict is never accepted.
    pub intent_request: PrepareInstallIntentInput,
    /// Classic G-address paying the fee and sequence; no private key is accepted.
    pub fee_payer: String,
    /// Inclusive maximum fee for the one returned envelope, in stroops.
    pub max_fee_stroops: u32,
    /// 1..=120 ledgers, measured from the sequence read. Not an authority validity window.
    pub validity_ledgers: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssembleInstallTransactionOutput {
    pub intent: PrepareInstallIntentOutput,
    pub envelope_xdr_base64: String,
    /// SHA-256 of envelope bytes, not the Stellar network transaction hash.
    pub envelope_xdr_sha256: String,
    pub network_id: String,
    pub fee_payer: String,
    /// The payer's observed sequence, before the +1 used in this envelope.
    pub source_sequence: String,
    pub fee_stroops: u32,
    /// These reads are separately labeled; they are not one atomic ledger snapshot.
    pub sequence_read_ledger: u32,
    pub simulation_ledger: u32,
    pub min_ledger: u32,
    /// Exclusive transaction ledger bound.
    pub max_ledger: u32,
    pub restoration: InstallAssemblyRestoration,
    /// Always `record`: no owner authorization was enforced by this simulation.
    pub simulation_auth_mode: String,
    /// Always `rpc_reported`; unsigned assembly is advisory.
    pub evidence_trust: String,
    pub state_dependent: bool,
    /// Always false. This tool never submits anything.
    pub writes_committed: bool,
    pub wallet_requirements: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallAssemblyRestoration {
    None,
    /// The envelope ONLY restores entries. After execution, acquire and assemble a new intent.
    SeparateTransactionReassembleRequired,
    /// Restoration is included by the protocol in the invocation's declared resources.
    AutomaticWithinInvocation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembly_exposes_no_operator_settings() {
        crate::test_support::no_build_settings_on_the_wire(
            "AssembleInstallTransactionInput",
            schemars::schema_for!(AssembleInstallTransactionInput),
        );
        let schema =
            serde_json::to_value(schemars::schema_for!(AssembleInstallTransactionInput)).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["properties"].get("intent").is_none());
        assert!(schema["properties"].get("rpc_url").is_none());
    }
}
