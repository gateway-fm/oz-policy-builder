//! Imported-evidence acquisition adapter (architecture §4.1).
//!
//! A pure import yields `self_supplied` trust: hashing a user-supplied bundle proves
//! internal identity, not that the network accepted it. This adapter never mints any
//! stronger trust level — `ledger_verified` requires an inclusion-proof checker that
//! does not exist in Phase 1.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_recorder_core::EvidenceSnapshot;
use serde::{Deserialize, Serialize};

/// The self-contained import format for transactions outside RPC retention.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedBundle {
    pub network_passphrase: String,
    pub envelope_xdr_base64: String,
    pub result_meta_xdr_base64: Option<String>,
    /// Raw `TransactionResult` XDR. The recorder checks it against `successful`; without
    /// it the outcome is a bare claim and the import is labeled `incomplete` (recordable,
    /// but synthesis refuses it).
    #[serde(default)]
    pub result_xdr_base64: Option<String>,
    pub ledger: Option<u32>,
    pub created_at_unix: Option<i64>,
    /// Whether the supplier claims the transaction succeeded (verified against
    /// `result_xdr_base64` when recording).
    pub successful: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("E_IMPORT_PARSE: {0}")]
    Parse(String),
}

/// Parse an import file (JSON) into a trust-labeled snapshot (`self_supplied`).
pub fn import_json(json: &str) -> Result<EvidenceSnapshot, ImportError> {
    let bundle: ImportedBundle =
        serde_json::from_str(json).map_err(|e| ImportError::Parse(e.to_string()))?;
    Ok(snapshot_from(bundle))
}

pub fn snapshot_from(bundle: ImportedBundle) -> EvidenceSnapshot {
    EvidenceSnapshot::from_import(
        bundle.network_passphrase,
        bundle.envelope_xdr_base64,
        bundle.result_meta_xdr_base64,
        bundle.result_xdr_base64,
        bundle.ledger,
        bundle.created_at_unix,
        bundle.successful,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bundle whose transaction result actually decodes to the claimed outcome — the only
    /// shape that earns `self_supplied`; a placeholder value would not, since presence is not
    /// backing.
    fn backed_import_json() -> String {
        format!(
            r#"{{
            "network_passphrase": "Test SDF Network ; September 2015",
            "envelope_xdr_base64": "AAAA",
            "result_meta_xdr_base64": null,
            "result_xdr_base64": "{}",
            "ledger": 123,
            "created_at_unix": 1780000000,
            "successful": true
        }}"#,
            ozpb_recorder_core::fixtures::transaction_result_base64(true)
        )
    }

    #[test]
    fn imports_are_self_supplied_and_closed_schema() {
        let json = &backed_import_json();
        let snap = import_json(json).unwrap();
        assert_eq!(snap.trust().as_str(), "self_supplied");

        let with_extra = json.replace(
            "\"successful\": true",
            "\"successful\": true, \"trust\": \"rpc_reported\"",
        );
        assert!(
            import_json(&with_extra).is_err(),
            "an import must not be able to smuggle a trust level in"
        );
    }

    /// A result that cannot back the claim is no better than none: it parses, but the label
    /// stays `incomplete` rather than overstating what the bundle proves.
    #[test]
    fn imports_whose_result_cannot_back_the_claim_are_incomplete() {
        let unusable = backed_import_json().replace(
            &ozpb_recorder_core::fixtures::transaction_result_base64(true),
            "AAAA",
        );
        assert_eq!(
            import_json(&unusable).unwrap().trust().as_str(),
            "incomplete"
        );

        let contradicting = backed_import_json().replace(
            &ozpb_recorder_core::fixtures::transaction_result_base64(true),
            &ozpb_recorder_core::fixtures::transaction_result_base64(false),
        );
        assert_eq!(
            import_json(&contradicting).unwrap().trust().as_str(),
            "incomplete"
        );
    }

    /// A bundle that ships no transaction result asserts an outcome with nothing to check
    /// it against: it still parses, but as `incomplete` evidence.
    #[test]
    fn imports_without_a_transaction_result_are_incomplete() {
        let json = r#"{
            "network_passphrase": "Test SDF Network ; September 2015",
            "envelope_xdr_base64": "AAAA",
            "result_meta_xdr_base64": null,
            "ledger": 123,
            "created_at_unix": 1780000000,
            "successful": true
        }"#;
        let snap = import_json(json).unwrap();
        assert_eq!(snap.trust().as_str(), "incomplete");
    }
}
