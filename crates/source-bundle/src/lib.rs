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
    pub ledger: Option<u32>,
    pub created_at_unix: Option<i64>,
    /// Whether the supplier claims the transaction succeeded (unverified claim).
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
        bundle.ledger,
        bundle.created_at_unix,
        bundle.successful,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_are_self_supplied_and_closed_schema() {
        let json = r#"{
            "network_passphrase": "Test SDF Network ; September 2015",
            "envelope_xdr_base64": "AAAA",
            "result_meta_xdr_base64": null,
            "ledger": 123,
            "created_at_unix": 1780000000,
            "successful": true
        }"#;
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
}
