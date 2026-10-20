//! Bounded, endpoint-reported target observations. These are not inclusion proofs.
//! Produced by `ozpb_source_rpc::capture_native_target`; consumed by the execution runtime.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEntry {
    pub key_xdr: String,
    /// Bare LedgerEntryData, exactly as exposed by getLedgerEntries.
    pub data_xdr: String,
    pub last_modified_ledger: u32,
    pub live_until_ledger: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCapture {
    pub schema: u32,
    pub provenance: String,
    pub network_id: String,
    pub observed_ledger: u32,
    /// Canonical LedgerHeaderHistoryEntry XDR.
    pub header_xdr: String,
    pub state_archival: TargetEntry,
    /// Canonical InvokeContractArgs XDR, with no authorization.
    pub invocation_xdr: String,
    /// Record-mode discovery only; never evidence of enforcement.
    pub recording_auth_xdr: String,
    /// Lowercase hex Wasm hash the account instance executed at the observed ledger. The account's
    /// own instance, code and authorization nonce are authorization context, not target state:
    /// they are read to bind this hash and are not carried as entries.
    pub account_code_hash: String,
    pub read_only_keys: Vec<String>,
    pub read_write_keys: Vec<String>,
    pub entries: Vec<TargetEntry>,
}
