//! Soroban RPC acquisition adapter (architecture §4.1, §4.11).
//!
//! Does the network I/O and produces immutable, trust-labeled [`EvidenceSnapshot`]s for
//! the pure recorder. Executed transactions and record-mode simulations both come back
//! as `rpc_reported` — trusted exactly as far as the configured endpoint is. The
//! transport is split from the JSON handling so the parsing is unit-testable offline.

#![forbid(unsafe_code)]

use ozpb_recorder_core::{
    referenced_contract_addresses, EvidenceSnapshot, ExecutableObservation, ObservedExecutable,
    StateChange, StateChangeKind, StateChangeSource,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, WriteXdr,
};

const MAX_XDR_BYTES: usize = 16 * 1024 * 1024;
const MAX_XDR_DEPTH: u32 = 128;

fn xdr_limits() -> Limits {
    Limits {
        depth: MAX_XDR_DEPTH,
        len: MAX_XDR_BYTES,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("E_RPC: transport error: {0}")]
    Transport(String),
    #[error("E_RPC: malformed response: {0}")]
    Malformed(String),
    #[error("E_RPC: rpc error: {0}")]
    Rpc(String),
    #[error("E_TX_NOT_FOUND: transaction {0} not found (may be outside RPC retention)")]
    NotFound(String),
    #[error("E_NETWORK_MISMATCH: expected '{expected}', RPC reports '{actual}'")]
    NetworkMismatch { expected: String, actual: String },
    #[error("E_RPC: recording evidence error: {0}")]
    Evidence(String),
}

/// A minimal JSON-RPC transport. The real client uses HTTP; tests inject a canned
/// responder so parsing is verified without a network.
pub trait RpcTransport {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError>;
}

/// HTTP transport over a single Soroban RPC endpoint.
pub struct HttpTransport {
    url: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            // Redirects could escape a hosted server's exact RPC allowlist and turn an
            // otherwise approved endpoint into SSRF. Callers must approve the final URL.
            .redirects(0)
            .build();
        HttpTransport {
            url: url.into(),
            agent,
        }
    }
}

impl RpcTransport for HttpTransport {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp: serde_json::Value = self
            .agent
            .post(&self.url)
            .send_json(req)
            .map_err(|e| RpcError::Transport(e.to_string()))?
            .into_json()
            .map_err(|e| RpcError::Malformed(e.to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(RpcError::Rpc(err.to_string()));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| RpcError::Malformed("response has no result".to_string()))
    }
}

/// Fetch an executed transaction by hash and build a snapshot (`rpc_reported`).
pub fn get_transaction<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    tx_hash: &str,
) -> Result<EvidenceSnapshot, RpcError> {
    verify_network(transport, network_passphrase)?;
    let result = transport.call(
        "getTransaction",
        json!({ "hash": tx_hash, "xdrFormat": "base64" }),
    )?;
    let snapshot = parse_get_transaction(network_passphrase, tx_hash, &result)?;
    acquire_contract_executables(transport, snapshot)
}

fn parse_get_transaction(
    network_passphrase: &str,
    tx_hash: &str,
    result: &serde_json::Value,
) -> Result<EvidenceSnapshot, RpcError> {
    let status = str_field(result, "status")?;
    match status.as_str() {
        "NOT_FOUND" => return Err(RpcError::NotFound(tx_hash.to_string())),
        "SUCCESS" | "FAILED" => {}
        other => return Err(RpcError::Rpc(format!("unexpected tx status: {other}"))),
    }
    let envelope = str_field(result, "envelopeXdr")?;
    let meta = result
        .get("resultMetaXdr")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ledger: u32 = result
        .get("ledger")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::Malformed("missing integer field 'ledger'".to_string()))?
        .try_into()
        .map_err(|_| RpcError::Malformed("field 'ledger' exceeds u32".to_string()))?;
    let created_at = result
        .get("createdAt")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| RpcError::Malformed("missing integer field 'createdAt'".to_string()))?;
    Ok(EvidenceSnapshot::from_rpc_transaction(
        network_passphrase,
        envelope,
        meta,
        ledger,
        created_at,
        status == "SUCCESS",
    ))
}

/// Simulate an unsigned envelope in record mode and build a snapshot (`rpc_reported`;
/// confidential input — §6.5).
pub fn simulate_transaction<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    envelope_xdr_base64: &str,
) -> Result<EvidenceSnapshot, RpcError> {
    verify_network(transport, network_passphrase)?;
    let result = transport.call(
        "simulateTransaction",
        json!({
            "transaction": envelope_xdr_base64,
            "authMode": "record",
            "xdrFormat": "base64"
        }),
    )?;
    let snapshot = parse_simulate(network_passphrase, envelope_xdr_base64, &result)?;
    acquire_contract_executables(transport, snapshot)
}

fn acquire_contract_executables<T: RpcTransport>(
    transport: &T,
    snapshot: EvidenceSnapshot,
) -> Result<EvidenceSnapshot, RpcError> {
    let addresses = referenced_contract_addresses(&snapshot)
        .map_err(|error| RpcError::Evidence(error.to_string()))?;
    if addresses.is_empty() {
        return Ok(snapshot);
    }

    let mut requested = BTreeMap::new();
    for address in addresses {
        let contract = address
            .parse::<stellar_strkey::Contract>()
            .map_err(|error| {
                RpcError::Evidence(format!("invalid referenced contract {address}: {error}"))
            })?;
        let sc_address = ScAddress::Contract(ContractId(Hash(contract.0)));
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_address.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let encoded_key = key
            .to_xdr_base64(xdr_limits())
            .map_err(|error| RpcError::Evidence(error.to_string()))?;
        requested.insert(encoded_key, (address, sc_address));
    }

    let keys: Vec<&String> = requested.keys().collect();
    let result = transport.call(
        "getLedgerEntries",
        json!({ "keys": keys, "xdrFormat": "base64" }),
    )?;
    parse_contract_executables(&result, &requested)
        .map(|observations| snapshot.with_contract_executables(observations))
}

fn parse_contract_executables(
    result: &serde_json::Value,
    requested: &BTreeMap<String, (String, ScAddress)>,
) -> Result<BTreeMap<String, ExecutableObservation>, RpcError> {
    let observed_ledger: u32 = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed("getLedgerEntries has no integer latestLedger".to_string())
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed("latestLedger exceeds u32".to_string()))?;
    let entries = result
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RpcError::Malformed("getLedgerEntries has no entries array".to_string()))?;
    let mut observations = BTreeMap::new();
    let mut seen_keys = std::collections::BTreeSet::new();
    for (index, value) in entries.iter().enumerate() {
        let key = value
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RpcError::Malformed(format!("getLedgerEntries entry {index} has no string key"))
            })?;
        let (address, expected_address) = requested.get(key).ok_or_else(|| {
            RpcError::Malformed(format!(
                "getLedgerEntries returned an unrequested key at entry {index}"
            ))
        })?;
        if !seen_keys.insert(key.to_string()) {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries returned duplicate key at entry {index}"
            )));
        }
        let encoded = value
            .get("xdr")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RpcError::Malformed(format!("getLedgerEntries entry {index} has no string xdr"))
            })?;
        let _: u32 = value
            .get("lastModifiedLedgerSeq")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} has no integer lastModifiedLedgerSeq"
                ))
            })?
            .try_into()
            .map_err(|_| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} lastModifiedLedgerSeq exceeds u32"
                ))
            })?;
        if encoded.len() > MAX_XDR_BYTES.div_ceil(3) * 4 {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} exceeds the XDR size limit"
            )));
        }
        // `getLedgerEntries` puts **LedgerEntryData** in `xdr`, not a whole `LedgerEntry`:
        // `lastModifiedLedgerSeq` and `liveUntilLedgerSeq` are separate JSON fields, so the
        // wrapper's own fields are not in the payload. Decoding this as `LedgerEntry` fails
        // on every real response — see `a_real_rpc_ledger_entry_response_decodes`.
        let data = LedgerEntryData::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is invalid XDR: {error}"
            ))
        })?;
        let LedgerEntryData::ContractData(contract_data) = data else {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is not contract data"
            )));
        };
        if contract_data.contract != *expected_address
            || contract_data.key != ScVal::LedgerKeyContractInstance
            || contract_data.durability != ContractDataDurability::Persistent
        {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} does not match its requested contract instance"
            )));
        }
        let ScVal::ContractInstance(instance) = contract_data.val else {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is not a contract instance"
            )));
        };
        let executable = match instance.executable {
            ContractExecutable::Wasm(hash) => ObservedExecutable::Wasm {
                code_hash: ozpb_domain::Hash32(hash.0),
            },
            ContractExecutable::StellarAsset => ObservedExecutable::StellarAsset,
        };
        observations.insert(
            address.clone(),
            ExecutableObservation {
                executable,
                observed_ledger: ozpb_domain::LedgerSeq(observed_ledger),
            },
        );
    }
    if seen_keys.len() != requested.len() {
        let missing = requested
            .keys()
            .filter(|key| !seen_keys.contains(*key))
            .count();
        return Err(RpcError::Evidence(format!(
            "getLedgerEntries omitted {missing} referenced contract instances"
        )));
    }
    Ok(observations)
}

fn parse_simulate(
    network_passphrase: &str,
    envelope_xdr_base64: &str,
    result: &serde_json::Value,
) -> Result<EvidenceSnapshot, RpcError> {
    if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
        return Err(RpcError::Rpc(err.to_string()));
    }
    let auth_entries = result
        .get("results")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|r0| r0.get("auth"))
        .and_then(|a| a.as_array())
        .ok_or_else(|| {
            RpcError::Malformed("missing results[0].auth array in simulation response".to_string())
        })?;
    let auth: Vec<String> = auth_entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry.as_str().map(str::to_string).ok_or_else(|| {
                RpcError::Malformed(format!(
                    "simulation auth entry {index} is not base64 XDR text"
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    let latest_ledger: u32 = result
        .get("latestLedger")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::Malformed("missing integer field 'latestLedger'".to_string()))?
        .try_into()
        .map_err(|_| RpcError::Malformed("field 'latestLedger' exceeds u32".to_string()))?;
    let state_entries = result
        .get("stateChanges")
        .and_then(|changes| changes.as_array())
        .ok_or_else(|| {
            RpcError::Malformed("missing stateChanges array in simulation response".to_string())
        })?;
    let state_changes = state_entries
        .iter()
        .enumerate()
        .map(parse_simulation_state_change)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EvidenceSnapshot::from_rpc_simulation(
        network_passphrase,
        envelope_xdr_base64,
        auth,
        Some(latest_ledger),
    )
    .with_simulated_state_changes(state_changes))
}

fn parse_simulation_state_change(
    (index, value): (usize, &serde_json::Value),
) -> Result<StateChange, RpcError> {
    let kind = match value.get("type").and_then(|field| field.as_str()) {
        Some("created") => StateChangeKind::Created,
        Some("updated") => StateChangeKind::Updated,
        Some("deleted") | Some("removed") => StateChangeKind::Removed,
        Some("restored") => StateChangeKind::Restored,
        Some(other) => {
            return Err(RpcError::Malformed(format!(
                "stateChanges[{index}].type '{other}' is unsupported"
            )))
        }
        None => {
            return Err(RpcError::Malformed(format!(
                "stateChanges[{index}] has no string type"
            )))
        }
    };
    let key = value
        .get("key")
        .and_then(|field| field.as_str())
        .ok_or_else(|| RpcError::Malformed(format!("stateChanges[{index}] has no string key")))?;
    let optional_xdr = |field: &str| -> Result<Option<String>, RpcError> {
        match value.get(field) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(RpcError::Malformed(format!(
                "stateChanges[{index}].{field} is not base64 XDR text"
            ))),
        }
    };
    Ok(StateChange {
        kind,
        entry: "simulation_xdr".to_string(),
        contract: None,
        source: StateChangeSource::Simulation,
        key_xdr_base64: Some(key.to_string()),
        before_xdr_base64: optional_xdr("before")?,
        after_xdr_base64: optional_xdr("after")?,
    })
}

fn verify_network<T: RpcTransport>(
    transport: &T,
    expected_passphrase: &str,
) -> Result<(), RpcError> {
    let result = transport.call("getNetwork", json!({}))?;
    let actual = str_field(&result, "passphrase")?;
    if actual != expected_passphrase {
        return Err(RpcError::NetworkMismatch {
            expected: expected_passphrase.to_string(),
            actual,
        });
    }
    Ok(())
}

fn str_field(v: &serde_json::Value, field: &str) -> Result<String, RpcError> {
    v.get(field)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| RpcError::Malformed(format!("missing string field '{field}'")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_recorder_core::{fixtures as fx, record, RecordOptions};
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint, Hash,
        LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits, ScContractInstance, ScVal,
        WriteXdr,
    };

    const NET: &str = "Test SDF Network ; September 2015";

    /// A real `getLedgerEntries` response, captured verbatim from Stellar testnet
    /// (the native SAC's contract instance, protocol 27).
    ///
    /// This test exists because the hand-written mocks above did not catch a three-week
    /// outage of the live recording path. They encoded a whole `LedgerEntry`, while the RPC
    /// puts **LedgerEntryData** in `xdr` — `lastModifiedLedgerSeq` and `liveUntilLedgerSeq`
    /// are separate JSON fields. The mocks therefore agreed with our code instead of with
    /// the network, so `cargo test` was green while `ozpb record` failed against every real
    /// endpoint. A captured response is the only anchor that catches that class of error.
    ///
    /// Public-chain data, so it is a legitimate fixture (§6.5 forbids private bundles only).
    #[test]
    fn a_real_rpc_ledger_entry_response_decodes() {
        // Concatenated to keep the line width; this is one base64 string.
        const REAL_XDR: &str = concat!(
            "AAAABgAAAAAAAAAB15KLcsJwPM/q9+uf9O9NUEpVqLl5/JtFDqLIQrTRzmEAAAAUAAAAAQAAABMA",
            "AAABAAAAAQAAAAIAAAAPAAAACE1FVEFEQVRBAAAAEQAAAAEAAAADAAAADwAAAAdkZWNpbWFsAAAA",
            "AAMAAAAHAAAADwAAAARuYW1lAAAADgAAAAZuYXRpdmUAAAAAAA8AAAAGc3ltYm9sAAAAAAAOAAAA",
            "Bm5hdGl2ZQAAAAAAEAAAAAEAAAABAAAADwAAAAlBc3NldEluZm8AAAAAAAAQAAAAAQAAAAEAAAAP",
            "AAAABk5hdGl2ZQAA",
        );

        let data = LedgerEntryData::from_xdr_base64(REAL_XDR, xdr_limits())
            .expect("a real getLedgerEntries `xdr` field must decode as LedgerEntryData");
        let LedgerEntryData::ContractData(contract_data) = data else {
            panic!("expected contract data");
        };
        assert_eq!(contract_data.key, ScVal::LedgerKeyContractInstance);
        assert_eq!(contract_data.durability, ContractDataDurability::Persistent);
        let ScVal::ContractInstance(instance) = contract_data.val else {
            panic!("expected a contract instance");
        };
        assert_eq!(instance.executable, ContractExecutable::StellarAsset);

        // And the shape the code used to assume must still be rejected, so a future
        // "simplification" back to `LedgerEntry` fails here rather than in production.
        assert!(
            stellar_xdr::LedgerEntry::from_xdr_base64(REAL_XDR, xdr_limits()).is_err(),
            "the payload is LedgerEntryData; decoding it as LedgerEntry must fail"
        );
    }

    struct CannedTransport {
        result: serde_json::Value,
        last_method: RefCell<String>,
    }

    impl RpcTransport for CannedTransport {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            *self.last_method.borrow_mut() = method.to_string();
            if method == "getNetwork" {
                Ok(json!({"passphrase": NET}))
            } else if method == "getLedgerEntries" {
                let keys = params["keys"].as_array().ok_or_else(|| {
                    RpcError::Malformed("test transport received no keys".to_string())
                })?;
                let entries = keys
                    .iter()
                    .map(|encoded| {
                        let encoded = encoded.as_str().unwrap();
                        let key = LedgerKey::from_xdr_base64(encoded, Limits::none()).unwrap();
                        let LedgerKey::ContractData(contract_key) = key else {
                            panic!("expected contract-data key")
                        };
                        // LedgerEntryData, matching what the RPC actually returns in `xdr`.
                        // This mock previously encoded a whole `LedgerEntry`, so it agreed
                        // with the code rather than with the network and the decode bug was
                        // invisible for three weeks.
                        let entry = LedgerEntryData::ContractData(ContractDataEntry {
                            ext: ExtensionPoint::V0,
                            contract: contract_key.contract,
                            key: ScVal::LedgerKeyContractInstance,
                            durability: ContractDataDurability::Persistent,
                            val: ScVal::ContractInstance(ScContractInstance {
                                executable: ContractExecutable::StellarAsset,
                                storage: None,
                            }),
                        })
                        .to_xdr_base64(Limits::none())
                        .unwrap();
                        json!({
                            "key": encoded,
                            "xdr": entry,
                            "lastModifiedLedgerSeq": 4200099
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({"entries": entries, "latestLedger": 4200102}))
            } else {
                Ok(self.result.clone())
            }
        }
    }

    fn fixture_envelope_and_meta() -> (String, String) {
        let bundle = record(&fx::executed_snapshot(), RecordOptions::default()).unwrap();
        (
            bundle.raw.envelope_xdr_base64,
            bundle.raw.result_meta_xdr_base64.unwrap(),
        )
    }

    #[test]
    fn get_transaction_parses_and_records() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let t = CannedTransport {
            result: json!({
                "status": "SUCCESS",
                "envelopeXdr": envelope,
                "resultMetaXdr": meta,
                "ledger": 4200100,
                "createdAt": "1780000000"
            }),
            last_method: RefCell::new(String::new()),
        };
        let snap = get_transaction(&t, NET, "abc").unwrap();
        assert_eq!(*t.last_method.borrow(), "getLedgerEntries");
        assert_eq!(snap.trust().as_str(), "rpc_reported");
        let bundle = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(bundle.authorizations.len(), 1);
        assert_eq!(bundle.token_movements.len(), 1);
    }

    #[test]
    fn not_found_maps_to_retention_error() {
        let t = CannedTransport {
            result: json!({"status": "NOT_FOUND"}),
            last_method: RefCell::new(String::new()),
        };
        let err = get_transaction(&t, NET, "deadbeef").unwrap_err();
        assert!(matches!(err, RpcError::NotFound(_)));
    }

    #[test]
    fn simulate_collects_record_mode_auth_entries() {
        let (envelope, _) = fixture_envelope_and_meta();
        let t = CannedTransport {
            result: json!({
                "results": [{ "auth": [] }],
                "stateChanges": [],
                "latestLedger": 4200101
            }),
            last_method: RefCell::new(String::new()),
        };
        let snap = simulate_transaction(&t, NET, &envelope).unwrap();
        assert_eq!(*t.last_method.borrow(), "getLedgerEntries");
        assert_eq!(snap.trust().as_str(), "rpc_reported");
    }

    #[test]
    fn rpc_error_is_surfaced() {
        let result = json!({"error": "boom"});
        let err = parse_simulate(NET, "env", &result).unwrap_err();
        assert!(matches!(err, RpcError::Rpc(_)));
    }

    struct NetworkMismatchTransport {
        envelope: String,
        meta: String,
    }

    impl RpcTransport for NetworkMismatchTransport {
        fn call(
            &self,
            method: &str,
            _params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            match method {
                "getNetwork" => Ok(json!({
                    "passphrase": "Public Global Stellar Network ; September 2015"
                })),
                "getTransaction" => Ok(json!({
                    "status": "SUCCESS",
                    "envelopeXdr": self.envelope,
                    "resultMetaXdr": self.meta,
                    "ledger": 4200100,
                    "createdAt": "1780000000"
                })),
                other => Err(RpcError::Rpc(format!("unexpected method {other}"))),
            }
        }
    }

    #[test]
    fn rpc_network_must_match_the_requested_network() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let transport = NetworkMismatchTransport { envelope, meta };
        let err = get_transaction(&transport, NET, "abc").unwrap_err();
        assert!(
            err.to_string().starts_with("E_NETWORK_MISMATCH:"),
            "a mainnet response must never be labelled as testnet evidence: {err}"
        );
    }

    #[test]
    fn executed_rpc_evidence_requires_ledger_and_timestamp() {
        let (envelope, meta) = fixture_envelope_and_meta();
        for result in [
            json!({
                "status": "SUCCESS",
                "envelopeXdr": envelope,
                "resultMetaXdr": meta,
                "createdAt": "1780000000"
            }),
            json!({
                "status": "SUCCESS",
                "envelopeXdr": envelope,
                "resultMetaXdr": meta,
                "ledger": 4200100
            }),
        ] {
            assert!(parse_get_transaction(NET, "abc", &result).is_err());
        }
    }

    #[test]
    fn simulation_auth_shape_is_required_and_strict() {
        let (envelope, _) = fixture_envelope_and_meta();
        for result in [
            json!({"stateChanges": [], "latestLedger": 4200101}),
            json!({"results": [], "stateChanges": [], "latestLedger": 4200101}),
            json!({"results": [{"auth": [7]}], "stateChanges": [], "latestLedger": 4200101}),
            json!({"results": [{"auth": []}], "latestLedger": 4200101}),
        ] {
            assert!(parse_simulate(NET, &envelope, &result).is_err());
        }
    }

    #[test]
    fn simulation_state_changes_are_preserved_as_evidence() {
        let (envelope, _) = fixture_envelope_and_meta();
        let result = json!({
            "results": [{"auth": []}],
            "stateChanges": [{
                "type": "updated",
                "key": "AAAA-key-xdr",
                "before": "AAAA-before-xdr",
                "after": "AAAA-after-xdr"
            }],
            "latestLedger": 4200101
        });
        let snapshot = parse_simulate(NET, &envelope, &result).unwrap();
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();
        assert_eq!(bundle.state_changes.len(), 1);
        assert_eq!(
            bundle.state_changes[0].source,
            ozpb_recorder_core::StateChangeSource::Simulation
        );
    }

    struct ExecutableTransport {
        transaction: serde_json::Value,
        instance_keys: Vec<String>,
        instance_entries: Vec<serde_json::Value>,
        calls: RefCell<Vec<String>>,
    }

    impl RpcTransport for ExecutableTransport {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            self.calls.borrow_mut().push(method.to_string());
            match method {
                "getNetwork" => Ok(json!({"passphrase": NET})),
                "getTransaction" => Ok(self.transaction.clone()),
                "getLedgerEntries" => {
                    assert_eq!(params["keys"], json!(self.instance_keys));
                    Ok(json!({
                        "entries": self.instance_entries,
                        "latestLedger": 4200102
                    }))
                }
                other => Err(RpcError::Rpc(format!("unexpected method {other}"))),
            }
        }
    }

    #[test]
    fn rpc_acquisition_records_observed_contract_wasm_hashes() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let code_hash = [7u8; 32];
        let instance = |contract: stellar_xdr::ScAddress, executable: ContractExecutable| {
            let key = LedgerKey::ContractData(LedgerKeyContractData {
                contract: contract.clone(),
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            let entry = LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract,
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
                val: ScVal::ContractInstance(ScContractInstance {
                    executable,
                    storage: None,
                }),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            (
                key.clone(),
                json!({
                    "key": key,
                    "xdr": entry,
                    "lastModifiedLedgerSeq": 4200099
                }),
            )
        };
        let account = format!("{}", stellar_strkey::Contract(fx::ACCOUNT_CID));
        let token = format!("{}", stellar_strkey::Contract(fx::TOKEN_CID));
        let mut keyed_entries = vec![
            (
                account.clone(),
                instance(fx::account_sc(), ContractExecutable::Wasm(Hash(code_hash))),
            ),
            (
                token,
                instance(fx::token_sc(), ContractExecutable::StellarAsset),
            ),
        ];
        keyed_entries.sort_by(|left, right| left.1 .0.cmp(&right.1 .0));
        let instance_keys = keyed_entries
            .iter()
            .map(|(_, (key, _))| key.clone())
            .collect();
        let instance_entries = keyed_entries
            .into_iter()
            .map(|(_, (_, entry))| entry)
            .collect();
        let transport = ExecutableTransport {
            transaction: json!({
                "status": "SUCCESS",
                "envelopeXdr": envelope,
                "resultMetaXdr": meta,
                "ledger": 4200100,
                "createdAt": "1780000000"
            }),
            instance_keys,
            instance_entries,
            calls: RefCell::new(Vec::new()),
        };

        let snapshot = get_transaction(&transport, NET, "abc").unwrap();
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();
        let observation = bundle.contract_executables.get(&account).unwrap();
        assert!(matches!(
            observation.executable,
            ozpb_recorder_core::ObservedExecutable::Wasm { code_hash: observed }
                if observed.0 == code_hash
        ));
        assert_eq!(observation.observed_ledger.0, 4_200_102);
        assert_eq!(
            transport.calls.borrow().as_slice(),
            ["getNetwork", "getTransaction", "getLedgerEntries"]
        );
    }
}
