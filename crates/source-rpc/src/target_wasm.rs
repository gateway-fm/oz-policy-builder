//! Read a target's instance and Wasm bytes for later disposable execution.
//!
//! The two `getLedgerEntries` calls are separate, and each keeps its own reported ledger.
//! They do not prove historical coherence or capture the target's other storage. No dry-run
//! evidence layer is established by this reader alone.

use crate::{
    ensure_base64_size, redact_ledger_request_error, verify_network, xdr_limits, RpcError,
    RpcTransport, MAX_LEDGER_ENTRY_KEYS,
};
use ozpb_domain::{Hash32, LedgerSeq, NetworkId};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, ReadXdr, ScAddress, ScVal, WriteXdr,
};

const MAX_CONTRACT_ADDRESS_BYTES: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum TargetWasmError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("invalid target request: {0}")]
    InvalidRequest(String),
    #[error("{entry} is absent from getLedgerEntries (history unknown)")]
    MissingLedgerEntry { entry: &'static str },
    #[error("{entry} is archived at reported ledger {reported} (live until {live_until})")]
    ArchivedLedgerEntry {
        entry: &'static str,
        reported: u32,
        live_until: u32,
    },
    #[error("target contract {contract} does not use a Wasm executable")]
    NonWasmExecutable { contract: String },
    #[error("contract code hash mismatch: expected {expected}, received {actual}")]
    CodeHashMismatch { expected: String, actual: String },
}

const MAX_SELECTED_KEY_BASE64_BYTES: usize = 16 * 1024;
const MAX_SELECTED_KEYS_TOTAL_BYTES: usize = 256 * 1024;

/// One exact XDR entry returned with a target capture. The RPC supplied bare
/// `LedgerEntryData` plus these two metadata fields, not a full `LedgerEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedTargetEntry {
    pub key: LedgerKey,
    pub data: LedgerEntryData,
    pub last_modified_ledger: LedgerSeq,
    pub live_until_ledger: LedgerSeq,
}

/// Instance, matching code, and caller-selected storage from one final RPC response.
///
/// The reported ledger dates that response. The selected key list is not a proof of
/// all storage the target could read, including keys in other contracts. This has
/// not executed any invocation and is not layer-3 dry-run evidence by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetCapture {
    pub network_id: NetworkId,
    pub contract_address: String,
    pub code_hash: Hash32,
    pub reported_ledger: LedgerSeq,
    /// Canonical key XDR base64 to exact entry data and metadata.
    pub entries: BTreeMap<String, CapturedTargetEntry>,
    pub selected_storage_keys: usize,
}

/// Capture a target's instance, code, and selected storage in one final
/// `getLedgerEntries` reply after discovering its code hash.
///
/// All selected keys must belong to this target and be live in the final reply;
/// omitted or archived entries fail closed. The first two reads only discover and
/// validate the code key. The final reply rechecks the instance-to-code link and
/// the code bytes, so a code change between requests cannot silently pass. RPC
/// does not prove that the caller supplied the target's entire storage closure.
/// Endpoint error detail is withheld because it may echo a selected key.
pub fn read_target_capture<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    contract_address: &str,
    selected_key_xdr_base64: &[String],
) -> Result<TargetCapture, TargetWasmError> {
    if selected_key_xdr_base64.len() > MAX_LEDGER_ENTRY_KEYS - 2 {
        return Err(TargetWasmError::InvalidRequest(format!(
            "target capture accepts at most {} selected storage keys",
            MAX_LEDGER_ENTRY_KEYS - 2
        )));
    }
    if contract_address.len() > MAX_CONTRACT_ADDRESS_BYTES {
        return Err(TargetWasmError::InvalidRequest(
            "target contract address exceeds the encoded address size limit".to_string(),
        ));
    }
    let contract = contract_address
        .parse::<stellar_strkey::Contract>()
        .map_err(|error| {
            TargetWasmError::InvalidRequest(format!("invalid target contract address: {error}"))
        })?;
    let sc_address = ScAddress::Contract(ContractId(Hash(contract.0)));
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: sc_address.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let mut selected = BTreeMap::<String, LedgerKey>::new();
    let mut total_bytes = 0usize;
    for (index, encoded) in selected_key_xdr_base64.iter().enumerate() {
        if encoded.len() > MAX_SELECTED_KEY_BASE64_BYTES {
            return Err(TargetWasmError::InvalidRequest(format!(
                "selected key {index} exceeds the encoded key size limit"
            )));
        }
        total_bytes = total_bytes.saturating_add(encoded.len());
        if total_bytes > MAX_SELECTED_KEYS_TOTAL_BYTES {
            return Err(TargetWasmError::InvalidRequest(
                "selected storage keys exceed the request byte budget".to_string(),
            ));
        }
        let key = LedgerKey::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            TargetWasmError::InvalidRequest(format!("selected key {index} is invalid XDR: {error}"))
        })?;
        let LedgerKey::ContractData(data) = &key else {
            return Err(TargetWasmError::InvalidRequest(format!(
                "selected key {index} is not contract data"
            )));
        };
        if data.contract != sc_address || key == instance_key {
            return Err(TargetWasmError::InvalidRequest(format!(
                "selected key {index} is not target storage distinct from its instance"
            )));
        }
        let canonical = key.to_xdr_base64(xdr_limits()).map_err(|error| {
            TargetWasmError::InvalidRequest(format!("cannot encode selected key {index}: {error}"))
        })?;
        if selected.insert(canonical, key).is_some() {
            return Err(TargetWasmError::InvalidRequest(format!(
                "selected key {index} duplicates another selected key"
            )));
        }
    }

    let discovered = read_target_wasm(transport, network_passphrase, contract_address)?;
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(discovered.code_hash.0),
    });
    let instance_encoded = instance_key.to_xdr_base64(xdr_limits()).map_err(|error| {
        TargetWasmError::InvalidRequest(format!("cannot encode target instance key: {error}"))
    })?;
    let code_encoded = code_key.to_xdr_base64(xdr_limits()).map_err(|_| {
        TargetWasmError::InvalidRequest("cannot encode target code key".to_string())
    })?;
    selected.insert(instance_encoded.clone(), instance_key);
    selected.insert(code_encoded.clone(), code_key);
    let keys: Vec<&String> = selected.keys().collect();
    let response = transport
        .call(
            "getLedgerEntries",
            json!({ "keys": keys, "xdrFormat": "base64" }),
        )
        .map_err(redact_ledger_request_error)?;
    let reported_ledger: u32 = response
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed("target capture lacks integer latestLedger".to_string())
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed("target capture latestLedger exceeds u32".to_string()))?;
    if reported_ledger == 0 {
        return Err(RpcError::Malformed("target capture latestLedger is zero".to_string()).into());
    }
    if reported_ledger < discovered.instance_reported_ledger.0
        || reported_ledger < discovered.code_reported_ledger.0
    {
        return Err(RpcError::Malformed(
            "target capture reported ledger precedes code discovery".to_string(),
        )
        .into());
    }
    let values = response
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RpcError::Malformed("target capture lacks entries array".to_string()))?;
    let mut entries = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        let encoded_key = value
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RpcError::Malformed(format!("capture entry {index} lacks key")))?;
        let expected = selected.get(encoded_key).ok_or_else(|| {
            RpcError::Malformed(format!("capture entry {index} returned an unrequested key"))
        })?;
        if entries.contains_key(encoded_key) {
            return Err(RpcError::Malformed(format!(
                "capture entry {index} duplicates a requested key"
            ))
            .into());
        }
        let encoded_data = value
            .get("xdr")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RpcError::Malformed(format!("capture entry {index} lacks XDR")))?;
        ensure_base64_size("capture entry XDR", encoded_data)?;
        let data = LedgerEntryData::from_xdr_base64(encoded_data, xdr_limits())
            .map_err(|_| RpcError::Malformed(format!("capture entry {index} has invalid XDR")))?;
        if data.to_key() != *expected {
            return Err(RpcError::Malformed(format!(
                "capture entry {index} payload differs from its requested key"
            ))
            .into());
        }
        let last_modified = capture_ledger_field(value, index, "lastModifiedLedgerSeq")?;
        let live_until = capture_ledger_field(value, index, "liveUntilLedgerSeq")?;
        if last_modified > reported_ledger {
            return Err(RpcError::Malformed(format!(
                "capture entry {index} was modified after the reported ledger"
            ))
            .into());
        }
        if live_until < reported_ledger {
            return Err(TargetWasmError::ArchivedLedgerEntry {
                entry: "target capture entry",
                reported: reported_ledger,
                live_until,
            });
        }
        entries.insert(
            encoded_key.to_string(),
            CapturedTargetEntry {
                key: expected.clone(),
                data,
                last_modified_ledger: LedgerSeq(last_modified),
                live_until_ledger: LedgerSeq(live_until),
            },
        );
    }
    if entries.len() != selected.len() {
        return Err(TargetWasmError::MissingLedgerEntry {
            entry: "target instance, code, or selected storage",
        });
    }
    let instance = entries
        .get(&instance_encoded)
        .ok_or(TargetWasmError::MissingLedgerEntry {
            entry: "target instance",
        })?;
    let LedgerEntryData::ContractData(instance_data) = &instance.data else {
        return Err(
            RpcError::Malformed("capture instance is not contract data".to_string()).into(),
        );
    };
    let ScVal::ContractInstance(instance_value) = &instance_data.val else {
        return Err(
            RpcError::Malformed("capture instance has no instance value".to_string()).into(),
        );
    };
    let ContractExecutable::Wasm(final_hash) = &instance_value.executable else {
        return Err(RpcError::Malformed("capture instance no longer uses Wasm".to_string()).into());
    };
    if final_hash.0 != discovered.code_hash.0 {
        return Err(TargetWasmError::CodeHashMismatch {
            expected: discovered.code_hash.to_hex(),
            actual: Hash32(final_hash.0).to_hex(),
        });
    }
    let code = entries
        .get(&code_encoded)
        .ok_or(TargetWasmError::MissingLedgerEntry {
            entry: "target code",
        })?;
    let LedgerEntryData::ContractCode(code_data) = &code.data else {
        return Err(RpcError::Malformed("capture code is not contract code".to_string()).into());
    };
    let actual_hash: [u8; 32] = Sha256::digest(code_data.code.as_ref() as &[u8]).into();
    if actual_hash != discovered.code_hash.0 {
        return Err(TargetWasmError::CodeHashMismatch {
            expected: discovered.code_hash.to_hex(),
            actual: Hash32(actual_hash).to_hex(),
        });
    }
    Ok(TargetCapture {
        network_id: discovered.network_id,
        contract_address: contract.to_string().as_str().to_owned(),
        code_hash: discovered.code_hash,
        reported_ledger: LedgerSeq(reported_ledger),
        selected_storage_keys: selected_key_xdr_base64.len(),
        entries,
    })
}

fn capture_ledger_field(
    value: &serde_json::Value,
    index: usize,
    field: &str,
) -> Result<u32, RpcError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RpcError::Malformed(format!("capture entry {index} lacks integer {field}")))?
        .try_into()
        .map_err(|_| RpcError::Malformed(format!("capture entry {index} {field} exceeds u32")))
}

/// Code bytes bound to an instance according to one RPC endpoint's two ledger-entry replies.
/// This contains no target storage closure and has not executed the target contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndpointWasmObservation {
    pub network_id: NetworkId,
    pub contract_address: String,
    pub code_hash: Hash32,
    pub wasm: Vec<u8>,
    /// Bare `LedgerEntryData` XDR from the instance reply, for later fixture construction.
    pub instance_xdr_base64: String,
    /// The instance-to-code link was observed in this first response.
    pub instance_reported_ledger: LedgerSeq,
    /// Content-addressed code was fetched in this second response.
    pub code_reported_ledger: LedgerSeq,
    pub instance_last_modified_ledger: LedgerSeq,
    pub code_last_modified_ledger: LedgerSeq,
    pub instance_live_until_ledger: LedgerSeq,
    pub code_live_until_ledger: LedgerSeq,
}

struct EntryReply {
    reported_ledger: u32,
    last_modified_ledger: u32,
    live_until_ledger: u32,
    xdr_base64: String,
    data: LedgerEntryData,
}

/// Fetch a contract instance and its matching Wasm code from a configured RPC transport.
/// The network, entry keys, XDR variants, ledger fields, and SHA-256 are checked. The caller
/// must acquire relevant target storage separately before making disposable-execution claims.
pub(crate) fn read_target_wasm<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    contract_address: &str,
) -> Result<EndpointWasmObservation, TargetWasmError> {
    if contract_address.len() > MAX_CONTRACT_ADDRESS_BYTES {
        return Err(TargetWasmError::InvalidRequest(
            "target contract address exceeds the encoded address size limit".to_string(),
        ));
    }
    let contract = contract_address
        .parse::<stellar_strkey::Contract>()
        .map_err(|error| {
            TargetWasmError::InvalidRequest(format!("invalid target contract address: {error}"))
        })?;
    verify_network(transport, network_passphrase)?;

    let sc_address = ScAddress::Contract(ContractId(Hash(contract.0)));
    let instance = read_entry(
        transport,
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_address.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        }),
        "contract instance",
    )?;
    let LedgerEntryData::ContractData(instance_data) = &instance.data else {
        return Err(
            RpcError::Malformed("target instance reply is not contract data".to_string()).into(),
        );
    };
    if instance_data.contract != sc_address
        || instance_data.key != ScVal::LedgerKeyContractInstance
        || instance_data.durability != ContractDataDurability::Persistent
    {
        return Err(RpcError::Malformed(
            "target instance reply does not match its requested key".to_string(),
        )
        .into());
    }
    let ScVal::ContractInstance(contract_instance) = &instance_data.val else {
        return Err(RpcError::Malformed(
            "target instance reply does not contain a contract instance".to_string(),
        )
        .into());
    };
    let code_hash = match &contract_instance.executable {
        ContractExecutable::Wasm(hash) => hash.clone(),
        ContractExecutable::StellarAsset => {
            return Err(TargetWasmError::NonWasmExecutable {
                contract: contract_address.to_string(),
            });
        }
        ContractExecutable::ExternalRef(reference) => {
            return Err(RpcError::ExternalRefExecutable {
                contract: contract_address.to_string(),
                owner: reference.executable_owner.to_string(),
                tag: reference.tag.to_string(),
            }
            .into());
        }
    };

    let code = read_entry(
        transport,
        LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: code_hash.clone(),
        }),
        "contract code",
    )?;
    let LedgerEntryData::ContractCode(code_data) = code.data else {
        return Err(
            RpcError::Malformed("target code reply is not contract code".to_string()).into(),
        );
    };
    if code_data.hash != code_hash {
        return Err(TargetWasmError::CodeHashMismatch {
            expected: Hash32(code_hash.0).to_string(),
            actual: Hash32(code_data.hash.0).to_string(),
        });
    }
    let actual_hash: [u8; 32] = Sha256::digest(code_data.code.as_ref() as &[u8]).into();
    if actual_hash != code_hash.0 {
        return Err(TargetWasmError::CodeHashMismatch {
            expected: Hash32(code_hash.0).to_string(),
            actual: Hash32(actual_hash).to_string(),
        });
    }

    Ok(EndpointWasmObservation {
        network_id: NetworkId::from_passphrase(network_passphrase),
        contract_address: contract_address.to_string(),
        code_hash: Hash32(code_hash.0),
        wasm: code_data.code.into_vec(),
        instance_xdr_base64: instance.xdr_base64,
        instance_reported_ledger: LedgerSeq(instance.reported_ledger),
        code_reported_ledger: LedgerSeq(code.reported_ledger),
        instance_last_modified_ledger: LedgerSeq(instance.last_modified_ledger),
        code_last_modified_ledger: LedgerSeq(code.last_modified_ledger),
        instance_live_until_ledger: LedgerSeq(instance.live_until_ledger),
        code_live_until_ledger: LedgerSeq(code.live_until_ledger),
    })
}

fn read_entry<T: RpcTransport>(
    transport: &T,
    key: LedgerKey,
    entry: &'static str,
) -> Result<EntryReply, TargetWasmError> {
    let encoded_key = key
        .to_xdr_base64(xdr_limits())
        .map_err(|_| TargetWasmError::InvalidRequest(format!("cannot encode {entry} key")))?;
    let result = transport
        .call(
            "getLedgerEntries",
            json!({ "keys": [encoded_key], "xdrFormat": "base64" }),
        )
        .map_err(redact_ledger_request_error)?;
    let reported_ledger: u32 = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RpcError::Malformed(format!("{entry} reply has no integer latestLedger")))?
        .try_into()
        .map_err(|_| RpcError::Malformed(format!("{entry} latestLedger exceeds u32")))?;
    if reported_ledger == 0 {
        return Err(
            RpcError::Malformed(format!("{entry} reply has unusable latestLedger zero")).into(),
        );
    }
    let entries = result
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RpcError::Malformed(format!("{entry} reply has no entries array")))?;
    let [value] = entries.as_slice() else {
        return if entries.is_empty() {
            Err(TargetWasmError::MissingLedgerEntry { entry })
        } else {
            Err(RpcError::Malformed(format!(
                "{entry} reply has {} entries for one requested key",
                entries.len()
            ))
            .into())
        };
    };
    if value.get("key").and_then(serde_json::Value::as_str) != Some(encoded_key.as_str()) {
        return Err(
            RpcError::Malformed(format!("{entry} reply returned an unrequested key")).into(),
        );
    }
    let last_modified_ledger: u32 = value
        .get("lastModifiedLedgerSeq")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed(format!(
                "{entry} reply has no integer lastModifiedLedgerSeq"
            ))
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed(format!("{entry} lastModifiedLedgerSeq exceeds u32")))?;
    if last_modified_ledger > reported_ledger {
        return Err(
            RpcError::Malformed(format!("{entry} was modified after its reported ledger")).into(),
        );
    }
    let live_until_ledger: u32 = value
        .get("liveUntilLedgerSeq")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed(format!("{entry} reply has no integer liveUntilLedgerSeq"))
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed(format!("{entry} liveUntilLedgerSeq exceeds u32")))?;
    let xdr_base64 = value
        .get("xdr")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RpcError::Malformed(format!("{entry} reply has no string xdr")))?;
    ensure_base64_size("xdr", xdr_base64)?;
    let data = LedgerEntryData::from_xdr_base64(xdr_base64, xdr_limits())
        .map_err(|_| RpcError::Malformed(format!("{entry} reply has invalid XDR")))?;
    if live_until_ledger < reported_ledger {
        return Err(TargetWasmError::ArchivedLedgerEntry {
            entry,
            reported: reported_ledger,
            live_until: live_until_ledger,
        });
    }
    Ok(EntryReply {
        reported_ledger,
        last_modified_ledger,
        live_until_ledger,
        xdr_base64: xdr_base64.to_string(),
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractCodeEntry, ContractCodeEntryExt, ContractDataEntry, ExtensionPoint,
        ScContractInstance,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const CONTRACT_ID: [u8; 32] = [7; 32];
    const WASM: &[u8] = b"\0asm\x01\0\0\0";

    struct FixtureTransport {
        network: Value,
        instance: Value,
        code: Value,
        expected_code_hash: Hash,
        calls: RefCell<Vec<String>>,
        failure: RefCell<Option<RpcError>>,
    }

    impl RpcTransport for FixtureTransport {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            self.calls.borrow_mut().push(method.to_string());
            match method {
                "getNetwork" => Ok(self.network.clone()),
                "getLedgerEntries" => {
                    if let Some(error) = self.failure.borrow_mut().take() {
                        return Err(error);
                    }
                    let keys = params["keys"].as_array().expect("one key array");
                    assert_eq!(keys.len(), 1);
                    assert_eq!(params["xdrFormat"], "base64");
                    let encoded = keys[0].as_str().expect("encoded key");
                    let key = LedgerKey::from_xdr_base64(encoded, xdr_limits()).expect("key XDR");
                    match key {
                        LedgerKey::ContractData(data) => {
                            assert_eq!(
                                data.contract,
                                ScAddress::Contract(ContractId(Hash(CONTRACT_ID)))
                            );
                            assert_eq!(data.key, ScVal::LedgerKeyContractInstance);
                            Ok(self.instance.clone())
                        }
                        LedgerKey::ContractCode(code) => {
                            assert_eq!(code.hash, self.expected_code_hash);
                            Ok(self.code.clone())
                        }
                        other => panic!("unexpected ledger key: {other:?}"),
                    }
                }
                other => panic!("unexpected RPC method: {other}"),
            }
        }
    }

    fn contract_address() -> String {
        stellar_strkey::Contract(CONTRACT_ID)
            .to_string()
            .as_str()
            .to_owned()
    }

    fn instance_xdr_for(contract_id: [u8; 32], executable: ContractExecutable) -> String {
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(contract_id))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable,
                storage: None,
            }),
        })
        .to_xdr_base64(xdr_limits())
        .expect("instance XDR")
    }

    fn instance_xdr(executable: ContractExecutable) -> String {
        instance_xdr_for(CONTRACT_ID, executable)
    }

    fn code_xdr(hash: Hash, bytes: &[u8]) -> String {
        LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: ContractCodeEntryExt::V0,
            hash,
            code: bytes.try_into().expect("code bytes"),
        })
        .to_xdr_base64(xdr_limits())
        .expect("code XDR")
    }

    fn fixture() -> FixtureTransport {
        let hash = Hash(Sha256::digest(WASM).into());
        let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash(CONTRACT_ID))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        })
        .to_xdr_base64(xdr_limits())
        .expect("instance key");
        let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() })
            .to_xdr_base64(xdr_limits())
            .expect("code key");
        FixtureTransport {
            network: json!({"passphrase": NETWORK, "protocolVersion": 28}),
            instance: json!({
                "latestLedger": 100,
                "entries": [{
                    "key": instance_key,
                    "xdr": instance_xdr(ContractExecutable::Wasm(hash.clone())),
                    "lastModifiedLedgerSeq": 95,
                    "liveUntilLedgerSeq": 120
                }]
            }),
            code: json!({
                "latestLedger": 100,
                "entries": [{
                    "key": code_key,
                    "xdr": code_xdr(hash, WASM),
                    "lastModifiedLedgerSeq": 90,
                    "liveUntilLedgerSeq": 120
                }]
            }),
            expected_code_hash: Hash(Sha256::digest(WASM).into()),
            calls: RefCell::new(Vec::new()),
            failure: RefCell::new(None),
        }
    }

    struct CaptureTransport {
        base: FixtureTransport,
        final_response: Value,
        final_failure: RefCell<Option<RpcError>>,
    }

    impl RpcTransport for CaptureTransport {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            if method == "getLedgerEntries"
                && params["keys"].as_array().is_some_and(|keys| keys.len() > 1)
            {
                if let Some(error) = self.final_failure.borrow_mut().take() {
                    return Err(error);
                }
                let requested = params["keys"].as_array().unwrap();
                let returned = self.final_response["entries"].as_array().unwrap();
                for entry in returned {
                    assert!(requested.contains(&entry["key"]));
                }
                self.base.calls.borrow_mut().push(method.to_string());
                Ok(self.final_response.clone())
            } else {
                self.base.call(method, params)
            }
        }
    }

    fn storage_key() -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash(CONTRACT_ID))),
            key: ScVal::U32(42),
            durability: ContractDataDurability::Persistent,
        })
    }

    fn capture_fixture() -> (CaptureTransport, String) {
        let base = fixture();
        let key = storage_key().to_xdr_base64(xdr_limits()).unwrap();
        let data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(CONTRACT_ID))),
            key: ScVal::U32(42),
            durability: ContractDataDurability::Persistent,
            val: ScVal::U32(7),
        });
        let storage = json!({
            "key": key,
            "xdr": data.to_xdr_base64(xdr_limits()).unwrap(),
            "lastModifiedLedgerSeq": 96,
            "liveUntilLedgerSeq": 120
        });
        let final_response = json!({
            "latestLedger": 101,
            "entries": [base.instance["entries"][0].clone(), base.code["entries"][0].clone(), storage]
        });
        (
            CaptureTransport {
                base,
                final_response,
                final_failure: RefCell::new(None),
            },
            key,
        )
    }

    #[test]
    fn captures_selected_storage_with_matching_instance_and_code_in_one_reply() {
        let (transport, key) = capture_fixture();
        let capture = read_target_capture(
            &transport,
            NETWORK,
            &contract_address(),
            std::slice::from_ref(&key),
        )
        .expect("all requested entries are valid and live");
        assert_eq!(capture.network_id, NetworkId::from_passphrase(NETWORK));
        assert_eq!(capture.reported_ledger, LedgerSeq(101));
        assert_eq!(capture.selected_storage_keys, 1);
        assert_eq!(capture.entries.len(), 3);
        assert_eq!(capture.entries[&key].key, storage_key());
        assert_eq!(capture.entries[&key].last_modified_ledger, LedgerSeq(96));
        assert_eq!(capture.entries[&key].live_until_ledger, LedgerSeq(120));
        assert_eq!(transport.base.calls.borrow().len(), 4);
    }

    #[test]
    fn capture_endpoint_errors_cannot_echo_requested_keys() {
        let (transport, selected_key) = capture_fixture();
        *transport.final_failure.borrow_mut() = Some(RpcError::Transport(format!(
            "HTTP body echoed selected key {selected_key}"
        )));
        let error = read_target_capture(
            &transport,
            NETWORK,
            &contract_address(),
            std::slice::from_ref(&selected_key),
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            TargetWasmError::Rpc(RpcError::Transport(_))
        ));
        assert!(!error.to_string().contains(&selected_key));
        assert!(!error.to_string().contains("HTTP body"));

        let (transport, selected_key) = capture_fixture();
        let instance_key = transport.base.instance["entries"][0]["key"]
            .as_str()
            .unwrap()
            .to_string();
        *transport.base.failure.borrow_mut() = Some(RpcError::Rpc(format!(
            "JSON-RPC error echoed instance key {instance_key}"
        )));
        let error = read_target_capture(
            &transport,
            NETWORK,
            &contract_address(),
            std::slice::from_ref(&selected_key),
        )
        .unwrap_err();
        assert!(matches!(&error, TargetWasmError::Rpc(RpcError::Rpc(_))));
        assert!(!error.to_string().contains(&instance_key));
        assert!(!error.to_string().contains("JSON-RPC error"));
    }

    #[test]
    fn capture_refuses_missing_archived_and_changed_target_entries() {
        let (mut transport, key) = capture_fixture();
        transport.final_response["entries"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(matches!(
            read_target_capture(
                &transport,
                NETWORK,
                &contract_address(),
                std::slice::from_ref(&key)
            ),
            Err(TargetWasmError::MissingLedgerEntry { .. })
        ));

        let (mut transport, key) = capture_fixture();
        transport.final_response["entries"][2]["liveUntilLedgerSeq"] = json!(100);
        assert!(matches!(
            read_target_capture(
                &transport,
                NETWORK,
                &contract_address(),
                std::slice::from_ref(&key)
            ),
            Err(TargetWasmError::ArchivedLedgerEntry { .. })
        ));

        let (mut transport, key) = capture_fixture();
        transport.final_response["entries"][0]["xdr"] =
            json!(instance_xdr(ContractExecutable::Wasm(Hash([9; 32]))));
        assert!(matches!(
            read_target_capture(&transport, NETWORK, &contract_address(), &[key]),
            Err(TargetWasmError::CodeHashMismatch { .. })
        ));

        let (mut transport, key) = capture_fixture();
        transport.final_response["entries"][1]["xdr"] = json!(code_xdr(
            Hash(Sha256::digest(WASM).into()),
            b"\0asm\x01\0\0\0changed"
        ));
        assert!(matches!(
            read_target_capture(&transport, NETWORK, &contract_address(), &[key]),
            Err(TargetWasmError::CodeHashMismatch { .. })
        ));

        let (mut transport, key) = capture_fixture();
        transport.final_response["latestLedger"] = json!(99);
        assert!(matches!(
            read_target_capture(&transport, NETWORK, &contract_address(), &[key]),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("precedes code discovery")
        ));
    }

    #[test]
    fn capture_refuses_invalid_selection_and_inconsistent_final_reply() {
        let (transport, key) = capture_fixture();
        assert!(matches!(
            read_target_capture(
                &transport,
                NETWORK,
                &contract_address(),
                &[key.clone(), key]
            ),
            Err(TargetWasmError::InvalidRequest(_))
        ));
        assert!(transport.base.calls.borrow().is_empty());

        let (transport, _) = capture_fixture();
        let foreign_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([8; 32]))),
            key: ScVal::U32(42),
            durability: ContractDataDurability::Persistent,
        })
        .to_xdr_base64(xdr_limits())
        .unwrap();
        assert!(matches!(
            read_target_capture(&transport, NETWORK, &contract_address(), &[foreign_key]),
            Err(TargetWasmError::InvalidRequest(_))
        ));
        assert!(transport.base.calls.borrow().is_empty());

        let (mut transport, key) = capture_fixture();
        transport.final_response["entries"][2]["xdr"] =
            transport.final_response["entries"][0]["xdr"].clone();
        assert!(matches!(
            read_target_capture(&transport, NETWORK, &contract_address(), &[key]),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("payload differs")
        ));
    }

    #[test]
    fn acquires_instance_bound_wasm_with_endpoint_ledger_labels() {
        let transport = fixture();
        let observation = read_target_wasm(&transport, NETWORK, &contract_address())
            .expect("the matching instance and code must be acquired");
        assert_eq!(observation.network_id, NetworkId::from_passphrase(NETWORK));
        assert_eq!(observation.contract_address, contract_address());
        assert_eq!(observation.code_hash, Hash32(Sha256::digest(WASM).into()));
        assert_eq!(observation.wasm, WASM);
        assert_eq!(observation.instance_reported_ledger, LedgerSeq(100));
        assert_eq!(observation.code_reported_ledger, LedgerSeq(100));
        assert_eq!(observation.instance_last_modified_ledger, LedgerSeq(95));
        assert_eq!(observation.code_last_modified_ledger, LedgerSeq(90));
        assert_eq!(observation.instance_live_until_ledger, LedgerSeq(120));
        assert_eq!(observation.code_live_until_ledger, LedgerSeq(120));
        assert_eq!(
            LedgerEntryData::from_xdr_base64(&observation.instance_xdr_base64, xdr_limits())
                .expect("preserved instance XDR"),
            LedgerEntryData::from_xdr_base64(
                transport.instance["entries"][0]["xdr"].as_str().unwrap(),
                xdr_limits()
            )
            .unwrap()
        );
        assert_eq!(
            *transport.calls.borrow(),
            ["getNetwork", "getLedgerEntries", "getLedgerEntries"]
        );
    }

    #[test]
    fn distinguishes_missing_entries_from_invalid_responses() {
        let mut transport = fixture();
        transport.instance["entries"] = json!([]);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::MissingLedgerEntry {
                entry: "contract instance"
            })
        ));

        let mut transport = fixture();
        transport.code["entries"] = json!([]);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::MissingLedgerEntry {
                entry: "contract code"
            })
        ));

        let mut transport = fixture();
        transport.code["entries"][0]["xdr"] = json!("not-base64");
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(_)))
        ));

        let mut transport = fixture();
        transport.instance["entries"][0]["key"] = json!("unexpected");
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(_)))
        ));
    }

    #[test]
    fn refuses_both_claimed_and_actual_code_hash_mismatches() {
        let mut transport = fixture();
        transport.code["entries"][0]["xdr"] = json!(code_xdr(Hash([9; 32]), WASM));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::CodeHashMismatch { .. })
        ));

        let mut transport = fixture();
        transport.code["entries"][0]["xdr"] = json!(code_xdr(
            Hash(Sha256::digest(WASM).into()),
            b"\0asm\x01\0\0\0changed"
        ));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::CodeHashMismatch { .. })
        ));
    }

    #[test]
    fn records_different_reported_ledgers_and_refuses_non_wasm_instances() {
        let mut transport = fixture();
        transport.code["latestLedger"] = json!(101);
        let observation = read_target_wasm(&transport, NETWORK, &contract_address()).unwrap();
        assert_eq!(observation.instance_reported_ledger, LedgerSeq(100));
        assert_eq!(observation.code_reported_ledger, LedgerSeq(101));

        let mut transport = fixture();
        transport.instance["entries"][0]["xdr"] =
            json!(instance_xdr(ContractExecutable::StellarAsset));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::NonWasmExecutable { .. })
        ));
        assert_eq!(transport.calls.borrow().len(), 2, "no code read is needed");
    }

    #[test]
    fn refuses_unusable_ledger_fields_and_oversized_address() {
        let mut transport = fixture();
        transport.instance["latestLedger"] = json!(0);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("latestLedger zero")
        ));

        let mut transport = fixture();
        transport.code["entries"][0]["lastModifiedLedgerSeq"] = json!(0);
        assert_eq!(
            read_target_wasm(&transport, NETWORK, &contract_address())
                .unwrap()
                .code_last_modified_ledger,
            LedgerSeq(0)
        );

        let mut transport = fixture();
        transport.code["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("liveUntilLedgerSeq");
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("liveUntilLedgerSeq")
        ));

        let mut transport = fixture();
        transport.code["entries"][0]["liveUntilLedgerSeq"] = json!(99);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::ArchivedLedgerEntry {
                entry: "contract code",
                reported: 100,
                live_until: 99
            })
        ));

        let transport = fixture();
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &"C".repeat(129)),
            Err(TargetWasmError::InvalidRequest(message)) if message.contains("size limit")
        ));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, "not-a-contract"),
            Err(TargetWasmError::InvalidRequest(message)) if message.contains("invalid target contract address")
        ));
        assert!(transport.calls.borrow().is_empty(), "reject before RPC I/O");
    }

    #[test]
    fn refuses_response_key_payload_count_and_metadata_errors() {
        let mut transport = fixture();
        let different_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([8; 32]))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        })
        .to_xdr_base64(xdr_limits())
        .unwrap();
        transport.instance["entries"][0]["key"] = json!(different_key);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("unrequested key")
        ));

        let mut transport = fixture();
        transport.instance["entries"][0]["xdr"] = json!(instance_xdr_for(
            [8; 32],
            ContractExecutable::Wasm(transport.expected_code_hash.clone()),
        ));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("requested key")
        ));

        let mut transport = fixture();
        let entry = transport.instance["entries"][0].clone();
        transport.instance["entries"] = json!([entry.clone(), entry]);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("2 entries")
        ));

        let mut transport = fixture();
        transport.instance["entries"][0]["lastModifiedLedgerSeq"] = json!(101);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("modified after")
        ));

        let mut transport = fixture();
        transport.code["entries"][0]["xdr"] = json!("A".repeat(crate::MAX_XDR_BASE64_BYTES + 1));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("XDR size limit")
        ));

        let mut transport = fixture();
        transport.code["entries"][0]["xdr"] = json!(instance_xdr(ContractExecutable::Wasm(
            transport.expected_code_hash.clone()
        )));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("not contract code")
        ));
    }

    #[test]
    fn archived_entries_and_external_references_are_distinct_refusals() {
        let mut transport = fixture();
        transport.instance["entries"][0]["liveUntilLedgerSeq"] = json!(0);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::ArchivedLedgerEntry {
                entry: "contract instance",
                reported: 100,
                live_until: 0
            })
        ));

        let mut malformed_archive = fixture();
        malformed_archive.instance["entries"][0]["liveUntilLedgerSeq"] = json!(0);
        malformed_archive.instance["entries"][0]["xdr"] = json!("not-base64");
        assert!(matches!(
            read_target_wasm(&malformed_archive, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("invalid XDR")
        ));

        let mut transport = fixture();
        transport.instance["entries"][0]["xdr"] = json!(instance_xdr(
            ContractExecutable::ExternalRef(stellar_xdr::ContractExecutableExternalRef {
                executable_owner: ScAddress::Contract(ContractId(Hash([8; 32]))),
                tag: stellar_xdr::ScString("v1".try_into().unwrap()),
            })
        ));
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::ExternalRefExecutable { .. }))
        ));
    }
}
