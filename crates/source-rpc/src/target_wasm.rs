//! Read a target's instance and Wasm bytes for later disposable execution.
//!
//! The two `getLedgerEntries` calls are separate. Equal `latestLedger` values are only an
//! endpoint consistency check; they do not prove historical coherence or capture the target's
//! other storage. No dry-run evidence layer is established by this reader alone.

use crate::{ensure_base64_size, verify_network, xdr_limits, RpcError, RpcTransport};
use ozpb_domain::{Hash32, LedgerSeq, NetworkId};
use serde_json::json;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, ReadXdr, ScAddress, ScVal, WriteXdr,
};

const MAX_CONTRACT_ADDRESS_BYTES: usize = 128;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TargetWasmError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("{entry} is absent from getLedgerEntries (possibly archived)")]
    MissingLedgerEntry { entry: &'static str },
    #[error("target contract {contract} does not use a Wasm executable")]
    NonWasmExecutable { contract: String },
    #[error("instance and code reads report different ledgers ({instance}, {code})")]
    InconsistentLedgers { instance: u32, code: u32 },
    #[error("contract code hash mismatch: expected {expected}, received {actual}")]
    CodeHashMismatch { expected: String, actual: String },
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
    /// Both replies *reported* this ledger; the calls were not an atomic snapshot.
    pub endpoint_reported_ledger: LedgerSeq,
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
        return Err(RpcError::Malformed(
            "target contract address exceeds the encoded address size limit".to_string(),
        )
        .into());
    }
    let contract = contract_address
        .parse::<stellar_strkey::Contract>()
        .map_err(|error| {
            RpcError::Malformed(format!("invalid target contract address: {error}"))
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
    if instance.reported_ledger != code.reported_ledger {
        return Err(TargetWasmError::InconsistentLedgers {
            instance: instance.reported_ledger,
            code: code.reported_ledger,
        });
    }
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
        endpoint_reported_ledger: LedgerSeq(instance.reported_ledger),
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
        .map_err(|error| RpcError::Malformed(format!("cannot encode {entry} key: {error}")))?;
    let result = transport.call(
        "getLedgerEntries",
        json!({ "keys": [encoded_key], "xdrFormat": "base64" }),
    )?;
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
    if last_modified_ledger == 0 {
        return Err(RpcError::Malformed(format!(
            "{entry} reply has unusable lastModifiedLedgerSeq zero"
        ))
        .into());
    }
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
    if live_until_ledger < reported_ledger {
        return Err(
            RpcError::Malformed(format!("{entry} is not live at its reported ledger")).into(),
        );
    }
    let xdr_base64 = value
        .get("xdr")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RpcError::Malformed(format!("{entry} reply has no string xdr")))?;
    ensure_base64_size("xdr", xdr_base64)?;
    let data = LedgerEntryData::from_xdr_base64(xdr_base64, xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("{entry} reply has invalid XDR: {error}")))?;
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
    }

    impl RpcTransport for FixtureTransport {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            self.calls.borrow_mut().push(method.to_string());
            match method {
                "getNetwork" => Ok(self.network.clone()),
                "getLedgerEntries" => {
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

    fn instance_xdr(executable: ContractExecutable) -> String {
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(CONTRACT_ID))),
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
        }
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
        assert_eq!(observation.endpoint_reported_ledger, LedgerSeq(100));
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
    fn refuses_different_reported_ledgers_and_non_wasm_instances() {
        let mut transport = fixture();
        transport.code["latestLedger"] = json!(101);
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::InconsistentLedgers {
                instance: 100,
                code: 101
            })
        ));

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
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &contract_address()),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("lastModifiedLedgerSeq zero")
        ));

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
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("not live")
        ));

        let transport = fixture();
        assert!(matches!(
            read_target_wasm(&transport, NETWORK, &"C".repeat(129)),
            Err(TargetWasmError::Rpc(RpcError::Malformed(message))) if message.contains("size limit")
        ));
        assert!(transport.calls.borrow().is_empty(), "reject before RPC I/O");
    }
}
