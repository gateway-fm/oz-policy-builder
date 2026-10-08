//! Capture exactly the keys declared by one Soroban transaction footprint.
//!
//! This is endpoint-reported state for the original envelope's declared keys.
//! A candidate policy or changed invocation can touch other keys, and an omitted
//! RPC key could be absent or archived. Neither case is silently filled in.

use crate::{
    ensure_base64_size, envelope_operations, redact_ledger_request_error,
    validate_simulation_envelope, verify_network, xdr_limits, RpcError, RpcTransport,
    MAX_LEDGER_ENTRY_KEYS,
};
use ozpb_domain::{sha256, Hash32, LedgerSeq, NetworkId};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{
    ContractExecutable, HostFunction, LedgerEntryData, LedgerKey, LedgerKeyContractCode,
    OperationBody, ReadXdr, ScAddress, TransactionEnvelope, TransactionExt, WriteXdr,
};

const MAX_KEY_BASE64_BYTES: usize = 16 * 1024;
const MAX_KEYS_TOTAL_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FootprintCaptureError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("invalid invocation footprint: {0}")]
    InvalidFootprint(String),
    #[error(
        "declared key {index} is missing from getLedgerEntries (absence versus archive unknown)"
    )]
    MissingDeclaredKey { index: usize },
    #[error(
        "declared key {index} is archived at reported ledger {reported} (live until {live_until})"
    )]
    ArchivedDeclaredKey {
        index: usize,
        reported: u32,
        live_until: u32,
    },
    #[error("Wasm contract instance has no matching code key in the declared footprint")]
    MissingCodeKey,
    #[error("declared contract code bytes do not match their hash key")]
    CodeHashMismatch,
    #[error("external-reference executables are unsupported in a local footprint fixture")]
    ExternalExecutable,
}

/// Bare entry data and metadata returned by RPC for one declared key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedFootprintEntry {
    pub key: LedgerKey,
    pub data: LedgerEntryData,
    pub last_modified_ledger: LedgerSeq,
    /// Present for contract data and code; non-TTL ledger entries may omit it.
    pub live_until_ledger: Option<LedgerSeq>,
}

/// One endpoint response covering every key declared by the original envelope.
///
/// This does not prove the footprint is complete for a reconstructed invocation,
/// nor does it supply ledger header/configuration or execute any call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationFootprintCapture {
    pub envelope_xdr_sha256: Hash32,
    pub network_id: NetworkId,
    pub reported_ledger: LedgerSeq,
    pub read_only_keys: BTreeSet<String>,
    pub read_write_keys: BTreeSet<String>,
    pub entries: BTreeMap<String, CapturedFootprintEntry>,
    /// The exact contract call carried by this envelope, if its host function is
    /// InvokeContract. CreateContract and UploadContractWasm have no such call.
    pub invocation: Option<CapturedInvocation>,
    /// Number of captured Wasm instance entries whose matching code was captured
    /// and checked. Other contracts referenced by the invocation are not counted.
    pub validated_wasm_instances: usize,
}

/// Original call identity and argument bytes, decoded from the validated envelope.
/// These are inputs for reconstruction, not evidence that the footprint covers a
/// changed candidate call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedInvocation {
    pub contract_address: String,
    pub function_name: String,
    pub args_xdr_base64: Vec<String>,
}

/// Acquire one bounded, exact footprint response for an InvokeHostFunction envelope.
///
/// Every declared key must be returned, live if it has TTL, and match its bare
/// entry data. Duplicate, missing, or oversized keys are refused before RPC I/O.
/// Every captured Wasm instance must have its matching code key in this same
/// response, and the code bytes must hash to the key. New write keys that are
/// absent at the endpoint are refused because RPC cannot establish their
/// history or TTL from this method. Endpoint error detail is withheld because
/// it may echo a declared key.
pub fn read_invocation_footprint<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    envelope_xdr_base64: &str,
) -> Result<InvocationFootprintCapture, FootprintCaptureError> {
    let envelope = validate_simulation_envelope(envelope_xdr_base64)?;
    let invocation = match &envelope_operations(&envelope)[0].body {
        OperationBody::InvokeHostFunction(op) => match &op.host_function {
            HostFunction::InvokeContract(call) => {
                let ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(id))) =
                    &call.contract_address
                else {
                    return Err(FootprintCaptureError::InvalidFootprint(
                        "InvokeContract does not target a contract address".to_string(),
                    ));
                };
                let function_name = std::str::from_utf8(call.function_name.as_slice())
                    .map_err(|_| {
                        FootprintCaptureError::InvalidFootprint(
                            "InvokeContract function name is not UTF-8".to_string(),
                        )
                    })?
                    .to_string();
                let mut args_xdr_base64 = Vec::with_capacity(call.args.len());
                for arg in call.args.iter() {
                    args_xdr_base64.push(arg.to_xdr_base64(xdr_limits()).map_err(|_| {
                        FootprintCaptureError::InvalidFootprint(
                            "cannot encode an InvokeContract argument".to_string(),
                        )
                    })?);
                }
                Some(CapturedInvocation {
                    contract_address: stellar_strkey::Contract(*id)
                        .to_string()
                        .as_str()
                        .to_owned(),
                    function_name,
                    args_xdr_base64,
                })
            }
            _ => None,
        },
        _ => unreachable!("validated single InvokeHostFunction operation"),
    };
    let ext = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx.ext,
        TransactionEnvelope::TxFeeBump(bump) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &bump.tx.inner_tx;
            &inner.tx.ext
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(FootprintCaptureError::InvalidFootprint(
                "v0 transaction has no Soroban footprint".to_string(),
            ));
        }
    };
    let TransactionExt::V1(data) = ext else {
        return Err(FootprintCaptureError::InvalidFootprint(
            "transaction has no SorobanData footprint".to_string(),
        ));
    };
    let footprint = &data.resources.footprint;
    let total_count = footprint
        .read_only
        .len()
        .saturating_add(footprint.read_write.len());
    if total_count == 0 || total_count > MAX_LEDGER_ENTRY_KEYS {
        return Err(FootprintCaptureError::InvalidFootprint(format!(
            "declared footprint requires 1..={MAX_LEDGER_ENTRY_KEYS} keys"
        )));
    }
    let mut requested = BTreeMap::<String, LedgerKey>::new();
    let mut read_only_keys = BTreeSet::new();
    let mut read_write_keys = BTreeSet::new();
    let mut total_bytes = 0usize;
    for (is_write, keys) in [
        (false, footprint.read_only.as_slice()),
        (true, footprint.read_write.as_slice()),
    ] {
        for key in keys {
            let encoded = key.to_xdr_base64(xdr_limits()).map_err(|error| {
                FootprintCaptureError::InvalidFootprint(format!(
                    "cannot encode a declared key: {error}"
                ))
            })?;
            if encoded.len() > MAX_KEY_BASE64_BYTES {
                return Err(FootprintCaptureError::InvalidFootprint(
                    "a declared key exceeds the encoded size limit".to_string(),
                ));
            }
            total_bytes = total_bytes.saturating_add(encoded.len());
            if total_bytes > MAX_KEYS_TOTAL_BYTES {
                return Err(FootprintCaptureError::InvalidFootprint(
                    "declared keys exceed the request byte budget".to_string(),
                ));
            }
            if requested.insert(encoded.clone(), key.clone()).is_some() {
                return Err(FootprintCaptureError::InvalidFootprint(
                    "duplicate declared ledger key".to_string(),
                ));
            }
            if is_write {
                read_write_keys.insert(encoded);
            } else {
                read_only_keys.insert(encoded);
            }
        }
    }
    let canonical = envelope.to_xdr(xdr_limits()).map_err(|error| {
        FootprintCaptureError::InvalidFootprint(format!("cannot encode envelope: {error}"))
    })?;
    let envelope_xdr_sha256 = sha256(&canonical);
    verify_network(transport, network_passphrase)?;
    let keys: Vec<&String> = requested.keys().collect();
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
            RpcError::Malformed("footprint capture lacks integer latestLedger".to_string())
        })?
        .try_into()
        .map_err(|_| {
            RpcError::Malformed("footprint capture latestLedger exceeds u32".to_string())
        })?;
    if reported_ledger == 0 {
        return Err(
            RpcError::Malformed("footprint capture latestLedger is zero".to_string()).into(),
        );
    }
    let values = response
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RpcError::Malformed("footprint capture lacks entries array".to_string()))?;
    let mut entries = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        let encoded_key = value
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RpcError::Malformed(format!("footprint entry {index} lacks key")))?;
        let key = requested.get(encoded_key).ok_or_else(|| {
            RpcError::Malformed(format!(
                "footprint entry {index} returned an undeclared key"
            ))
        })?;
        if entries.contains_key(encoded_key) {
            return Err(RpcError::Malformed(format!(
                "footprint entry {index} duplicates a declared key"
            ))
            .into());
        }
        let encoded_data = value
            .get("xdr")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RpcError::Malformed(format!("footprint entry {index} lacks XDR")))?;
        ensure_base64_size("footprint entry XDR", encoded_data)?;
        let data = LedgerEntryData::from_xdr_base64(encoded_data, xdr_limits())
            .map_err(|_| RpcError::Malformed(format!("footprint entry {index} has invalid XDR")))?;
        if data.to_key() != *key {
            return Err(RpcError::Malformed(format!(
                "footprint entry {index} payload differs from its declared key"
            ))
            .into());
        }
        let last_modified = ledger_field(value, index, "lastModifiedLedgerSeq")?;
        if last_modified > reported_ledger {
            return Err(RpcError::Malformed(format!(
                "footprint entry {index} was modified after reported ledger"
            ))
            .into());
        }
        let live_until = match value.get("liveUntilLedgerSeq") {
            None | Some(serde_json::Value::Null) => None,
            Some(_) => Some(ledger_field(value, index, "liveUntilLedgerSeq")?),
        };
        if matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_))
            && live_until.is_none()
        {
            return Err(
                RpcError::Malformed(format!("footprint entry {index} lacks contract TTL")).into(),
            );
        }
        if let Some(live_until) = live_until {
            if live_until < reported_ledger {
                return Err(FootprintCaptureError::ArchivedDeclaredKey {
                    index,
                    reported: reported_ledger,
                    live_until,
                });
            }
        }
        entries.insert(
            encoded_key.to_string(),
            CapturedFootprintEntry {
                key: key.clone(),
                data,
                last_modified_ledger: LedgerSeq(last_modified),
                live_until_ledger: live_until.map(LedgerSeq),
            },
        );
    }
    for (index, encoded) in requested.keys().enumerate() {
        if !entries.contains_key(encoded) {
            return Err(FootprintCaptureError::MissingDeclaredKey { index });
        }
    }
    let mut validated_wasm_instances = 0;
    for entry in entries.values() {
        match &entry.data {
            LedgerEntryData::ContractCode(code) => {
                let actual: [u8; 32] = Sha256::digest(code.code.as_ref() as &[u8]).into();
                if actual != code.hash.0 {
                    return Err(FootprintCaptureError::CodeHashMismatch);
                }
            }
            LedgerEntryData::ContractData(data)
                if data.key == stellar_xdr::ScVal::LedgerKeyContractInstance =>
            {
                let stellar_xdr::ScVal::ContractInstance(instance) = &data.val else {
                    return Err(RpcError::Malformed(
                        "contract instance key has no instance value".to_string(),
                    )
                    .into());
                };
                match &instance.executable {
                    ContractExecutable::Wasm(hash) => {
                        let code_key =
                            LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
                        let encoded = code_key.to_xdr_base64(xdr_limits()).map_err(|_| {
                            FootprintCaptureError::InvalidFootprint(
                                "cannot encode captured code key".to_string(),
                            )
                        })?;
                        if !entries.contains_key(&encoded) {
                            return Err(FootprintCaptureError::MissingCodeKey);
                        }
                        validated_wasm_instances += 1;
                    }
                    ContractExecutable::StellarAsset => {}
                    ContractExecutable::ExternalRef(_) => {
                        return Err(FootprintCaptureError::ExternalExecutable)
                    }
                }
            }
            _ => {}
        }
    }
    Ok(InvocationFootprintCapture {
        envelope_xdr_sha256,
        network_id: NetworkId::from_passphrase(network_passphrase),
        reported_ledger: LedgerSeq(reported_ledger),
        read_only_keys,
        read_write_keys,
        entries,
        invocation,
        validated_wasm_instances,
    })
}

fn ledger_field(value: &serde_json::Value, index: usize, field: &str) -> Result<u32, RpcError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed(format!("footprint entry {index} lacks integer {field}"))
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed(format!("footprint entry {index} {field} exceeds u32")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_recorder_core::{fixtures, record, RecordOptions};
    use serde_json::Value;
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, ContractDataEntry,
        ContractId, ExtensionPoint, Hash, LedgerFootprint, LedgerKeyAccount, LedgerKeyContractData,
        ScAddress, ScContractInstance, ScVal, SorobanTransactionData, VecM,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const WASM: &[u8] = b"\0asm\x01\0\0\0";

    struct CannedRpc {
        response: Value,
        calls: RefCell<Vec<String>>,
        failure: RefCell<Option<RpcError>>,
    }

    impl RpcTransport for CannedRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            self.calls.borrow_mut().push(method.to_string());
            match method {
                "getNetwork" => Ok(json!({"passphrase": NETWORK, "protocolVersion": 28})),
                "getLedgerEntries" => {
                    if let Some(error) = self.failure.borrow_mut().take() {
                        return Err(error);
                    }
                    assert_eq!(params["xdrFormat"], "base64");
                    let requested = params["keys"].as_array().unwrap();
                    assert!(!requested.is_empty());
                    Ok(self.response.clone())
                }
                other => panic!("unexpected RPC method {other}"),
            }
        }
    }

    fn envelope(read_only: Vec<LedgerKey>, read_write: Vec<LedgerKey>) -> String {
        let raw = record(&fixtures::executed_snapshot(), RecordOptions::default())
            .unwrap()
            .raw
            .envelope_xdr_base64;
        let mut envelope = TransactionEnvelope::from_xdr_base64(&raw, xdr_limits()).unwrap();
        let TransactionEnvelope::Tx(v1) = &mut envelope else {
            panic!("fixture has one ordinary transaction")
        };
        let mut data = SorobanTransactionData::default();
        data.resources.footprint = LedgerFootprint {
            read_only: VecM::try_from(read_only).unwrap(),
            read_write: VecM::try_from(read_write).unwrap(),
        };
        v1.tx.ext = TransactionExt::V1(data);
        envelope.to_xdr_base64(xdr_limits()).unwrap()
    }

    fn fixture() -> (String, CannedRpc) {
        let contract = ScAddress::Contract(ContractId(Hash([7; 32])));
        let dependency = ScAddress::Contract(ContractId(Hash([8; 32])));
        let hash = Hash(Sha256::digest(WASM).into());
        let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let instance_data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(hash.clone()),
                storage: None,
            }),
        });
        let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
        let code_data = LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: ContractCodeEntryExt::V0,
            hash,
            code: WASM.try_into().unwrap(),
        });
        let target_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract.clone(),
            key: ScVal::U32(1),
            durability: ContractDataDurability::Persistent,
        });
        let target_data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract,
            key: ScVal::U32(1),
            durability: ContractDataDurability::Persistent,
            val: ScVal::U32(2),
        });
        let dependency_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: dependency.clone(),
            key: ScVal::U32(3),
            durability: ContractDataDurability::Persistent,
        });
        let dependency_data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: dependency,
            key: ScVal::U32(3),
            durability: ContractDataDurability::Persistent,
            val: ScVal::U32(4),
        });
        let account_data = stellar_xdr::AccountEntry::default();
        let account_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_data.account_id.clone(),
        });
        let account_entry = json!({
            "key": account_key.to_xdr_base64(xdr_limits()).unwrap(),
            "xdr": LedgerEntryData::Account(account_data).to_xdr_base64(xdr_limits()).unwrap(),
            "lastModifiedLedgerSeq": 95
        });
        let entry = |key: LedgerKey, data: LedgerEntryData| {
            json!({
                "key": key.to_xdr_base64(xdr_limits()).unwrap(),
                "xdr": data.to_xdr_base64(xdr_limits()).unwrap(),
                "lastModifiedLedgerSeq": 95,
                "liveUntilLedgerSeq": 120
            })
        };
        let encoded = envelope(
            vec![
                instance_key.clone(),
                code_key.clone(),
                dependency_key.clone(),
                account_key,
            ],
            vec![target_key.clone()],
        );
        let response = json!({"latestLedger": 101, "entries": [
            entry(instance_key, instance_data), entry(code_key, code_data),
            entry(target_key, target_data), entry(dependency_key, dependency_data), account_entry
        ]});
        (
            encoded,
            CannedRpc {
                response,
                calls: RefCell::new(Vec::new()),
                failure: RefCell::new(None),
            },
        )
    }

    #[test]
    fn captures_target_and_dependency_keys_declared_by_the_envelope() {
        let (envelope, rpc) = fixture();
        let capture = read_invocation_footprint(&rpc, NETWORK, &envelope).unwrap();
        assert_eq!(capture.network_id, NetworkId::from_passphrase(NETWORK));
        assert_eq!(capture.reported_ledger, LedgerSeq(101));
        assert_eq!(capture.validated_wasm_instances, 1);
        assert_eq!(capture.entries.len(), 5);
        assert_eq!(capture.read_only_keys.len(), 4);
        assert_eq!(capture.read_write_keys.len(), 1);
        assert_eq!(
            capture
                .entries
                .values()
                .filter(|entry| entry.live_until_ledger.is_none())
                .count(),
            1
        );
        assert_eq!(*rpc.calls.borrow(), ["getNetwork", "getLedgerEntries"]);
    }

    #[test]
    fn refuses_incomplete_or_changed_declared_state() {
        let (envelope, mut rpc) = fixture();
        rpc.response["entries"].as_array_mut().unwrap().pop();
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &envelope),
            Err(FootprintCaptureError::MissingDeclaredKey { .. })
        ));

        let (envelope, mut rpc) = fixture();
        rpc.response["entries"][1]["xdr"] =
            json!(LedgerEntryData::ContractCode(ContractCodeEntry {
                ext: ContractCodeEntryExt::V0,
                hash: Hash(Sha256::digest(WASM).into()),
                code: b"\0asm\x01\0\0\0changed".as_slice().try_into().unwrap(),
            })
            .to_xdr_base64(xdr_limits())
            .unwrap());
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &envelope),
            Err(FootprintCaptureError::CodeHashMismatch)
        ));

        let (envelope, mut rpc) = fixture();
        rpc.response["entries"][3]["liveUntilLedgerSeq"] = json!(100);
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &envelope),
            Err(FootprintCaptureError::ArchivedDeclaredKey { .. })
        ));

        let (envelope, mut rpc) = fixture();
        rpc.response["entries"][3]
            .as_object_mut()
            .unwrap()
            .remove("liveUntilLedgerSeq");
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &envelope),
            Err(FootprintCaptureError::Rpc(RpcError::Malformed(message))) if message.contains("lacks contract TTL")
        ));

        let (envelope, mut rpc) = fixture();
        let undeclared = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([9; 32]))),
            key: ScVal::U32(77),
            durability: ContractDataDurability::Persistent,
        });
        let mut extra = rpc.response["entries"][3].clone();
        extra["key"] = json!(undeclared.to_xdr_base64(xdr_limits()).unwrap());
        rpc.response["entries"].as_array_mut().unwrap().push(extra);
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &envelope),
            Err(FootprintCaptureError::Rpc(RpcError::Malformed(message))) if message.contains("undeclared key")
        ));
    }

    #[test]
    fn endpoint_errors_cannot_echo_declared_keys() {
        let (envelope, rpc) = fixture();
        let key = rpc.response["entries"][0]["key"]
            .as_str()
            .unwrap()
            .to_string();
        *rpc.failure.borrow_mut() = Some(RpcError::Transport(format!(
            "HTTP body echoed confidential key {key}"
        )));
        let error = read_invocation_footprint(&rpc, NETWORK, &envelope).unwrap_err();
        assert!(matches!(
            &error,
            FootprintCaptureError::Rpc(RpcError::Transport(_))
        ));
        assert!(!error.to_string().contains(&key));
        assert!(!error.to_string().contains("HTTP body"));

        *rpc.failure.borrow_mut() = Some(RpcError::Rpc(format!(
            "JSON-RPC error echoed confidential key {key}"
        )));
        let error = read_invocation_footprint(&rpc, NETWORK, &envelope).unwrap_err();
        assert!(matches!(
            &error,
            FootprintCaptureError::Rpc(RpcError::Rpc(_))
        ));
        assert!(!error.to_string().contains(&key));
        assert!(!error.to_string().contains("JSON-RPC error"));
    }

    #[test]
    fn rejects_duplicate_and_missing_code_footprints_before_claiming_capture() {
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
            key: ScVal::U32(1),
            durability: ContractDataDurability::Persistent,
        });
        let duplicate = envelope(vec![key.clone()], vec![key]);
        let (_, rpc) = fixture();
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &duplicate),
            Err(FootprintCaptureError::InvalidFootprint(_))
        ));
        assert!(rpc.calls.borrow().is_empty());

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
            key: ScVal::U32(1),
            durability: ContractDataDurability::Persistent,
        });
        let oversized = envelope(vec![key; MAX_LEDGER_ENTRY_KEYS + 1], vec![]);
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &oversized),
            Err(FootprintCaptureError::InvalidFootprint(_))
        ));
        assert!(rpc.calls.borrow().is_empty());

        let (encoded, rpc) = fixture();
        let mut parsed = TransactionEnvelope::from_xdr_base64(&encoded, xdr_limits()).unwrap();
        let TransactionEnvelope::Tx(v1) = &mut parsed else {
            panic!("ordinary transaction")
        };
        let TransactionExt::V1(data) = &mut v1.tx.ext else {
            panic!("SorobanData")
        };
        let only_instance = data.resources.footprint.read_only[0].clone();
        data.resources.footprint.read_only = VecM::try_from(vec![only_instance]).unwrap();
        data.resources.footprint.read_write = VecM::try_from(vec![]).unwrap();
        let encoded = parsed.to_xdr_base64(xdr_limits()).unwrap();
        let mut rpc = rpc;
        rpc.response["entries"] = json!([rpc.response["entries"][0].clone()]);
        assert!(matches!(
            read_invocation_footprint(&rpc, NETWORK, &encoded),
            Err(FootprintCaptureError::MissingCodeKey)
        ));
    }
}
