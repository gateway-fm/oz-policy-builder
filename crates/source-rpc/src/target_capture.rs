//! Read-only acquisition of one native Stellar Asset Contract transfer's target state.
//!
//! Record-mode simulation discovers the target's authorization root and footprint. That is
//! acquisition only: recording mode records the authorization a call needs instead of
//! enforcing it, so a successful simulation is never evidence that a policy permits the call.
//! The footprint is then re-read in one bounded `getLedgerEntries` batch together with the
//! network's state-archival configuration, and the exact ledger header comes from `getLedgers`.
//! Every value is endpoint-reported (`rpc_reported`); none of it is an inclusion proof.

use crate::{
    envelope_carries_signatures, read_invocation_footprint, validate_simulation_envelope,
    verify_network, xdr_limits, CapturedFootprintEntry, RpcError, RpcTransport,
    MAX_XDR_BASE64_BYTES,
};
use ozpb_domain::{sha256, NetworkId, TargetCapture, TargetEntry};
use serde_json::{json, Value};
use stellar_xdr::{
    Asset, ConfigSettingEntry, ConfigSettingId, ContractDataDurability, ContractExecutable,
    ContractId, ContractIdPreimage, Hash, HashIdPreimage, HashIdPreimageContractId, HostFunction,
    LedgerEntryData, LedgerHeaderHistoryEntry, LedgerKey, LedgerKeyConfigSetting,
    LedgerKeyContractCode, LedgerKeyContractData, OperationBody, ReadXdr, ScAddress, ScNonceKey,
    ScVal, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanCredentials,
    SorobanTransactionData, TransactionEnvelope, TransactionExt, WriteXdr,
};

/// The only source protocol whose captured state the execution runtime reproduces.
const CAPTURE_PROTOCOL: u32 = 29;
/// Simulation and the entry read may observe different ledgers; retry once, then give up.
const CAPTURE_ATTEMPTS: usize = 2;
/// Bound on the captured entry payload carried into an execution job.
const MAX_CAPTURED_ENTRY_BYTES: usize = 2 * 1024 * 1024;

fn refuse(reason: &str) -> RpcError {
    RpcError::Malformed(format!("native target capture refused: {reason}"))
}

/// Decode canonical base64 XDR, refusing any encoding that does not round-trip byte for byte.
fn decode<T: ReadXdr + WriteXdr>(encoded: &str, what: &str) -> Result<T, RpcError> {
    if encoded.len() > MAX_XDR_BASE64_BYTES {
        return Err(refuse(&format!("{what} exceeds the XDR size bound")));
    }
    let value = T::from_xdr_base64(encoded, xdr_limits())
        .map_err(|_| refuse(&format!("{what} is not valid XDR")))?;
    if encode(&value, what)? != encoded {
        return Err(refuse(&format!("{what} is not canonical XDR")));
    }
    Ok(value)
}

fn encode<T: WriteXdr>(value: &T, what: &str) -> Result<String, RpcError> {
    value
        .to_xdr_base64(xdr_limits())
        .map_err(|_| refuse(&format!("cannot encode {what}")))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, RpcError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| refuse(&format!("response lacks string {field}")))
}

fn ledger(value: &Value, field: &str) -> Result<u32, RpcError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| refuse(&format!("response lacks positive u32 {field}")))
}

/// The native asset's contract address on `network`.
pub fn native_asset_contract(network: &NetworkId) -> Result<ScAddress, RpcError> {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network.0 .0),
        contract_id_preimage: ContractIdPreimage::Asset(Asset::Native),
    });
    let bytes = preimage
        .to_xdr(xdr_limits())
        .map_err(|_| refuse("cannot encode the native asset contract preimage"))?;
    Ok(ScAddress::Contract(ContractId(Hash(sha256(&bytes).0))))
}

fn target_entry(entry: &CapturedFootprintEntry) -> Result<TargetEntry, RpcError> {
    Ok(TargetEntry {
        key_xdr: encode(&entry.key, "captured key")?,
        data_xdr: encode(&entry.data, "captured entry")?,
        last_modified_ledger: entry.last_modified_ledger.0,
        live_until_ledger: entry.live_until_ledger.map(|v| v.0),
    })
}

/// Acquire the target state of one native SAC `transfer(C-account, existing G, amount)`.
///
/// The envelope must be unsigned, carry no authorization entries, and call the source network's
/// native asset contract. Simulation must report exactly one authorization root, for the account,
/// equal to the call itself with no sub-invocations; a restoration preamble is refused rather
/// than performed. Every footprint key and the state-archival configuration are read at the
/// simulation's ledger, and that ledger's header must hash to the reported hash. No signature
/// is accepted or created and nothing is submitted. The caller binds the returned invocation to
/// its independently prepared candidate; this function does not know the candidate.
///
/// Record-mode footprints also name the account's own instance, its code and the recorded
/// authorization's fresh nonce. The nonce key is new by construction and is not read; instance
/// and code are read only to bind the account's executable hash. None of them become target
/// entries, and a footprint touching any other account storage is refused.
pub fn capture_native_target<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    envelope_xdr_base64: &str,
) -> Result<TargetCapture, RpcError> {
    let envelope = validate_simulation_envelope(envelope_xdr_base64)?;
    if encode(&envelope, "envelope")? != envelope_xdr_base64 {
        return Err(refuse("the envelope is not canonical XDR"));
    }
    if envelope_carries_signatures(envelope_xdr_base64)? {
        return Err(refuse("the envelope carries signatures"));
    }
    let TransactionEnvelope::Tx(v1) = &envelope else {
        return Err(refuse("only an unwrapped v1 transaction is supported"));
    };
    let OperationBody::InvokeHostFunction(operation) = &v1.tx.operations[0].body else {
        return Err(refuse("the operation is not InvokeHostFunction"));
    };
    if !operation.auth.is_empty() {
        return Err(refuse("the envelope already carries authorization entries"));
    }
    let HostFunction::InvokeContract(call) = &operation.host_function else {
        return Err(refuse("the host function is not InvokeContract"));
    };
    let network = NetworkId::from_passphrase(network_passphrase);
    let [ScVal::Address(account @ ScAddress::Contract(_)), ScVal::Address(ScAddress::Account(_)), ScVal::I128(amount)] =
        call.args.as_slice()
    else {
        return Err(refuse(
            "only transfer(contract account, G recipient, i128) is supported",
        ));
    };
    let amount = i128::from(amount);
    if call.contract_address != native_asset_contract(&network)?
        || call.function_name.as_slice() != b"transfer"
        || amount <= 0
        || amount >= i128::from(i64::MAX)
    {
        return Err(refuse(
            "only a positive native-asset transfer below i64::MAX is supported",
        ));
    }
    let config_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let encoded_config_key = encode(&config_key, "state-archival key")?;
    verify_network(transport, network_passphrase)?;
    for _ in 0..CAPTURE_ATTEMPTS {
        let simulation = transport.call(
            "simulateTransaction",
            json!({
                "transaction": envelope_xdr_base64,
                "authMode": "record",
                "xdrFormat": "base64",
            }),
        )?;
        if simulation.get("error").is_some() {
            return Err(refuse("record-mode simulation failed"));
        }
        if simulation.get("restorePreamble").is_some() {
            return Err(refuse("the target footprint requires restoration"));
        }
        let observed = ledger(&simulation, "latestLedger")?;
        let [result] = simulation
            .get("results")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| refuse("simulation lacks results"))?
        else {
            return Err(refuse("simulation must report exactly one result"));
        };
        if decode::<ScVal>(text(result, "xdr")?, "simulation result")? != ScVal::Void {
            return Err(refuse("transfer simulation did not return void"));
        }
        let [recorded] = result
            .get("auth")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| refuse("simulation lacks recorded authorization"))?
        else {
            return Err(refuse(
                "exactly one recorded authorization root is supported",
            ));
        };
        let recording_auth_xdr = recorded
            .as_str()
            .ok_or_else(|| refuse("recorded authorization is not a string"))?;
        let recorded: SorobanAuthorizationEntry =
            decode(recording_auth_xdr, "recorded authorization")?;
        let (address, nonce) = match &recorded.credentials {
            SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => {
                (&c.address, c.nonce)
            }
            _ => return Err(refuse("recorded authorization is not address-bound")),
        };
        if address != account
            || recorded.root_invocation.function
                != SorobanAuthorizedFunction::ContractFn(call.clone())
            || !recorded.root_invocation.sub_invocations.is_empty()
        {
            return Err(refuse(
                "the recorded authorization root is not exactly the account's transfer",
            ));
        }
        let mut resources: SorobanTransactionData =
            decode(text(&simulation, "transactionData")?, "transaction data")?;
        let footprint = &mut resources.resources.footprint;
        if footprint
            .read_only
            .iter()
            .chain(footprint.read_write.iter())
            .any(|key| key == &config_key)
        {
            return Err(refuse(
                "the target footprint already names network configuration",
            ));
        }
        let mut read_only = footprint.read_only.to_vec();
        read_only.push(config_key.clone());
        footprint.read_only = read_only
            .try_into()
            .map_err(|_| refuse("footprint too large"))?;
        // The recorded authorization's nonce is a fresh temporary key: absent by construction,
        // and replaced by the execution's own nonce. It is the only key not read back.
        let nonce_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: account.clone(),
            key: ScVal::LedgerKeyNonce(ScNonceKey { nonce }),
            durability: ContractDataDurability::Temporary,
        });
        footprint.read_write = footprint
            .read_write
            .iter()
            .filter(|key| **key != nonce_key)
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| refuse("footprint too large"))?;
        let mut acquisition = envelope.clone();
        let TransactionEnvelope::Tx(acquisition_v1) = &mut acquisition else {
            unreachable!("checked above");
        };
        acquisition_v1.tx.ext = TransactionExt::V1(resources);
        let mut capture = read_invocation_footprint(
            transport,
            network_passphrase,
            &encode(&acquisition, "acquisition envelope")?,
        )
        .map_err(|error| refuse(&error.to_string()))?;
        if capture.reported_ledger.0 != observed {
            continue;
        }
        // A submission based on this capture lands at L + 1 or later; an entry living only
        // until L would be archived by then.
        if capture
            .entries
            .values()
            .any(|entry| entry.live_until_ledger.is_some_and(|ttl| ttl.0 <= observed))
        {
            return Err(refuse("a footprint entry expires at the captured ledger"));
        }
        let headers = transport.call(
            "getLedgers",
            json!({
                "startLedger": observed,
                "pagination": { "limit": 1 },
                "xdrFormat": "base64",
            }),
        )?;
        let [returned] = headers
            .get("ledgers")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| refuse("getLedgers lacks ledgers"))?
        else {
            return Err(refuse("getLedgers must return exactly the captured ledger"));
        };
        let header_xdr = text(returned, "headerXdr")?;
        let header: LedgerHeaderHistoryEntry = decode(header_xdr, "ledger header")?;
        let header_hash = sha256(
            &header
                .header
                .to_xdr(xdr_limits())
                .map_err(|_| refuse("cannot encode the ledger header"))?,
        );
        if header.hash.0 != header_hash.0
            || text(returned, "hash")? != header_hash.to_hex()
            || header.header.ledger_seq != observed
            || ledger(returned, "sequence")? != observed
            || header.header.ledger_version != CAPTURE_PROTOCOL
            || text(returned, "ledgerCloseTime")?
                != header.header.scp_value.close_time.0.to_string()
        {
            return Err(refuse(
                "the ledger header does not hash to, or describe, the captured ledger",
            ));
        }
        let config = capture
            .entries
            .remove(&encoded_config_key)
            .ok_or_else(|| refuse("state-archival configuration was not returned"))?;
        capture.read_only_keys.remove(&encoded_config_key);
        let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) =
            &config.data
        else {
            return Err(refuse("state-archival key returned other data"));
        };
        if settings.min_temporary_ttl == 0
            || settings.min_persistent_ttl == 0
            || settings.max_entry_ttl < settings.min_temporary_ttl
            || settings.max_entry_ttl < settings.min_persistent_ttl
            || config.live_until_ledger.is_some()
        {
            return Err(refuse("state-archival configuration is inconsistent"));
        }
        // Partition the account's own instance and code out of the target state.
        let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: account.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let encoded_instance_key = encode(&instance_key, "account instance key")?;
        let instance = capture
            .entries
            .remove(&encoded_instance_key)
            .ok_or_else(|| refuse("the account instance was not in the footprint"))?;
        capture.read_only_keys.remove(&encoded_instance_key);
        let LedgerEntryData::ContractData(instance) = &instance.data else {
            return Err(refuse("the account instance key returned other data"));
        };
        let ScVal::ContractInstance(instance) = &instance.val else {
            return Err(refuse("the account instance holds no instance value"));
        };
        let ContractExecutable::Wasm(account_code) = &instance.executable else {
            return Err(refuse("the account is not a Wasm contract"));
        };
        let encoded_code_key = encode(
            &LedgerKey::ContractCode(LedgerKeyContractCode {
                hash: account_code.clone(),
            }),
            "account code key",
        )?;
        if capture.entries.remove(&encoded_code_key).is_none() {
            return Err(refuse("the account code was not in the footprint"));
        }
        capture.read_only_keys.remove(&encoded_code_key);
        if capture.entries.values().any(|entry| {
            matches!(&entry.key, LedgerKey::ContractData(data) if data.contract == *account)
        }) {
            return Err(refuse("the target reads account storage"));
        }
        let entries = capture
            .entries
            .values()
            .map(target_entry)
            .collect::<Result<Vec<_>, _>>()?;
        if entries
            .iter()
            .map(|v| v.key_xdr.len() + v.data_xdr.len())
            .sum::<usize>()
            > MAX_CAPTURED_ENTRY_BYTES
        {
            return Err(refuse("captured entries exceed the job size bound"));
        }
        return Ok(TargetCapture {
            schema: 1,
            provenance: "rpc_reported".into(),
            network_id: network.0.to_hex(),
            observed_ledger: observed,
            header_xdr: header_xdr.into(),
            state_archival: target_entry(&config)?,
            invocation_xdr: encode(call, "invocation")?,
            recording_auth_xdr: recording_auth_xdr.into(),
            account_code_hash: hex::encode(account_code.0),
            read_only_keys: capture.read_only_keys.into_iter().collect(),
            read_write_keys: capture.read_write_keys.into_iter().collect(),
            entries,
        });
    }
    Err(refuse(
        "simulation and entry reads kept observing different ledgers",
    ))
}

#[cfg(test)]
mod tests;
