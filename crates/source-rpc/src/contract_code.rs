//! Exact contract code observations for a bounded set of contract instances.
//!
//! This is a prerequisite for an account authority scanner, not a rule-state snapshot. RPC's
//! `latestLedger` is the latest sequence known when it handled the request; its documented
//! response does not prove that every returned entry belongs to one coherent ledger state.
//! In particular, this value cannot be used to construct a trusted `AccountState` or a Safe
//! authority verdict without a separate snapshot and rule-enumeration protocol.

use super::{
    parse_contract_executables, verify_network, xdr_limits, ObservedExecutable, RpcError,
    RpcTransport, MAX_LEDGER_ENTRY_KEYS,
};
use ozpb_domain::{Hash32, LedgerSeq, NetworkId};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{
    ContractDataDurability, ContractId, Hash, LedgerKey, LedgerKeyContractData, ScAddress, ScVal,
    WriteXdr,
};

/// Wasm code identities returned in one checked `getLedgerEntries` response.
/// `reported_latest_ledger` is RPC metadata, not a coherent-snapshot attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractCodeRead {
    pub network_id: NetworkId,
    pub reported_latest_ledger: LedgerSeq,
    pub wasm_hashes: BTreeMap<String, Hash32>,
}

/// Read the current instance code for at most one RPC request's worth of C-addresses.
///
/// A successful read establishes that the configured endpoint returned a complete, exact set
/// of well-formed contract instances with Wasm executables. It does not establish account
/// rule completeness, a coherent cross-entry snapshot, or code identity at signing time. The
/// endpoint is the trust boundary; this read verifies no cryptographic ledger proof.
pub fn read_contract_wasm_hashes<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    addresses: &[String],
) -> Result<ContractCodeRead, RpcError> {
    if addresses.is_empty() || addresses.len() > MAX_LEDGER_ENTRY_KEYS {
        return Err(RpcError::CodeRead(format!(
            "contract code read requires 1..={MAX_LEDGER_ENTRY_KEYS} unique addresses"
        )));
    }

    let mut requested = BTreeMap::new();
    let mut seen_contracts = BTreeSet::new();
    for address in addresses {
        let contract = address
            .parse::<stellar_strkey::Contract>()
            .map_err(|error| {
                RpcError::CodeRead(format!("invalid contract address {address:?}: {error}"))
            })?;
        if !seen_contracts.insert(contract.0) {
            return Err(RpcError::CodeRead(
                "contract code read contains a duplicate contract address".to_string(),
            ));
        }
        let sc_address = ScAddress::Contract(ContractId(Hash(contract.0)));
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_address.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let encoded_key = key
            .to_xdr_base64(xdr_limits())
            .map_err(|error| RpcError::CodeRead(error.to_string()))?;
        requested.insert(encoded_key, (address.clone(), sc_address));
    }

    verify_network(transport, network_passphrase)?;
    let keys: Vec<&String> = requested.keys().collect();
    let result = transport.call(
        "getLedgerEntries",
        json!({ "keys": keys, "xdrFormat": "base64" }),
    )?;
    let reported_latest_ledger: u32 = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed("getLedgerEntries has no integer latestLedger".to_string())
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed("latestLedger exceeds u32".to_string()))?;
    if reported_latest_ledger == 0 {
        return Err(RpcError::Malformed(
            "getLedgerEntries reported ledger zero for deployed contract instances".to_string(),
        ));
    }
    let observations =
        parse_contract_executables(&result, &requested).map_err(|error| match error {
            RpcError::Evidence(message) => RpcError::CodeRead(message),
            other => other,
        })?;
    // A contract instance is persistent storage. Require its TTL metadata to be present and
    // still live at the reported ledger, instead of silently accepting an archived entry.
    let entries = result["entries"]
        .as_array()
        .ok_or_else(|| RpcError::Malformed("getLedgerEntries has no entries array".to_string()))?;
    for (index, entry) in entries.iter().enumerate() {
        let live_until: u32 = entry
            .get("liveUntilLedgerSeq")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} has no integer liveUntilLedgerSeq"
                ))
            })?
            .try_into()
            .map_err(|_| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} liveUntilLedgerSeq exceeds u32"
                ))
            })?;
        if live_until < reported_latest_ledger {
            return Err(RpcError::CodeRead(format!(
                "getLedgerEntries entry {index} is not live at reported ledger {reported_latest_ledger}"
            )));
        }
    }

    let mut wasm_hashes = BTreeMap::new();
    for (address, observation) in observations {
        let ObservedExecutable::Wasm { code_hash } = observation.executable else {
            return Err(RpcError::CodeRead(format!(
                "contract {address} does not run a Wasm executable"
            )));
        };
        wasm_hashes.insert(address, code_hash);
    }
    Ok(ContractCodeRead {
        network_id: NetworkId::from_passphrase(network_passphrase),
        reported_latest_ledger: LedgerSeq(reported_latest_ledger),
        wasm_hashes,
    })
}
