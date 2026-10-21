//! Bounded selected-rule capture. Observations are endpoint-reported, not inclusion proofs.

use super::{
    decode_account_storage, verify_network, xdr_limits, AccountStorageEntry, RpcError,
    RpcTransport, SignerIdentity, MAX_LEDGER_ENTRY_KEYS, MAX_SUPPORTED_PROTOCOL,
    MAX_XDR_BASE64_BYTES,
};
use ozpb_domain::{sha256, Hash32, NetworkId};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{
    AccountId, ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData,
    LedgerHeader, LedgerKey, LedgerKeyAccount, LedgerKeyContractCode, LedgerKeyContractData,
    PublicKey, ReadXdr, ScAddress, ScVal, Uint256, Validate, WriteXdr,
};

const MAX_TOTAL_XDR_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct CapturedPolicyEntry {
    pub data: LedgerEntryData,
    pub last_modified_ledger: u32,
    /// Classic Account entries have no TTL.
    pub live_until_ledger: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct PolicyStateCapture {
    pub network_id: NetworkId,
    pub account_address: String,
    pub installed_context_rule_id: u32,
    pub observed_ledger: u32,
    pub ledger_hash: Hash32,
    /// Every requested key, including explicit endpoint omission.
    pub entries: BTreeMap<LedgerKey, Option<CapturedPolicyEntry>>,
}

/// Operator-side acquisition only. Additional keys are derived by the validated toolkit
/// plan; no public tool accepts caller-supplied ledger observations.
pub fn capture_policy_state<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    installed_context_rule_id: u32,
    contract_addresses: &[String],
    additional_keys: &[LedgerKey],
) -> Result<PolicyStateCapture, RpcError> {
    let account = contract_address(account_address)?;
    if contract_addresses.len() > 64 || additional_keys.len() > 64 {
        return Err(invalid("initial key budget exceeded"));
    }
    let mut initial = BTreeSet::from([
        data_key(account.clone(), ScVal::LedgerKeyContractInstance),
        account_key(&account, "ContextRuleData", installed_context_rule_id)?,
    ]);
    for address in contract_addresses {
        initial.insert(data_key(
            contract_address(address)?,
            ScVal::LedgerKeyContractInstance,
        ));
    }
    for key in additional_keys {
        let LedgerKey::ContractData(data) = key else {
            return Err(invalid("additional key is not persistent contract data"));
        };
        if data.durability != ContractDataDurability::Persistent
            || !matches!(data.contract, ScAddress::Contract(_))
            || key
                .to_xdr(xdr_limits())
                .map_err(|_| invalid("invalid key"))?
                .len()
                > 16 * 1024
        {
            return Err(invalid("invalid additional contract-data key"));
        }
        initial.insert(key.clone());
    }
    check_key_budget(&initial)?;
    verify_network(transport, network_passphrase).map_err(redacted)?;
    // Discovery values only determine a bounded key set. Every final value is reacquired.
    for _ in 0..2 {
        let mut keys = initial.clone();
        for _ in 0..5 {
            let (_, entries) = read_entries(transport, &keys)?;
            let expanded = closure(&initial, &entries, &account)?;
            if expanded == keys {
                break;
            }
            keys = expanded;
        }
        let before = header(transport)?;
        let (ledger, entries) = read_entries(transport, &keys)?;
        let after = header(transport)?;
        if before != after || ledger != before.sequence {
            continue;
        }
        if closure(&initial, &entries, &account)? != keys {
            continue;
        }
        return Ok(PolicyStateCapture {
            network_id: NetworkId::from_passphrase(network_passphrase),
            account_address: account_address.into(),
            installed_context_rule_id,
            observed_ledger: ledger,
            ledger_hash: before.hash,
            entries,
        });
    }
    Err(malformed(
        "ledger anchor or selected-rule closure changed; retry",
    ))
}

fn contract_address(address: &str) -> Result<ScAddress, RpcError> {
    let parsed = address
        .parse::<stellar_strkey::Contract>()
        .map_err(|_| invalid("invalid C-address"))?;
    if parsed.to_string() != address {
        return Err(invalid("noncanonical C-address"));
    }
    Ok(ScAddress::Contract(ContractId(Hash(parsed.0))))
}

fn data_key(contract: ScAddress, key: ScVal) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract,
        key,
        durability: ContractDataDurability::Persistent,
    })
}

fn account_key(contract: &ScAddress, name: &str, id: u32) -> Result<LedgerKey, RpcError> {
    let tag = ScVal::Symbol(name.try_into().map_err(|_| invalid("storage tag"))?);
    Ok(data_key(
        contract.clone(),
        ScVal::Vec(Some(
            vec![tag, ScVal::U32(id)]
                .try_into()
                .map_err(|_| invalid("storage key"))?,
        )),
    ))
}

fn closure(
    initial: &BTreeSet<LedgerKey>,
    entries: &BTreeMap<LedgerKey, Option<CapturedPolicyEntry>>,
    account: &ScAddress,
) -> Result<BTreeSet<LedgerKey>, RpcError> {
    let mut keys = initial.clone();
    for (key, entry) in entries {
        let Some(entry) = entry else { continue };
        let LedgerEntryData::ContractData(data) = &entry.data else {
            continue;
        };
        if data.key == ScVal::LedgerKeyContractInstance {
            match &data.val {
                ScVal::ContractInstance(instance) => {
                    if let ContractExecutable::Wasm(hash) = &instance.executable {
                        keys.insert(LedgerKey::ContractCode(LedgerKeyContractCode {
                            hash: hash.clone(),
                        }));
                    }
                }
                _ => return Err(malformed("instance key has a non-instance value")),
            }
        }
        if &data.contract != account || data.key == ScVal::LedgerKeyContractInstance {
            continue;
        }
        let LedgerKey::ContractData(key) = key else {
            return Err(malformed("contract data key"));
        };
        match decode_account_storage(key, &data.val)
            .map_err(|_| malformed("account storage shape"))?
        {
            AccountStorageEntry::ContextRule(rule) => {
                for id in rule.signer_ids {
                    keys.insert(account_key(account, "SignerData", id)?);
                }
                for id in rule.policy_ids {
                    keys.insert(account_key(account, "PolicyData", id)?);
                }
            }
            AccountStorageEntry::Signer(signer) => match signer.signer {
                SignerIdentity::Delegated(address) => {
                    if let Ok(key) = address.parse::<stellar_strkey::ed25519::PublicKey>() {
                        keys.insert(LedgerKey::Account(LedgerKeyAccount {
                            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))),
                        }));
                    }
                    // Delegated C-address authentication is unsupported by the finisher.
                }
                SignerIdentity::External { verifier, .. } => {
                    keys.insert(data_key(
                        contract_address(&verifier)?,
                        ScVal::LedgerKeyContractInstance,
                    ));
                }
            },
            AccountStorageEntry::Policy(policy) => {
                keys.insert(data_key(
                    contract_address(&policy.address)?,
                    ScVal::LedgerKeyContractInstance,
                ));
            }
            AccountStorageEntry::Instance(_) => {}
        }
    }
    // Preserve keys needed to decode the entries that discovered their own dependencies.
    // A subsequent final read rederives the exact selected-rule closure from scratch.
    let selected = keys.clone();
    for key in selected {
        if let Some(Some(entry)) = entries.get(&key) {
            if let LedgerEntryData::ContractData(data) = &entry.data {
                if let ScVal::ContractInstance(instance) = &data.val {
                    if let ContractExecutable::Wasm(hash) = &instance.executable {
                        keys.insert(LedgerKey::ContractCode(LedgerKeyContractCode {
                            hash: hash.clone(),
                        }));
                    }
                }
            }
        }
    }
    check_key_budget(&keys)?;
    Ok(keys)
}

fn check_key_budget(keys: &BTreeSet<LedgerKey>) -> Result<(), RpcError> {
    if keys.len() > MAX_LEDGER_ENTRY_KEYS {
        return Err(invalid("final key set exceeds 200 entries"));
    }
    Ok(())
}

fn read_entries<T: RpcTransport>(
    transport: &T,
    keys: &BTreeSet<LedgerKey>,
) -> Result<(u32, BTreeMap<LedgerKey, Option<CapturedPolicyEntry>>), RpcError> {
    check_key_budget(keys)?;
    let encoded = keys
        .iter()
        .map(|key| {
            key.to_xdr_base64(xdr_limits())
                .map_err(|_| invalid("cannot encode key"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if encoded.iter().map(String::len).sum::<usize>() > 256 * 1024 {
        return Err(invalid("key byte budget exceeded"));
    }
    let response = transport
        .call(
            "getLedgerEntries",
            json!({"keys":encoded,"xdrFormat":"base64"}),
        )
        .map_err(redacted)?;
    let ledger = u32_field(&response, "latestLedger")?;
    if ledger == 0 {
        return Err(malformed("zero ledger"));
    }
    let values = response["entries"]
        .as_array()
        .ok_or_else(|| malformed("missing entries array"))?;
    if values.len() > keys.len() {
        return Err(malformed("too many entries"));
    }
    let mut entries: BTreeMap<_, _> = keys.iter().cloned().map(|key| (key, None)).collect();
    let mut total = 0usize;
    for value in values {
        let key_text = bounded_xdr(value, "key")?;
        let key = LedgerKey::from_xdr_base64(key_text, xdr_limits())
            .map_err(|_| malformed("invalid key XDR"))?;
        if key
            .to_xdr_base64(xdr_limits())
            .map_err(|_| malformed("key XDR"))?
            != key_text
        {
            return Err(malformed("noncanonical key XDR"));
        }
        let slot = entries
            .get_mut(&key)
            .ok_or_else(|| malformed("unrequested key"))?;
        if slot.is_some() {
            return Err(malformed("duplicate key"));
        }
        let data_text = bounded_xdr(value, "xdr")?;
        total = total
            .saturating_add(data_text.len())
            .saturating_add(key_text.len());
        if total > MAX_TOTAL_XDR_BYTES {
            return Err(malformed("entry byte budget exceeded"));
        }
        let data = LedgerEntryData::from_xdr_base64(data_text, xdr_limits())
            .map_err(|_| malformed("invalid value XDR"))?;
        if let LedgerEntryData::ContractData(data) = &data {
            data.key
                .validate()
                .map_err(|_| malformed("invalid contract key"))?;
            data.val
                .validate()
                .map_err(|_| malformed("invalid entry value"))?;
        }
        if data.to_key() != key
            || data
                .to_xdr_base64(xdr_limits())
                .map_err(|_| malformed("value XDR"))?
                != data_text
        {
            return Err(malformed("value identity or canonical XDR mismatch"));
        }
        let last_modified_ledger = u32_field(value, "lastModifiedLedgerSeq")?;
        if last_modified_ledger > ledger {
            return Err(malformed("future modification ledger"));
        }
        let live_until_ledger = match &data {
            LedgerEntryData::Account(_) => None,
            LedgerEntryData::ContractData(_) => Some(u32_field(value, "liveUntilLedgerSeq")?),
            LedgerEntryData::ContractCode(code) => {
                if sha256(code.code.as_slice()).0 != code.hash.0 {
                    return Err(malformed("code hash mismatch"));
                }
                Some(u32_field(value, "liveUntilLedgerSeq")?)
            }
            _ => return Err(malformed("unsupported ledger entry type")),
        };
        *slot = Some(CapturedPolicyEntry {
            data,
            last_modified_ledger,
            live_until_ledger,
        });
    }
    Ok((ledger, entries))
}

#[derive(PartialEq, Eq)]
struct Header {
    sequence: u32,
    hash: Hash32,
    protocol: u32,
}
fn header<T: RpcTransport>(transport: &T) -> Result<Header, RpcError> {
    let response = transport
        .call("getLatestLedger", json!({}))
        .map_err(redacted)?;
    let sequence = u32_field(&response, "sequence")?;
    let protocol = u32_field(&response, "protocolVersion")?;
    let text = response["id"]
        .as_str()
        .ok_or_else(|| malformed("missing ledger hash"))?;
    let hash = Hash32::from_hex(text).map_err(|_| malformed("invalid ledger hash"))?;
    if text != hash.to_hex() || sequence == 0 || !(1..=MAX_SUPPORTED_PROTOCOL).contains(&protocol) {
        return Err(malformed("unsupported or invalid ledger header"));
    }
    if response.get("headerXdr").is_some() {
        let raw = bounded_xdr(&response, "headerXdr")?;
        let decoded = LedgerHeader::from_xdr_base64(raw, xdr_limits())
            .map_err(|_| malformed("invalid header XDR"))?;
        let bytes = decoded
            .to_xdr(xdr_limits())
            .map_err(|_| malformed("header XDR"))?;
        if sha256(&bytes) != hash
            || decoded.ledger_seq != sequence
            || decoded.ledger_version != protocol
        {
            return Err(malformed(
                "header XDR disagrees with reported hash/sequence/protocol",
            ));
        }
    }
    Ok(Header {
        sequence,
        hash,
        protocol,
    })
}
fn bounded_xdr<'a>(value: &'a Value, field: &str) -> Result<&'a str, RpcError> {
    let text = value[field]
        .as_str()
        .ok_or_else(|| malformed("missing XDR field"))?;
    if text.len() > MAX_XDR_BASE64_BYTES {
        return Err(malformed("XDR size limit"));
    }
    Ok(text)
}
fn u32_field(value: &Value, field: &str) -> Result<u32, RpcError> {
    value[field]
        .as_u64()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| malformed("invalid ledger integer"))
}
fn malformed(message: &str) -> RpcError {
    RpcError::Malformed(format!("policy state: {message}"))
}
fn invalid(message: &str) -> RpcError {
    RpcError::InvalidRequest(format!("policy state: {message}"))
}
fn redacted(_: RpcError) -> RpcError {
    RpcError::Transport("policy state RPC request failed; details withheld".into())
}

#[cfg(test)]
mod tests;
