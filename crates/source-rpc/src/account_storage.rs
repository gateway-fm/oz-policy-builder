//! Pure decoder for the pinned `stellar-accounts` 0.7.2 storage schema.
//!
//! This reads only already-acquired XDR values. It neither finds every rule nor decides
//! whether an omitted ledger entry is archived, so it cannot establish account authority.
//! Unknown keys in the contract-instance map are allowed because other account extensions
//! and the pinned account's own counters share that map. Targeted keys and records are exact.

use std::collections::BTreeSet;
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, LedgerKeyContractData, ScAddress, ScMap, ScVal,
    Validate,
};

const MAX_NAME_BYTES: usize = 20;
const MAX_SIGNERS: usize = 15;
const MAX_POLICIES: usize = 5;
const MAX_EXTERNAL_KEY_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountStorageError {
    #[error("invalid pinned account storage: {0}")]
    Invalid(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StorageKey {
    Instance,
    ContextRuleData(u32),
    SignerData(u32),
    PolicyData(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceCounters {
    /// Both fields are absent before the first rule is added. A later scanner must apply
    /// the release-specific default and must not infer anything from an absent ledger entry.
    pub next_id: Option<u32>,
    pub count: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextType {
    Default,
    CallContract(String),
    CreateContract([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextRuleRecord {
    pub id: u32,
    pub name: String,
    pub context_type: ContextType,
    pub valid_until: Option<u32>,
    pub signer_ids: Vec<u32>,
    pub policy_ids: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerIdentity {
    Delegated(String),
    External { verifier: String, key: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerRecord {
    pub id: u32,
    pub signer: SignerIdentity,
    pub reference_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRecord {
    pub id: u32,
    pub address: String,
    pub reference_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountStorageEntry {
    Instance(InstanceCounters),
    ContextRule(ContextRuleRecord),
    Signer(SignerRecord),
    Policy(PolicyRecord),
}

/// Decode one present, already checked contract-data entry. The ID comes from its ledger
/// key, never from the caller's interpretation of the value. Only persistent entries owned
/// by a contract address are accepted. The result is data, not a completeness or safety claim.
pub fn decode_account_storage(
    key: &LedgerKeyContractData,
    value: &ScVal,
) -> Result<AccountStorageEntry, AccountStorageError> {
    if !matches!(key.contract, ScAddress::Contract(_))
        || key.durability != ContractDataDurability::Persistent
    {
        return Err(AccountStorageError::Invalid("contract and durability"));
    }
    value
        .validate()
        .map_err(|_| AccountStorageError::Invalid("invalid ScVal"))?;
    match parse_key(&key.key)? {
        StorageKey::Instance => decode_instance(value).map(AccountStorageEntry::Instance),
        StorageKey::ContextRuleData(id) => {
            decode_rule(id, value).map(AccountStorageEntry::ContextRule)
        }
        StorageKey::SignerData(id) => decode_signer(id, value).map(AccountStorageEntry::Signer),
        StorageKey::PolicyData(id) => decode_policy(id, value).map(AccountStorageEntry::Policy),
    }
}

fn parse_key(value: &ScVal) -> Result<StorageKey, AccountStorageError> {
    if value == &ScVal::LedgerKeyContractInstance {
        return Ok(StorageKey::Instance);
    }
    let (tag, args) = variant(value)?;
    let id = match args {
        [ScVal::U32(id)] => *id,
        _ => return Err(AccountStorageError::Invalid("storage key ID")),
    };
    match tag {
        "ContextRuleData" => Ok(StorageKey::ContextRuleData(id)),
        "SignerData" => Ok(StorageKey::SignerData(id)),
        "PolicyData" => Ok(StorageKey::PolicyData(id)),
        _ => Err(AccountStorageError::Invalid("unsupported storage key")),
    }
}

fn decode_instance(value: &ScVal) -> Result<InstanceCounters, AccountStorageError> {
    let ScVal::ContractInstance(instance) = value else {
        return Err(AccountStorageError::Invalid("contract instance value"));
    };
    if !matches!(instance.executable, ContractExecutable::Wasm(_)) {
        return Err(AccountStorageError::Invalid(
            "account executable is not Wasm",
        ));
    }
    let mut counters = InstanceCounters {
        next_id: None,
        count: None,
    };
    if let Some(storage) = &instance.storage {
        storage
            .validate()
            .map_err(|_| AccountStorageError::Invalid("contract instance storage map"))?;
        for entry in storage.iter() {
            let (tag, arity) = match &entry.key {
                ScVal::Vec(Some(parts)) => match parts.first() {
                    Some(ScVal::Symbol(tag)) => (tag.as_slice(), parts.len()),
                    _ => continue,
                },
                ScVal::Symbol(tag) => (tag.as_slice(), 0),
                ScVal::String(tag) => (tag.as_slice(), 0),
                _ => continue,
            };
            match tag {
                b"NextId" => {
                    if arity != 1 || counters.next_id.is_some() {
                        return Err(AccountStorageError::Invalid("NextId key"));
                    }
                    counters.next_id = Some(u32_value(&entry.val, "NextId value")?);
                }
                b"Count" => {
                    if arity != 1 || counters.count.is_some() {
                        return Err(AccountStorageError::Invalid("Count key"));
                    }
                    counters.count = Some(u32_value(&entry.val, "Count value")?);
                }
                _ => {}
            }
        }
    }
    if counters.next_id.is_some() != counters.count.is_some() {
        return Err(AccountStorageError::Invalid(
            "NextId and Count must appear together",
        ));
    }
    if let (Some(next_id), Some(count)) = (counters.next_id, counters.count) {
        if count > next_id {
            return Err(AccountStorageError::Invalid("Count exceeds NextId"));
        }
    }
    Ok(counters)
}

fn decode_rule(id: u32, value: &ScVal) -> Result<ContextRuleRecord, AccountStorageError> {
    let map = exact_map(value, 5, "ContextRuleEntry")?;
    let name = match field(map, b"name")? {
        ScVal::String(s) => std::str::from_utf8(s.as_slice())
            .map_err(|_| AccountStorageError::Invalid("name UTF-8"))?
            .to_string(),
        _ => return Err(AccountStorageError::Invalid("name value")),
    };
    if name.len() > MAX_NAME_BYTES {
        return Err(AccountStorageError::Invalid("name length"));
    }
    let context_type = decode_context_type(field(map, b"context_type")?)?;
    let valid_until = match field(map, b"valid_until")? {
        ScVal::Void => None,
        ScVal::U32(n) => Some(*n),
        _ => return Err(AccountStorageError::Invalid("valid_until value")),
    };
    let signer_ids = ids(field(map, b"signer_ids")?, MAX_SIGNERS, "signer_ids")?;
    let policy_ids = ids(field(map, b"policy_ids")?, MAX_POLICIES, "policy_ids")?;
    if signer_ids.is_empty() && policy_ids.is_empty() {
        return Err(AccountStorageError::Invalid(
            "rule has no signers or policies",
        ));
    }
    Ok(ContextRuleRecord {
        id,
        name,
        context_type,
        valid_until,
        signer_ids,
        policy_ids,
    })
}

fn decode_context_type(value: &ScVal) -> Result<ContextType, AccountStorageError> {
    let (tag, args) = variant(value)?;
    match (tag, args) {
        ("Default", []) => Ok(ContextType::Default),
        ("CallContract", [address]) => Ok(ContextType::CallContract(address_value(address)?)),
        ("CreateContract", [ScVal::Bytes(bytes)]) if bytes.len() == 32 => {
            let hash: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| AccountStorageError::Invalid("CreateContract hash"))?;
            Ok(ContextType::CreateContract(hash))
        }
        _ => Err(AccountStorageError::Invalid("context type")),
    }
}

fn decode_signer(id: u32, value: &ScVal) -> Result<SignerRecord, AccountStorageError> {
    let map = exact_map(value, 2, "SignerEntry")?;
    let reference_count = u32_value(field(map, b"count")?, "signer count")?;
    if reference_count == 0 {
        return Err(AccountStorageError::Invalid("signer count zero"));
    }
    let (tag, args) = variant(field(map, b"signer")?)?;
    let signer = match (tag, args) {
        ("Delegated", [address]) => SignerIdentity::Delegated(address_value(address)?),
        ("External", [address, ScVal::Bytes(bytes)]) if bytes.len() <= MAX_EXTERNAL_KEY_BYTES => {
            SignerIdentity::External {
                verifier: address_value(address)?,
                key: bytes.as_slice().to_vec(),
            }
        }
        _ => return Err(AccountStorageError::Invalid("signer value")),
    };
    Ok(SignerRecord {
        id,
        signer,
        reference_count,
    })
}

fn decode_policy(id: u32, value: &ScVal) -> Result<PolicyRecord, AccountStorageError> {
    let map = exact_map(value, 2, "PolicyEntry")?;
    let reference_count = u32_value(field(map, b"count")?, "policy count")?;
    if reference_count == 0 {
        return Err(AccountStorageError::Invalid("policy count zero"));
    }
    Ok(PolicyRecord {
        id,
        address: address_value(field(map, b"policy")?)?,
        reference_count,
    })
}

fn exact_map<'a>(
    value: &'a ScVal,
    len: usize,
    label: &'static str,
) -> Result<&'a ScMap, AccountStorageError> {
    let ScVal::Map(Some(map)) = value else {
        return Err(AccountStorageError::Invalid(label));
    };
    if map.len() != len {
        return Err(AccountStorageError::Invalid(label));
    }
    map.validate()
        .map_err(|_| AccountStorageError::Invalid(label))?;
    Ok(map)
}

fn field<'a>(map: &'a ScMap, name: &'static [u8]) -> Result<&'a ScVal, AccountStorageError> {
    map.iter()
        .find(|entry| matches!(&entry.key, ScVal::Symbol(symbol) if symbol.as_slice() == name))
        .map(|entry| &entry.val)
        .ok_or(AccountStorageError::Invalid("missing required field"))
}

fn variant(value: &ScVal) -> Result<(&str, &[ScVal]), AccountStorageError> {
    let ScVal::Vec(Some(values)) = value else {
        return Err(AccountStorageError::Invalid("enum vector"));
    };
    let Some(ScVal::Symbol(tag)) = values.first() else {
        return Err(AccountStorageError::Invalid("enum tag"));
    };
    let name = std::str::from_utf8(tag.as_slice())
        .map_err(|_| AccountStorageError::Invalid("enum tag UTF-8"))?;
    Ok((name, &values.as_slice()[1..]))
}

fn ids(value: &ScVal, max: usize, label: &'static str) -> Result<Vec<u32>, AccountStorageError> {
    let ScVal::Vec(Some(values)) = value else {
        return Err(AccountStorageError::Invalid(label));
    };
    if values.len() > max {
        return Err(AccountStorageError::Invalid(label));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(values.len());
    for value in values.iter() {
        let id = u32_value(value, label)?;
        if !seen.insert(id) {
            return Err(AccountStorageError::Invalid(label));
        }
        out.push(id);
    }
    Ok(out)
}

fn u32_value(value: &ScVal, label: &'static str) -> Result<u32, AccountStorageError> {
    match value {
        ScVal::U32(n) => Ok(*n),
        _ => Err(AccountStorageError::Invalid(label)),
    }
}

fn address_value(value: &ScVal) -> Result<String, AccountStorageError> {
    match value {
        ScVal::Address(ScAddress::Contract(contract)) => {
            Ok(format!("{}", stellar_strkey::Contract(contract.0 .0)))
        }
        ScVal::Address(ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(key)),
        ))) => Ok(format!("{}", stellar_strkey::ed25519::PublicKey(*key))),
        _ => Err(AccountStorageError::Invalid("address value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{
        AccountId, ContractExecutable, ContractId, Hash, PublicKey, ScBytes, ScContractInstance,
        ScMapEntry, ScString, Uint256,
    };

    fn symbol(name: &str) -> ScVal {
        ScVal::Symbol(name.try_into().unwrap())
    }

    fn vector(values: Vec<ScVal>) -> ScVal {
        ScVal::Vec(Some(values.try_into().unwrap()))
    }

    fn record(fields: Vec<(&str, ScVal)>) -> ScVal {
        let mut entries = fields
            .into_iter()
            .map(|(name, val)| ScMapEntry {
                key: symbol(name),
                val,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        ScVal::Map(Some(entries.try_into().unwrap()))
    }

    fn contract_address(byte: u8) -> ScVal {
        ScVal::Address(ScAddress::Contract(ContractId(Hash([byte; 32]))))
    }

    fn key(name: &str, id: u32) -> LedgerKeyContractData {
        LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
            key: vector(vec![symbol(name), ScVal::U32(id)]),
            durability: ContractDataDurability::Persistent,
        }
    }

    fn instance_key() -> LedgerKeyContractData {
        LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        }
    }

    fn instance(fields: Vec<(&str, ScVal)>) -> ScVal {
        let mut entries = fields
            .into_iter()
            .map(|(name, val)| ScMapEntry {
                key: vector(vec![symbol(name)]),
                val,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([9; 32])),
            storage: Some(entries.try_into().unwrap()),
        })
    }

    fn rule() -> ScVal {
        record(vec![
            (
                "context_type",
                vector(vec![symbol("CallContract"), contract_address(8)]),
            ),
            ("name", ScVal::String(ScString("admin".try_into().unwrap()))),
            ("policy_ids", vector(vec![ScVal::U32(3)])),
            ("signer_ids", vector(vec![ScVal::U32(2)])),
            ("valid_until", ScVal::Void),
        ])
    }

    fn invalid(key: &LedgerKeyContractData, value: &ScVal, expected: &'static str) {
        assert_eq!(
            decode_account_storage(key, value),
            Err(AccountStorageError::Invalid(expected))
        );
    }

    #[test]
    fn instance_counters_are_exact_but_unrelated_keys_are_allowed() {
        let value = instance(vec![
            ("Count", ScVal::U32(1)),
            ("NextId", ScVal::U32(3)),
            ("NextSignerId", ScVal::U32(4)),
        ]);
        assert_eq!(
            decode_account_storage(&instance_key(), &value).unwrap(),
            AccountStorageEntry::Instance(InstanceCounters {
                next_id: Some(3),
                count: Some(1),
            })
        );
        assert_eq!(
            decode_account_storage(&instance_key(), &instance(vec![])).unwrap(),
            AccountStorageEntry::Instance(InstanceCounters {
                next_id: None,
                count: None,
            })
        );
        invalid(
            &instance_key(),
            &instance(vec![("NextId", ScVal::U32(1))]),
            "NextId and Count must appear together",
        );
        invalid(
            &instance_key(),
            &instance(vec![("Count", ScVal::U32(1))]),
            "NextId and Count must appear together",
        );
        invalid(
            &instance_key(),
            &instance(vec![("Count", ScVal::I32(1)), ("NextId", ScVal::U32(1))]),
            "Count value",
        );
        invalid(
            &instance_key(),
            &instance(vec![("Count", ScVal::U32(2)), ("NextId", ScVal::U32(1))]),
            "Count exceeds NextId",
        );
        let non_wasm = ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::StellarAsset,
            storage: None,
        });
        invalid(&instance_key(), &non_wasm, "account executable is not Wasm");
        let malformed_key = ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([9; 32])),
            storage: Some(
                vec![ScMapEntry {
                    key: symbol("NextId"),
                    val: ScVal::U32(1),
                }]
                .try_into()
                .unwrap(),
            ),
        });
        invalid(&instance_key(), &malformed_key, "NextId key");
    }

    #[test]
    fn rule_id_comes_from_the_key_and_required_fields_are_exact() {
        let expected_address = format!("{}", stellar_strkey::Contract([8; 32]));
        assert_eq!(
            decode_account_storage(&key("ContextRuleData", 17), &rule()).unwrap(),
            AccountStorageEntry::ContextRule(ContextRuleRecord {
                id: 17,
                name: "admin".into(),
                context_type: ContextType::CallContract(expected_address),
                valid_until: None,
                signer_ids: vec![2],
                policy_ids: vec![3],
            })
        );
        let malformed = record(vec![
            ("context_type", vector(vec![symbol("Default")])),
            ("name", ScVal::String(ScString("admin".try_into().unwrap()))),
            ("policy_ids", vector(vec![])),
            ("signer_ids", vector(vec![])),
        ]);
        invalid(&key("ContextRuleData", 17), &malformed, "ContextRuleEntry");
        let unknown = record(vec![
            ("context_type", vector(vec![symbol("Unknown")])),
            ("name", ScVal::String(ScString("admin".try_into().unwrap()))),
            ("policy_ids", vector(vec![ScVal::U32(3)])),
            ("signer_ids", vector(vec![ScVal::U32(2)])),
            ("valid_until", ScVal::Void),
        ]);
        invalid(&key("ContextRuleData", 17), &unknown, "context type");
        let no_authorizers = record(vec![
            ("context_type", vector(vec![symbol("Default")])),
            ("name", ScVal::String(ScString("admin".try_into().unwrap()))),
            ("policy_ids", vector(vec![])),
            ("signer_ids", vector(vec![])),
            ("valid_until", ScVal::Void),
        ]);
        invalid(
            &key("ContextRuleData", 17),
            &no_authorizers,
            "rule has no signers or policies",
        );
    }

    #[test]
    fn signer_and_policy_records_preserve_ids_counts_and_address_kind() {
        let signer = record(vec![
            ("count", ScVal::U32(2)),
            (
                "signer",
                vector(vec![symbol("Delegated"), contract_address(8)]),
            ),
        ]);
        assert_eq!(
            decode_account_storage(&key("SignerData", 9), &signer).unwrap(),
            AccountStorageEntry::Signer(SignerRecord {
                id: 9,
                signer: SignerIdentity::Delegated(format!("{}", stellar_strkey::Contract([8; 32]))),
                reference_count: 2,
            })
        );
        let external = record(vec![
            ("count", ScVal::U32(1)),
            (
                "signer",
                vector(vec![
                    symbol("External"),
                    contract_address(6),
                    ScVal::Bytes(ScBytes::try_from(vec![1, 2, 3]).unwrap()),
                ]),
            ),
        ]);
        assert!(matches!(
            decode_account_storage(&key("SignerData", 10), &external).unwrap(),
            AccountStorageEntry::Signer(SignerRecord {
                id: 10,
                signer: SignerIdentity::External { key, .. },
                reference_count: 1,
            }) if key == [1, 2, 3]
        ));
        let policy = record(vec![
            ("count", ScVal::U32(1)),
            ("policy", contract_address(5)),
        ]);
        assert_eq!(
            decode_account_storage(&key("PolicyData", 11), &policy).unwrap(),
            AccountStorageEntry::Policy(PolicyRecord {
                id: 11,
                address: format!("{}", stellar_strkey::Contract([5; 32])),
                reference_count: 1,
            })
        );
        let zero = record(vec![
            ("count", ScVal::U32(0)),
            ("policy", contract_address(5)),
        ]);
        invalid(&key("PolicyData", 11), &zero, "policy count zero");
    }

    #[test]
    fn wrong_storage_keys_and_durability_are_refused() {
        invalid(&key("Unknown", 0), &rule(), "unsupported storage key");
        let mut temporary = key("ContextRuleData", 1);
        temporary.durability = ContractDataDurability::Temporary;
        invalid(&temporary, &rule(), "contract and durability");
        let bad = LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
            key: vector(vec![symbol("ContextRuleData"), ScVal::I32(1)]),
            durability: ContractDataDurability::Persistent,
        };
        invalid(&bad, &rule(), "storage key ID");
    }

    #[test]
    fn address_and_byte_shapes_follow_the_sdk_types() {
        let account = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([4; 32])),
        )));
        let delegated = record(vec![
            ("count", ScVal::U32(1)),
            ("signer", vector(vec![symbol("Delegated"), account])),
        ]);
        assert_eq!(
            decode_account_storage(&key("SignerData", 4), &delegated).unwrap(),
            AccountStorageEntry::Signer(SignerRecord {
                id: 4,
                signer: SignerIdentity::Delegated(format!(
                    "{}",
                    stellar_strkey::ed25519::PublicKey([4; 32])
                )),
                reference_count: 1,
            })
        );
        let make_rule = |hash: Vec<u8>| {
            record(vec![
                (
                    "context_type",
                    vector(vec![
                        symbol("CreateContract"),
                        ScVal::Bytes(ScBytes::try_from(hash).unwrap()),
                    ]),
                ),
                (
                    "name",
                    ScVal::String(ScString("create".try_into().unwrap())),
                ),
                ("policy_ids", vector(vec![])),
                ("signer_ids", vector(vec![ScVal::U32(4)])),
                ("valid_until", ScVal::U32(42)),
            ])
        };
        assert!(matches!(
            decode_account_storage(&key("ContextRuleData", 5), &make_rule(vec![8; 32])).unwrap(),
            AccountStorageEntry::ContextRule(ContextRuleRecord {
                id: 5,
                context_type: ContextType::CreateContract(hash),
                valid_until: Some(42),
                ..
            }) if hash == [8; 32]
        ));
        invalid(
            &key("ContextRuleData", 5),
            &make_rule(vec![8; 31]),
            "context type",
        );
        let oversized_external = record(vec![
            ("count", ScVal::U32(1)),
            (
                "signer",
                vector(vec![
                    symbol("External"),
                    contract_address(6),
                    ScVal::Bytes(ScBytes::try_from(vec![1; 257]).unwrap()),
                ]),
            ),
        ]);
        invalid(&key("SignerData", 4), &oversized_external, "signer value");
    }
}
