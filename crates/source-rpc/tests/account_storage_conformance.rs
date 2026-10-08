//! Wire fixtures emitted by the pinned SDK's `#[contracttype]` implementation, independent
//! of the decoder's hand-written shape checks. See the fixture file for provenance.

use ozpb_source_rpc::{
    decode_account_storage, xdr_limits, AccountStorageEntry, ContextRuleRecord, ContextType,
    InstanceCounters, PolicyRecord, SignerIdentity, SignerRecord,
};
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerKeyContractData, ReadXdr,
    ScAddress, ScContractInstance, ScMapEntry, ScVal,
};

fn fixture(name: &str) -> ScVal {
    let (_, hex) = include_str!("fixtures/account_storage_sdk_0_7_2.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| line.split_once(' ').filter(|(found, _)| *found == name))
        .unwrap_or_else(|| panic!("missing SDK fixture {name}"));
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect::<Vec<_>>();
    ScVal::from_xdr(bytes, xdr_limits()).unwrap()
}

fn ledger_key(key: ScVal) -> LedgerKeyContractData {
    LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
        key,
        durability: ContractDataDurability::Persistent,
    }
}

#[test]
fn sdk_encoded_rule_signer_and_policy_entries_decode_exactly() {
    let account = format!("{}", stellar_strkey::Contract([8; 32]));
    assert_eq!(
        decode_account_storage(&ledger_key(fixture("rule_key")), &fixture("rule_value")).unwrap(),
        AccountStorageEntry::ContextRule(ContextRuleRecord {
            id: 17,
            name: "admin".into(),
            context_type: ContextType::CallContract(account.clone()),
            valid_until: None,
            signer_ids: vec![2],
            policy_ids: vec![3],
        })
    );
    assert_eq!(
        decode_account_storage(&ledger_key(fixture("signer_key")), &fixture("signer_value"))
            .unwrap(),
        AccountStorageEntry::Signer(SignerRecord {
            id: 9,
            signer: SignerIdentity::Delegated(account.clone()),
            reference_count: 2,
        })
    );
    assert_eq!(
        decode_account_storage(&ledger_key(fixture("policy_key")), &fixture("policy_value"))
            .unwrap(),
        AccountStorageEntry::Policy(PolicyRecord {
            id: 11,
            address: account,
            reference_count: 1,
        })
    );
}

#[test]
fn sdk_encoded_instance_keys_find_both_counters() {
    let mut storage = vec![
        ScMapEntry {
            key: fixture("next_id_key"),
            val: ScVal::U32(18),
        },
        ScMapEntry {
            key: fixture("count_key"),
            val: ScVal::U32(3),
        },
    ];
    storage.sort_by(|a, b| a.key.cmp(&b.key));
    let value = ScVal::ContractInstance(ScContractInstance {
        executable: ContractExecutable::Wasm(Hash([9; 32])),
        storage: Some(storage.try_into().unwrap()),
    });
    assert_eq!(
        decode_account_storage(&ledger_key(ScVal::LedgerKeyContractInstance), &value).unwrap(),
        AccountStorageEntry::Instance(InstanceCounters {
            wasm_hash: ozpb_domain::Hash32([9; 32]),
            next_id: Some(18),
            count: Some(3),
        })
    );
}
