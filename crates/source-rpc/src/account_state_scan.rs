//! Bounded acquisition of the pinned account's rules and transitive storage entries.
//!
//! Every returned value is decoded against its requested key. The scanner checks the
//! endpoint's ledger number on every response, re-reads the instance, and reconciles
//! `NextId`, `Count`, and reference counts. These checks catch ordinary races and
//! incomplete responses; the endpoint's `latestLedger` is metadata, not a ledger-state
//! proof. An omitted rule can be a removed hole only when the complete count agrees.
//! This result carries no ordered key/value/TTL digest or designated administrator and
//! cannot establish a Safe install verdict.

use super::{
    account_entry_page::{read_account_entry_page, AccountEntryKey, AccountEntryStatus},
    account_reconciliation::{
        check_supplied_account_entries, ReconciliationBounds, ReconciliationError,
    },
    account_storage::{AccountStorageEntry, ContextRuleRecord, PolicyRecord, SignerRecord},
    read_contract_wasm_hashes, RpcError, RpcTransport, MAX_LEDGER_ENTRY_KEYS,
};
use ozpb_domain::{Hash32, LedgerSeq, NetworkId};
use std::collections::{BTreeMap, BTreeSet};

/// Operational ceilings for one inspection. Registry-backed verified mode would need
/// signed, release-specific bounds; caller-chosen bounds here grant no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountScanBounds {
    pub max_scan_ids: u32,
    /// Maximum `getLedgerEntries` calls per complete attempt. The total is additionally
    /// bounded by `max_attempts` (at most three).
    pub max_rpc_batches: u32,
    pub max_transitive_entries: usize,
    /// A changed endpoint ledger or instance causes a complete retry, never a mix of
    /// successful fragments from different attempts. The allowed range is 1..=3.
    pub max_attempts: u32,
}

impl Default for AccountScanBounds {
    fn default() -> Self {
        Self {
            max_scan_ids: 1_000,
            max_rpc_batches: 16,
            max_transitive_entries: 1_000,
            max_attempts: 2,
        }
    }
}

/// Checked endpoint observations, explicitly insufficient for an authority verdict.
#[derive(Clone, Debug)]
pub struct AccountStateScan {
    pub network_id: NetworkId,
    pub account_address: String,
    /// Every successful read in the last attempt returned this number. It does not
    /// attest that the endpoint served one coherent ledger state.
    pub reported_latest_ledger: LedgerSeq,
    pub account_wasm_hash: Hash32,
    pub next_id: u32,
    /// Stored `Count`: nonremoved rules, including expired rules.
    pub extant_count: u32,
    pub rules: BTreeMap<u32, ContextRuleRecord>,
    pub signers: BTreeMap<u32, SignerRecord>,
    pub policies: BTreeMap<u32, PolicyRecord>,
    /// Includes every installed policy and each extra contract requested by the caller.
    /// Each instance was live when its individual response was read.
    pub observed_code_hashes: BTreeMap<String, Hash32>,
    pub rpc_batches: u32,
    pub attempts: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountScanError {
    #[error("{0}")]
    Rpc(#[from] RpcError),
    #[error("E_RPC: invalid account scan bounds: {0}")]
    InvalidBounds(&'static str),
    #[error("E_SCAN_BUDGET_EXCEEDED: {0}")]
    Budget(&'static str),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: {0}")]
    Incomplete(String),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: returned archived {0}")]
    Archived(String),
    #[error(
        "E_INCOMPLETE_ACCOUNT_STATE: endpoint ledger or account instance changed during inspection"
    )]
    SnapshotChanged,
}

impl AccountScanError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Budget(_) => "E_SCAN_BUDGET_EXCEEDED",
            Self::Incomplete(_) | Self::Archived(_) | Self::SnapshotChanged => {
                "E_INCOMPLETE_ACCOUNT_STATE"
            }
            Self::Rpc(RpcError::NetworkMismatch { .. }) => "E_NETWORK_MISMATCH",
            Self::Rpc(_) | Self::InvalidBounds(_) => "E_RPC",
        }
    }
}

/// Inspect an account and the code of every installed policy through a chosen endpoint.
/// The address selects keys; code identity and storage values come from checked RPC data.
pub fn scan_account_state<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    bounds: AccountScanBounds,
) -> Result<AccountStateScan, AccountScanError> {
    scan_account_state_with_targets(transport, network_passphrase, account_address, &[], bounds)
}

/// Also inspect instances at the given candidate policy addresses. The extra addresses
/// are caller-selected targets; observing them does not recognize their implementations.
pub fn scan_account_state_with_targets<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    target_addresses: &[String],
    bounds: AccountScanBounds,
) -> Result<AccountStateScan, AccountScanError> {
    validate_bounds(bounds)?;
    if target_addresses.len() > bounds.max_transitive_entries {
        return Err(AccountScanError::Budget(
            "too many candidate policy addresses",
        ));
    }
    for address in target_addresses {
        if address.len() > 128 || address.parse::<stellar_strkey::Contract>().is_err() {
            return Err(AccountScanError::Rpc(RpcError::InvalidRequest(
                "candidate policy address must be a valid C-strkey".into(),
            )));
        }
    }
    for attempt in 1..=bounds.max_attempts {
        match scan_once(
            transport,
            network_passphrase,
            account_address,
            target_addresses,
            bounds,
        ) {
            Ok(mut scan) => {
                scan.attempts = attempt;
                return Ok(scan);
            }
            Err(AccountScanError::SnapshotChanged) if attempt < bounds.max_attempts => continue,
            other => return other,
        }
    }
    Err(AccountScanError::SnapshotChanged)
}

fn validate_bounds(bounds: AccountScanBounds) -> Result<(), AccountScanError> {
    if bounds.max_scan_ids == 0 || bounds.max_scan_ids > 10_000 {
        return Err(AccountScanError::InvalidBounds(
            "max_scan_ids must be 1..=10000",
        ));
    }
    if bounds.max_rpc_batches == 0 || bounds.max_rpc_batches > 128 {
        return Err(AccountScanError::InvalidBounds(
            "max_rpc_batches must be 1..=128",
        ));
    }
    if bounds.max_transitive_entries == 0 || bounds.max_transitive_entries > 10_000 {
        return Err(AccountScanError::InvalidBounds(
            "max_transitive_entries must be 1..=10000",
        ));
    }
    if !(1..=3).contains(&bounds.max_attempts) {
        return Err(AccountScanError::InvalidBounds(
            "max_attempts must be 1..=3",
        ));
    }
    Ok(())
}

fn scan_once<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    account_address: &str,
    target_addresses: &[String],
    bounds: AccountScanBounds,
) -> Result<AccountStateScan, AccountScanError> {
    let mut batches = 0;
    let first = read_page(
        transport,
        network_passphrase,
        account_address,
        &[AccountEntryKey::Instance],
        &mut batches,
        bounds,
    )?;
    let ledger = first.rpc_reported_latest_ledger;
    let status = first
        .entries
        .get(&AccountEntryKey::Instance)
        .ok_or_else(|| {
            AccountScanError::Incomplete("instance key missing from decoded page".into())
        })?;
    let (counters, first_status) = match status {
        AccountEntryStatus::Present {
            entry: AccountStorageEntry::Instance(value),
            ..
        } => (value.clone(), status.clone()),
        AccountEntryStatus::Archived { .. } => {
            return Err(AccountScanError::Archived("account instance".into()));
        }
        AccountEntryStatus::Absent => {
            return Err(AccountScanError::Incomplete(
                "account instance omitted".into(),
            ));
        }
        _ => {
            return Err(AccountScanError::Incomplete(
                "instance key returned a different entry kind".into(),
            ));
        }
    };
    let (Some(next_id), Some(extant_count)) = (counters.next_id, counters.count) else {
        return Err(AccountScanError::Incomplete(
            "account instance has no initialized NextId/Count pair".into(),
        ));
    };
    if next_id > bounds.max_scan_ids {
        return Err(AccountScanError::Budget("NextId exceeds max_scan_ids"));
    }

    let mut slots = BTreeMap::new();
    for keys in (0..next_id)
        .map(AccountEntryKey::Rule)
        .collect::<Vec<_>>()
        .chunks(MAX_LEDGER_ENTRY_KEYS)
    {
        let page = read_page(
            transport,
            network_passphrase,
            account_address,
            keys,
            &mut batches,
            bounds,
        )?;
        same_ledger(ledger, page.rpc_reported_latest_ledger)?;
        for (&key, status) in &page.entries {
            let AccountEntryKey::Rule(id) = key else {
                return Err(AccountScanError::Incomplete("unexpected rule key".into()));
            };
            let rule = match status {
                AccountEntryStatus::Absent => None,
                AccountEntryStatus::Archived { .. } => {
                    return Err(AccountScanError::Archived(format!("rule {id}")));
                }
                AccountEntryStatus::Present {
                    entry: AccountStorageEntry::ContextRule(value),
                    ..
                } => Some(value.clone()),
                _ => {
                    return Err(AccountScanError::Incomplete(format!(
                        "rule {id} has wrong entry kind"
                    )));
                }
            };
            slots.insert(id, rule);
        }
    }

    let (signer_ids, policy_ids) = closure_ids(&slots, bounds)?;
    let keys = signer_ids
        .iter()
        .copied()
        .map(AccountEntryKey::Signer)
        .chain(policy_ids.iter().copied().map(AccountEntryKey::Policy))
        .collect::<Vec<_>>();
    let mut signers = BTreeMap::new();
    let mut policies = BTreeMap::new();
    for keys in keys.chunks(MAX_LEDGER_ENTRY_KEYS) {
        let page = read_page(
            transport,
            network_passphrase,
            account_address,
            keys,
            &mut batches,
            bounds,
        )?;
        same_ledger(ledger, page.rpc_reported_latest_ledger)?;
        for (&key, status) in &page.entries {
            let entry = match status {
                AccountEntryStatus::Present { entry, .. } => entry,
                AccountEntryStatus::Archived { .. } => {
                    return Err(AccountScanError::Archived(format!("{key:?}")));
                }
                AccountEntryStatus::Absent => {
                    return Err(AccountScanError::Incomplete(format!(
                        "referenced {key:?} was omitted"
                    )));
                }
            };
            match (key, entry) {
                (AccountEntryKey::Signer(id), AccountStorageEntry::Signer(value)) => {
                    signers.insert(id, value.clone());
                }
                (AccountEntryKey::Policy(id), AccountStorageEntry::Policy(value)) => {
                    policies.insert(id, value.clone());
                }
                _ => {
                    return Err(AccountScanError::Incomplete(format!(
                        "{key:?} has wrong entry kind"
                    )));
                }
            }
        }
    }
    check_supplied_account_entries(
        &counters,
        &slots,
        &signers,
        &policies,
        ReconciliationBounds {
            max_scan_ids: bounds.max_scan_ids,
            max_transitive_entries: bounds.max_transitive_entries,
        },
    )
    .map_err(reconciliation_error)?;

    let mut addresses = target_addresses.iter().cloned().collect::<BTreeSet<_>>();
    for policy in policies.values() {
        addresses.insert(policy.address.clone());
    }
    if addresses.len() > bounds.max_transitive_entries {
        return Err(AccountScanError::Budget(
            "policy code closure exceeds bound",
        ));
    }
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    let mut observed_code_hashes = BTreeMap::new();
    for chunk in addresses.chunks(MAX_LEDGER_ENTRY_KEYS) {
        reserve_batch(&mut batches, bounds)?;
        let read =
            read_contract_wasm_hashes(transport, network_passphrase, chunk).map_err(|error| {
                match error {
                    RpcError::CodeRead(detail) => AccountScanError::Incomplete(format!(
                        "installed or candidate policy code is unavailable: {detail}"
                    )),
                    other => AccountScanError::Rpc(other),
                }
            })?;
        same_ledger(ledger, read.reported_latest_ledger)?;
        observed_code_hashes.extend(read.wasm_hashes);
    }
    if observed_code_hashes
        .get(account_address)
        .is_some_and(|hash| *hash != counters.wasm_hash)
    {
        return Err(AccountScanError::SnapshotChanged);
    }

    let last = read_page(
        transport,
        network_passphrase,
        account_address,
        &[AccountEntryKey::Instance],
        &mut batches,
        bounds,
    )?;
    same_ledger(ledger, last.rpc_reported_latest_ledger)?;
    if last.entries.get(&AccountEntryKey::Instance) != Some(&first_status) {
        return Err(AccountScanError::SnapshotChanged);
    }
    Ok(AccountStateScan {
        network_id: first.network_id,
        account_address: account_address.to_string(),
        reported_latest_ledger: ledger,
        account_wasm_hash: counters.wasm_hash,
        next_id,
        extant_count,
        rules: slots
            .into_iter()
            .filter_map(|(id, rule)| rule.map(|v| (id, v)))
            .collect(),
        signers,
        policies,
        observed_code_hashes,
        rpc_batches: batches,
        attempts: 0,
    })
}

fn closure_ids(
    slots: &BTreeMap<u32, Option<ContextRuleRecord>>,
    bounds: AccountScanBounds,
) -> Result<(BTreeSet<u32>, BTreeSet<u32>), AccountScanError> {
    let mut signers = BTreeSet::new();
    let mut policies = BTreeSet::new();
    for rule in slots.values().flatten() {
        signers.extend(rule.signer_ids.iter().copied());
        policies.extend(rule.policy_ids.iter().copied());
        if signers.len().saturating_add(policies.len()) > bounds.max_transitive_entries {
            return Err(AccountScanError::Budget(
                "transitive entry closure exceeds bound",
            ));
        }
    }
    Ok((signers, policies))
}

fn read_page<T: RpcTransport>(
    transport: &T,
    passphrase: &str,
    account: &str,
    keys: &[AccountEntryKey],
    batches: &mut u32,
    bounds: AccountScanBounds,
) -> Result<super::account_entry_page::AccountEntryPage, AccountScanError> {
    reserve_batch(batches, bounds)?;
    read_account_entry_page(transport, passphrase, account, keys).map_err(Into::into)
}

fn reserve_batch(batches: &mut u32, bounds: AccountScanBounds) -> Result<(), AccountScanError> {
    if *batches >= bounds.max_rpc_batches {
        return Err(AccountScanError::Budget(
            "getLedgerEntries batch count exceeds bound",
        ));
    }
    *batches += 1;
    Ok(())
}

fn same_ledger(expected: LedgerSeq, observed: LedgerSeq) -> Result<(), AccountScanError> {
    if expected == observed {
        Ok(())
    } else {
        Err(AccountScanError::SnapshotChanged)
    }
}

fn reconciliation_error(error: ReconciliationError) -> AccountScanError {
    match error {
        ReconciliationError::ScanBudgetExceeded | ReconciliationError::ClosureBudgetExceeded => {
            AccountScanError::Budget("reconciliation bound exceeded")
        }
        other => AccountScanError::Incomplete(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account_entry_page::ledger_key, xdr_limits};
    use serde_json::{json, Value};
    use std::cell::{Cell, RefCell};
    use stellar_xdr::{
        ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint, Hash, LedgerEntryData,
        LedgerKey, ReadXdr, ScAddress, ScContractInstance, ScMapEntry, ScString, ScVal, WriteXdr,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const ACCOUNT: [u8; 32] = [7; 32];

    struct Mock {
        values: RefCell<BTreeMap<String, (ScVal, u32)>>,
        calls: Cell<usize>,
        changed_ledger_at: Option<usize>,
        changed_instance_at: Option<usize>,
    }

    impl RpcTransport for Mock {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            match method {
                "getNetwork" => Ok(json!({"passphrase": NETWORK, "protocolVersion": 28})),
                "getLedgerEntries" => {
                    let call = self.calls.get() + 1;
                    self.calls.set(call);
                    let keys = params["keys"].as_array().unwrap();
                    let mut entries = Vec::new();
                    for encoded in keys {
                        let encoded = encoded.as_str().unwrap();
                        if let Some((value, ttl)) = self.values.borrow().get(encoded) {
                            let LedgerKey::ContractData(key) =
                                LedgerKey::from_xdr_base64(encoded, xdr_limits()).unwrap()
                            else {
                                panic!("contract-data key");
                            };
                            let mut value = value.clone();
                            if self.changed_instance_at == Some(call)
                                && key.key == ScVal::LedgerKeyContractInstance
                            {
                                value = instance(2, 0);
                            }
                            entries.push(json!({
                                "key": encoded,
                                "xdr": LedgerEntryData::ContractData(ContractDataEntry {
                                    ext: ExtensionPoint::V0,
                                    contract: key.contract,
                                    key: key.key,
                                    durability: key.durability,
                                    val: value,
                                }).to_xdr_base64(xdr_limits()).unwrap(),
                                "lastModifiedLedgerSeq": 9,
                                "liveUntilLedgerSeq": ttl,
                            }));
                        }
                    }
                    let ledger = if self.changed_ledger_at == Some(call) {
                        11
                    } else {
                        10
                    };
                    Ok(json!({"latestLedger": ledger, "entries": entries}))
                }
                other => panic!("unexpected method {other}"),
            }
        }
    }

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn map(entries: Vec<(&str, ScVal)>) -> ScVal {
        let mut entries = entries
            .into_iter()
            .map(|(key, val)| ScMapEntry {
                key: ScVal::Symbol(key.try_into().unwrap()),
                val,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        ScVal::Map(Some(entries.try_into().unwrap()))
    }

    fn vector(values: Vec<ScVal>) -> ScVal {
        ScVal::Vec(Some(values.try_into().unwrap()))
    }

    fn symbol(value: &str) -> ScVal {
        ScVal::Symbol(value.try_into().unwrap())
    }

    fn instance(next_id: u32, count: u32) -> ScVal {
        let mut storage = vec![
            ScMapEntry {
                key: vector(vec![symbol("NextId")]),
                val: ScVal::U32(next_id),
            },
            ScMapEntry {
                key: vector(vec![symbol("Count")]),
                val: ScVal::U32(count),
            },
        ];
        storage.sort_by(|a, b| a.key.cmp(&b.key));
        ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash([9; 32])),
            storage: Some(storage.try_into().unwrap()),
        })
    }

    fn rule_with_policies(policy_ids: Vec<u32>) -> ScVal {
        map(vec![
            ("context_type", vector(vec![symbol("Default")])),
            (
                "name",
                ScVal::String(ScString(b"admin".to_vec().try_into().unwrap())),
            ),
            (
                "policy_ids",
                vector(policy_ids.into_iter().map(ScVal::U32).collect()),
            ),
            ("signer_ids", vector(vec![ScVal::U32(2)])),
            ("valid_until", ScVal::Void),
        ])
    }

    fn rule() -> ScVal {
        rule_with_policies(vec![])
    }

    fn signer() -> ScVal {
        map(vec![
            ("count", ScVal::U32(1)),
            (
                "signer",
                vector(vec![
                    symbol("Delegated"),
                    ScVal::Address(ScAddress::Contract(ContractId(Hash([8; 32])))),
                ]),
            ),
        ])
    }

    fn policy() -> ScVal {
        map(vec![
            ("count", ScVal::U32(1)),
            (
                "policy",
                ScVal::Address(ScAddress::Contract(ContractId(Hash([8; 32])))),
            ),
        ])
    }

    fn encoded(account: u8, key: AccountEntryKey) -> String {
        LedgerKey::ContractData(ledger_key(&ContractId(Hash([account; 32])), key))
            .to_xdr_base64(xdr_limits())
            .unwrap()
    }

    fn mock() -> Mock {
        Mock {
            values: RefCell::new(BTreeMap::from([
                (encoded(7, AccountEntryKey::Instance), (instance(1, 1), 20)),
                (encoded(7, AccountEntryKey::Rule(0)), (rule(), 20)),
                (encoded(7, AccountEntryKey::Signer(2)), (signer(), 20)),
            ])),
            calls: Cell::new(0),
            changed_ledger_at: None,
            changed_instance_at: None,
        }
    }

    fn inspect(mock: &Mock) -> Result<AccountStateScan, AccountScanError> {
        scan_account_state(
            mock,
            NETWORK,
            &address(ACCOUNT[0]),
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
    }

    #[test]
    fn complete_bounded_read_reconciles_rule_and_signer_closure() {
        let scan = inspect(&mock()).unwrap();
        assert_eq!(scan.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(scan.account_wasm_hash, Hash32([9; 32]));
        assert_eq!((scan.next_id, scan.extant_count), (1, 1));
        assert_eq!(scan.rules.len(), 1);
        assert_eq!(scan.signers.len(), 1);
        assert!(scan.policies.is_empty());
        assert_eq!(scan.rpc_batches, 4);
    }

    #[test]
    fn missing_archived_and_mixed_rule_pages_fail_closed() {
        let missing = mock();
        missing
            .values
            .borrow_mut()
            .remove(&encoded(7, AccountEntryKey::Rule(0)));
        assert!(matches!(
            inspect(&missing),
            Err(AccountScanError::Incomplete(_))
        ));

        let archived = mock();
        archived
            .values
            .borrow_mut()
            .get_mut(&encoded(7, AccountEntryKey::Rule(0)))
            .unwrap()
            .1 = 0;
        assert!(matches!(
            inspect(&archived),
            Err(AccountScanError::Archived(_))
        ));

        let mixed = Mock {
            changed_ledger_at: Some(2),
            ..mock()
        };
        assert!(matches!(
            inspect(&mixed),
            Err(AccountScanError::SnapshotChanged)
        ));

        let missing_signer = mock();
        missing_signer
            .values
            .borrow_mut()
            .remove(&encoded(7, AccountEntryKey::Signer(2)));
        assert!(matches!(
            inspect(&missing_signer),
            Err(AccountScanError::Incomplete(_))
        ));
    }

    #[test]
    fn instance_reread_detects_same_ledger_mutation_and_budget_is_enforced() {
        let changed = Mock {
            changed_instance_at: Some(4),
            ..mock()
        };
        assert!(matches!(
            inspect(&changed),
            Err(AccountScanError::SnapshotChanged)
        ));

        let limited = scan_account_state(
            &mock(),
            NETWORK,
            &address(7),
            AccountScanBounds {
                max_rpc_batches: 3,
                max_attempts: 1,
                ..Default::default()
            },
        );
        assert!(matches!(limited, Err(AccountScanError::Budget(_))));
    }

    #[test]
    fn candidate_policy_code_is_observed_by_address() {
        let mock = mock();
        mock.values.borrow_mut().insert(
            encoded(8, AccountEntryKey::Instance),
            (
                ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash([3; 32])),
                    storage: None,
                }),
                20,
            ),
        );
        let scan = scan_account_state_with_targets(
            &mock,
            NETWORK,
            &address(7),
            &[address(8)],
            AccountScanBounds {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(scan.observed_code_hashes[&address(8)], Hash32([3; 32]));
        assert_eq!(scan.rpc_batches, 5);

        let invalid = self::mock();
        let error = scan_account_state_with_targets(
            &invalid,
            NETWORK,
            &address(7),
            &["not-a-contract".into()],
            AccountScanBounds::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AccountScanError::Rpc(RpcError::InvalidRequest(_))
        ));
        assert_eq!(invalid.calls.get(), 0);
    }

    #[test]
    fn installed_policy_requires_transitive_entry_and_live_code() {
        let mock = mock();
        mock.values.borrow_mut().insert(
            encoded(7, AccountEntryKey::Rule(0)),
            (rule_with_policies(vec![3]), 20),
        );
        mock.values
            .borrow_mut()
            .insert(encoded(7, AccountEntryKey::Policy(3)), (policy(), 20));
        assert!(matches!(
            inspect(&mock),
            Err(AccountScanError::Incomplete(_))
        ));

        mock.values.borrow_mut().insert(
            encoded(8, AccountEntryKey::Instance),
            (
                ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash([3; 32])),
                    storage: None,
                }),
                20,
            ),
        );
        let scan = inspect(&mock).unwrap();
        assert_eq!(scan.policies.len(), 1);
        assert_eq!(scan.observed_code_hashes[&address(8)], Hash32([3; 32]));
    }

    #[test]
    fn changed_ledger_retries_the_entire_scan() {
        let unstable = Mock {
            changed_ledger_at: Some(2),
            ..mock()
        };
        let scan = scan_account_state(
            &unstable,
            NETWORK,
            &address(7),
            AccountScanBounds::default(),
        )
        .unwrap();
        assert_eq!(scan.attempts, 2);
        assert_eq!(scan.rpc_batches, 4);
        assert_eq!(unstable.calls.get(), 6);
    }

    #[test]
    fn scan_spans_the_rpc_key_limit_without_treating_removed_holes_as_rules() {
        let empty = mock();
        let mut values = empty.values.borrow_mut();
        values.insert(
            encoded(7, AccountEntryKey::Instance),
            (instance(201, 0), 20),
        );
        values.remove(&encoded(7, AccountEntryKey::Rule(0)));
        values.remove(&encoded(7, AccountEntryKey::Signer(2)));
        drop(values);
        let scan = scan_account_state(
            &empty,
            NETWORK,
            &address(7),
            AccountScanBounds {
                max_scan_ids: 201,
                max_rpc_batches: 4,
                max_attempts: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(scan.next_id, 201);
        assert_eq!(scan.extant_count, 0);
        assert!(scan.rules.is_empty());
        assert_eq!(scan.rpc_batches, 4);
    }
}
