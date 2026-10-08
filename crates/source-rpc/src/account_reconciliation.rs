//! Internal checks over caller-supplied decoded account entries.
//!
//! A passing check does not authenticate the entries, establish one ledger snapshot, identify
//! archive status, recognize code, derive an administrator, inspect reverse lookup keys, or decide
//! authority. A later reader must earn those claims through acquisition before using this guard
//! in a public operation.

#![allow(dead_code, reason = "awaiting the trusted account-state reader")]

use super::account_storage::{ContextRuleRecord, InstanceCounters, PolicyRecord, SignerRecord};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReconciliationBounds {
    pub max_scan_ids: u32,
    pub max_transitive_entries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ReconciliationError {
    #[error("both NextId and Count must be present in the supplied instance")]
    MissingCounters,
    #[error("supplied Count exceeds NextId")]
    CountExceedsNextId,
    #[error("NextId exceeds the declared scan bound")]
    ScanBudgetExceeded,
    #[error("signer and policy entry count exceeds the declared closure bound")]
    ClosureBudgetExceeded,
    #[error("missing supplied rule slot {0}")]
    MissingRuleSlot(u32),
    #[error("unexpected supplied rule slot {0}")]
    UnexpectedRuleSlot(u32),
    #[error("rule in slot {slot} carries ID {record}")]
    RuleIdMismatch { slot: u32, record: u32 },
    #[error("rule {rule} repeats {kind} ID {id}")]
    DuplicateReference {
        rule: u32,
        kind: &'static str,
        id: u32,
    },
    #[error("supplied Count is {declared}, but {decoded} rule entries were supplied")]
    RuleCountMismatch { declared: u32, decoded: u32 },
    #[error("missing referenced {kind} entry {id}")]
    MissingTransitive { kind: &'static str, id: u32 },
    #[error("unexpected {kind} entry {id}")]
    UnexpectedTransitive { kind: &'static str, id: u32 },
    #[error("{kind} map key {key} disagrees with record ID {record}")]
    TransitiveIdMismatch {
        kind: &'static str,
        key: u32,
        record: u32,
    },
    #[error("{kind} entry {id} has reference count {declared}, expected {observed}")]
    ReferenceCountMismatch {
        kind: &'static str,
        id: u32,
        declared: u32,
        observed: u32,
    },
}

/// Check structural consistency of an explicitly supplied bounded rule scan and its exact
/// transitive signer/policy closure. Every ID in `0..NextId` must have a slot: `None` means an
/// omitted rule key. Its count can be consistent with a removed hole only if the supplied
/// stored `Count` matches the number of present rules. That match does not establish archival
/// status or a coherent observation. Unrecognized code and administrator identity are outside
/// this check.
pub(crate) fn check_supplied_account_entries(
    counters: &InstanceCounters,
    rule_slots: &BTreeMap<u32, Option<ContextRuleRecord>>,
    signers: &BTreeMap<u32, SignerRecord>,
    policies: &BTreeMap<u32, PolicyRecord>,
    bounds: ReconciliationBounds,
) -> Result<(), ReconciliationError> {
    let (Some(next_id), Some(count)) = (counters.next_id, counters.count) else {
        return Err(ReconciliationError::MissingCounters);
    };
    if count > next_id {
        return Err(ReconciliationError::CountExceedsNextId);
    }
    if next_id > bounds.max_scan_ids || rule_slots.len() > bounds.max_scan_ids as usize {
        return Err(ReconciliationError::ScanBudgetExceeded);
    }
    if signers.len().saturating_add(policies.len()) > bounds.max_transitive_entries {
        return Err(ReconciliationError::ClosureBudgetExceeded);
    }
    for id in 0..next_id {
        if !rule_slots.contains_key(&id) {
            return Err(ReconciliationError::MissingRuleSlot(id));
        }
    }
    if let Some(&id) = rule_slots.keys().find(|&&id| id >= next_id) {
        return Err(ReconciliationError::UnexpectedRuleSlot(id));
    }

    let mut decoded_count = 0u32;
    let mut signer_uses = BTreeMap::<u32, u32>::new();
    let mut policy_uses = BTreeMap::<u32, u32>::new();
    for (&slot, record) in rule_slots {
        let Some(rule) = record else { continue };
        if rule.id != slot {
            return Err(ReconciliationError::RuleIdMismatch {
                slot,
                record: rule.id,
            });
        }
        decoded_count += 1; // bounded by NextId <= u32::MAX
        count_ids(&mut signer_uses, &rule.signer_ids, rule.id, "signer")?;
        count_ids(&mut policy_uses, &rule.policy_ids, rule.id, "policy")?;
        if signer_uses.len().saturating_add(policy_uses.len()) > bounds.max_transitive_entries {
            return Err(ReconciliationError::ClosureBudgetExceeded);
        }
    }
    if decoded_count != count {
        return Err(ReconciliationError::RuleCountMismatch {
            declared: count,
            decoded: decoded_count,
        });
    }
    check_transitive(&signer_uses, signers, "signer", |entry| {
        (entry.id, entry.reference_count)
    })?;
    check_transitive(&policy_uses, policies, "policy", |entry| {
        (entry.id, entry.reference_count)
    })?;
    Ok(())
}

fn count_ids(
    uses: &mut BTreeMap<u32, u32>,
    ids: &[u32],
    rule: u32,
    kind: &'static str,
) -> Result<(), ReconciliationError> {
    let mut seen = BTreeSet::new();
    for &id in ids {
        if !seen.insert(id) {
            return Err(ReconciliationError::DuplicateReference { rule, kind, id });
        }
        *uses.entry(id).or_default() += 1; // at most one per rule, bounded by NextId
    }
    Ok(())
}

fn check_transitive<T>(
    expected: &BTreeMap<u32, u32>,
    supplied: &BTreeMap<u32, T>,
    kind: &'static str,
    identity: impl Fn(&T) -> (u32, u32),
) -> Result<(), ReconciliationError> {
    for (&id, &observed) in expected {
        let entry = supplied
            .get(&id)
            .ok_or(ReconciliationError::MissingTransitive { kind, id })?;
        let (record, declared) = identity(entry);
        if record != id {
            return Err(ReconciliationError::TransitiveIdMismatch {
                kind,
                key: id,
                record,
            });
        }
        if declared != observed {
            return Err(ReconciliationError::ReferenceCountMismatch {
                kind,
                id,
                declared,
                observed,
            });
        }
    }
    if let Some(&id) = supplied.keys().find(|id| !expected.contains_key(id)) {
        return Err(ReconciliationError::UnexpectedTransitive { kind, id });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_storage::{ContextType, SignerIdentity};

    struct Fixture {
        counters: InstanceCounters,
        slots: BTreeMap<u32, Option<ContextRuleRecord>>,
        signers: BTreeMap<u32, SignerRecord>,
        policies: BTreeMap<u32, PolicyRecord>,
    }

    fn rule(id: u32, policy_id: u32) -> ContextRuleRecord {
        ContextRuleRecord {
            id,
            name: format!("rule-{id}"),
            context_type: ContextType::Default,
            valid_until: Some(1), // expired rules still count until removed
            signer_ids: vec![1],
            policy_ids: vec![policy_id],
        }
    }

    fn fixture() -> Fixture {
        Fixture {
            counters: InstanceCounters {
                wasm_hash: ozpb_domain::Hash32([9; 32]),
                next_id: Some(3),
                count: Some(2),
            },
            slots: BTreeMap::from([(0, Some(rule(0, 7))), (1, None), (2, Some(rule(2, 8)))]),
            signers: BTreeMap::from([(
                1,
                SignerRecord {
                    id: 1,
                    signer: SignerIdentity::Delegated(format!(
                        "{}",
                        stellar_strkey::ed25519::PublicKey([1; 32])
                    )),
                    reference_count: 2,
                },
            )]),
            policies: BTreeMap::from([
                (
                    7,
                    PolicyRecord {
                        id: 7,
                        address: format!("{}", stellar_strkey::Contract([7; 32])),
                        reference_count: 1,
                    },
                ),
                (
                    8,
                    PolicyRecord {
                        id: 8,
                        address: format!("{}", stellar_strkey::Contract([8; 32])),
                        reference_count: 1,
                    },
                ),
            ]),
        }
    }

    fn bounds() -> ReconciliationBounds {
        ReconciliationBounds {
            max_scan_ids: 5,
            max_transitive_entries: 5,
        }
    }

    fn check(fixture: &Fixture, bounds: ReconciliationBounds) -> Result<(), ReconciliationError> {
        check_supplied_account_entries(
            &fixture.counters,
            &fixture.slots,
            &fixture.signers,
            &fixture.policies,
            bounds,
        )
    }

    #[test]
    fn complete_supplied_slots_and_closure_pass_structural_checks() {
        assert_eq!(check(&fixture(), bounds()), Ok(()));
        // Removing the last rule leaves the monotonic NextId at one and Count at zero.
        let all_removed = Fixture {
            counters: InstanceCounters {
                wasm_hash: ozpb_domain::Hash32([9; 32]),
                next_id: Some(1),
                count: Some(0),
            },
            slots: BTreeMap::from([(0, None)]),
            signers: BTreeMap::new(),
            policies: BTreeMap::new(),
        };
        assert_eq!(check(&all_removed, bounds()), Ok(()));
    }

    #[test]
    fn counters_and_every_rule_slot_are_required() {
        let mut input = fixture();
        input.counters.next_id = None;
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::MissingCounters)
        );

        // A newly deployed account can have neither counter. This internal check
        // deliberately refuses that shape until a trusted reader handles the pinned
        // release's default and proves the account has no unseen rules.
        let mut input = fixture();
        input.counters.next_id = None;
        input.counters.count = None;
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::MissingCounters)
        );

        let mut input = fixture();
        input.slots.remove(&1);
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::MissingRuleSlot(1))
        );

        let mut input = fixture();
        input.slots.insert(3, None);
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::UnexpectedRuleSlot(3))
        );

        let mut input = fixture();
        input.slots.get_mut(&0).unwrap().as_mut().unwrap().id = 4;
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::RuleIdMismatch { slot: 0, record: 4 })
        );
    }

    #[test]
    fn count_reconciles_all_present_rules_including_expired_ones() {
        let mut input = fixture();
        input.counters.count = Some(3);
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::RuleCountMismatch {
                declared: 3,
                decoded: 2,
            })
        );
        let mut input = fixture();
        input.counters.count = Some(4);
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::CountExceedsNextId)
        );
    }

    #[test]
    fn transitive_entries_and_reference_counts_are_exact() {
        let mut input = fixture();
        input.signers.remove(&1);
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::MissingTransitive {
                kind: "signer",
                id: 1,
            })
        );

        let mut input = fixture();
        input.policies.get_mut(&7).unwrap().reference_count = 2;
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::ReferenceCountMismatch {
                kind: "policy",
                id: 7,
                declared: 2,
                observed: 1,
            })
        );

        let mut input = fixture();
        input.policies.get_mut(&8).unwrap().id = 9;
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::TransitiveIdMismatch {
                kind: "policy",
                key: 8,
                record: 9,
            })
        );

        let mut input = fixture();
        input.signers.insert(
            9,
            SignerRecord {
                id: 9,
                signer: SignerIdentity::Delegated(format!(
                    "{}",
                    stellar_strkey::ed25519::PublicKey([9; 32])
                )),
                reference_count: 1,
            },
        );
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::UnexpectedTransitive {
                kind: "signer",
                id: 9,
            })
        );

        let mut input = fixture();
        input
            .slots
            .get_mut(&0)
            .unwrap()
            .as_mut()
            .unwrap()
            .signer_ids
            .push(1);
        assert_eq!(
            check(&input, bounds()),
            Err(ReconciliationError::DuplicateReference {
                rule: 0,
                kind: "signer",
                id: 1,
            })
        );
    }

    #[test]
    fn both_scan_and_transitive_budgets_are_enforced() {
        let mut limit = bounds();
        limit.max_scan_ids = 2;
        assert_eq!(
            check(&fixture(), limit),
            Err(ReconciliationError::ScanBudgetExceeded)
        );
        let mut limit = bounds();
        limit.max_transitive_entries = 2;
        assert_eq!(
            check(&fixture(), limit),
            Err(ReconciliationError::ClosureBudgetExceeded)
        );
    }
}
