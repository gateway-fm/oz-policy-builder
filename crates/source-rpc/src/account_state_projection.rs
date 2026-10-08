//! Structural projection of a bounded account scan into the pure authority model.
//!
//! A scan remains endpoint-reported and caller-constructible. This module neither
//! authenticates a coherent ledger snapshot nor designates the wallet's administrator.
//! Its fingerprints identify observed eligible rules so a future trusted wallet binding
//! can compare its own intended identity with the scanned state.

use super::{
    account_reconciliation::{check_supplied_account_entries, ReconciliationBounds},
    AccountStateScan, ContextType, InstanceCounters, SignerIdentity,
};
use ozpb_call_surface_core::{
    AccountState, StoredContextType, StoredPolicy, StoredRule, StoredSigner, StoredSignerKey,
};
use ozpb_domain::{canonical_hash, domains, Hash32, LedgerSeq, NetworkId};
use std::collections::BTreeMap;

/// A rule that could be designated by separately authenticated wallet intent.
/// Eligibility is only structural: active, management-capable, policy-free, and backed
/// by nonexternal signers. It grants no authority verdict on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminRuleCandidate {
    pub rule_id: u32,
    pub observed_fingerprint: Hash32,
    /// (Signer storage ID, canonical delegated address), ordered by ID.
    pub delegated_signers: Vec<(u32, String)>,
}

/// Checked mapping of one scan into the pure model, without an administrator choice.
/// The source scan's provenance and ledger limitations remain in force.
#[derive(Clone, Debug)]
pub struct AccountStateProjection {
    pub network_id: NetworkId,
    pub account_address: String,
    pub reported_latest_ledger: LedgerSeq,
    pub account_wasm_hash: Hash32,
    /// Hash of validated raw entry payloads, keys, TTL metadata, and requested absences.
    /// This is an endpoint-observation identity, not a cryptographic ledger proof.
    pub raw_ordered_entry_digest: Hash32,
    /// Canonical hash of the decoded `AccountState` model. TTLs and unmodeled storage
    /// fields are absent here, so it must never replace `raw_ordered_entry_digest`.
    pub decoded_state_digest: Hash32,
    pub account_state: AccountState,
    pub admin_candidates: Vec<AdminRuleCandidate>,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountProjectionError {
    #[error("E_INCOMPLETE_ACCOUNT_STATE: invalid scan identity or ledger: {0}")]
    Identity(&'static str),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: inconsistent account closure: {0}")]
    Closure(String),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: no observed code for installed policy {0}")]
    MissingPolicyCode(String),
    #[error("E_INTERNAL: account projection digest: {0}")]
    Digest(String),
}

/// Reconcile a scan again at the model boundary and attach observed code to every
/// installed policy. The result is data for a later authenticated check, never `Safe`.
pub fn project_account_state(
    scan: &AccountStateScan,
) -> Result<AccountStateProjection, AccountProjectionError> {
    let account = scan
        .account_address
        .parse::<stellar_strkey::Contract>()
        .map_err(|_| AccountProjectionError::Identity("invalid account C-address"))?;
    if scan.account_address != format!("{account}") {
        return Err(AccountProjectionError::Identity(
            "noncanonical account C-address",
        ));
    }
    if scan.reported_latest_ledger.0 == 0 {
        return Err(AccountProjectionError::Identity("zero observed ledger"));
    }
    if scan
        .observed_code_hashes
        .get(&scan.account_address)
        .is_some_and(|hash| *hash != scan.account_wasm_hash)
    {
        return Err(AccountProjectionError::Identity(
            "conflicting account code identity",
        ));
    }
    if scan.next_id > 10_000 {
        return Err(AccountProjectionError::Identity(
            "NextId exceeds scan ceiling",
        ));
    }
    if let Some(id) = scan.rules.keys().find(|&&id| id >= scan.next_id) {
        return Err(AccountProjectionError::Closure(format!(
            "rule ID {id} is outside 0..NextId"
        )));
    }
    let counters = InstanceCounters {
        wasm_hash: scan.account_wasm_hash,
        next_id: Some(scan.next_id),
        count: Some(scan.extant_count),
    };
    let slots = (0..scan.next_id)
        .map(|id| (id, scan.rules.get(&id).cloned()))
        .collect::<BTreeMap<_, _>>();
    // These are the scanner's implementation ceilings, not caller-chosen evidence.
    check_supplied_account_entries(
        &counters,
        &slots,
        &scan.signers,
        &scan.policies,
        ReconciliationBounds {
            max_scan_ids: 10_000,
            max_transitive_entries: 10_000,
        },
    )
    .map_err(|error| AccountProjectionError::Closure(error.to_string()))?;

    let rules = scan
        .rules
        .iter()
        .map(|(&id, rule)| {
            let context_type = match &rule.context_type {
                ContextType::Default => StoredContextType::Default,
                ContextType::CallContract(address) => StoredContextType::CallContract {
                    address: address.clone(),
                },
                ContextType::CreateContract(hash) => StoredContextType::CreateContract {
                    wasm_hash: Hash32(*hash).to_hex(),
                },
            };
            (
                id,
                StoredRule {
                    id,
                    context_type,
                    valid_until: rule.valid_until,
                    signer_ids: rule.signer_ids.clone(),
                    policy_ids: rule.policy_ids.clone(),
                },
            )
        })
        .collect();
    let signers = scan
        .signers
        .iter()
        .map(|(&id, record)| {
            let key = match &record.signer {
                SignerIdentity::Delegated(address) => StoredSignerKey::Delegated {
                    address: address.clone(),
                },
                SignerIdentity::External { verifier, key } => StoredSignerKey::External {
                    verifier: verifier.clone(),
                    key_hex: hex::encode(key),
                },
            };
            (id, StoredSigner { id, key })
        })
        .collect();
    let policies = scan
        .policies
        .iter()
        .map(|(&id, record)| {
            let observed = scan
                .observed_code_hashes
                .get(&record.address)
                .ok_or_else(|| AccountProjectionError::MissingPolicyCode(record.address.clone()))?;
            Ok((
                id,
                StoredPolicy {
                    id,
                    address: record.address.clone(),
                    observed_wasm_hash: observed.to_hex(),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AccountProjectionError>>()?;

    let mut admin_candidates = Vec::new();
    for (&id, rule) in &scan.rules {
        if rule
            .valid_until
            .is_some_and(|until| scan.reported_latest_ledger.0 > until)
            || !rule.policy_ids.is_empty()
            || rule.signer_ids.is_empty()
        {
            continue;
        }
        let scope = match &rule.context_type {
            ContextType::Default => "default",
            ContextType::CallContract(address) if address == &scan.account_address => {
                "call_account"
            }
            _ => continue,
        };
        let mut signer_entries = Vec::new();
        for signer_id in &rule.signer_ids {
            let Some(signer) = scan.signers.get(signer_id) else {
                // Reconciliation above requires this entry; retain a hard failure if
                // the model and that invariant ever drift apart.
                return Err(AccountProjectionError::Identity("missing candidate signer"));
            };
            let SignerIdentity::Delegated(address) = &signer.signer else {
                signer_entries.clear();
                break;
            };
            signer_entries.push((*signer_id, address.clone()));
        }
        if signer_entries.is_empty() {
            continue;
        }
        signer_entries.sort_by_key(|(id, _)| *id);
        let preimage = serde_json::json!({
            "network_id": scan.network_id.0.to_hex(),
            "account_address": scan.account_address,
            "rule_id": id,
            "scope": scope,
            "valid_until": rule.valid_until,
            "signer_entries": signer_entries,
        });
        let observed_fingerprint = canonical_hash(domains::ACCOUNT_ADMIN_CANDIDATE, &preimage)
            .map_err(|error| AccountProjectionError::Digest(error.to_string()))?;
        admin_candidates.push(AdminRuleCandidate {
            rule_id: id,
            observed_fingerprint,
            delegated_signers: signer_entries,
        });
    }
    let account_state = AccountState {
        next_id: scan.next_id,
        // The core's historical field name means the stored nonremoved Count,
        // which also includes expired rules.
        active_count: scan.extant_count,
        rules,
        signers,
        policies,
    };
    let decoded_state_digest = canonical_hash(domains::ACCOUNT_STATE, &account_state)
        .map_err(|error| AccountProjectionError::Digest(error.to_string()))?;
    Ok(AccountStateProjection {
        network_id: scan.network_id,
        account_address: scan.account_address.clone(),
        reported_latest_ledger: scan.reported_latest_ledger,
        account_wasm_hash: scan.account_wasm_hash,
        raw_ordered_entry_digest: scan.ordered_entry_digest,
        decoded_state_digest,
        account_state,
        admin_candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContextRuleRecord, PolicyRecord, SignerRecord};
    use ozpb_domain::{LedgerSeq, NetworkId};

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn scan() -> AccountStateScan {
        AccountStateScan {
            network_id: NetworkId(Hash32([3; 32])),
            account_address: address(7),
            reported_latest_ledger: LedgerSeq(10),
            account_wasm_hash: Hash32([9; 32]),
            next_id: 3,
            extant_count: 2,
            rules: BTreeMap::from([
                (
                    0,
                    ContextRuleRecord {
                        id: 0,
                        name: "admin".into(),
                        context_type: ContextType::Default,
                        valid_until: None,
                        signer_ids: vec![10],
                        policy_ids: vec![],
                    },
                ),
                (
                    2,
                    ContextRuleRecord {
                        id: 2,
                        name: "other".into(),
                        context_type: ContextType::CallContract(address(8)),
                        valid_until: None,
                        signer_ids: vec![10],
                        policy_ids: vec![11],
                    },
                ),
            ]),
            signers: BTreeMap::from([(
                10,
                SignerRecord {
                    id: 10,
                    signer: SignerIdentity::Delegated(address(12)),
                    reference_count: 2,
                },
            )]),
            policies: BTreeMap::from([(
                11,
                PolicyRecord {
                    id: 11,
                    address: address(13),
                    reference_count: 1,
                },
            )]),
            observed_code_hashes: BTreeMap::from([(address(13), Hash32([14; 32]))]),
            ordered_entry_digest: Hash32([20; 32]),
            rpc_batches: 4,
            attempts: 1,
        }
    }

    #[test]
    fn projection_preserves_closure_and_lists_observed_candidates() {
        let scan = scan();
        let projection = project_account_state(&scan).unwrap();
        assert_eq!(projection.network_id, scan.network_id);
        assert_eq!(projection.account_address, scan.account_address);
        assert_eq!(
            projection.reported_latest_ledger,
            scan.reported_latest_ledger
        );
        assert_eq!(projection.account_wasm_hash, scan.account_wasm_hash);
        assert_eq!(
            projection.raw_ordered_entry_digest,
            scan.ordered_entry_digest
        );
        assert_eq!(projection.account_state.rules.len(), 2);
        assert_eq!(
            projection.account_state.policies[&11].observed_wasm_hash,
            Hash32([14; 32]).to_hex()
        );
        assert_eq!(projection.admin_candidates.len(), 1);
        assert_eq!(projection.admin_candidates[0].rule_id, 0);
        assert_eq!(
            projection.admin_candidates[0].delegated_signers,
            vec![(10, address(12))]
        );

        let mut renamed = scan.clone();
        renamed.rules.get_mut(&0).unwrap().name = "display only".into();
        assert_eq!(
            projection.admin_candidates[0].observed_fingerprint,
            project_account_state(&renamed).unwrap().admin_candidates[0].observed_fingerprint
        );
        let mut other_network = scan.clone();
        other_network.network_id = NetworkId(Hash32([4; 32]));
        assert_ne!(
            projection.admin_candidates[0].observed_fingerprint,
            project_account_state(&other_network)
                .unwrap()
                .admin_candidates[0]
                .observed_fingerprint
        );
        let mut other_account = scan.clone();
        other_account.account_address = address(6);
        assert_ne!(
            projection.admin_candidates[0].observed_fingerprint,
            project_account_state(&other_account)
                .unwrap()
                .admin_candidates[0]
                .observed_fingerprint
        );
        let mut reused_address = scan.clone();
        reused_address.rules.get_mut(&0).unwrap().signer_ids = vec![20];
        let signer = reused_address.signers.get_mut(&10).unwrap();
        signer.reference_count = 1;
        let identity = signer.signer.clone();
        reused_address.signers.insert(
            20,
            SignerRecord {
                id: 20,
                signer: identity,
                reference_count: 1,
            },
        );
        assert_ne!(
            projection.admin_candidates[0].observed_fingerprint,
            project_account_state(&reused_address)
                .unwrap()
                .admin_candidates[0]
                .observed_fingerprint
        );

        let mut changed = scan;
        changed.rules.get_mut(&0).unwrap().valid_until = Some(20);
        assert_ne!(
            projection.admin_candidates[0].observed_fingerprint,
            project_account_state(&changed).unwrap().admin_candidates[0].observed_fingerprint
        );
    }

    #[test]
    fn missing_policy_code_and_inconsistent_closure_are_refused() {
        let mut missing = scan();
        missing.observed_code_hashes.clear();
        assert!(matches!(
            project_account_state(&missing),
            Err(AccountProjectionError::MissingPolicyCode(_))
        ));

        let mut conflicting = scan();
        conflicting
            .observed_code_hashes
            .insert(conflicting.account_address.clone(), Hash32([42; 32]));
        assert!(matches!(
            project_account_state(&conflicting),
            Err(AccountProjectionError::Identity(
                "conflicting account code identity"
            ))
        ));

        let mut inconsistent = scan();
        inconsistent.signers.get_mut(&10).unwrap().reference_count = 1;
        assert!(matches!(
            project_account_state(&inconsistent),
            Err(AccountProjectionError::Closure(_))
        ));

        let mut oversized = scan();
        oversized.next_id = u32::MAX;
        assert!(matches!(
            project_account_state(&oversized),
            Err(AccountProjectionError::Identity(
                "NextId exceeds scan ceiling"
            ))
        ));

        let mut forged_rule = scan();
        let mut extra = forged_rule.rules[&0].clone();
        extra.id = 3;
        forged_rule.rules.insert(3, extra);
        assert!(matches!(
            project_account_state(&forged_rule),
            Err(AccountProjectionError::Closure(message)) if message.contains("outside 0..NextId")
        ));
    }

    #[test]
    fn ambiguous_or_external_management_rules_are_not_designated() {
        let mut ambiguous = scan();
        ambiguous.rules.get_mut(&2).unwrap().context_type = ContextType::Default;
        ambiguous.rules.get_mut(&2).unwrap().policy_ids.clear();
        ambiguous.policies.clear();
        let candidates = project_account_state(&ambiguous).unwrap().admin_candidates;
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.rule_id)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );

        let mut external = scan();
        external.signers.get_mut(&10).unwrap().signer = SignerIdentity::External {
            verifier: address(15),
            key: vec![1, 2],
        };
        assert!(project_account_state(&external)
            .unwrap()
            .admin_candidates
            .is_empty());
    }
}
