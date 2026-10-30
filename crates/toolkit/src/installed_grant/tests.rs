use super::*;
use crate::call_surface_live::tests::fixture;
use crate::plan_call_surface_read;
use crate::test_support::{build_config, registry_trust};
use ozpb_call_surface_core::StoredSignerKey;
use ozpb_source_rpc::{ContextRuleRecord, ContextType, PolicyRecord, SignerIdentity, SignerRecord};

fn installed() -> (
    CallSurfaceReadPlan,
    AccountStateScan,
    AccountStateScan,
    InstalledGrantRule,
) {
    let (input, before) = fixture();
    let plan = plan_call_surface_read(&input, &registry_trust(), &build_config()).unwrap();
    let mut after = before.clone();
    let grant = &plan.prepared.grant;
    let signer_ids: Vec<_> = grant
        .signers
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let id = 10 + i as u32;
            let signer = match key {
                StoredSignerKey::Delegated { address } => {
                    SignerIdentity::Delegated(address.clone())
                }
                StoredSignerKey::External { verifier, key_hex } => SignerIdentity::External {
                    verifier: verifier.clone(),
                    key: hex::decode(key_hex).unwrap(),
                },
            };
            after.signers.insert(
                id,
                SignerRecord {
                    id,
                    signer,
                    reference_count: 1,
                },
            );
            id
        })
        .collect();
    let policy_ids: Vec<_> = grant
        .policies
        .iter()
        .enumerate()
        .map(|(i, policy)| {
            let id = 20 + i as u32;
            after.policies.insert(
                id,
                PolicyRecord {
                    id,
                    address: policy.address.clone(),
                    reference_count: 1,
                },
            );
            id
        })
        .collect();
    let expected = InstalledGrantRule {
        id: 1,
        name: grant.name.clone(),
        context_contract: grant.target.clone(),
        valid_until: grant.valid_until,
        signer_ids: signer_ids.clone(),
        policy_ids: policy_ids.clone(),
    };
    after.rules.insert(
        1,
        ContextRuleRecord {
            id: 1,
            name: expected.name.clone(),
            context_type: ContextType::CallContract(expected.context_contract.clone()),
            valid_until: expected.valid_until,
            signer_ids,
            policy_ids,
        },
    );
    after.next_id = 2;
    after.extant_count = 2;
    (plan, before, after, expected)
}

#[test]
fn exact_last_install_round_trips_to_original_authority_without_weakening_install_checks() {
    let (plan, before, after, expected) = installed();
    let original = finish_call_surface_check(&plan, "fixture", &before).unwrap();
    let current = finish_call_surface_check(&plan, "fixture", &after).unwrap();
    assert!(
        !current.verdict.refusals.is_empty(),
        "ordinary check still refuses the installed overlap"
    );
    let observed = check_installed_grant_from_scan(&plan, "fixture", &after, &expected).unwrap();
    assert_eq!(observed.status, "observed");
    assert_ne!(
        observed.actual_account_state_digest,
        original.verdict.authority_state.ordered_state_digest
    );
    let projected = observed.projected_authority.unwrap();
    assert_eq!(
        projected.verdict.authority_commitment,
        original.verdict.authority_commitment
    );
    assert!(projected.verdict.refusals.is_empty() && projected.verdict.unresolved.is_empty());
    assert_eq!(
        serde_json::to_value(projected.verdict.evidence.enumeration_evidence).unwrap(),
        serde_json::to_value(current.verdict.evidence.enumeration_evidence).unwrap(),
        "evidence remains of the actual unmodified scan"
    );
}

#[test]
fn shared_signer_and_policy_closure_is_preserved() {
    let (plan, mut before, mut after, expected) = installed();
    // Another policy-constrained rule on an unrelated target shares these registry entries.
    let mut shared = after.rules[&1].clone();
    shared.id = 0;
    shared.context_type =
        ContextType::CallContract(format!("{}", stellar_strkey::Contract([90; 32])));
    before.rules.insert(0, shared.clone());
    after.rules.insert(0, shared);
    before.signers = after.signers.clone();
    before.signers.remove(&0);
    before.policies = after.policies.clone();
    after.signers.remove(&0);
    for signer in after.signers.values_mut() {
        signer.reference_count = 2;
    }
    for policy in after.policies.values_mut() {
        policy.reference_count = 2;
    }
    let original = finish_call_surface_check(&plan, "fixture", &before).unwrap();
    let projected = check_installed_grant_from_scan(&plan, "fixture", &after, &expected)
        .unwrap()
        .projected_authority
        .unwrap();
    assert_eq!(
        projected.verdict.authority_commitment,
        original.verdict.authority_commitment
    );
}

#[test]
fn changed_recorded_ids_and_semantics_are_not_hidden_by_projection() {
    for mode in [
        "ids",
        "name",
        "context",
        "expiry",
        "missing",
        "later_allocation",
        "expected_ids",
    ] {
        let (plan, _, mut after, mut expected) = installed();
        match mode {
            "ids" => {
                let entry = after.signers.remove(&10).unwrap();
                after.signers.insert(11, SignerRecord { id: 11, ..entry });
                after.rules.get_mut(&1).unwrap().signer_ids[0] = 11;
            }
            "name" => after.rules.get_mut(&1).unwrap().name.push('x'),
            "context" => after.rules.get_mut(&1).unwrap().context_type = ContextType::Default,
            "expiry" => after.rules.get_mut(&1).unwrap().valid_until = Some(1),
            "missing" => {
                after = fixture().1;
                after.next_id = 2;
            }
            "later_allocation" => after.next_id = 3,
            "expected_ids" => expected.policy_ids.reverse(),
            _ => unreachable!(),
        }
        let observed =
            check_installed_grant_from_scan(&plan, "fixture", &after, &expected).unwrap();
        assert_eq!(observed.status, "changed", "{mode}");
        assert!(observed.projected_authority.is_none());
    }
}

#[test]
fn complete_actual_scan_is_validated_before_any_rule_can_be_hidden() {
    let (plan, _, mut after, expected) = installed();
    after.signers.remove(&10);
    assert!(check_installed_grant_from_scan(&plan, "fixture", &after, &expected).is_err());
    let (plan, _, mut after, expected) = installed();
    after.extant_count += 1;
    assert!(check_installed_grant_from_scan(&plan, "fixture", &after, &expected).is_err());
}

#[test]
fn authority_and_code_mutations_remain_visible_and_no_new_baseline_is_adopted() {
    let (plan, before, mut after, expected) = installed();
    let original = finish_call_surface_check(&plan, "fixture", &before).unwrap();
    after.rules.get_mut(&0).unwrap().valid_until = Some(after.reported_latest_ledger.0 - 1);
    let projected = check_installed_grant_from_scan(&plan, "fixture", &after, &expected)
        .unwrap()
        .projected_authority
        .unwrap();
    assert_ne!(
        projected.verdict.authority_commitment,
        original.verdict.authority_commitment
    );
    let (plan, _, mut after, expected) = installed();
    after.account_wasm_hash = ozpb_domain::Hash32([0x55; 32]);
    assert!(check_installed_grant_from_scan(&plan, "fixture", &after, &expected).is_err());
    let (plan, _, mut after, expected) = installed();
    after.observed_code_hashes.insert(
        expected.context_contract.clone(),
        ozpb_domain::Hash32([0x66; 32]),
    );
    after.observed_code_hashes.insert(
        plan.prepared.grant.policies[0].address.clone(),
        ozpb_domain::Hash32([0x66; 32]),
    );
    assert!(check_installed_grant_from_scan(&plan, "fixture", &after, &expected).is_err());
}

#[test]
fn an_exact_but_expired_installed_rule_is_inactive_not_unchanged() {
    let (mut plan, _, mut after, mut expected) = installed();
    let until = after.reported_latest_ledger.0 - 1;
    plan.prepared.grant.valid_until = Some(until);
    expected.valid_until = Some(until);
    after.rules.get_mut(&1).unwrap().valid_until = Some(until);
    let result = check_installed_grant_from_scan(&plan, "fixture", &after, &expected).unwrap();
    assert_eq!(result.reason.as_deref(), Some("installed_rule_expired"));
    assert_eq!(result.status, "observed");
    assert!(result.projected_authority.is_some());
}

#[test]
fn candidate_classic_signer_configuration_is_not_pruned_with_the_stored_signer() {
    let (plan, before, mut after, expected) = installed();
    let original = finish_call_surface_check(&plan, "fixture", &before).unwrap();
    let StoredSignerKey::Delegated { address } = &plan.prepared.grant.signers[0] else {
        panic!("classic fixture");
    };
    let ozpb_call_surface_core::ClassicAccount::Found {
        medium_threshold, ..
    } = after.classic_accounts.get_mut(address).unwrap()
    else {
        panic!("funded fixture");
    };
    *medium_threshold = 2;
    let observed = check_installed_grant_from_scan(&plan, "fixture", &after, &expected).unwrap();
    let projected = observed.projected_authority.unwrap();
    assert!(projected
        .verdict
        .authority_state
        .classic_accounts
        .contains_key(address));
    assert_ne!(
        projected.verdict.authority_commitment,
        original.verdict.authority_commitment
    );
}

#[test]
fn expiry_does_not_hide_candidate_classic_authority_drift() {
    let (mut plan, before, mut after, mut expected) = installed();
    let until = after.reported_latest_ledger.0 - 1;
    plan.prepared.grant.valid_until = Some(until);
    expected.valid_until = Some(until);
    after.rules.get_mut(&1).unwrap().valid_until = Some(until);
    let original = finish_call_surface_check(&plan, "fixture", &before).unwrap();
    let clean = check_installed_grant_from_scan(&plan, "fixture", &after, &expected).unwrap();
    assert_eq!(clean.reason.as_deref(), Some("installed_rule_expired"));
    assert_eq!(
        clean
            .projected_authority
            .unwrap()
            .verdict
            .authority_commitment,
        original.verdict.authority_commitment
    );
    let StoredSignerKey::Delegated { address } = &plan.prepared.grant.signers[0] else {
        panic!("classic fixture");
    };
    let ozpb_call_surface_core::ClassicAccount::Found {
        medium_threshold, ..
    } = after.classic_accounts.get_mut(address).unwrap()
    else {
        panic!("funded fixture");
    };
    *medium_threshold = 2;
    let observed = check_installed_grant_from_scan(&plan, "fixture", &after, &expected).unwrap();
    assert_eq!(observed.reason.as_deref(), Some("installed_rule_expired"));
    assert_ne!(
        observed
            .projected_authority
            .unwrap()
            .verdict
            .authority_commitment,
        original.verdict.authority_commitment
    );
}

#[test]
fn installed_policy_addresses_are_matched_independently_of_spec_order() {
    let (mut plan, before, after, expected) = installed();
    assert!(
        plan.prepared.grant.policies.len() > 1,
        "exercise actual order difference"
    );
    plan.prepared.grant.policies.reverse();
    let original = finish_call_surface_check(&plan, "fixture", &before).unwrap();
    let observed = check_installed_grant_from_scan(&plan, "fixture", &after, &expected).unwrap();
    assert_eq!(observed.status, "observed");
    assert_eq!(
        observed
            .projected_authority
            .unwrap()
            .verdict
            .authority_commitment,
        original.verdict.authority_commitment
    );
}
