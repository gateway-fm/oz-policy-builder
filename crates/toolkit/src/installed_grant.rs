//! Compare a retained installation's preinstallation authority with the current model.
//! Never synthesize a fictitious AccountStateScan or return an install intent.
use crate::call_surface_live::{finish_call_surface_with_state, CallSurfaceReadPlan};
use crate::finish_call_surface_check;
use ozpb_api_types::{CheckInstalledGrantOutput, ErrorCode as EC, InstalledGrantRule, ToolError};
use ozpb_call_surface_core::{AccountState, StoredContextType};
use ozpb_source_rpc::{project_account_state, AccountStateScan};
use std::collections::BTreeSet;

fn without_recorded_grant(
    plan: &CallSurfaceReadPlan,
    scan: &AccountStateScan,
    mut state: AccountState,
    expected: &InstalledGrantRule,
) -> Result<AccountState, &'static str> {
    let grant = &plan.prepared.grant;
    if expected.id == 0 || state.next_id != expected.id.checked_add(1).ok_or("rule_id_overflow")? {
        return Err("later_rule_allocation_or_changed_next_id");
    }
    let raw = scan
        .rules
        .get(&expected.id)
        .ok_or("installed_rule_missing")?;
    let rule = state
        .rules
        .get(&expected.id)
        .ok_or("installed_rule_missing")?;
    if raw.name != expected.name
        || raw.signer_ids != expected.signer_ids
        || raw.policy_ids != expected.policy_ids
        || expected.name != grant.name
        || expected.context_contract != grant.target
        || expected.valid_until != grant.valid_until
        || raw.valid_until != expected.valid_until
        || rule.context_type
            != (StoredContextType::CallContract {
                address: grant.target.clone(),
            })
        || rule.signer_ids.len() != grant.signers.len()
        || rule.policy_ids.len() != grant.policies.len()
    {
        return Err("installed_rule_changed");
    }
    if grant
        .valid_until
        .is_some_and(|until| scan.reported_latest_ledger.0 > until)
    {
        return Err("installed_rule_expired");
    }
    for (id, signer) in rule.signer_ids.iter().zip(&grant.signers) {
        if state.signers.get(id).map(|entry| &entry.key) != Some(signer) {
            return Err("installed_signer_changed");
        }
    }
    for (id, policy) in rule.policy_ids.iter().zip(&grant.policies) {
        if state.policies.get(id).map(|entry| &entry.address) != Some(&policy.address) {
            return Err("installed_policy_changed");
        }
    }
    // Prune only closure entries solely referenced by this exact rule. The validated real
    // scan remains untouched; model entries have no storage reference counters to rewrite.
    let removed_signers = rule.signer_ids.clone();
    let removed_policies = rule.policy_ids.clone();
    state.rules.remove(&expected.id);
    state.active_count = state
        .active_count
        .checked_sub(1)
        .ok_or("invalid_rule_count")?;
    state.next_id = expected.id;
    let signers: BTreeSet<_> = state
        .rules
        .values()
        .flat_map(|rule| rule.signer_ids.iter().copied())
        .collect();
    let policies: BTreeSet<_> = state
        .rules
        .values()
        .flat_map(|rule| rule.policy_ids.iter().copied())
        .collect();
    for id in removed_signers {
        if !signers.contains(&id) {
            state.signers.remove(&id);
        }
    }
    for id in removed_policies {
        if !policies.contains(&id) {
            state.policies.remove(&id);
        }
    }
    Ok(state)
}

pub fn check_installed_grant_from_scan(
    plan: &CallSurfaceReadPlan,
    source_name: &str,
    scan: &AccountStateScan,
    expected: &InstalledGrantRule,
) -> Result<CheckInstalledGrantOutput, ToolError> {
    // Validate the entire actual observation, reconciliation, registry/code bindings and
    // time before considering a projection. Ordinary overlap refusals remain unchanged.
    let actual = finish_call_surface_check(plan, source_name, scan)?;
    let projection = project_account_state(scan)
        .map_err(|error| ToolError::new(EC::EIncompleteAccountState, error.to_string()))?;
    let projected = without_recorded_grant(plan, scan, projection.account_state, expected);
    let (status, reason, authority) = match projected {
        Ok(state) => (
            "observed",
            None,
            Some(finish_call_surface_with_state(
                plan,
                source_name,
                scan,
                std::time::SystemTime::now(),
                Some(state),
            )?),
        ),
        Err(reason) => ("changed", Some(reason.to_string()), None),
    };
    Ok(CheckInstalledGrantOutput {
        schema: "ozpb:installed-grant-observation:v1".to_string(),
        installed_rule_id: expected.id,
        status: status.to_string(),
        reason,
        projection:
            "modeled_authority_without_exact_last_installed_rule; not_installation_approval"
                .to_string(),
        observed_ledger: scan.reported_latest_ledger.0,
        actual_account_state_digest: actual.verdict.authority_state.ordered_state_digest,
        actual_raw_entry_digest: scan.ordered_entry_digest.to_hex(),
        projected_authority: authority,
    })
}

#[cfg(test)]
mod tests;
