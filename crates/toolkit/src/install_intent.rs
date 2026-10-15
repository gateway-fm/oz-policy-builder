//! The install intent: the exact `add_context_rule` arguments for one spec rule, offered only
//! with the live authority answer they were checked against.
//!
//! It runs the authority check itself — there is no caller-supplied verdict to trust — and
//! derives every argument from the same `grant` the answer's commitment covers, so what the
//! wallet is asked to sign and what was checked cannot differ. A refusal or an unresolved item
//! is an error carrying every finding. It never says "safe": the wallet that holds the owner key
//! recomputes the answer, matches the listed owners, and decides.

use super::call_surface_live::{
    finish_call_surface_check, plan_call_surface_read, CallSurfaceReadPlan,
};
use super::{from_value, RegistryTrust};
use ozpb_api_types::{
    ErrorCode as EC, InstallOperation, InstallPolicy, PolicySurfaceFinding,
    PrepareInstallIntentInput, PrepareInstallIntentOutput, ToolError,
};
use ozpb_policy_spec::PolicySpec;
use ozpb_source_rpc::AccountStateScan;

/// Plan the read for an install intent. Beyond the check's own plan, the new rule must not
/// target the account itself or a policy bound for this spec: refused here, before any build
/// or read, with a fixed code (the check would refuse it too, after reading).
pub fn plan_install_intent_read(
    input: &PrepareInstallIntentInput,
    registry_trust: &RegistryTrust,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<CallSurfaceReadPlan, ToolError> {
    // The target as the request states it, before the plan rebuilds generated policies. A spec
    // that does not parse is left to the plan, which names what is wrong with it. On a request
    // that is also invalid in another way, this code can take the place of the plan's.
    if let Ok(spec) = from_value::<PolicySpec>(&input.spec) {
        if let Some(rule) = spec.rules.get(input.rule_index) {
            guard_target(&rule.context.contract, input)?;
        }
    }
    let plan = plan_call_surface_read(input, registry_trust, build_config)?;
    guard_target(plan.grant_target(), input)?;
    Ok(plan)
}

fn guard_target(target: &str, input: &PrepareInstallIntentInput) -> Result<(), ToolError> {
    if target == input.account_address {
        return Err(ToolError::new(
            EC::EUnsafeManagementSurface,
            "the new rule targets the account itself, so it would let the agent call the \
             account's management methods",
        ));
    }
    if input
        .binding_set
        .bindings
        .iter()
        .any(|binding| binding.contract_address == target)
    {
        return Err(ToolError::new(
            EC::EUnsafeCallSurface,
            "the new rule targets a policy bound for this spec, so the agent could reset or \
             uninstall it",
        ));
    }
    Ok(())
}

/// The code an intent refusal carries: fixed by priority, never by finding order. Any refusal
/// outranks unresolved evidence, which alone is incomplete state. A refusal code outside the
/// list (none today) still yields the same answer for any order: the least by name.
fn refusal_code(refusals: &[PolicySurfaceFinding]) -> EC {
    const PRIORITY: [EC; 5] = [
        EC::EDelegateHasAuthority,
        EC::EUnsafeManagementSurface,
        EC::EUnsafeCallSurface,
        EC::EDelegateGrantOverlap,
        EC::EUnsupportedAuthority,
    ];
    PRIORITY
        .into_iter()
        .find(|code| refusals.iter().any(|finding| finding.code == *code))
        .or_else(|| {
            refusals
                .iter()
                .map(|finding| finding.code)
                .min_by_key(|code| code.as_str())
        })
        .unwrap_or(EC::EIncompleteAccountState)
}

/// One line per finding: code, rule, the refused shape when there is one, reason and fix.
fn detail_line(finding: &PolicySurfaceFinding) -> String {
    let rule = finding
        .rule_id
        .map_or_else(|| "the new rule".to_string(), |id| format!("rule {id}"));
    let shape = finding
        .unsupported
        .and_then(|reason| serde_json::to_value(reason).ok())
        .and_then(|value| value.as_str().map(|name| format!(" [{name}]")))
        .unwrap_or_default();
    format!(
        "{} ({rule}){shape}: {}. Fix: {}",
        finding.code.as_str(),
        finding.reason.trim_end_matches('.'),
        finding.remediation
    )
}

/// Run the check over one scan and, only when nothing is refused or unresolved, derive the
/// install arguments.
pub fn prepare_install_intent_from_scan(
    plan: &CallSurfaceReadPlan,
    source_name: &str,
    scan: &AccountStateScan,
) -> Result<PrepareInstallIntentOutput, ToolError> {
    let authority = finish_call_surface_check(plan, source_name, scan)?;
    let authority = &authority;
    let verdict = &authority.verdict;
    if !verdict.refusals.is_empty() || !verdict.unresolved.is_empty() {
        let findings: Vec<PolicySurfaceFinding> = verdict
            .refusals
            .iter()
            .chain(&verdict.unresolved)
            .cloned()
            .collect();
        return Err(ToolError::new(
            refusal_code(&verdict.refusals),
            "the authority check did not clear this install; there is nothing to sign",
        )
        .with_details(findings.iter().map(detail_line).collect()));
    }
    let grant = &verdict.grant;
    if grant
        .valid_until
        .is_some_and(|until| until <= verdict.observed_ledger)
    {
        return Err(ToolError::new(
            EC::ESpecInvalid,
            "the rule expires at or before the ledger the account was read at",
        ));
    }
    Ok(PrepareInstallIntentOutput {
        operation: InstallOperation::AddContextRule,
        account_contract: verdict.account_address.clone(),
        context_contract: grant.target.clone(),
        rule_name: grant.name.clone(),
        valid_until_ledger: grant.valid_until,
        delegate_signers: grant.signers.clone(),
        policies: grant
            .policies
            .iter()
            .enumerate()
            .map(|(policy_index, policy)| InstallPolicy {
                policy_index,
                address: policy.address.clone(),
                install_params: policy.install_params.clone(),
            })
            .collect(),
        next_steps: vec![
            "Check that these arguments equal `authority.verdict.grant` and the grant the \
             wallet's own re-run of the check reports; any difference means do not sign"
                .to_string(),
            "Advisory: the wallet that holds the owner key must re-run this check against its own \
             RPC, match every rule in `authority.verdict.authority_list` to its own keys or \
             identities its user trusts, and re-read immediately before signing; the \
             authority_commitment must not change"
                .to_string(),
            "The wallet assembles, simulates and signs the transaction; this intent does not \
             assemble or submit one"
                .to_string(),
        ],
        authority: authority.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_surface_live::tests::fixture;
    use crate::test_support::{build_config, registry_trust};
    use ozpb_domain::LedgerSeq;

    #[test]
    fn a_clear_answer_yields_the_exact_arguments_it_committed_to() {
        let (input, scan) = fixture();
        let plan = plan_install_intent_read(&input, &registry_trust(), &build_config()).unwrap();
        let intent = prepare_install_intent_from_scan(&plan, "testnet", &scan).unwrap();
        let grant = &intent.authority.verdict.grant;
        assert!(matches!(intent.operation, InstallOperation::AddContextRule));
        assert_eq!(intent.account_contract, input.account_address);
        assert_eq!(intent.context_contract, grant.target);
        assert_eq!(intent.rule_name, grant.name);
        assert_eq!(intent.valid_until_ledger, grant.valid_until);
        assert_eq!(intent.delegate_signers, grant.signers);
        let addresses: Vec<&str> = intent.policies.iter().map(|p| p.address.as_str()).collect();
        let mut bound: Vec<_> = input
            .binding_set
            .bindings
            .iter()
            .filter(|binding| binding.rule_index == input.rule_index)
            .collect();
        bound.sort_by_key(|binding| binding.policy_index);
        let bound: Vec<&str> = bound
            .iter()
            .map(|binding| binding.contract_address.as_str())
            .collect();
        assert_eq!(addresses, bound);
        let committed: Vec<&str> = grant.policies.iter().map(|p| p.address.as_str()).collect();
        assert_eq!(addresses, committed);
        assert!(intent
            .policies
            .iter()
            .enumerate()
            .all(|(i, p)| p.policy_index == i));
        let text = serde_json::to_string(&intent).unwrap().to_lowercase();
        assert!(
            !text
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|word| word == "safe"),
            "the intent never calls anything safe"
        );
    }

    #[test]
    fn a_refusal_is_an_error_carrying_every_finding_with_a_fixed_code() {
        let (input, mut scan) = fixture();
        // The agent's own key on a second Default rule: it could change the account alone.
        let agent = input.spec["rules"][0]["authorization"]["signers"][0]["delegated"]["address"]
            .as_str()
            .unwrap()
            .to_string();
        scan.next_id = 2;
        scan.extant_count = 2;
        scan.rules.insert(
            1,
            ozpb_source_rpc::ContextRuleRecord {
                id: 1,
                name: "agent".into(),
                context_type: ozpb_source_rpc::ContextType::Default,
                valid_until: None,
                signer_ids: vec![1],
                policy_ids: vec![],
            },
        );
        scan.signers.insert(
            1,
            ozpb_source_rpc::SignerRecord {
                id: 1,
                signer: ozpb_source_rpc::SignerIdentity::Delegated(agent),
                reference_count: 1,
            },
        );
        let plan = plan_install_intent_read(&input, &registry_trust(), &build_config()).unwrap();
        let error = prepare_install_intent_from_scan(&plan, "testnet", &scan).unwrap_err();
        assert_eq!(error.code, EC::EDelegateHasAuthority);
        let answer = finish_call_surface_check(&plan, "testnet", &scan).unwrap();
        let findings: Vec<_> = answer
            .verdict
            .refusals
            .iter()
            .chain(&answer.verdict.unresolved)
            .collect();
        assert!(!findings.is_empty());
        assert_eq!(
            error.details.len(),
            findings.len(),
            "every finding is reported"
        );
        for (line, finding) in error.details.iter().zip(&findings) {
            assert!(line.starts_with(finding.code.as_str()) && line.contains("Fix:"));
        }
        assert!(error.details.iter().any(|line| line.contains("rule 1")));
    }

    fn finding(code: EC) -> PolicySurfaceFinding {
        PolicySurfaceFinding {
            code,
            rule_id: Some(7),
            unsupported: None,
            reason: "reason".into(),
            remediation: "remediation".into(),
        }
    }

    #[test]
    fn the_refusal_code_does_not_depend_on_finding_order() {
        let cases = [
            (
                vec![
                    EC::EUnsupportedAuthority,
                    EC::EDelegateGrantOverlap,
                    EC::EDelegateHasAuthority,
                ],
                EC::EDelegateHasAuthority,
            ),
            (
                vec![
                    EC::EUnsupportedAuthority,
                    EC::EUnsafeCallSurface,
                    EC::EUnsafeManagementSurface,
                ],
                EC::EUnsafeManagementSurface,
            ),
            (
                vec![EC::ESpecInvalid, EC::EUnsupportedAuthority],
                EC::EUnsupportedAuthority,
            ),
            // Outside the priority list: the least code by name, whatever the order.
            (
                vec![EC::ESpecInvalid, EC::EPolicyBindingInvalid],
                EC::EPolicyBindingInvalid,
            ),
            // No refusal: what remains is unresolved evidence.
            (vec![], EC::EIncompleteAccountState),
        ];
        for (codes, expected) in cases {
            let forward: Vec<_> = codes.iter().copied().map(finding).collect();
            let mut backward = forward.clone();
            backward.reverse();
            let mut rotated = forward.clone();
            if !rotated.is_empty() {
                rotated.rotate_left(1);
            }
            for findings in [forward, backward, rotated] {
                assert_eq!(refusal_code(&findings), expected, "{codes:?}");
            }
        }
    }

    #[test]
    fn a_detail_line_names_the_refused_shape() {
        let mut unsupported = finding(EC::EUnsupportedAuthority);
        unsupported.unsupported = Some(ozpb_api_types::PolicyUnsupportedReason::ClassicMultisig);
        assert_eq!(
            detail_line(&unsupported),
            "E_UNSUPPORTED_AUTHORITY (rule 7) [classic_multisig]: reason. Fix: remediation"
        );
        let mut about_new_rule = finding(EC::EDelegateGrantOverlap);
        about_new_rule.rule_id = None;
        assert_eq!(
            detail_line(&about_new_rule),
            "E_DELEGATE_GRANT_OVERLAP (the new rule): reason. Fix: remediation"
        );
    }

    #[test]
    fn a_rule_already_expired_at_the_read_ledger_is_refused() {
        let (input, mut scan) = fixture();
        let valid_until = input.spec["rules"][0]["valid_until"]["ledger"]
            .as_u64()
            .expect("the fixture rule expires") as u32;
        let plan = plan_install_intent_read(&input, &registry_trust(), &build_config()).unwrap();
        scan.reported_latest_ledger = LedgerSeq(valid_until - 1);
        assert!(prepare_install_intent_from_scan(&plan, "testnet", &scan).is_ok());
        scan.reported_latest_ledger = LedgerSeq(valid_until);
        assert_eq!(
            prepare_install_intent_from_scan(&plan, "testnet", &scan)
                .unwrap_err()
                .code,
            EC::ESpecInvalid
        );
    }

    #[test]
    fn a_rule_aimed_at_the_account_or_its_policies_is_refused_before_any_build_or_read() {
        let (input, _) = fixture();
        let aimed_at = |target: &str| {
            let mut aimed = input.clone();
            aimed.spec["rules"][input.rule_index]["context"]["contract"] = target.into();
            // The spec no longer matches its bindings, so a plan that got as far as validating
            // them would fail differently: the code shows the guard ran first.
            plan_install_intent_read(&aimed, &registry_trust(), &build_config())
                .err()
                .expect("refused before any build or read")
                .code
        };
        assert_eq!(
            aimed_at(&input.account_address),
            EC::EUnsafeManagementSurface
        );
        let policy = input.binding_set.bindings[1].contract_address.clone();
        assert_eq!(aimed_at(&policy), EC::EUnsafeCallSurface);
        let plan = plan_install_intent_read(&input, &registry_trust(), &build_config()).unwrap();
        assert!(guard_target(plan.grant_target(), &input).is_ok());
    }
}
