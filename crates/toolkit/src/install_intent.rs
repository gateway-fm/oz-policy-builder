//! Internal consistency checks for an install-intent draft.
//!
//! A `PrepareInstallIntentInput` is caller-controlled, including its claimed `Safe`
//! authority artifact. These checks catch contradictions and derive exact typed account
//! arguments, but they cannot authenticate ledger acquisition, prove a complete exported-
//! method inventory, or establish freshness. Keep this operation internal until a trusted
//! reader can provide the complete method-level authority evidence.

use super::{from_value, spec_error};
use ozpb_api_types::{
    ErrorCode as EC, InstallOperation, InstallPolicy, InstallPolicyParams, InstallSigner,
    PolicyBindingSet, PolicyCallSurfaceResult, PolicyProtectedSurface, PolicyRecognition,
    PolicyRuleEnumerationEvidence, PrepareInstallIntentInput, PrepareInstallIntentOutput,
    ToolError, POLICY_BINDING_SET_SCHEMA,
};
use ozpb_build_runner::{BuildManifest, BUILD_MANIFEST_SCHEMA};
use ozpb_domain::{domains, Hash32};
use ozpb_policy_spec::{PolicyRef, PolicySpec, ReviewedParams, SignerSpec, ValidatedSpec};
use std::collections::BTreeSet;

/// Construct an untrusted draft only after its submitted fields agree with each other.
///
/// Acceptance here means consistency, not a verified authority check. In particular, the
/// `Safe` value and method list are still supplied by the caller, and this function is not
/// exported from the toolkit. A later trusted acquisition path must establish them before
/// any intent is offered for wallet review.
pub(super) fn draft_install_intent(
    input: &PrepareInstallIntentInput,
) -> Result<PrepareInstallIntentOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errors| spec_error(&errors))?;
    let rule = validated
        .spec()
        .rules
        .get(input.rule_index)
        .ok_or_else(|| ToolError::new(EC::ESpecInvalid, "rule_index is out of range"))?;
    let account_address = validated.spec().smart_account.address.as_str();
    if rule.context.contract == account_address {
        return Err(ToolError::new(
            EC::EUnsafeManagementSurface,
            "selected rule targets the account management surface",
        ));
    }
    let binding_hash = validate_binding_shape(&validated, &input.binding_set)?;
    if input
        .binding_set
        .bindings
        .iter()
        .any(|binding| binding.contract_address == rule.context.contract)
    {
        return Err(unsafe_artifact(
            "selected rule targets a bound policy's direct surface",
        ));
    }
    validate_artifact_consistency(input, &validated, binding_hash)?;

    let policies = rule
        .policies
        .iter()
        .enumerate()
        .map(|(policy_index, policy)| {
            let binding = input
                .binding_set
                .bindings
                .iter()
                .find(|binding| {
                    binding.rule_index == input.rule_index && binding.policy_index == policy_index
                })
                .ok_or_else(|| binding_error("selected rule is missing a policy binding"))?;
            let install_params = match policy {
                PolicyRef::Generated { .. } => InstallPolicyParams::Generated,
                PolicyRef::Reviewed {
                    params:
                        ReviewedParams::SpendingLimit {
                            limit,
                            period_ledgers,
                        },
                    ..
                } => InstallPolicyParams::SpendingLimit {
                    spending_limit: limit.clone(),
                    period_ledgers: *period_ledgers,
                },
            };
            Ok(InstallPolicy {
                policy_index,
                address: binding.contract_address.clone(),
                install_params,
            })
        })
        .collect::<Result<Vec<_>, ToolError>>()?;
    let delegate_signers = rule
        .authorization
        .signers
        .iter()
        .map(|signer| match signer {
            SignerSpec::Delegated { address } => InstallSigner::Delegated {
                address: address.clone(),
            },
            SignerSpec::External {
                verifier, key_hex, ..
            } => InstallSigner::External {
                verifier: verifier.clone(),
                key_hex: key_hex.clone(),
            },
        })
        .collect();

    Ok(PrepareInstallIntentOutput {
        operation: InstallOperation::AddContextRule,
        account_contract: validated.spec().smart_account.address.clone(),
        context_contract: rule.context.contract.clone(),
        rule_name: validated.spec().name.clone(),
        valid_until_ledger: rule.valid_until.as_ref().map(|until| until.ledger.0),
        delegate_signers,
        policies,
        next_steps: vec![
            "A trusted reader must establish complete method-level authority evidence and \
             recheck it immediately before wallet signing; this draft does not prove safety"
                .to_string(),
            "The wallet reviews, assembles and signs the transaction; this draft does not \
             assemble or submit one"
                .to_string(),
        ],
    })
}

fn validate_binding_shape(
    spec: &ValidatedSpec,
    binding_set: &PolicyBindingSet,
) -> Result<Hash32, ToolError> {
    if binding_set.schema != POLICY_BINDING_SET_SCHEMA
        || binding_set.spec_hash != spec.hash().to_hex()
        || binding_set.network_id != spec.spec().network_id.0.to_hex()
    {
        return Err(binding_error(
            "binding set schema/spec/network does not match",
        ));
    }
    let expected: usize = spec
        .spec()
        .rules
        .iter()
        .map(|rule| rule.policies.len())
        .sum();
    if binding_set.bindings.len() != expected {
        return Err(binding_error(
            "binding set does not cover every spec policy",
        ));
    }
    let mut positions = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for binding in &binding_set.bindings {
        let policy = spec
            .spec()
            .rules
            .get(binding.rule_index)
            .and_then(|rule| rule.policies.get(binding.policy_index))
            .ok_or_else(|| binding_error("binding position is out of range"))?;
        if !positions.insert((binding.rule_index, binding.policy_index)) {
            return Err(binding_error("binding position is duplicated"));
        }
        if binding.contract_address == spec.spec().smart_account.address {
            return Err(binding_error(
                "policy binding cannot use the smart account address",
            ));
        }
        if !addresses.insert(&binding.contract_address)
            || !matches!(
                stellar_strkey::Strkey::from_string(&binding.contract_address),
                Ok(stellar_strkey::Strkey::Contract(_))
            )
        {
            return Err(binding_error("policy address is duplicated or invalid"));
        }
        if binding.resolution_reference.trim().is_empty() {
            return Err(binding_error("binding resolution reference is empty"));
        }
        let observed = canonical_hash(&binding.observed_wasm_hash)
            .ok_or_else(|| binding_error("binding code hash is invalid"))?;
        match (policy, &binding.recognition) {
            (PolicyRef::Reviewed { capability, .. }, PolicyRecognition::ReviewedRegistry)
                if *capability == observed => {}
            (
                PolicyRef::Generated {
                    template_family, ..
                },
                PolicyRecognition::VerifiedGeneratedManifest { build_manifest },
            ) => {
                // Local identity checks only. Rebuilding and registry recognition remain
                // responsibilities of the trusted authority check.
                let manifest: BuildManifest = serde_json::from_value(build_manifest.clone())
                    .map_err(|_| binding_error("generated binding manifest is malformed"))?;
                if manifest.schema != BUILD_MANIFEST_SCHEMA
                    || manifest.spec_hash != spec.hash()
                    || manifest.registry_snapshot != spec.spec().registry_snapshot
                    || manifest.rule_index as usize != binding.rule_index
                    || manifest.template_family != *template_family
                    || manifest.wasm_hash != observed
                {
                    return Err(binding_error("generated binding manifest identity differs"));
                }
            }
            _ => {
                return Err(binding_error(
                    "binding recognition differs from its PolicyRef",
                ))
            }
        }
    }
    ozpb_domain::canonical_hash(domains::POLICY_BINDING_SET, binding_set)
        .map_err(|error| ToolError::new(EC::EInternal, error.to_string()))
}

fn validate_artifact_consistency(
    input: &PrepareInstallIntentInput,
    spec: &ValidatedSpec,
    binding_hash: Hash32,
) -> Result<(), ToolError> {
    let artifact = &input.call_surface_check;
    let verdict = &artifact.verdict;
    if artifact.spec_hash != spec.hash().to_hex()
        || artifact.registry_snapshot_root != spec.spec().registry_snapshot.to_hex()
        || artifact.binding_set_hash != binding_hash.to_hex()
        || verdict.binding_set_hash != binding_hash.to_hex()
        || verdict.network_id != spec.spec().network_id.0.to_hex()
        || verdict.account_address != spec.spec().smart_account.address
        || verdict.account_code_hash != spec.spec().smart_account.observed_code_hash.to_hex()
        || verdict.bound_policy_addresses
            != input
                .binding_set
                .bindings
                .iter()
                .map(|binding| binding.contract_address.clone())
                .collect::<Vec<_>>()
    {
        return Err(unsafe_artifact(
            "authority artifact identity differs from the request",
        ));
    }
    if !matches!(&verdict.result, PolicyCallSurfaceResult::Safe) {
        return Err(unsafe_artifact(
            "authority artifact does not claim a Safe result",
        ));
    }
    if verdict.observed_ledger == 0
        || canonical_hash(&verdict.ordered_state_digest).is_none()
        || spec.spec().rules[input.rule_index]
            .valid_until
            .as_ref()
            .is_some_and(|until| until.ledger.0 <= verdict.observed_ledger)
    {
        return Err(unsafe_artifact(
            "authority observation is unanchored or the selected rule already expired",
        ));
    }
    let (next_id, active_count, rule_ids, signer_ids, policy_ids) =
        match &verdict.enumeration_evidence {
            PolicyRuleEnumerationEvidence::BoundedNextId {
                next_id,
                active_count,
                rule_ids,
                signer_ids,
                policy_ids,
            } => (next_id, active_count, rule_ids, signer_ids, policy_ids),
            PolicyRuleEnumerationEvidence::OnchainList { .. } => {
                return Err(ToolError::new(
                    EC::EAccountRuleEnumerationUnsupported,
                    "on-chain list enumeration has no supported trusted reader",
                ));
            }
        };
    if *active_count as usize != rule_ids.len()
        || rule_ids.iter().any(|id| id >= next_id)
        || !strictly_ascending(rule_ids)
        || !strictly_ascending(signer_ids)
        || !strictly_ascending(policy_ids)
    {
        return Err(unsafe_artifact(
            "authority enumeration is internally incomplete",
        ));
    }
    let dominance = &verdict.dominance_evidence;
    if !rule_ids.contains(&dominance.designated_admin_rule_id)
        || canonical_hash(&dominance.admin_rule_fingerprint).is_none()
        || dominance.assessed_rule_ids
            != rule_ids
                .iter()
                .copied()
                .filter(|id| *id != dominance.designated_admin_rule_id)
                .collect::<Vec<_>>()
    {
        return Err(unsafe_artifact(
            "authority dominance omits an enumerated rule",
        ));
    }
    let policy_addresses: BTreeSet<&str> = input
        .binding_set
        .bindings
        .iter()
        .map(|binding| binding.contract_address.as_str())
        .collect();
    let account = spec.spec().smart_account.address.as_str();
    let mut methods = BTreeSet::new();
    let mut covered_policies = BTreeSet::new();
    let mut covered_management = BTreeSet::new();
    for method in &dominance.protected_methods {
        let surface = match &method.surface {
            PolicyProtectedSurface::DirectPolicy => 0,
            PolicyProtectedSurface::AccountManagement => 1,
        };
        if method.function.trim().is_empty()
            || !methods.insert((
                surface,
                method.contract_address.as_str(),
                method.function.as_str(),
            ))
        {
            return Err(unsafe_artifact(
                "protected method entry is empty or duplicated",
            ));
        }
        match &method.surface {
            PolicyProtectedSurface::DirectPolicy
                if policy_addresses.contains(method.contract_address.as_str()) =>
            {
                covered_policies.insert(method.contract_address.as_str());
            }
            PolicyProtectedSurface::AccountManagement if method.contract_address == account => {
                covered_management.insert(method.function.as_str());
            }
            _ => {
                return Err(unsafe_artifact(
                    "protected method names an unrelated surface",
                ))
            }
        }
    }
    // These known methods are a floor, not a claim that the caller-supplied list is
    // complete. The trusted reader must still establish the full binary surface.
    const POLICY_METHODS: [&str; 3] = ["install", "enforce", "uninstall"];
    const ACCOUNT_METHODS: [&str; 11] = [
        "add_context_rule",
        "update_context_rule_name",
        "update_context_rule_valid_until",
        "remove_context_rule",
        "add_signer",
        "remove_signer",
        "add_policy",
        "remove_policy",
        "batch_add_signer",
        "execute",
        "upgrade",
    ];
    if covered_policies != policy_addresses
        || policy_addresses.iter().any(|address| {
            POLICY_METHODS
                .iter()
                .any(|name| !methods.contains(&(0, *address, *name)))
        })
        || ACCOUNT_METHODS
            .iter()
            .any(|name| !covered_management.contains(name))
    {
        return Err(unsafe_artifact(
            "protected method list omits a known method or required surface",
        ));
    }
    Ok(())
}

fn canonical_hash(value: &str) -> Option<Hash32> {
    Hash32::from_hex(value)
        .ok()
        .filter(|hash| hash.to_hex() == value)
}

fn strictly_ascending(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn binding_error(message: impl Into<String>) -> ToolError {
    ToolError::new(EC::EPolicyBindingInvalid, message)
}

fn unsafe_artifact(message: impl Into<String>) -> ToolError {
    ToolError::new(EC::EUnsafeCallSurface, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_code_with_build_config;
    use crate::test_support::{build_config, wire_spec};
    use ozpb_api_types::{
        CheckPolicyCallSurfaceOutput, GenerateCodeInput, PolicyBinding, PolicyCallSurfaceVerdict,
        PolicyDominanceEvidence, PolicyProtectedMethod, PolicyRuleEnumerationEvidence,
    };

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    /// The artifact here is synthetic. Its acceptance proves only the consistency
    /// checks, never that its `Safe` claim or method inventory was observed.
    fn fixture(no_expiry: bool) -> PrepareInstallIntentInput {
        let mut raw = wire_spec().spec().clone();
        if no_expiry {
            raw.rules[0].valid_until = None;
        }
        let spec = raw.validate().unwrap();
        let spec_json = serde_json::to_value(spec.spec()).unwrap();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec_json.clone(),
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap();
        let PolicyRef::Reviewed { capability, .. } = &spec.spec().rules[0].policies[0] else {
            panic!("fixture needs a reviewed policy at index 0");
        };
        let bindings = PolicyBindingSet {
            schema: POLICY_BINDING_SET_SCHEMA.to_string(),
            spec_hash: spec.hash().to_hex(),
            network_id: spec.spec().network_id.0.to_hex(),
            bindings: vec![
                PolicyBinding {
                    rule_index: 0,
                    policy_index: 0,
                    contract_address: address(40),
                    observed_wasm_hash: capability.to_hex(),
                    recognition: PolicyRecognition::ReviewedRegistry,
                    resolution_reference: "reviewed instance".to_string(),
                },
                PolicyBinding {
                    rule_index: 0,
                    policy_index: 1,
                    contract_address: address(41),
                    observed_wasm_hash: generated.wasm_hash,
                    recognition: PolicyRecognition::VerifiedGeneratedManifest {
                        build_manifest: generated.build_manifest,
                    },
                    resolution_reference: "generated instance".to_string(),
                },
            ],
        };
        let binding_hash = ozpb_domain::canonical_hash(domains::POLICY_BINDING_SET, &bindings)
            .unwrap()
            .to_hex();
        let account = spec.spec().smart_account.address.clone();
        let check = CheckPolicyCallSurfaceOutput {
            spec_hash: spec.hash().to_hex(),
            binding_set_hash: binding_hash.clone(),
            registry_snapshot_root: spec.spec().registry_snapshot.to_hex(),
            verdict: PolicyCallSurfaceVerdict {
                observed_ledger: 4_200_000,
                network_id: spec.spec().network_id.0.to_hex(),
                account_address: account.clone(),
                account_code_hash: spec.spec().smart_account.observed_code_hash.to_hex(),
                binding_set_hash: binding_hash,
                bound_policy_addresses: bindings
                    .bindings
                    .iter()
                    .map(|binding| binding.contract_address.clone())
                    .collect(),
                ordered_state_digest: "11".repeat(32),
                enumeration_evidence: PolicyRuleEnumerationEvidence::BoundedNextId {
                    next_id: 2,
                    active_count: 2,
                    rule_ids: vec![0, 1],
                    signer_ids: vec![0],
                    policy_ids: vec![0],
                },
                dominance_evidence: PolicyDominanceEvidence {
                    designated_admin_rule_id: 0,
                    admin_rule_fingerprint: "22".repeat(32),
                    assessed_rule_ids: vec![1],
                    protected_methods: [address(40), address(41)]
                        .into_iter()
                        .flat_map(|contract_address| {
                            ["install", "enforce", "uninstall"].map(|function| {
                                PolicyProtectedMethod {
                                    surface: PolicyProtectedSurface::DirectPolicy,
                                    contract_address: contract_address.clone(),
                                    function: function.to_string(),
                                }
                            })
                        })
                        .chain(
                            [
                                "add_context_rule",
                                "update_context_rule_name",
                                "update_context_rule_valid_until",
                                "remove_context_rule",
                                "add_signer",
                                "remove_signer",
                                "add_policy",
                                "remove_policy",
                                "batch_add_signer",
                                "execute",
                                "upgrade",
                            ]
                            .map(|function| PolicyProtectedMethod {
                                surface: PolicyProtectedSurface::AccountManagement,
                                contract_address: account.clone(),
                                function: function.to_string(),
                            }),
                        )
                        .collect(),
                },
                result: PolicyCallSurfaceResult::Safe,
            },
        };
        PrepareInstallIntentInput {
            spec: spec_json,
            rule_index: 0,
            binding_set: bindings,
            call_surface_check: check,
        }
    }

    fn rejected(
        mut input: PrepareInstallIntentInput,
        change: impl FnOnce(&mut PrepareInstallIntentInput),
        code: EC,
    ) {
        change(&mut input);
        assert_eq!(draft_install_intent(&input).unwrap_err().code, code);
    }

    fn rejected_with_message(
        mut input: PrepareInstallIntentInput,
        change: impl FnOnce(&mut PrepareInstallIntentInput),
        code: EC,
        message: &str,
    ) {
        change(&mut input);
        let error = draft_install_intent(&input).unwrap_err();
        assert_eq!(error.code, code, "{error}");
        assert!(error.message.contains(message), "{error}");
    }

    fn retarget_context(
        mut input: PrepareInstallIntentInput,
        contract: &str,
    ) -> PrepareInstallIntentInput {
        input.spec["rules"][0]["context"]["contract"] = serde_json::json!(contract);
        let spec: PolicySpec = serde_json::from_value(input.spec.clone()).unwrap();
        let validated = spec.validate().unwrap();
        input.binding_set.spec_hash = validated.hash().to_hex();
        let PolicyRecognition::VerifiedGeneratedManifest { build_manifest } =
            &mut input.binding_set.bindings[1].recognition
        else {
            panic!("generated binding")
        };
        build_manifest["spec_hash"] = serde_json::json!(validated.hash().to_hex());
        let binding_hash =
            ozpb_domain::canonical_hash(domains::POLICY_BINDING_SET, &input.binding_set)
                .unwrap()
                .to_hex();
        input.call_surface_check.spec_hash = validated.hash().to_hex();
        input.call_surface_check.binding_set_hash = binding_hash.clone();
        input.call_surface_check.verdict.binding_set_hash = binding_hash;
        input
    }

    #[test]
    fn new_rule_cannot_target_account_or_bound_policy_surface() {
        let base = fixture(false);
        let account = base.call_surface_check.verdict.account_address.clone();
        let account_target = retarget_context(base.clone(), &account);
        let error = draft_install_intent(&account_target).unwrap_err();
        assert_eq!(error.code, EC::EUnsafeManagementSurface);
        assert!(error.message.contains("account management"));

        let policy_target = retarget_context(base, &address(40));
        let error = draft_install_intent(&policy_target).unwrap_err();
        assert_eq!(error.code, EC::EUnsafeCallSurface);
        assert!(error.message.contains("bound policy"));
    }

    #[test]
    fn account_cannot_be_its_own_policy_binding() {
        rejected_with_message(
            fixture(false),
            |input| {
                input.binding_set.bindings[0].contract_address =
                    input.call_surface_check.verdict.account_address.clone();
            },
            EC::EPolicyBindingInvalid,
            "cannot use the smart account address",
        );
    }

    #[test]
    fn minimum_known_method_coverage_is_required_for_every_surface() {
        let base = fixture(false);
        let methods = &base
            .call_surface_check
            .verdict
            .dominance_evidence
            .protected_methods;
        for method in methods {
            rejected_with_message(
                base.clone(),
                |input| {
                    input
                        .call_surface_check
                        .verdict
                        .dominance_evidence
                        .protected_methods
                        .retain(|entry| {
                            std::mem::discriminant(&entry.surface)
                                != std::mem::discriminant(&method.surface)
                                || entry.contract_address != method.contract_address
                                || entry.function != method.function
                        });
                },
                EC::EUnsafeCallSurface,
                "omits a known method",
            );
        }
    }

    #[test]
    fn binding_structure_and_each_manifest_identity_field_are_checked() {
        let base = fixture(false);
        rejected_with_message(
            base.clone(),
            |input| input.binding_set.schema = "other/v1".into(),
            EC::EPolicyBindingInvalid,
            "schema/spec/network",
        );
        rejected_with_message(
            base.clone(),
            |input| {
                input.binding_set.bindings.pop();
            },
            EC::EPolicyBindingInvalid,
            "cover every spec policy",
        );
        rejected_with_message(
            base.clone(),
            |input| {
                let reviewed = &input.binding_set.bindings[0];
                input.binding_set.bindings[1] = PolicyBinding {
                    rule_index: 0,
                    policy_index: 0,
                    contract_address: address(42),
                    observed_wasm_hash: reviewed.observed_wasm_hash.clone(),
                    recognition: PolicyRecognition::ReviewedRegistry,
                    resolution_reference: "second reviewed instance".into(),
                };
            },
            EC::EPolicyBindingInvalid,
            "position is duplicated",
        );
        rejected_with_message(
            base.clone(),
            |input| input.binding_set.bindings[0].contract_address = "bad-address".into(),
            EC::EPolicyBindingInvalid,
            "policy address is duplicated or invalid",
        );
        for (field, value) in [
            ("schema", serde_json::json!("other/v1")),
            ("spec_hash", serde_json::json!("00".repeat(32))),
            ("registry_snapshot", serde_json::json!("00".repeat(32))),
            ("rule_index", serde_json::json!(1)),
            ("template_family", serde_json::json!("other-template")),
            ("wasm_hash", serde_json::json!("00".repeat(32))),
        ] {
            rejected_with_message(
                base.clone(),
                |input| {
                    let PolicyRecognition::VerifiedGeneratedManifest { build_manifest } =
                        &mut input.binding_set.bindings[1].recognition
                    else {
                        panic!("generated binding")
                    };
                    build_manifest[field] = value;
                },
                EC::EPolicyBindingInvalid,
                "manifest identity differs",
            );
        }
    }

    #[test]
    fn every_independent_authority_artifact_constraint_is_checked() {
        let base = fixture(false);
        rejected_with_message(
            base.clone(),
            |input| input.call_surface_check.verdict.ordered_state_digest = "not-hex".into(),
            EC::EUnsafeCallSurface,
            "unanchored",
        );
        rejected_with_message(
            base.clone(),
            |input| {
                let PolicyRuleEnumerationEvidence::BoundedNextId { next_id, .. } =
                    &mut input.call_surface_check.verdict.enumeration_evidence
                else {
                    panic!("bounded")
                };
                *next_id = 1;
            },
            EC::EUnsafeCallSurface,
            "enumeration is internally incomplete",
        );
        for field in ["rule_ids", "signer_ids", "policy_ids"] {
            rejected_with_message(
                base.clone(),
                |input| {
                    let PolicyRuleEnumerationEvidence::BoundedNextId {
                        rule_ids,
                        signer_ids,
                        policy_ids,
                        ..
                    } = &mut input.call_surface_check.verdict.enumeration_evidence
                    else {
                        panic!("bounded")
                    };
                    match field {
                        "rule_ids" => *rule_ids = vec![1, 0],
                        "signer_ids" => *signer_ids = vec![1, 0],
                        _ => *policy_ids = vec![1, 0],
                    }
                },
                EC::EUnsafeCallSurface,
                "enumeration is internally incomplete",
            );
        }
        rejected_with_message(
            base.clone(),
            |input| {
                input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .designated_admin_rule_id = 9
            },
            EC::EUnsafeCallSurface,
            "dominance omits",
        );
        rejected_with_message(
            base.clone(),
            |input| {
                input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .admin_rule_fingerprint = "bad".into()
            },
            EC::EUnsafeCallSurface,
            "dominance omits",
        );
        rejected_with_message(
            base.clone(),
            |input| {
                input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .protected_methods[0]
                    .function
                    .clear()
            },
            EC::EUnsafeCallSurface,
            "empty or duplicated",
        );
        rejected_with_message(
            base.clone(),
            |input| {
                let first = input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .protected_methods[0]
                    .clone();
                input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .protected_methods
                    .push(first);
            },
            EC::EUnsafeCallSurface,
            "empty or duplicated",
        );
        rejected_with_message(
            base.clone(),
            |input| {
                input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .protected_methods[0]
                    .contract_address = address(99)
            },
            EC::EUnsafeCallSurface,
            "unrelated surface",
        );
        rejected_with_message(
            base,
            |input| {
                input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .protected_methods
                    .retain(|method| method.contract_address != address(41));
            },
            EC::EUnsafeCallSurface,
            "omits a known method",
        );
    }

    #[test]
    fn expiry_boundary_allows_the_last_viable_observation() {
        let mut input = fixture(false);
        let spec: PolicySpec = serde_json::from_value(input.spec.clone()).unwrap();
        let valid_until = spec.rules[0].valid_until.as_ref().unwrap().ledger.0;
        input.call_surface_check.verdict.observed_ledger = valid_until - 1;
        assert!(draft_install_intent(&input).is_ok());
    }

    #[test]
    fn coherent_synthetic_input_derives_exact_typed_arguments() {
        let input = fixture(false);
        let draft = draft_install_intent(&input).unwrap();
        let spec: PolicySpec = serde_json::from_value(input.spec).unwrap();
        assert!(matches!(draft.operation, InstallOperation::AddContextRule));
        assert_eq!(draft.account_contract, spec.smart_account.address);
        assert_eq!(draft.context_contract, spec.rules[0].context.contract);
        assert_eq!(draft.rule_name, spec.name);
        assert_eq!(
            draft.valid_until_ledger,
            spec.rules[0].valid_until.as_ref().map(|v| v.ledger.0)
        );
        assert_eq!(draft.policies.len(), 2);
        assert_eq!(draft.policies[0].policy_index, 0);
        assert_eq!(draft.policies[0].address, address(40));
        assert_eq!(draft.policies[1].policy_index, 1);
        assert_eq!(draft.policies[1].address, address(41));
        assert!(matches!(
            &draft.policies[1].install_params,
            InstallPolicyParams::Generated
        ));
        let PolicyRef::Reviewed {
            params:
                ReviewedParams::SpendingLimit {
                    limit,
                    period_ledgers,
                },
            ..
        } = &spec.rules[0].policies[0]
        else {
            panic!("reviewed policy at index 0")
        };
        assert!(matches!(
            &draft.policies[0].install_params,
            InstallPolicyParams::SpendingLimit { spending_limit, period_ledgers: period }
                if spending_limit == limit && period == period_ledgers
        ));
        assert_eq!(
            draft.delegate_signers.len(),
            spec.rules[0].authorization.signers.len()
        );
        for (derived, signer) in draft
            .delegate_signers
            .iter()
            .zip(&spec.rules[0].authorization.signers)
        {
            match (derived, signer) {
                (
                    InstallSigner::Delegated { address: actual },
                    SignerSpec::Delegated { address },
                ) => assert_eq!(actual, address),
                (
                    InstallSigner::External {
                        verifier: actual_verifier,
                        key_hex: actual_key,
                    },
                    SignerSpec::External {
                        verifier, key_hex, ..
                    },
                ) => {
                    assert_eq!(actual_verifier, verifier);
                    assert_eq!(actual_key, key_hex);
                }
                _ => panic!("signer shape changed"),
            }
        }
    }

    #[test]
    fn absent_expiry_is_serialized_as_explicit_null() {
        let draft = draft_install_intent(&fixture(true)).unwrap();
        let json = serde_json::to_value(&draft).unwrap();
        assert!(json.get("valid_until_ledger").is_some());
        assert!(json["valid_until_ledger"].is_null());
        assert!(serde_json::from_value::<PrepareInstallIntentOutput>(json).is_ok());
    }

    #[test]
    fn every_artifact_identity_must_agree_with_the_spec_and_bindings() {
        let base = fixture(false);
        rejected(
            base.clone(),
            |input| input.call_surface_check.spec_hash = "00".repeat(32),
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| input.call_surface_check.binding_set_hash = "00".repeat(32),
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| input.call_surface_check.verdict.binding_set_hash = "00".repeat(32),
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| input.call_surface_check.registry_snapshot_root = "00".repeat(32),
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| input.call_surface_check.verdict.network_id = "00".repeat(32),
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| input.call_surface_check.verdict.account_address = address(99),
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| input.call_surface_check.verdict.account_code_hash = "00".repeat(32),
            EC::EUnsafeCallSurface,
        );
        rejected(
            base,
            |input| {
                input
                    .call_surface_check
                    .verdict
                    .bound_policy_addresses
                    .swap(0, 1)
            },
            EC::EUnsafeCallSurface,
        );
    }

    #[test]
    fn changed_or_incomplete_binding_positions_fail_before_drafting() {
        let base = fixture(false);
        rejected(base.clone(), |input| input.rule_index = 1, EC::ESpecInvalid);
        rejected(
            base.clone(),
            |input| input.binding_set.spec_hash = "00".repeat(32),
            EC::EPolicyBindingInvalid,
        );
        rejected(
            base.clone(),
            |input| input.binding_set.network_id = "00".repeat(32),
            EC::EPolicyBindingInvalid,
        );
        rejected(
            base.clone(),
            |input| input.binding_set.bindings[1].policy_index = 0,
            EC::EPolicyBindingInvalid,
        );
        rejected(
            base.clone(),
            |input| input.binding_set.bindings[1].contract_address = address(40),
            EC::EPolicyBindingInvalid,
        );
        rejected(
            base.clone(),
            |input| input.binding_set.bindings[0].observed_wasm_hash = "00".repeat(32),
            EC::EPolicyBindingInvalid,
        );
        rejected(
            base.clone(),
            |input| input.binding_set.bindings[1].resolution_reference.clear(),
            EC::EPolicyBindingInvalid,
        );
        rejected(
            base,
            |input| {
                let PolicyRecognition::VerifiedGeneratedManifest { build_manifest } =
                    &mut input.binding_set.bindings[1].recognition
                else {
                    panic!("generated")
                };
                build_manifest["wasm_hash"] = serde_json::json!("00".repeat(32));
            },
            EC::EPolicyBindingInvalid,
        );
    }

    #[test]
    fn unsafe_or_incomplete_authority_claims_fail_closed() {
        let base = fixture(false);
        rejected(
            base.clone(),
            |input| input.call_surface_check.verdict.observed_ledger = 4_223_456,
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| {
                input.call_surface_check.verdict.result =
                    PolicyCallSurfaceResult::Unsafe { findings: vec![] }
            },
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| input.call_surface_check.verdict.observed_ledger = 0,
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| {
                input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .assessed_rule_ids
                    .clear()
            },
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| {
                let _ = input
                    .call_surface_check
                    .verdict
                    .dominance_evidence
                    .protected_methods
                    .pop();
            },
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| {
                let PolicyRuleEnumerationEvidence::BoundedNextId { active_count, .. } =
                    &mut input.call_surface_check.verdict.enumeration_evidence
                else {
                    panic!("bounded")
                };
                *active_count = 1;
            },
            EC::EUnsafeCallSurface,
        );
        rejected(
            base.clone(),
            |input| {
                input.call_surface_check.verdict.enumeration_evidence =
                    PolicyRuleEnumerationEvidence::OnchainList {
                        active_count: 2,
                        rule_ids: vec![0, 1],
                        signer_ids: vec![0],
                        policy_ids: vec![0],
                    }
            },
            EC::EAccountRuleEnumerationUnsupported,
        );
        rejected(
            base,
            |input| input.call_surface_check.verdict.observed_ledger = u32::MAX,
            EC::EUnsafeCallSurface,
        );
    }
}
