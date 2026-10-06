//! Pure authority-surface checks over observations acquired by a trusted reader.
//!
//! This module does not acquire ledger state. In particular, a client request cannot choose
//! the designated administrator, code hashes, or the account-rule snapshot. The future RPC
//! reader must establish one coherent ledger, complete rule enumeration and transitive storage
//! closure, and the observed code at every bound address before calling this function.
//!
//! The result is a check over supplied observations, not the public
//! `CheckPolicyCallSurfaceOutput`: that wire artifact additionally promises full protected-
//! method and enumeration evidence. The current account registry does not yet carry a complete
//! exported management-method inventory, so emitting that artifact here would overclaim.

use super::{
    from_value, generate_code_with_build_config, map_registry_err, parse_hash, spec_error,
    to_value, RegistryTrust,
};
use ozpb_api_types::{
    CheckPolicyCallSurfaceInput, ErrorCode as EC, GenerateCodeInput, PolicyBindingSet,
    PolicyRecognition, ToolError, POLICY_BINDING_SET_SCHEMA,
};
use ozpb_call_surface_core::{
    AccountState, BoundPolicy, CheckError, CheckInput, Enumeration, PolicyRecognitionPath,
    SurfaceVerdict, VerifiedPolicy,
};
use ozpb_domain::{domains, Hash32};
use ozpb_policy_spec::{PolicyRef, PolicySpec, ValidatedSpec};
use ozpb_registry::{
    Registry, SignedSnapshot, MANAGEMENT_EVIDENCE_RETURN_VALUE_AND_EVENTS_MUST_AGREE,
};
use std::collections::{BTreeMap, BTreeSet};

/// Ledger observations supplied by a trusted acquisition adapter, never by a tool client.
/// All code hashes and account state must refer to `observed_ledger`.
#[derive(Clone, Debug)]
pub struct CallSurfaceObservation {
    pub observed_ledger: u32,
    pub network_id: String,
    pub account_address: String,
    pub account_code_hash: String,
    pub account_state: AccountState,
    pub bound_policies: Vec<BoundPolicy>,
    /// Identified from the recognized account's release-specific management evidence.
    pub admin_rule_id: u32,
}

/// Validated identities and the conservative address-level core verdict over a supplied
/// observation. This is deliberately not a public wire artifact or a freshness guarantee.
#[derive(Clone, Debug)]
pub struct ObservedCallSurfaceCheck {
    pub spec_hash: Hash32,
    pub binding_set_hash: Hash32,
    pub registry_snapshot_root: Hash32,
    /// `Safe` covers the core's address-level model for this supplied observation only.
    /// It is not a complete live installation verdict or a substitute for method evidence.
    pub verdict: SurfaceVerdict,
}

/// Check exact policy bindings against the signed registry, reproduced generated artifacts,
/// and a supplied same-ledger observation, then run the conservative two-surface core.
///
/// The caller must authenticate and reconcile the observation. This function checks its
/// consistency with the spec and bindings; it cannot prove where its ledger entries came from.
pub fn check_observed_call_surface_with_build_config(
    input: &CheckPolicyCallSurfaceInput,
    observation: &CallSurfaceObservation,
    registry_trust: &RegistryTrust,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<ObservedCallSurfaceCheck, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errors| spec_error(&errors))?;
    if input.account_address != validated.spec().smart_account.address {
        return Err(binding_error(
            "account address does not match the PolicySpec",
        ));
    }
    if input.network_id != validated.spec().network_id.0.to_hex() {
        return Err(binding_error("network ID does not match the PolicySpec"));
    }
    if observation.network_id != input.network_id
        || observation.account_address != input.account_address
    {
        return Err(ToolError::new(
            EC::EIncompleteAccountState,
            "trusted observation is for a different account or network",
        ));
    }
    let observed_account_hash = parse_hash(&observation.account_code_hash).map_err(|_| {
        ToolError::new(
            EC::EIncompleteAccountState,
            "trusted observation account code hash is not a 32-byte hex digest",
        )
    })?;
    if observed_account_hash != validated.spec().smart_account.observed_code_hash {
        return Err(ToolError::new(
            EC::EIncompleteAccountState,
            "trusted observation account code hash does not match the PolicySpec",
        ));
    }

    let signed: SignedSnapshot = serde_json::from_value(input.signed_registry_snapshot.clone())
        .map_err(|error| {
            ToolError::new(
                EC::ERegistrySignature,
                format!("malformed signed registry snapshot: {error}"),
            )
        })?;
    let mut registry = registry_for(registry_trust, validated.spec().network_id)?;
    let loaded_root = registry.load(&signed).map_err(map_registry_err)?;
    if loaded_root != validated.spec().registry_snapshot {
        return Err(binding_error(
            "signed registry root does not match the PolicySpec registry snapshot",
        ));
    }
    let account = registry
        .resolve_account(&observed_account_hash)
        .map_err(map_registry_err)?;
    if account.management_evidence != MANAGEMENT_EVIDENCE_RETURN_VALUE_AND_EVENTS_MUST_AGREE {
        return Err(ToolError::new(
            EC::EIncompatibleAccount,
            "account management-rule evidence strategy is not supported by this checker",
        ));
    }
    if observation.observed_ledger == 0 {
        return Err(ToolError::new(
            EC::EIncompleteAccountState,
            "trusted observation has no ledger anchor",
        ));
    }
    let enumeration = supported_rule_enumeration(&account.rule_enumeration)?;

    let (binding_set_hash, mut recognized_policies) =
        validate_bindings(&validated, &input.binding_set, &registry, build_config)?;
    let observed_by_address: BTreeMap<&str, &str> = observation
        .bound_policies
        .iter()
        .map(|policy| (policy.address.as_str(), policy.observed_wasm_hash.as_str()))
        .collect();
    if observed_by_address.len() != input.binding_set.bindings.len()
        || observation.bound_policies.len() != input.binding_set.bindings.len()
        || input.binding_set.bindings.iter().any(|binding| {
            observed_by_address
                .get(binding.contract_address.as_str())
                .is_none_or(|hash| *hash != binding.observed_wasm_hash)
        })
    {
        return Err(binding_error(
            "same-ledger bound policy observations do not match the exact PolicyBindingSet",
        ));
    }
    let mut stored_hashes: BTreeMap<&str, &str> = BTreeMap::new();
    for policy in observation.account_state.policies.values() {
        if !matches!(
            stellar_strkey::Strkey::from_string(&policy.address),
            Ok(stellar_strkey::Strkey::Contract(_))
        ) || Hash32::from_hex(&policy.observed_wasm_hash).is_err()
        {
            return Err(ToolError::new(
                EC::EIncompleteAccountState,
                "account policy data contains an invalid address or code hash",
            ));
        }
        if stored_hashes
            .insert(policy.address.as_str(), policy.observed_wasm_hash.as_str())
            .is_some_and(|earlier| earlier != policy.observed_wasm_hash.as_str())
            || observed_by_address
                .get(policy.address.as_str())
                .is_some_and(|hash| *hash != policy.observed_wasm_hash.as_str())
        {
            return Err(ToolError::new(
                EC::EIncompleteAccountState,
                "account policy data and code observations disagree at one ledger",
            ));
        }
    }

    // A policy already installed in another rule is recognized only if its *observed*
    // implementation resolves in the signed registry. Address-only recognition would let an
    // upgrade at that address pass. Generated policies outside the binding set need their own
    // reproduced manifest and are therefore deliberately left unrecognized here.
    for policy in observation.account_state.policies.values() {
        if recognized_policies.contains_key(&policy.address) {
            continue;
        }
        let Ok(hash) = Hash32::from_hex(&policy.observed_wasm_hash) else {
            continue;
        };
        if registry.resolve_policy(&hash).is_ok() {
            recognized_policies.insert(
                policy.address.clone(),
                VerifiedPolicy {
                    wasm_hash: hash.to_hex(),
                    path: PolicyRecognitionPath::ReviewedRegistry,
                },
            );
        }
    }

    let bound_policies = input
        .binding_set
        .bindings
        .iter()
        .map(|binding| BoundPolicy {
            address: binding.contract_address.clone(),
            observed_wasm_hash: binding.observed_wasm_hash.clone(),
        })
        .collect();
    let verdict = ozpb_call_surface_core::check(&CheckInput {
        account_state: &observation.account_state,
        account_address: input.account_address.clone(),
        account_code_hash: observed_account_hash.to_hex(),
        binding_set_hash,
        account_recognized: true,
        bound_policies,
        recognized_policies,
        admin_rule_id: observation.admin_rule_id,
        current_ledger: observation.observed_ledger,
        enumeration,
    })
    .map_err(map_surface_err)?;

    Ok(ObservedCallSurfaceCheck {
        spec_hash: validated.hash(),
        binding_set_hash,
        registry_snapshot_root: loaded_root,
        verdict,
    })
}

fn registry_for(
    trust: &RegistryTrust,
    network: ozpb_domain::NetworkId,
) -> Result<Registry, ToolError> {
    match trust.checkpoint.clone() {
        Some(checkpoint) => Registry::with_pinned_roots_for_network_at_checkpoint(
            trust.root_policy.clone(),
            network,
            checkpoint,
        ),
        None => Registry::with_pinned_roots_for_network_at_version(
            trust.root_policy.clone(),
            network,
            trust.minimum_version,
        ),
    }
    .map_err(map_registry_err)
}

fn supported_rule_enumeration(method: &str) -> Result<Enumeration, ToolError> {
    // AccountState and the core currently require a real NextId value. An on-chain list
    // has no such field; deriving one from its largest ID would invent ledger evidence.
    // Accept only the strategy this state model actually implements.
    if method == "bounded_next_id" {
        Ok(Enumeration::BoundedNextId)
    } else {
        Err(ToolError::new(
            EC::EAccountRuleEnumerationUnsupported,
            format!("account rule enumeration '{method}' is unsupported by this checker"),
        ))
    }
}

fn validate_bindings(
    spec: &ValidatedSpec,
    binding_set: &PolicyBindingSet,
    registry: &Registry,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<(Hash32, BTreeMap<String, VerifiedPolicy>), ToolError> {
    if binding_set.schema != POLICY_BINDING_SET_SCHEMA
        || binding_set.spec_hash != spec.hash().to_hex()
        || binding_set.network_id != spec.spec().network_id.0.to_hex()
    {
        return Err(binding_error(
            "PolicyBindingSet schema/spec/network binding is invalid",
        ));
    }
    let expected: usize = spec
        .spec()
        .rules
        .iter()
        .map(|rule| rule.policies.len())
        .sum();
    if binding_set.bindings.len() != expected {
        return Err(binding_error(format!(
            "PolicyBindingSet has {} entries; expected {expected}",
            binding_set.bindings.len()
        )));
    }

    let mut positions = BTreeSet::new();
    let mut recognized = BTreeMap::new();
    let mut generated = BTreeMap::new();
    for binding in &binding_set.bindings {
        let policy = spec
            .spec()
            .rules
            .get(binding.rule_index)
            .and_then(|rule| rule.policies.get(binding.policy_index))
            .ok_or_else(|| binding_error("PolicyBindingSet position is out of range"))?;
        if !positions.insert((binding.rule_index, binding.policy_index)) {
            return Err(binding_error("PolicyBindingSet has a duplicate position"));
        }
        if !matches!(
            stellar_strkey::Strkey::from_string(&binding.contract_address),
            Ok(stellar_strkey::Strkey::Contract(_))
        ) {
            return Err(binding_error(
                "policy contract address is not a valid C-strkey",
            ));
        }
        if recognized.contains_key(&binding.contract_address) {
            return Err(binding_error(
                "PolicyBindingSet has a duplicate contract address",
            ));
        }
        if binding.resolution_reference.trim().is_empty() {
            return Err(binding_error(
                "policy binding resolution reference is empty",
            ));
        }
        let observed_hash = Hash32::from_hex(&binding.observed_wasm_hash)
            .map_err(|_| binding_error("binding observed_wasm_hash is not a 32-byte hex digest"))?;
        if binding.observed_wasm_hash != observed_hash.to_hex() {
            return Err(binding_error(
                "binding observed_wasm_hash must use canonical lowercase hex",
            ));
        }
        let path = match (policy, &binding.recognition) {
            (
                PolicyRef::Reviewed {
                    kind, capability, ..
                },
                PolicyRecognition::ReviewedRegistry,
            ) => {
                if *capability != observed_hash {
                    return Err(binding_error(
                        "reviewed binding code hash differs from its PolicyRef",
                    ));
                }
                let entry = registry
                    .resolve_policy(&observed_hash)
                    .map_err(map_registry_err)?;
                if entry.kind != *kind {
                    return Err(binding_error(
                        "reviewed binding kind differs from its registry entry",
                    ));
                }
                PolicyRecognitionPath::ReviewedRegistry
            }
            (
                PolicyRef::Generated {
                    template_family,
                    capability_schema,
                    ..
                },
                PolicyRecognition::VerifiedGeneratedManifest { build_manifest },
            ) => {
                let template = registry
                    .resolve_template(template_family)
                    .map_err(map_registry_err)?;
                if template.capability_schema != *capability_schema {
                    return Err(binding_error(
                        "generated binding capability schema differs from the registry",
                    ));
                }
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    generated.entry(binding.rule_index)
                {
                    let artifact = generate_code_with_build_config(
                        &GenerateCodeInput {
                            spec: to_value(spec.spec())?,
                            rule_index: binding.rule_index,
                        },
                        build_config,
                    )?;
                    entry.insert(artifact);
                }
                let artifact: &ozpb_api_types::GenerateCodeOutput = &generated[&binding.rule_index];
                if &artifact.build_manifest != build_manifest
                    || artifact.wasm_hash != observed_hash.to_hex()
                    || artifact.build_manifest["template_family"]
                        != serde_json::Value::String(template_family.clone())
                {
                    return Err(binding_error(
                        "generated binding failed artifact reproduction",
                    ));
                }
                PolicyRecognitionPath::VerifiedGeneratedManifest
            }
            _ => {
                return Err(binding_error(
                    "binding recognition does not match its PolicyRef",
                ))
            }
        };
        recognized.insert(
            binding.contract_address.clone(),
            VerifiedPolicy {
                wasm_hash: observed_hash.to_hex(),
                path,
            },
        );
    }
    let hash = ozpb_domain::canonical_hash(domains::POLICY_BINDING_SET, binding_set)
        .map_err(|error| ToolError::new(EC::EInternal, error.to_string()))?;
    Ok((hash, recognized))
}

fn binding_error(message: impl Into<String>) -> ToolError {
    ToolError::new(EC::EPolicyBindingInvalid, message)
}

fn map_surface_err(error: CheckError) -> ToolError {
    let code = match &error {
        CheckError::EnumerationUnsupported(_) => EC::EAccountRuleEnumerationUnsupported,
        CheckError::IncompleteState { .. } => EC::EIncompleteAccountState,
        CheckError::IncompatibleAccount(_) => EC::EIncompatibleAccount,
        CheckError::AdminRuleNotFound(_) => EC::EAdminRuleNotFound,
        CheckError::AdminRuleUnsafe(_, _) => EC::EAdminRuleUnsafe,
        CheckError::UnrecognizedBoundPolicy(_) => EC::EUnregisteredPolicy,
        CheckError::InvalidBindingSet(_) => EC::EPolicyBindingInvalid,
        CheckError::Internal(_) => EC::EInternal,
    };
    ToolError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{build_config, registry_trust, signed_registry_json, wire_spec};
    use ozpb_api_types::PolicyBinding;
    use ozpb_call_surface_core::{
        CheckResult, StoredContextType, StoredPolicy, StoredRule, StoredSigner, StoredSignerKey,
    };

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn fixture() -> (CheckPolicyCallSurfaceInput, CallSurfaceObservation) {
        let mut spec = wire_spec().spec().clone();
        let signed: SignedSnapshot = serde_json::from_value(signed_registry_json()).unwrap();
        spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
        let spec = spec.validate().unwrap();
        let spec_json = serde_json::to_value(spec.spec()).unwrap();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec_json.clone(),
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap();
        let reviewed_hash = match &spec.spec().rules[0].policies[0] {
            PolicyRef::Reviewed { capability, .. } => capability.to_hex(),
            other => panic!("expected reviewed policy, got {other:?}"),
        };
        let binding_set = PolicyBindingSet {
            schema: POLICY_BINDING_SET_SCHEMA.to_string(),
            spec_hash: spec.hash().to_hex(),
            network_id: spec.spec().network_id.0.to_hex(),
            bindings: vec![
                PolicyBinding {
                    rule_index: 0,
                    policy_index: 0,
                    contract_address: address(40),
                    observed_wasm_hash: reviewed_hash,
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
        let bound_policies = binding_set
            .bindings
            .iter()
            .map(|binding| BoundPolicy {
                address: binding.contract_address.clone(),
                observed_wasm_hash: binding.observed_wasm_hash.clone(),
            })
            .collect();
        let state = AccountState {
            next_id: 2,
            active_count: 2,
            rules: BTreeMap::from([
                (
                    0,
                    StoredRule {
                        id: 0,
                        context_type: StoredContextType::Default,
                        valid_until: None,
                        signer_ids: vec![0],
                        policy_ids: vec![],
                    },
                ),
                (
                    1,
                    StoredRule {
                        id: 1,
                        context_type: StoredContextType::CallContract {
                            address: ozpb_synthesizer::fixtures::golden_token_strkey(),
                        },
                        valid_until: Some(4_223_456),
                        signer_ids: vec![1],
                        policy_ids: vec![0, 1],
                    },
                ),
            ]),
            signers: BTreeMap::from([
                (
                    0,
                    StoredSigner {
                        id: 0,
                        key: StoredSignerKey::Delegated {
                            address: address(10),
                        },
                    },
                ),
                (
                    1,
                    StoredSigner {
                        id: 1,
                        key: StoredSignerKey::Delegated {
                            address: address(11),
                        },
                    },
                ),
            ]),
            policies: binding_set
                .bindings
                .iter()
                .enumerate()
                .map(|(id, binding)| {
                    (
                        id as u32,
                        StoredPolicy {
                            id: id as u32,
                            address: binding.contract_address.clone(),
                            observed_wasm_hash: binding.observed_wasm_hash.clone(),
                        },
                    )
                })
                .collect(),
        };
        (
            CheckPolicyCallSurfaceInput {
                spec: spec_json,
                binding_set,
                signed_registry_snapshot: signed_registry_json(),
                account_address: spec.spec().smart_account.address.clone(),
                network_id: spec.spec().network_id.0.to_hex(),
                rpc_source: "configured-testnet".to_string(),
            },
            CallSurfaceObservation {
                observed_ledger: 4_200_000,
                network_id: spec.spec().network_id.0.to_hex(),
                account_address: spec.spec().smart_account.address.clone(),
                account_code_hash: spec.spec().smart_account.observed_code_hash.to_hex(),
                account_state: state,
                bound_policies,
                admin_rule_id: 0,
            },
        )
    }

    fn check(
        request: &CheckPolicyCallSurfaceInput,
        observation: &CallSurfaceObservation,
    ) -> Result<ObservedCallSurfaceCheck, ToolError> {
        check_observed_call_surface_with_build_config(
            request,
            observation,
            &registry_trust(),
            &build_config(),
        )
    }

    #[test]
    fn exact_checked_bindings_produce_a_safe_core_verdict() {
        let (request, observation) = fixture();
        let output = check(&request, &observation).unwrap();
        assert_eq!(output.spec_hash.to_hex(), request.binding_set.spec_hash);
        assert_eq!(output.verdict.binding_set_hash, output.binding_set_hash);
        assert_eq!(output.verdict.observed_ledger, observation.observed_ledger);
        assert_eq!(output.verdict.result, CheckResult::Safe);
    }

    #[test]
    fn observed_code_and_binding_evidence_must_match_exactly() {
        let (mut request, mut observation) = fixture();
        observation.bound_policies[0].observed_wasm_hash = "00".repeat(32);
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EPolicyBindingInvalid
        );

        observation.bound_policies[0].observed_wasm_hash =
            request.binding_set.bindings[0].observed_wasm_hash.clone();
        observation
            .account_state
            .policies
            .get_mut(&0)
            .unwrap()
            .observed_wasm_hash = "00".repeat(32);
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EIncompleteAccountState
        );

        observation
            .account_state
            .policies
            .get_mut(&0)
            .unwrap()
            .observed_wasm_hash = "not-a-hash".to_string();
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EIncompleteAccountState
        );

        observation
            .account_state
            .policies
            .get_mut(&0)
            .unwrap()
            .observed_wasm_hash = request.binding_set.bindings[0].observed_wasm_hash.clone();
        if let PolicyRecognition::VerifiedGeneratedManifest { build_manifest } =
            &mut request.binding_set.bindings[1].recognition
        {
            build_manifest["wasm_hash"] = serde_json::json!("00".repeat(32));
        }
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EPolicyBindingInvalid
        );
    }

    #[test]
    fn incomplete_state_and_weak_management_rule_never_pass() {
        let (request, mut observation) = fixture();
        observation.account_state.active_count = 3;
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EIncompleteAccountState
        );

        observation.account_state.active_count = 2;
        observation
            .account_state
            .rules
            .get_mut(&1)
            .unwrap()
            .context_type = StoredContextType::CallContract {
            address: request.account_address.clone(),
        };
        let output = check(&request, &observation).unwrap();
        assert!(matches!(output.verdict.result, CheckResult::Unsafe { .. }));
    }

    #[test]
    fn request_identity_and_registry_signature_are_gates() {
        let (mut request, observation) = fixture();
        request.network_id = "00".repeat(32);
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EPolicyBindingInvalid
        );

        let (request, mut observation) = fixture();
        observation.account_code_hash = "not-a-hash".to_string();
        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EIncompleteAccountState);
        assert!(error.message.contains("observation"));

        let (request, mut observation) = fixture();
        observation.account_code_hash = "00".repeat(32);
        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EIncompleteAccountState);
        assert!(error.message.contains("does not match"));

        let (request, mut observation) = fixture();
        observation.account_address = address(99);
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EIncompleteAccountState
        );

        let (request, mut observation) = fixture();
        observation.network_id = "00".repeat(32);
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EIncompleteAccountState
        );

        let (mut request, observation) = fixture();
        request.signed_registry_snapshot["signatures"]["legacy"] =
            serde_json::json!("00".repeat(64));
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::ERegistrySignature
        );

        let (mut request, observation) = fixture();
        request.binding_set.bindings[1].policy_index = 0;
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EPolicyBindingInvalid
        );
    }

    #[test]
    fn signed_onchain_list_capability_cannot_claim_a_bounded_next_id_verdict() {
        let (mut request, mut observation) = fixture();
        let network = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
        let mut snapshot = ozpb_registry::dev::dev_snapshot(network, 1);
        snapshot
            .accounts
            .get_mut(&observation.account_code_hash)
            .unwrap()
            .rule_enumeration = "onchain_list".to_string();
        let signed =
            ozpb_registry::sign_snapshot(&ozpb_registry::dev::dev_signing_key(), snapshot).unwrap();
        let mut spec: PolicySpec = serde_json::from_value(request.spec).unwrap();
        spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
        let spec = spec.validate().unwrap();
        request.spec = serde_json::to_value(spec.spec()).unwrap();
        request.binding_set.spec_hash = spec.hash().to_hex();
        request.signed_registry_snapshot = serde_json::to_value(signed).unwrap();

        // Keep every other binding coherent, so the refusal is about the unsupported
        // enumeration strategy rather than a mismatched generated artifact.
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: request.spec.clone(),
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap();
        request.binding_set.bindings[1].observed_wasm_hash = generated.wasm_hash.clone();
        request.binding_set.bindings[1].recognition =
            PolicyRecognition::VerifiedGeneratedManifest {
                build_manifest: generated.build_manifest,
            };
        observation.bound_policies[1].observed_wasm_hash = generated.wasm_hash.clone();
        observation
            .account_state
            .policies
            .get_mut(&1)
            .unwrap()
            .observed_wasm_hash = generated.wasm_hash;

        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EAccountRuleEnumerationUnsupported);
        assert!(error.message.contains("onchain_list"));
    }
}
