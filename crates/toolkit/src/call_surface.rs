//! Pure authority checks over observations acquired by a trusted reader.
//!
//! This module does not acquire ledger state. In particular, a client request cannot supply
//! code hashes, the account-rule snapshot, or anything about who owns the account: the
//! authority list is derived from the observation (Decision D7). The RPC reader must
//! establish one ledger, complete rule enumeration and transitive storage closure, and the
//! observed code at every bound address before calling this function.
//!
//! The result is a check over supplied observations, not the public
//! `CheckPolicyCallSurfaceOutput`, which the live operation builds from it.

use super::{
    from_value, generate_code_with_build_config, map_registry_err, parse_hash, spec_error,
    to_value, within_declared_capabilities, RegistryTrust,
};
use ozpb_api_types::{
    CheckPolicyCallSurfaceInput, ErrorCode as EC, GenerateCodeInput, PolicyBindingSet,
    PolicyRecognition, ToolError, POLICY_BINDING_SET_SCHEMA,
};
use ozpb_call_surface_core::{
    AccountState, BoundPolicy, CheckError, CheckInput, ClassicAccount, Enumeration, Grant,
    GrantPolicy, GrantPolicyParams, KeyScheme, PolicyRecognitionPath, PolicySignerSemantics,
    StoredSignerKey, SurfaceVerdict, VerifiedPolicy, VerifierObservation,
};
use ozpb_domain::{domains, Hash32};
use ozpb_policy_spec::{
    PolicyRef, PolicySpec, ReviewedParams, RuleSpec, SignerSpec, ValidatedSpec,
};
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
    /// Classic accounts read with the account: at least every `Delegated(G…)` signer of a
    /// rule that can change the account, reach a bound policy or call the target.
    pub classic_accounts: BTreeMap<String, ClassicAccount>,
    /// Code observed at every contract verifier an external signer names, same ledger.
    pub verifier_code_hashes: BTreeMap<String, String>,
}

/// Validated identities and the conservative address-level core verdict over a supplied
/// observation. This is deliberately not a public wire artifact or a freshness guarantee.
#[derive(Clone, Debug)]
pub struct ObservedCallSurfaceCheck {
    pub spec_hash: Hash32,
    pub binding_set_hash: Hash32,
    pub registry_snapshot_root: Hash32,
    /// The authority list and findings for this supplied observation only. Never a safety
    /// verdict: the wallet holding the owner key confirms the list (Decision D7).
    pub verdict: SurfaceVerdict,
}

/// Check exact policy bindings against the signed registry, reproduced generated artifacts,
/// and a supplied same-ledger observation, then derive who can change the account.
///
/// The caller must authenticate and reconcile the observation. This function checks its
/// consistency with the spec and bindings; it cannot prove where its ledger entries came from.
pub fn check_observed_call_surface_with_build_config(
    input: &CheckPolicyCallSurfaceInput,
    observation: &CallSurfaceObservation,
    registry_trust: &RegistryTrust,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<ObservedCallSurfaceCheck, ToolError> {
    let prepared = prepare_call_surface_check(input, registry_trust, build_config)?;
    check_prepared(input, &prepared, observation)
}

/// Everything about a request that does not depend on the ledger read: the validated spec,
/// the signed registry loaded under the pinned trust, the account capability, the bindings
/// recognized (generated ones rebuilt, once) and the grant. A live check prepares this before
/// it reads anything, so a request that cannot be answered costs no read and no build after it.
pub(crate) struct PreparedCallSurfaceCheck {
    pub(crate) spec: ValidatedSpec,
    pub(crate) registry: Registry,
    pub(crate) loaded_root: Hash32,
    enumeration: Enumeration,
    binding_set_hash: Hash32,
    bound_recognition: BTreeMap<String, VerifiedPolicy>,
    pub(crate) grant: Grant,
}

pub(crate) fn prepare_call_surface_check(
    input: &CheckPolicyCallSurfaceInput,
    registry_trust: &RegistryTrust,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<PreparedCallSurfaceCheck, ToolError> {
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
    if input.rule_index >= validated.spec().rules.len() {
        return Err(ToolError::new(
            EC::ESpecInvalid,
            "rule_index is out of range",
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
        .resolve_account(&validated.spec().smart_account.observed_code_hash)
        .map_err(map_registry_err)?;
    if account.management_evidence != MANAGEMENT_EVIDENCE_RETURN_VALUE_AND_EVENTS_MUST_AGREE {
        return Err(ToolError::new(
            EC::EIncompatibleAccount,
            "account management-rule evidence strategy is not supported by this checker",
        ));
    }
    let enumeration = supported_rule_enumeration(&account.rule_enumeration)?;
    let (binding_set_hash, bound_recognition) =
        validate_bindings(&validated, &input.binding_set, &registry, build_config)?;
    let grant = grant_for(&validated, input.rule_index, &input.binding_set)?;
    Ok(PreparedCallSurfaceCheck {
        spec: validated,
        registry,
        loaded_root,
        enumeration,
        binding_set_hash,
        bound_recognition,
        grant,
    })
}

/// Run the core over one observation for a prepared request.
pub(crate) fn check_prepared(
    input: &CheckPolicyCallSurfaceInput,
    prepared: &PreparedCallSurfaceCheck,
    observation: &CallSurfaceObservation,
) -> Result<ObservedCallSurfaceCheck, ToolError> {
    let validated = &prepared.spec;
    let registry = &prepared.registry;
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
    if observation.observed_ledger == 0 {
        return Err(ToolError::new(
            EC::EIncompleteAccountState,
            "trusted observation has no ledger anchor",
        ));
    }
    let binding_set_hash = prepared.binding_set_hash;
    let mut recognized_policies = prepared.bound_recognition.clone();
    let grant = prepared.grant.clone();
    let loaded_root = prepared.loaded_root;
    let enumeration = prepared.enumeration;
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
    // An address has one executable at one ledger, even if it appears as both the
    // account and a policy. Compare parsed hashes across every observation source.
    let mut code_by_address = BTreeMap::new();
    code_by_address.insert(observation.account_address.as_str(), observed_account_hash);
    for policy in &observation.bound_policies {
        let hash = Hash32::from_hex(&policy.observed_wasm_hash).map_err(|_| {
            ToolError::new(
                EC::EIncompleteAccountState,
                "bound policy observation has an invalid code hash",
            )
        })?;
        record_observed_code(&mut code_by_address, &policy.address, hash)?;
    }
    for policy in observation.account_state.policies.values() {
        if !matches!(
            stellar_strkey::Strkey::from_string(&policy.address),
            Ok(stellar_strkey::Strkey::Contract(_))
        ) {
            return Err(ToolError::new(
                EC::EIncompleteAccountState,
                "account policy data contains an invalid address",
            ));
        }
        let hash = Hash32::from_hex(&policy.observed_wasm_hash).map_err(|_| {
            ToolError::new(
                EC::EIncompleteAccountState,
                "account policy data contains an invalid code hash",
            )
        })?;
        record_observed_code(&mut code_by_address, &policy.address, hash)?;
    }

    // A policy installed on any rule is readable only if its *observed* implementation
    // resolves in the signed registry with established signer semantics. Address-only
    // recognition would let an upgrade at that address pass.
    for policy in observation.account_state.policies.values() {
        if recognized_policies.contains_key(&policy.address) {
            continue;
        }
        let Ok(hash) = Hash32::from_hex(&policy.observed_wasm_hash) else {
            continue;
        };
        if let Ok(entry) = registry.resolve_policy(&hash) {
            recognized_policies.insert(
                policy.address.clone(),
                VerifiedPolicy {
                    wasm_hash: hash.to_hex(),
                    path: PolicyRecognitionPath::ReviewedRegistry,
                    signers: signer_semantics(&entry.kind),
                },
            );
        }
    }

    // A verifier vouches for an owner identity only through its observed code: reviewed,
    // immutable, stateless, with the scheme its reviewed source implements. Anything else is
    // passed on as unrecognized code, which the core refuses where it matters.
    let mut verifiers = BTreeMap::new();
    for (address, observed) in &observation.verifier_code_hashes {
        let hash = Hash32::from_hex(observed).map_err(|_| {
            ToolError::new(
                EC::EIncompleteAccountState,
                "verifier observation has an invalid code hash",
            )
        })?;
        record_observed_code(&mut code_by_address, address, hash)?;
        let scheme = registry
            .resolve_signature_verifier(&hash)
            .ok()
            .map(|scheme| match scheme {
                ozpb_registry::VerifierKeyScheme::Ed25519 => KeyScheme::Ed25519,
                ozpb_registry::VerifierKeyScheme::WebauthnP256 => KeyScheme::WebauthnP256,
            });
        verifiers.insert(
            address.clone(),
            VerifierObservation {
                code_hash: hash.to_hex(),
                scheme,
            },
        );
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
        network_id: input.network_id.clone(),
        spec_hash: validated.hash(),
        account_state: &observation.account_state,
        account_address: input.account_address.clone(),
        account_code_hash: observed_account_hash.to_hex(),
        binding_set_hash,
        account_recognized: true,
        bound_policies,
        recognized_policies,
        classic_accounts: observation.classic_accounts.clone(),
        verifiers,
        registry_snapshot_root: loaded_root,
        grant,
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

/// What a reviewed policy kind demands of its rule's signers, from source review. OZ's
/// spending limit refuses unless at least one of the rule's own signers authenticated
/// (`stellar-accounts` 0.7.2 `policies/spending_limit.rs`, `enforce`: an empty
/// `authenticated_signers` panics). Any kind not named here is unknown, which leaves a rule
/// carrying it unresolved: the account hands such a rule to its policies with whatever
/// signers came, possibly none.
fn signer_semantics(kind: &str) -> PolicySignerSemantics {
    match kind {
        "oz:spending_limit" => PolicySignerSemantics::AtLeastOneRuleSigner,
        _ => PolicySignerSemantics::Unknown,
    }
}

/// The rule being installed, from the hashed spec: its target, its signers (the restricted
/// keys), and whether it keeps state. A reviewed policy is counted as stateful: the only
/// reviewed kind, OZ's spending limit, keeps a window per rule.
pub(crate) fn grant_for(
    spec: &ValidatedSpec,
    rule_index: usize,
    binding_set: &PolicyBindingSet,
) -> Result<Grant, ToolError> {
    let rule: &RuleSpec = spec
        .spec()
        .rules
        .get(rule_index)
        .ok_or_else(|| ToolError::new(EC::ESpecInvalid, "rule_index is out of range"))?;
    let policies = rule
        .policies
        .iter()
        .enumerate()
        .map(|(policy_index, policy)| {
            let binding = binding_set
                .bindings
                .iter()
                .find(|binding| {
                    binding.rule_index == rule_index && binding.policy_index == policy_index
                })
                .ok_or_else(|| binding_error("selected rule is missing a policy binding"))?;
            let install_params = match policy {
                PolicyRef::Generated { .. } => GrantPolicyParams::Generated,
                PolicyRef::Reviewed {
                    params:
                        ReviewedParams::SpendingLimit {
                            limit,
                            period_ledgers,
                        },
                    ..
                } => GrantPolicyParams::SpendingLimit {
                    spending_limit: limit.clone(),
                    period_ledgers: *period_ledgers,
                },
            };
            Ok(GrantPolicy {
                address: binding.contract_address.clone(),
                install_params,
            })
        })
        .collect::<Result<Vec<_>, ToolError>>()?;
    let rule_index = u32::try_from(rule_index)
        .map_err(|_| ToolError::new(EC::ESpecInvalid, "rule_index is out of range"))?;
    Ok(Grant {
        rule_index,
        target: rule.context.contract.clone(),
        stateful: !rule.state.is_empty()
            || rule
                .policies
                .iter()
                .any(|policy| matches!(policy, PolicyRef::Reviewed { .. })),
        signers: rule
            .authorization
            .signers
            .iter()
            .map(|signer| match signer {
                SignerSpec::Delegated { address } => StoredSignerKey::Delegated {
                    address: address.clone(),
                },
                SignerSpec::External {
                    verifier, key_hex, ..
                } => StoredSignerKey::External {
                    verifier: verifier.clone(),
                    key_hex: key_hex.clone(),
                },
            })
            .collect(),
        name: spec.spec().name.clone(),
        valid_until: rule.valid_until.as_ref().map(|until| until.ledger.0),
        policies,
    })
}

fn record_observed_code<'a>(
    code_by_address: &mut BTreeMap<&'a str, Hash32>,
    address: &'a str,
    hash: Hash32,
) -> Result<(), ToolError> {
    if code_by_address
        .get(address)
        .is_some_and(|previous| *previous != hash)
    {
        return Err(ToolError::new(
            EC::EIncompleteAccountState,
            format!("trusted observation reports conflicting code hashes for {address}"),
        ));
    }
    code_by_address.insert(address, hash);
    Ok(())
}

pub(crate) fn registry_for(
    trust: &RegistryTrust,
    network: ozpb_domain::NetworkId,
) -> Result<Registry, ToolError> {
    // Anyone can recompute the development root's private key from its published seed, so a
    // snapshot it signs carries no review authority: an agent could sign one recognizing its
    // own verifier as an owner verifier. Only the testnet example may use it.
    let development_root = ozpb_registry::dev::dev_root_verifying_bytes();
    if network != ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE)
        && trust
            .root_policy
            .keys
            .values()
            .any(|key| *key == development_root)
    {
        return Err(map_registry_err(ozpb_registry::RegistryError::RootPolicy(
            "the public development registry root is accepted only on testnet".into(),
        )));
    }
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
        let rule = spec
            .spec()
            .rules
            .get(binding.rule_index)
            .ok_or_else(|| binding_error("PolicyBindingSet position is out of range"))?;
        let policy = rule
            .policies
            .get(binding.policy_index)
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
        if binding.contract_address == spec.spec().smart_account.address {
            return Err(binding_error(
                "policy binding cannot use the smart account address",
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
        let (path, signers) = match (policy, &binding.recognition) {
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
                (
                    PolicyRecognitionPath::ReviewedRegistry,
                    signer_semantics(&entry.kind),
                )
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
                within_declared_capabilities(
                    std::iter::once((binding.rule_index, rule)),
                    template_family,
                    &template.constraint_kinds,
                    &template.signer_predicates,
                )?;
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
                // Reproduced from this spec, but what it demands of another rule's signers is
                // not something this check reads; a rule carrying it elsewhere stays unresolved.
                (
                    PolicyRecognitionPath::VerifiedGeneratedManifest,
                    PolicySignerSemantics::Unknown,
                )
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
                signers,
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
        FindingCode, StoredContextType, StoredPolicy, StoredRule, StoredSigner, UnsupportedReason,
    };

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn classic(byte: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
    }

    fn master_key_only() -> ClassicAccount {
        ClassicAccount::Found {
            master_weight: 1,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        }
    }

    /// Before the install: rule 0 is the owner's (`Default`, one classic account), rule 1 is
    /// someone's grant on an unrelated contract that reuses the shared reviewed policy
    /// instance (OZ's spending limit keeps state per rule, so sharing it is ordinary).
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
                            address: address(43),
                        },
                        valid_until: Some(4_223_456),
                        signer_ids: vec![1],
                        policy_ids: vec![0],
                    },
                ),
            ]),
            signers: BTreeMap::from([
                (
                    0,
                    StoredSigner {
                        id: 0,
                        key: StoredSignerKey::Delegated {
                            address: classic(10),
                        },
                    },
                ),
                (
                    1,
                    StoredSigner {
                        id: 1,
                        key: StoredSignerKey::Delegated {
                            address: classic(11),
                        },
                    },
                ),
            ]),
            policies: BTreeMap::from([(
                0,
                StoredPolicy {
                    id: 0,
                    address: binding_set.bindings[0].contract_address.clone(),
                    observed_wasm_hash: binding_set.bindings[0].observed_wasm_hash.clone(),
                },
            )]),
        };
        (
            CheckPolicyCallSurfaceInput {
                spec: spec_json,
                rule_index: 0,
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
                // Every classic account the check needs, master key alone in control: the two
                // stored signers and the spec rule's own signers.
                classic_accounts: [classic(10), classic(11)]
                    .into_iter()
                    .chain(
                        spec.spec().rules[0]
                            .authorization
                            .signers
                            .iter()
                            .filter_map(|signer| match signer {
                                SignerSpec::Delegated { address } => Some(address.clone()),
                                SignerSpec::External { .. } => None,
                            }),
                    )
                    .map(|address| (address, master_key_only()))
                    .collect(),
                verifier_code_hashes: BTreeMap::new(),
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

    /// Keep the test spec, generated artifact, and same-ledger observations coherent after
    /// replacing the signed capability snapshot.
    fn replace_fixture_snapshot(
        request: &mut CheckPolicyCallSurfaceInput,
        observation: &mut CallSurfaceObservation,
        snapshot: ozpb_registry::RegistrySnapshot,
    ) {
        let signed =
            ozpb_registry::sign_snapshot(&ozpb_registry::dev::dev_signing_key(), snapshot).unwrap();
        let mut spec: PolicySpec = serde_json::from_value(request.spec.clone()).unwrap();
        spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
        let spec = spec.validate().unwrap();
        request.spec = serde_json::to_value(spec.spec()).unwrap();
        request.binding_set.spec_hash = spec.hash().to_hex();
        request.signed_registry_snapshot = serde_json::to_value(signed).unwrap();

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
        observation.bound_policies[1].observed_wasm_hash = generated.wasm_hash;
    }

    #[test]
    fn exact_checked_bindings_produce_the_authority_list() {
        let (request, observation) = fixture();
        let output = check(&request, &observation).unwrap();
        assert_eq!(output.spec_hash.to_hex(), request.binding_set.spec_hash);
        assert_eq!(output.verdict.binding_set_hash, output.binding_set_hash);
        assert_eq!(output.verdict.observed_ledger, observation.observed_ledger);
        assert!(output.verdict.refusals.is_empty() && output.verdict.unresolved.is_empty());
        let rules = &output.verdict.authority_list;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_id, 0);
    }

    /// The restricted keys, the target and statefulness come from the selected spec rule,
    /// never from the caller separately.
    #[test]
    fn the_grant_is_the_selected_spec_rule() {
        let (request, observation) = fixture();
        let spec: PolicySpec = serde_json::from_value(request.spec.clone()).unwrap();
        let grant = check(&request, &observation).unwrap().verdict.grant;
        assert_eq!(grant.rule_index, 0);
        assert_eq!(grant.target, spec.rules[0].context.contract);
        // The fixture rule carries the reviewed spending limit.
        assert!(grant.stateful);
        assert_eq!(
            grant.signers.len(),
            spec.rules[0].authorization.signers.len()
        );

        let mut out_of_range = request.clone();
        out_of_range.rule_index = spec.rules.len();
        assert_eq!(
            check(&out_of_range, &observation).unwrap_err().code,
            EC::ESpecInvalid
        );
    }

    /// The fixture spec's first signer is the agent; put its key on a management rule.
    #[test]
    fn the_agent_key_on_a_management_rule_is_refused_automatically() {
        let (request, mut observation) = fixture();
        let spec: PolicySpec = serde_json::from_value(request.spec.clone()).unwrap();
        let agent = match &spec.rules[0].authorization.signers[0] {
            SignerSpec::Delegated { address } => StoredSignerKey::Delegated {
                address: address.clone(),
            },
            SignerSpec::External {
                verifier, key_hex, ..
            } => StoredSignerKey::External {
                verifier: verifier.clone(),
                key_hex: key_hex.clone(),
            },
        };
        observation.account_state.signers.get_mut(&1).unwrap().key = agent;
        observation
            .account_state
            .rules
            .get_mut(&1)
            .unwrap()
            .context_type = StoredContextType::CallContract {
            address: request.account_address.clone(),
        };
        let output = check(&request, &observation).unwrap();
        assert!(output
            .verdict
            .refusals
            .iter()
            .any(|finding| finding.code == FindingCode::DelegateHasAuthority));
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
    fn account_address_has_one_code_hash_across_policy_observations() {
        let (mut request, mut observation) = fixture();
        assert_ne!(
            request.binding_set.bindings[0].observed_wasm_hash,
            observation.account_code_hash
        );
        request.binding_set.bindings[0].contract_address = observation.account_address.clone();
        observation.bound_policies[0].address = observation.account_address.clone();
        observation
            .account_state
            .policies
            .get_mut(&0)
            .unwrap()
            .address = observation.account_address.clone();

        // A binding at the account's own address is refused as a binding, before any
        // observation is compared.
        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EPolicyBindingInvalid);
        assert!(error
            .message
            .contains("cannot use the smart account address"));

        let (request, mut observation) = fixture();
        observation.account_state.policies.insert(
            2,
            StoredPolicy {
                id: 2,
                address: observation.account_address.clone(),
                observed_wasm_hash: request.binding_set.bindings[0].observed_wasm_hash.clone(),
            },
        );
        observation
            .account_state
            .rules
            .get_mut(&1)
            .unwrap()
            .policy_ids
            .push(2);

        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EIncompleteAccountState);
        assert!(error.message.contains("conflicting code hashes"));
    }

    #[test]
    fn incomplete_state_never_yields_a_list() {
        let (request, mut observation) = fixture();
        observation.account_state.active_count = 3;
        assert_eq!(
            check(&request, &observation).unwrap_err().code,
            EC::EIncompleteAccountState
        );
    }

    #[test]
    fn any_policy_on_a_management_rule_is_refused() {
        let (request, mut observation) = fixture();
        let reviewed_hash = request.binding_set.bindings[0].observed_wasm_hash.clone();
        observation.account_state.policies.insert(
            2,
            StoredPolicy {
                id: 2,
                address: address(42),
                observed_wasm_hash: reviewed_hash,
            },
        );
        observation
            .account_state
            .rules
            .get_mut(&0)
            .unwrap()
            .policy_ids
            .push(2);

        // Recognized or not, a policy on a rule that can change the account is refused: it,
        // not the signer list, decides who may act there.
        for observed in [None, Some("77".repeat(32))] {
            if let Some(hash) = observed {
                observation
                    .account_state
                    .policies
                    .get_mut(&2)
                    .unwrap()
                    .observed_wasm_hash = hash;
            }
            let output = check(&request, &observation).unwrap();
            assert_eq!(
                output.verdict.refusals[0].code,
                FindingCode::UnsupportedAuthority
            );
            assert_eq!(
                output.verdict.refusals[0].unsupported,
                Some(UnsupportedReason::PolicyGuarded)
            );
        }
    }

    /// The core's answer is exactly the wire verdict, once the shell adds what only it
    /// knows (how the state was acquired). The authority list, a refusal with a named reason,
    /// an exclusion and an expired rule are all populated, so a renamed or retagged field in
    /// any of them fails here rather than on a client.
    #[test]
    fn the_core_answer_is_the_wire_verdict() {
        let (request, mut observation) = fixture();
        // Rule 2: the account's own surface, signed by a classic account with another signer
        // (refused). Rule 3: an expired `Default` rule.
        for (id, signer, valid_until) in [(2, 1, None), (3, 0, Some(1))] {
            observation.account_state.rules.insert(
                id,
                StoredRule {
                    id,
                    context_type: if id == 2 {
                        StoredContextType::CallContract {
                            address: request.account_address.clone(),
                        }
                    } else {
                        StoredContextType::Default
                    },
                    valid_until,
                    signer_ids: vec![signer],
                    policy_ids: vec![],
                },
            );
        }
        observation.account_state.next_id = 4;
        observation.account_state.active_count = 4;
        observation.classic_accounts.insert(
            classic(11),
            ClassicAccount::Found {
                master_weight: 1,
                low_threshold: 0,
                medium_threshold: 1,
                high_threshold: 1,
                signers: vec![ozpb_call_surface_core::ClassicSigner {
                    key: classic(12),
                    weight: 1,
                }],
            },
        );
        let verdict = check(&request, &observation).unwrap().verdict;
        assert!(!verdict.authority_list.is_empty());
        assert_eq!(
            verdict.refusals[0].unsupported,
            Some(UnsupportedReason::ClassicMultisig)
        );
        assert!(!verdict.coverage_exclusions.is_empty());
        assert!(!verdict.notes.expired_rules.is_empty());
        let mut wire = serde_json::to_value(&verdict).unwrap();
        wire["evidence"] = serde_json::json!({
            "enumeration_evidence": {
                "method": "bounded_next_id",
                "next_id": 4,
                "active_count": 4,
                "rule_ids": [0, 1, 2, 3],
                "signer_ids": [0, 1],
                "policy_ids": [0]
            },
            "source": "testnet",
            "evidence_trust": "rpc_reported",
            "raw_ordered_entry_digest": "raw",
            "rpc_batches": 5,
            "attempts": 1
        });
        let decoded: ozpb_api_types::PolicyCallSurfaceVerdict =
            serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), wire);
    }

    /// A passkey owner is an identity only through a verifier the signed registry recognizes
    /// as an immutable, stateless owner verifier, by the code observed at its address.
    #[test]
    fn a_passkey_owner_is_listed_through_the_registry() {
        let network = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
        let passkey_owner = |request: &CheckPolicyCallSurfaceInput,
                             observation: &mut CallSurfaceObservation,
                             code: ozpb_domain::Hash32| {
            let mut key = vec![0x04];
            key.extend_from_slice(&[0x31; 64]);
            key.extend_from_slice(b"credential");
            observation.account_state.signers.get_mut(&0).unwrap().key =
                StoredSignerKey::External {
                    verifier: address(60),
                    key_hex: hex::encode(key),
                };
            observation
                .verifier_code_hashes
                .insert(address(60), code.to_hex());
            check(request, observation).unwrap().verdict
        };

        // Version 3 of the signed example recognizes OZ's WebAuthn verifier.
        let (mut request, mut observation) = fixture();
        replace_fixture_snapshot(
            &mut request,
            &mut observation,
            ozpb_registry::dev::verifier_successor(network).unwrap(),
        );
        let verdict = passkey_owner(
            &request,
            &mut observation,
            ozpb_domain::pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM,
        );
        assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());
        let mut wire = serde_json::to_value(&verdict).unwrap();
        assert_eq!(
            wire["authority_list"][0]["requirement"]["signers"][0]["kind"],
            "external"
        );
        assert_eq!(
            wire["authority_list"][0]["requirement"]["signers"][0]["scheme"],
            "webauthn_p256"
        );
        wire["evidence"] = serde_json::json!({
            "enumeration_evidence": {
                "method": "bounded_next_id", "next_id": 2, "active_count": 2,
                "rule_ids": [0, 1], "signer_ids": [0, 1], "policy_ids": [0]
            },
            "source": "testnet", "evidence_trust": "rpc_reported",
            "raw_ordered_entry_digest": "raw", "rpc_batches": 5, "attempts": 1
        });
        let decoded: ozpb_api_types::PolicyCallSurfaceVerdict =
            serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), wire);

        // A verifier address cannot run two codes at one ledger: one that is also a bound
        // policy with other code is an inconsistent observation.
        let mut conflicting = observation.clone();
        conflicting.verifier_code_hashes.insert(
            request.binding_set.bindings[0].contract_address.clone(),
            ozpb_domain::pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM.to_hex(),
        );
        assert_eq!(
            check(&request, &conflicting).unwrap_err().code,
            EC::EIncompleteAccountState
        );

        // Version 1 recognizes no owner verifier, and other code is never one.
        let (request, mut observation) = fixture();
        let verdict = passkey_owner(
            &request,
            &mut observation,
            ozpb_domain::pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM,
        );
        assert_eq!(
            verdict.refusals[0].unsupported,
            Some(UnsupportedReason::ExternalSigner)
        );
    }

    /// A classic-account owner the reader did not read is not described.
    #[test]
    fn unread_classic_owner_is_unresolved() {
        let (request, mut observation) = fixture();
        observation.classic_accounts.remove(&classic(10));
        let output = check(&request, &observation).unwrap();
        assert!(output.verdict.refusals.is_empty());
        assert_eq!(
            output.verdict.unresolved[0].code,
            FindingCode::IncompleteAccountState
        );
        assert_eq!(output.verdict.unresolved[0].rule_id, Some(0));
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
        replace_fixture_snapshot(&mut request, &mut observation, snapshot);

        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EAccountRuleEnumerationUnsupported);
        assert!(error.message.contains("onchain_list"));
    }

    #[test]
    fn signed_template_must_declare_the_generated_rules_capabilities() {
        let (mut request, mut observation) = fixture();
        let network = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
        let mut snapshot = ozpb_registry::dev::dev_snapshot(network, 1);
        snapshot
            .templates
            .get_mut("policy-templates/scope@1")
            .unwrap()
            .constraint_kinds
            .retain(|kind| kind != "eq_address");
        replace_fixture_snapshot(&mut request, &mut observation, snapshot);

        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EUnsupportedPattern);
        assert!(error.message.contains("policy-templates/scope@1"));
        assert!(error
            .details
            .iter()
            .any(|detail| detail.contains("eq_address")));

        let (mut request, mut observation) = fixture();
        let spec: PolicySpec = serde_json::from_value(request.spec.clone()).unwrap();
        let predicate = spec.rules[0].authorization.kind.kind_name();
        let mut snapshot = ozpb_registry::dev::dev_snapshot(network, 1);
        snapshot
            .templates
            .get_mut("policy-templates/scope@1")
            .unwrap()
            .signer_predicates
            .retain(|kind| kind != predicate);
        replace_fixture_snapshot(&mut request, &mut observation, snapshot);

        let error = check(&request, &observation).unwrap_err();
        assert_eq!(error.code, EC::EUnsupportedPattern);
        assert!(error
            .details
            .iter()
            .any(|detail| detail.contains(predicate)));
    }
}
