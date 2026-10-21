use super::*;
use crate::test_support::{build_config, registry_trust, signed_registry_json, wire_spec};
use ozpb_api_types::{
    CheckPolicyCallSurfaceInput, DryRunInput, DryRunLayerId, DryRunLayerStatus, PolicyBinding,
    PolicyBindingSet, PolicyRecognition, VerifyInput, POLICY_BINDING_SET_SCHEMA,
};

fn request() -> DryRunInput {
    request_with_composition(false)
}

fn request_with_composition(composed: bool) -> DryRunInput {
    let mut spec = wire_spec().spec().clone();
    if !composed {
        spec.rules[0]
            .policies
            .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
    }
    let signed: SignedSnapshot = serde_json::from_value(signed_registry_json()).unwrap();
    spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
    let spec = spec.validate().unwrap();
    let json = serde_json::to_value(spec.spec()).unwrap();
    let generated = generate_code_with_build_config(
        &GenerateCodeInput {
            spec: json.clone(),
            rule_index: 0,
        },
        &build_config(),
    )
    .unwrap();
    DryRunInput {
        candidate: CheckPolicyCallSurfaceInput {
            spec: json.clone(),
            rule_index: 0,
            binding_set: PolicyBindingSet {
                schema: POLICY_BINDING_SET_SCHEMA.to_string(),
                spec_hash: spec.hash().to_hex(),
                network_id: spec.spec().network_id.0.to_hex(),
                bindings: spec.spec().rules[0]
                    .policies
                    .iter()
                    .enumerate()
                    .map(|(index, policy)| {
                        let (hash, recognition) = match policy {
                            PolicyRef::Generated { .. } => (
                                generated.wasm_hash.clone(),
                                PolicyRecognition::VerifiedGeneratedManifest {
                                    build_manifest: generated.build_manifest.clone(),
                                },
                            ),
                            PolicyRef::Reviewed { capability, .. } => {
                                (capability.to_hex(), PolicyRecognition::ReviewedRegistry)
                            }
                        };
                        PolicyBinding {
                            rule_index: 0,
                            policy_index: index,
                            contract_address: format!(
                                "{}",
                                stellar_strkey::Contract([40 + index as u8; 32])
                            ),
                            observed_wasm_hash: hash,
                            recognition,
                            resolution_reference: "candidate policy instance".into(),
                        }
                    })
                    .collect(),
            },
            signed_registry_snapshot: signed_registry_json(),
            account_address: spec.spec().smart_account.address.clone(),
            network_id: spec.spec().network_id.0.to_hex(),
            rpc_source: "wallet".into(),
        },
        artifact: VerifyInput {
            spec: json,
            rule_index: 0,
            claimed_generated_files: generated
                .files
                .into_iter()
                .filter(|(name, _)| name != "Cargo.lock")
                .collect(),
            claimed_wasm_base64: Some(generated.wasm_base64),
            claimed_build_manifest: Some(generated.build_manifest),
        },
        candidate_context_rule_id: 7,
        run_nonce: "11".repeat(32),
    }
}

#[test]
fn agreeing_generated_cases_do_not_cover_an_unmodeled_composed_policy() {
    let input = request_with_composition(true);
    let out =
        prepare_dry_run_with_build_config(&input, &registry_trust(), &build_config()).unwrap();
    assert!(out.artifact_verification.matches);
    assert!(!out.artifact_verification.models_all_policies);
    assert_eq!(out.layers[0].status, DryRunLayerStatus::Unsupported);
    assert_eq!(out.reference_report["disagreements"], 0);
    assert!(!out.complete);
}

#[test]
fn reproduced_reference_cannot_become_a_complete_four_layer_run() {
    let input = request();
    let out =
        prepare_dry_run_with_build_config(&input, &registry_trust(), &build_config()).unwrap();
    assert!(!out.complete);
    assert!(out.artifact_verification.matches);
    assert_eq!(out.layers.len(), 4);
    assert_eq!(out.layers[0].id, DryRunLayerId::Reference);
    assert_eq!(out.layers[0].status, DryRunLayerStatus::Passed);
    assert!(out.layers[0].cases > 0);
    assert_eq!(out.layers[1].id, DryRunLayerId::AccountWasm);
    assert_eq!(out.layers[2].id, DryRunLayerId::CapturedTarget);
    assert_eq!(out.layers[3].id, DryRunLayerId::LiveEnforcement);
    for layer in &out.layers[1..] {
        assert_eq!(layer.status, DryRunLayerStatus::Unavailable);
        assert_eq!(layer.cases, 0);
        assert!(!layer.writes_committed);
    }
    assert_eq!(out.binding.candidate_context_rule_id, 7);
    assert_eq!(out.binding.account_address, input.candidate.account_address);
    assert_eq!(out.binding.network_id, input.candidate.network_id);
    assert_eq!(out.binding.spec_hash, input.candidate.binding_set.spec_hash);
}

#[test]
fn arbitrary_layer_results_commands_and_credentials_are_not_request_fields() {
    let input = serde_json::to_value(request()).unwrap();
    for field in ["layers", "complete", "signing_key", "command", "rpc_url"] {
        let mut value = input.clone();
        value[field] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<DryRunInput>(value).is_err(),
            "unexpected field {field}"
        );
    }
}

#[test]
fn candidate_and_artifact_must_describe_the_same_rule_and_spec() {
    let input = request();
    for alter in [
        |i: &mut DryRunInput| i.artifact.rule_index = 1,
        |i: &mut DryRunInput| i.artifact.spec["rules"][0]["name"] = "other".into(),
        |i: &mut DryRunInput| i.run_nonce = "FF".repeat(32),
        |i: &mut DryRunInput| i.run_nonce = "11".into(),
    ] {
        let mut changed = input.clone();
        alter(&mut changed);
        assert!(
            prepare_dry_run_with_build_config(&changed, &registry_trust(), &build_config())
                .is_err()
        );
    }
}

#[test]
fn changed_claims_and_bindings_cannot_produce_a_passed_artifact() {
    let mut input = request();
    input
        .artifact
        .claimed_generated_files
        .insert("src/injected.rs".into(), "unsafe source".into());
    let out =
        prepare_dry_run_with_build_config(&input, &registry_trust(), &build_config()).unwrap();
    assert!(!out.artifact_verification.matches);
    assert!(!out.complete);

    input = request();
    input.candidate.binding_set.bindings[0].observed_wasm_hash = "ff".repeat(32);
    assert!(prepare_dry_run_with_build_config(&input, &registry_trust(), &build_config()).is_err());
}

#[test]
fn run_identity_binds_nonce_rule_id_rpc_source_and_every_artifact_claim() {
    let input = request();
    let baseline =
        prepare_dry_run_with_build_config(&input, &registry_trust(), &build_config()).unwrap();
    for alter in [
        |i: &mut DryRunInput| i.run_nonce = "22".repeat(32),
        |i: &mut DryRunInput| i.candidate_context_rule_id = 8,
        |i: &mut DryRunInput| i.candidate.rpc_source = "other-configured-source".into(),
        |i: &mut DryRunInput| {
            i.artifact
                .claimed_generated_files
                .insert("extra".into(), "changed".into());
        },
    ] {
        let mut changed = input.clone();
        alter(&mut changed);
        let out = prepare_dry_run_with_build_config(&changed, &registry_trust(), &build_config())
            .unwrap();
        assert_ne!(out.run_hash, baseline.run_hash);
    }
}
