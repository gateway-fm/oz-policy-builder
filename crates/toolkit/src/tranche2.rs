//! Operations that evaluate runtime policy behavior.

use super::{from_value, generate_code_with_build_config, spec_error, to_value, EC};
use base64::Engine;
use ozpb_api_types::{
    GenerateCodeInput, ReferenceSuiteInput, ReferenceSuiteOutput, ToolError, VerifyInput,
    VerifyOutput,
};
use ozpb_policy_spec::PolicySpec;
use std::collections::BTreeMap;

/// Run the layer-1 reference suite over a validated policy specification.
pub fn reference_suite(input: &ReferenceSuiteInput) -> Result<ReferenceSuiteOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errors| spec_error(&errors))?;
    let report = ozpb_harness::run_layer1(&validated);

    Ok(ReferenceSuiteOutput {
        total: report.total,
        disagreements: report.disagreements,
        all_agree: report.all_agree(),
        unmodeled_reviewed_policies: report
            .unmodeled_policies
            .iter()
            .map(|policy| format!("rule[{}]: {}", policy.rule_index, policy.kind))
            .collect(),
        coverage: report
            .coverage
            .iter()
            .map(|(class, count)| format!("{class:?}: {count}"))
            .collect(),
        missing_classes: report
            .missing_classes()
            .iter()
            .map(|(rule, class)| format!("rule[{rule}]: {class:?}"))
            .collect(),
        permit_only_classes: report
            .permit_only_classes()
            .iter()
            .map(|(rule, class)| format!("rule[{rule}]: {class:?}"))
            .collect(),
        report: to_value(&report)?,
    })
}

/// Reproduce generated files and Wasm, and report each verification dimension separately.
pub fn verify_with_build_config(
    input: &VerifyInput,
    build_config: &super::BuildConfig,
) -> Result<VerifyOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errors| spec_error(&errors))?;
    let generated = generate_code_with_build_config(
        &GenerateCodeInput {
            spec: input.spec.clone(),
            rule_index: input.rule_index,
        },
        build_config,
    )?;

    // BuildManifest.source_hash covers every generated file except Cargo.lock. Compare the
    // complete path set and contents so a changed toolchain or manifest cannot pass as source
    // reproduction.
    let regenerated: BTreeMap<String, String> = generated
        .files
        .iter()
        .filter(|(path, _)| path.as_str() != "Cargo.lock")
        .map(|(path, contents)| (path.clone(), contents.clone()))
        .collect();
    let source_matches = regenerated == input.claimed_generated_files;

    let claimed_wasm = input.claimed_wasm_base64.as_deref().and_then(|encoded| {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()
    });
    let reproduced_wasm = base64::engine::general_purpose::STANDARD
        .decode(&generated.wasm_base64)
        .map_err(|error| ToolError::new(EC::EInternal, error.to_string()))?;
    let wasm_matches = claimed_wasm
        .as_deref()
        .is_some_and(|claimed| claimed == reproduced_wasm);
    let manifest_matches = input
        .claimed_build_manifest
        .as_ref()
        .is_some_and(|claimed| claimed == &generated.build_manifest);

    let report = ozpb_harness::run_layer1(&validated);
    let missing_classes: Vec<String> = report
        .missing_classes()
        .iter()
        .map(|(rule, class)| format!("rule[{rule}]: {class:?}"))
        .collect();
    let behavior_ok = report.all_agree() && missing_classes.is_empty();

    Ok(VerifyOutput {
        spec_conformance: "conforms (validated PolicySpec v1)".to_string(),
        source_reproduction: if source_matches {
            "reproduced: generated non-lock files are byte-identical".to_string()
        } else {
            "MISMATCH: generated non-lock files differ from regeneration".to_string()
        },
        offline_behavioral_conformance: if !report.all_agree() {
            format!("FAIL: {} permit/deny disagreements", report.disagreements)
        } else if !missing_classes.is_empty() {
            format!(
                "FAIL: missing boundary classes: {}",
                missing_classes.join(", ")
            )
        } else if report.models_all_policies() {
            format!("pass: {} constraint-derived cases all agree", report.total)
        } else {
            format!(
                "pass (scope+count only): {} cases agree; {} composed reviewed policies are \
                 enforced on-chain and not modeled here",
                report.total,
                report.unmodeled_policies.len()
            )
        },
        wasm_reproduction: match (
            &input.claimed_wasm_base64,
            wasm_matches,
            &input.claimed_build_manifest,
            manifest_matches,
        ) {
            (None, _, _, _) => "not_verified: no claimed Wasm was supplied".to_string(),
            (Some(_), false, _, _) => {
                "MISMATCH: claimed Wasm differs from reproduction".to_string()
            }
            (Some(_), true, None, _) => "not_verified: no BuildManifest was supplied".to_string(),
            (Some(_), true, Some(_), false) => {
                "MISMATCH: claimed BuildManifest differs from reproduction".to_string()
            }
            (Some(_), true, Some(_), true) => {
                "reproduced: Wasm and BuildManifest are identical".to_string()
            }
        },
        current_network_preflight: "not_checked_here: state-dependent (wallet/live)".to_string(),
        normalized_input_hash: generated.normalized_input_hash,
        models_all_policies: report.models_all_policies(),
        unmodeled_reviewed_policies: report
            .unmodeled_policies
            .iter()
            .map(|policy| format!("rule[{}]: {}", policy.rule_index, policy.kind))
            .collect(),
        matches: source_matches && behavior_ok && wasm_matches && manifest_matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{build_config, wire_spec};

    #[test]
    fn reference_suite_reports_layer_one_evidence_and_coverage() {
        let spec = serde_json::to_value(wire_spec().spec()).unwrap();
        let output = reference_suite(&ReferenceSuiteInput { spec }).unwrap();
        let report: ozpb_harness::EvidenceReport =
            serde_json::from_value(output.report.clone()).unwrap();

        assert_eq!(report.layer, "layer1-reference-evaluator");
        assert!(output.total > 10);
        assert_eq!(output.total, report.total);
        assert_eq!(output.disagreements, report.disagreements);
        assert!(output.all_agree);
        assert!(!output.coverage.is_empty());
        assert_eq!(output.missing_classes.len(), report.missing_classes().len());
        assert!(!output.unmodeled_reviewed_policies.is_empty());
    }

    #[test]
    fn verification_reports_reproduction_without_claiming_live_preflight() {
        let spec = serde_json::to_value(wire_spec().spec()).unwrap();
        let build_config = build_config();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec.clone(),
                rule_index: 0,
            },
            &build_config,
        )
        .unwrap();
        let claimed_generated_files = generated
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != "Cargo.lock")
            .map(|(path, contents)| (path.clone(), contents.clone()))
            .collect();
        let output = verify_with_build_config(
            &VerifyInput {
                spec,
                rule_index: 0,
                claimed_generated_files,
                claimed_wasm_base64: Some(generated.wasm_base64),
                claimed_build_manifest: Some(generated.build_manifest),
            },
            &build_config,
        )
        .unwrap();

        assert!(output.matches);
        assert!(output.source_reproduction.starts_with("reproduced"));
        assert!(output.wasm_reproduction.starts_with("reproduced"));
        assert!(output
            .current_network_preflight
            .starts_with("not_checked_here"));
        assert!(!output.models_all_policies);
        assert!(!output.unmodeled_reviewed_policies.is_empty());
    }

    #[test]
    fn verification_checks_every_non_lock_file_and_requires_the_manifest() {
        let spec = serde_json::to_value(wire_spec().spec()).unwrap();
        let build_config = build_config();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec.clone(),
                rule_index: 0,
            },
            &build_config,
        )
        .unwrap();
        let claimed_generated_files = generated
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != "Cargo.lock")
            .map(|(path, contents)| (path.clone(), contents.clone()))
            .collect();
        let base = VerifyInput {
            spec,
            rule_index: 0,
            claimed_generated_files,
            claimed_wasm_base64: Some(generated.wasm_base64),
            claimed_build_manifest: Some(generated.build_manifest),
        };

        for path in ["Cargo.toml", "rust-toolchain.toml", "rustfmt.toml"] {
            let mut edited = base.clone();
            edited
                .claimed_generated_files
                .insert(path.to_string(), "changed".to_string());
            let output = verify_with_build_config(&edited, &build_config).unwrap();
            assert!(!output.matches, "{path} must be checked");
            assert!(output.source_reproduction.starts_with("MISMATCH"));
        }

        let mut missing_file = base.clone();
        missing_file.claimed_generated_files.remove("Cargo.toml");
        assert!(
            !verify_with_build_config(&missing_file, &build_config)
                .unwrap()
                .matches
        );
        let mut extra_file = base.clone();
        extra_file
            .claimed_generated_files
            .insert("src/extra.rs".to_string(), String::new());
        assert!(
            !verify_with_build_config(&extra_file, &build_config)
                .unwrap()
                .matches
        );

        let mut missing_manifest = base;
        missing_manifest.claimed_build_manifest = None;
        let output = verify_with_build_config(&missing_manifest, &build_config).unwrap();
        assert!(!output.matches);
        assert!(output.wasm_reproduction.starts_with("not_verified"));
    }
}
