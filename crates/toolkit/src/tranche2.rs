//! Operations that evaluate runtime policy behavior.

use super::{from_value, spec_error, to_value};
use ozpb_api_types::{ReferenceSuiteInput, ReferenceSuiteOutput, ToolError};
use ozpb_policy_spec::PolicySpec;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::wire_spec;

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
}
