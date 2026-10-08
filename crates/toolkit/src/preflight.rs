//! The wire form of one exact-envelope preflight. Acquisition is the shell's job: the CLI
//! and the MCP server each run the simulation through `ozpb_source_rpc` and hand the
//! observation here, so the two cannot describe the same outcome in different words.

use ozpb_api_types::{
    PreflightDeclaredResource, PreflightEstimatedResource, PreflightTransactionOutcome,
    PreflightTransactionOutput,
};
use ozpb_source_rpc::{
    DeclaredResource, EstimatedResource, PreflightObservation, PreflightOutcome, SimulationAuthMode,
};

/// The wire output for one observation. Only a shortfall lists declared resources, and it
/// lists dimensions, never keys: the footprint is confidential envelope content. Values below
/// the endpoint's estimate travel beside the outcome as advice and never change it.
pub fn preflight_transaction_output(
    observation: PreflightObservation,
) -> PreflightTransactionOutput {
    let (outcome, insufficient_declared_resources) = match observation.outcome {
        PreflightOutcome::SimulatedSuccess => {
            (PreflightTransactionOutcome::SimulatedSuccess, vec![])
        }
        PreflightOutcome::SimulationFailed => {
            (PreflightTransactionOutcome::SimulationFailed, vec![])
        }
        PreflightOutcome::RestorationRequired => {
            (PreflightTransactionOutcome::RestorationRequired, vec![])
        }
        PreflightOutcome::DeclaredResourcesInsufficient(short) => (
            PreflightTransactionOutcome::DeclaredResourcesInsufficient,
            short.into_iter().map(declared_resource).collect(),
        ),
    };
    let auth_mode = match observation.auth_mode {
        SimulationAuthMode::Enforce => "enforce",
    };
    PreflightTransactionOutput {
        envelope_xdr_sha256: observation.envelope_xdr_sha256,
        network_id: observation.network_id,
        reported_ledger: observation.reported_ledger,
        outcome,
        insufficient_declared_resources,
        below_endpoint_estimate: observation
            .below_endpoint_estimate
            .into_iter()
            .map(estimated_resource)
            .collect(),
        auth_mode: auth_mode.to_string(),
        evidence_trust: observation.evidence_trust.as_str().to_string(),
        state_dependent: observation.state_dependent,
        writes_committed: observation.writes_committed,
    }
}

fn declared_resource(resource: DeclaredResource) -> PreflightDeclaredResource {
    match resource {
        DeclaredResource::ReadOnlyFootprint => PreflightDeclaredResource::ReadOnlyFootprint,
        DeclaredResource::ReadWriteFootprint => PreflightDeclaredResource::ReadWriteFootprint,
        DeclaredResource::DiskReadBytes => PreflightDeclaredResource::DiskReadBytes,
        DeclaredResource::WriteBytes => PreflightDeclaredResource::WriteBytes,
    }
}

fn estimated_resource(resource: EstimatedResource) -> PreflightEstimatedResource {
    match resource {
        EstimatedResource::Instructions => PreflightEstimatedResource::Instructions,
        EstimatedResource::ResourceFee => PreflightEstimatedResource::ResourceFee,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_domain::TrustLevel;
    use ozpb_source_rpc::EstimatedResource;

    fn observed(
        outcome: PreflightOutcome,
        below_endpoint_estimate: Vec<EstimatedResource>,
    ) -> PreflightObservation {
        PreflightObservation {
            envelope_xdr_sha256: "ab".repeat(32),
            network_id: "cd".repeat(32),
            reported_ledger: 7,
            outcome,
            below_endpoint_estimate,
            auth_mode: SimulationAuthMode::Enforce,
            evidence_trust: TrustLevel::rpc_reported(),
            state_dependent: true,
            writes_committed: false,
        }
    }

    #[test]
    fn every_outcome_keeps_its_wire_name_and_only_a_shortfall_lists_resources() {
        for (outcome, name, listed) in [
            (
                PreflightOutcome::SimulatedSuccess,
                "simulated_success",
                vec![],
            ),
            (
                PreflightOutcome::SimulationFailed,
                "simulation_failed",
                vec![],
            ),
            (
                PreflightOutcome::RestorationRequired,
                "restoration_required",
                vec![],
            ),
            (
                PreflightOutcome::DeclaredResourcesInsufficient(vec![
                    DeclaredResource::ReadOnlyFootprint,
                    DeclaredResource::ReadWriteFootprint,
                    DeclaredResource::DiskReadBytes,
                    DeclaredResource::WriteBytes,
                ]),
                "declared_resources_insufficient",
                vec![
                    "read_only_footprint",
                    "read_write_footprint",
                    "disk_read_bytes",
                    "write_bytes",
                ],
            ),
        ] {
            let wire =
                serde_json::to_value(preflight_transaction_output(observed(outcome, vec![])))
                    .expect("preflight output JSON");
            assert_eq!(wire["outcome"], name, "{wire}");
            assert_eq!(
                wire["insufficient_declared_resources"],
                serde_json::json!(listed),
                "{wire}"
            );
            assert_eq!(
                wire["below_endpoint_estimate"],
                serde_json::json!([]),
                "{wire}"
            );
            assert_eq!(wire["auth_mode"], "enforce", "{wire}");
            assert_eq!(wire["evidence_trust"], "rpc_reported", "{wire}");
            assert_eq!(wire["reported_ledger"], 7, "{wire}");
            assert_eq!(wire["envelope_xdr_sha256"], "ab".repeat(32), "{wire}");
            assert_eq!(wire["network_id"], "cd".repeat(32), "{wire}");
            assert_eq!(wire["state_dependent"], true, "{wire}");
            assert_eq!(wire["writes_committed"], false, "{wire}");
        }
    }

    #[test]
    fn an_estimate_shortfall_is_advice_beside_the_outcome() {
        // The adapter compares against the endpoint's padded estimates only after a simulated
        // success; the wire keeps them apart from the outcome and the declared shortfall.
        for (outcome, name) in [
            (PreflightOutcome::SimulatedSuccess, "simulated_success"),
            (
                PreflightOutcome::DeclaredResourcesInsufficient(vec![DeclaredResource::WriteBytes]),
                "declared_resources_insufficient",
            ),
        ] {
            let wire = serde_json::to_value(preflight_transaction_output(observed(
                outcome,
                vec![
                    EstimatedResource::Instructions,
                    EstimatedResource::ResourceFee,
                ],
            )))
            .expect("preflight output JSON");
            assert_eq!(wire["outcome"], name, "{wire}");
            assert_eq!(
                wire["below_endpoint_estimate"],
                serde_json::json!(["instructions", "resource_fee"]),
                "{wire}"
            );
        }
    }
}
