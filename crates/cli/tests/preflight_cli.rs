//! Exercise the CLI path through a local RPC responder.

#[path = "../../../tests/support/preflight_rpc.rs"]
mod preflight_rpc;

use preflight_rpc::ENDPOINT_DETAIL;
use std::process::{Command, Output};

/// Run the command on an envelope file holding exactly `contents`.
fn preflight(rpc_url: &str, contents: &str) -> Output {
    let directory = tempfile::tempdir().expect("temporary envelope directory");
    let envelope_file = directory.path().join("authorization.xdr.base64");
    std::fs::write(&envelope_file, contents).expect("write envelope file");
    Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .arg("preflight-transaction")
        .arg("--envelope-file")
        .arg(&envelope_file)
        .args(["--rpc-url", rpc_url, "--network", preflight_rpc::NETWORK])
        .output()
        .expect("run CLI")
}

#[test]
fn preflight_command_reports_the_same_bounded_evidence_as_rpc_acquisition() {
    let envelope = preflight_rpc::envelope();
    let (rpc_url, requests) = preflight_rpc::spawn(preflight_rpc::success(&envelope));
    let output = preflight(&rpc_url, &format!("{envelope}\n"));
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI JSON output");
    assert_eq!(result["outcome"], "simulated_success");
    assert_eq!(
        result["insufficient_declared_resources"],
        serde_json::json!([])
    );
    assert_eq!(result["below_endpoint_estimate"], serde_json::json!([]));
    assert_eq!(result["auth_mode"], "enforce");
    assert_eq!(result["evidence_trust"], "rpc_reported");
    assert_eq!(result["reported_ledger"], 4_104_380);
    assert_eq!(result["state_dependent"], true);
    assert_eq!(result["writes_committed"], false);
    assert!(result.get("policy_verdict").is_none());
    let requests = requests.join().expect("RPC fixture thread");
    assert_eq!(requests[0]["method"], "getNetwork");
    assert_eq!(requests[1]["method"], "simulateTransaction");
    assert_eq!(requests[1]["params"]["authMode"], "enforce");
    assert_eq!(requests[1]["params"]["transaction"], envelope);
}

#[test]
fn every_simulation_outcome_is_reported_without_endpoint_text() {
    let envelope = preflight_rpc::envelope();
    for case in preflight_rpc::outcome_cases(&envelope) {
        let (rpc_url, requests) = preflight_rpc::spawn(case.simulation);
        let output = preflight(&rpc_url, &format!("{envelope}\n"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A reported outcome is a completed observation, so the command exits 0 for each one;
        // a caller reads `outcome` rather than the exit status.
        assert!(output.status.success(), "{}: {stderr}", case.name);
        let result: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("CLI JSON output");
        assert_eq!(result["outcome"], case.outcome, "{}: {result}", case.name);
        assert_eq!(
            result["insufficient_declared_resources"],
            serde_json::json!(case.insufficient_declared_resources),
            "{}: {result}",
            case.name
        );
        assert_eq!(
            result["below_endpoint_estimate"],
            serde_json::json!(case.below_endpoint_estimate),
            "{}: {result}",
            case.name
        );
        assert!(
            !stdout.contains(ENDPOINT_DETAIL) && !stderr.contains(ENDPOINT_DETAIL),
            "{}: endpoint text reached the output",
            case.name
        );
        requests.join().expect("RPC fixture thread");
    }
}

#[test]
fn an_endpoint_refusal_is_an_rpc_error_without_endpoint_text() {
    let envelope = preflight_rpc::envelope();
    let (rpc_url, requests) = preflight_rpc::spawn(preflight_rpc::refusal());
    let output = preflight(&rpc_url, &format!("{envelope}\n"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(output.stdout.is_empty(), "a refusal prints no observation");
    assert!(stderr.contains("E_RPC: rpc error"), "{stderr}");
    assert!(stderr.contains("withheld"), "{stderr}");
    assert!(!stderr.contains(ENDPOINT_DETAIL), "{stderr}");
    requests.join().expect("RPC fixture thread");
}

#[test]
fn malformed_envelope_fails_before_any_rpc_request() {
    let endpoint = preflight_rpc::CountingEndpoint::bind();
    let output = preflight(&endpoint.url, "not-base64");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("E_ENVELOPE_PARSE: invalid transaction envelope"),
        "{stderr}"
    );
    assert!(!stderr.contains("transport"), "{stderr}");
    assert_eq!(
        endpoint.connections(),
        0,
        "the envelope reached the network: {stderr}"
    );
}

#[test]
fn whitespace_inside_the_envelope_is_refused_before_the_network() {
    let envelope = preflight_rpc::envelope();
    for whitespace in preflight_rpc::ENVELOPE_WHITESPACE {
        let endpoint = preflight_rpc::CountingEndpoint::bind();
        let spaced = preflight_rpc::with_inner(&envelope, whitespace);
        // The file still ends with the one line break a text editor adds.
        let output = preflight(&endpoint.url, &format!("{spaced}\n"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{whitespace:?}: {stderr}");
        assert!(
            stderr.contains(preflight_rpc::WHITESPACE_REFUSAL),
            "{whitespace:?}: {stderr}"
        );
        assert_eq!(endpoint.connections(), 0, "{whitespace:?}: {stderr}");
    }
}

#[test]
fn an_oversized_envelope_file_is_a_resource_limit_before_the_network() {
    let limit = ozpb_source_rpc::MAX_XDR_BASE64_BYTES;
    // One byte over the envelope bound fits the file reader's allowance for a line ending, so
    // the shared envelope check refuses it; three bytes over, the file reader itself does.
    for contents in ["A".repeat(limit + 1), "A".repeat(limit + 3)] {
        let endpoint = preflight_rpc::CountingEndpoint::bind();
        let output = preflight(&endpoint.url, &contents);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains("E_RESOURCE_LIMIT: "), "{stderr}");
        assert!(!stderr.contains("E_RPC"), "{stderr}");
        assert_eq!(endpoint.connections(), 0, "{stderr}");
    }
}
