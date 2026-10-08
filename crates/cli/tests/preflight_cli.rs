//! Exercise the CLI path through a local RPC responder.

#[path = "../../../tests/support/preflight_rpc.rs"]
mod preflight_rpc;

use std::process::Command;

#[test]
fn preflight_command_reports_the_same_bounded_evidence_as_rpc_acquisition() {
    let (rpc_url, requests) = preflight_rpc::spawn();
    let envelope = preflight_rpc::envelope();
    let directory = tempfile::tempdir().expect("temporary envelope directory");
    let envelope_file = directory.path().join("authorization.xdr.base64");
    std::fs::write(&envelope_file, format!("{envelope}\n")).expect("write exact envelope");
    let output = Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .arg("preflight-transaction")
        .arg("--envelope-file")
        .arg(&envelope_file)
        .args(["--rpc-url", &rpc_url, "--network", preflight_rpc::NETWORK])
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI JSON output");
    assert_eq!(result["outcome"], "simulated_success");
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
fn malformed_envelope_fails_before_any_rpc_request() {
    let directory = tempfile::tempdir().expect("temporary envelope directory");
    let envelope_file = directory.path().join("invalid.xdr.base64");
    std::fs::write(&envelope_file, "not-base64").expect("write invalid envelope");
    let output = Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .arg("preflight-transaction")
        .arg("--envelope-file")
        .arg(&envelope_file)
        .args([
            "--rpc-url",
            "http://127.0.0.1:1",
            "--network",
            preflight_rpc::NETWORK,
        ])
        .output()
        .expect("run CLI");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("E_RPC"), "{stderr}");
}
