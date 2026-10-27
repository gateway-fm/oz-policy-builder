//! The live authority command refuses, before any build or read, a request naming a source the
//! operator did not configure or one for another network. The endpoint is never the request's.

use std::process::{Command, Output};

const TESTNET: &str = "Test SDF Network ; September 2015";
const MAINNET: &str = "Public Global Stellar Network ; September 2015";

fn run(rpc_source: &str, sources: serde_json::Value) -> Output {
    run_command("check-policy-call-surface", rpc_source, sources)
}

fn run_command(command: &str, rpc_source: &str, sources: serde_json::Value) -> Output {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = env!("CARGO_MANIFEST_DIR");
    let spec: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{root}/../../docs/examples/subscription-spec.json"))
            .unwrap(),
    )
    .unwrap();
    let request = serde_json::json!({
        "spec": spec,
        "rule_index": 0,
        "binding_set": {"schema": "policy-binding-set/v1", "spec_hash": "00",
                        "network_id": spec["network_id"], "bindings": []},
        "signed_registry_snapshot": {},
        "account_address": spec["smart_account"]["address"],
        "network_id": spec["network_id"],
        "rpc_source": rpc_source
    });
    let request_file = directory.path().join("request.json");
    std::fs::write(&request_file, request.to_string()).unwrap();
    let sources_file = directory.path().join("sources.json");
    std::fs::write(&sources_file, sources.to_string()).unwrap();
    Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .arg(command)
        .arg("--request")
        .arg(&request_file)
        .arg("--registry-roots")
        .arg(format!("{root}/../../docs/examples/registry-roots.json"))
        .args(["--registry-min-version", "4"])
        .arg("--rpc-sources")
        .arg(&sources_file)
        .output()
        .expect("run CLI")
}

#[test]
fn an_unconfigured_source_is_refused_before_any_read() {
    let output = run(
        "anywhere",
        serde_json::json!({"testnet": {"rpc_url": "https://rpc.invalid", "network_passphrase": TESTNET}}),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("E_RPC") && stderr.contains("anywhere"),
        "{stderr}"
    );
}

#[test]
fn the_install_intent_refuses_an_unconfigured_source_before_any_read() {
    let output = run_command(
        "prepare-install-intent",
        "anywhere",
        serde_json::json!({"testnet": {"rpc_url": "https://rpc.invalid", "network_passphrase": TESTNET}}),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("E_RPC"), "{stderr}");
}

#[test]
fn a_source_for_another_network_is_refused_before_any_read() {
    let output = run(
        "mainnet",
        serde_json::json!({"mainnet": {"rpc_url": "https://rpc.invalid", "network_passphrase": MAINNET}}),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("E_NETWORK_MISMATCH"), "{stderr}");
}
