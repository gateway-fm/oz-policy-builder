//! The live authority command refuses, before any build or read, a request naming a source the
//! operator did not configure or one for another network. The endpoint is never the request's.

use std::process::{Command, Output};

const TESTNET: &str = "Test SDF Network ; September 2015";
const MAINNET: &str = "Public Global Stellar Network ; September 2015";

fn run(rpc_source: &str, sources: serde_json::Value) -> Output {
    run_command("check-policy-call-surface", rpc_source, sources)
}

fn run_command(command: &str, rpc_source: &str, sources: serde_json::Value) -> Output {
    run_with(command, rpc_source, sources, &[])
}

fn run_with(command: &str, rpc_source: &str, sources: serde_json::Value, extra: &[&str]) -> Output {
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
    let request = if command == "check-installed-grant" {
        serde_json::json!({"candidate": request, "installed_rule": {"id": 1, "name": "retained grant",
            "context_contract": spec["rules"][0]["context"]["contract"], "valid_until": null,
            "signer_ids": [1], "policy_ids": [0]}})
    } else {
        request
    };
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
        .args(["--registry-min-version", "6"])
        .arg("--rpc-sources")
        .arg(&sources_file)
        .args(extra)
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

#[test]
fn installed_monitoring_refuses_an_unconfigured_source_before_any_build_or_read() {
    let output = run_command(
        "check-installed-grant",
        "anywhere",
        serde_json::json!({
        "testnet": {"rpc_url": "https://rpc.invalid", "network_passphrase": TESTNET}}),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("E_RPC") && stderr.contains("anywhere"),
        "{stderr}"
    );
}

/// Scheduled from cron, the installed-grant check says what it found by its exit status alone:
/// 0 unchanged, 3 changed, 5 inactive, 4 no answer from the read or the check, 1 an error before
/// any read. A configuration error is 1, never a status cron could take for an observation, and a
/// recorded commitment that is not one is refused before anything runs.
#[test]
fn scheduled_installed_monitoring_exits_with_a_status_cron_can_alert_on() {
    let help = Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .args(["check-installed-grant", "--help"])
        .output()
        .expect("run CLI");
    let help = String::from_utf8_lossy(&help.stdout);
    for status in [
        "0 unchanged",
        "3 changed",
        "5 inactive",
        "4 no answer",
        "1 an error",
        "2 a usage error",
        "--min-ledger",
    ] {
        assert!(
            help.contains(status),
            "the help must document {status:?}: {help}"
        );
    }

    let sources = serde_json::json!({
        "testnet": {"rpc_url": "https://rpc.invalid", "network_passphrase": TESTNET}});
    let commitment = "ab".repeat(32);
    let output = run_with(
        "check-installed-grant",
        "anywhere",
        sources.clone(),
        &[
            "--recorded-authority-commitment",
            &commitment,
            "--min-ledger",
            "100",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("E_RPC") && stderr.contains("anywhere"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "no observation was made");

    for malformed in [&"AB".repeat(32), &"ab".repeat(31), "not-a-commitment"] {
        let output = run_with(
            "check-installed-grant",
            "testnet",
            sources.clone(),
            &[
                "--recorded-authority-commitment",
                malformed,
                "--min-ledger",
                "100",
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{malformed}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("lowercase hex"),
            "{output:?}"
        );
    }
    // A scheduled run without a ledger floor could read a stuck endpoint's old ledger as unchanged
    // forever, and a floor alone schedules nothing: each needs the other.
    for alone in [
        vec!["--recorded-authority-commitment", commitment.as_str()],
        vec!["--min-ledger", "100"],
    ] {
        let output = run_with("check-installed-grant", "testnet", sources.clone(), &alone);
        assert_eq!(output.status.code(), Some(2), "{alone:?}: {output:?}");
    }
}
