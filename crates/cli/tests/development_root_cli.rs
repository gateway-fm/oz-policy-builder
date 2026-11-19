//! The public development registry root, configured through the committed roots file, is refused
//! for mainnet by every CLI command that pins registry trust — with `E_REGISTRY_ROOT_POLICY`, before
//! any read. Each request is otherwise consistent: the snapshot is correctly signed for mainnet and
//! the spec names its root, so the only thing wrong is a root anyone can sign with.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MAINNET: &str = "Public Global Stellar Network ; September 2015";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn mainnet() -> ozpb_domain::NetworkId {
    ozpb_domain::NetworkId::from_passphrase(MAINNET)
}

/// A mainnet snapshot signed with the development key, as anyone could sign one.
fn signed_mainnet_snapshot() -> ozpb_registry::SignedSnapshot {
    let snapshot = ozpb_registry::dev::account_advisory_successor(mainnet()).unwrap();
    ozpb_registry::sign_snapshot(&ozpb_registry::dev::dev_signing_key(), snapshot).unwrap()
}

fn ozpb(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .args(args)
        .output()
        .expect("run CLI")
}

fn assert_refused(output: &Output, command: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{command} must fail: {stderr}");
    // The code that leads the error, not a label inside its message: the refusal used to arrive
    // as `E_REGISTRY_SIGNATURE` carrying a root-policy message.
    assert!(
        stderr.starts_with("Error: E_REGISTRY_ROOT_POLICY: ") && stderr.contains("only on testnet"),
        "{command}: {stderr}"
    );
}

#[test]
fn synthesize_refuses_the_development_root_for_mainnet() {
    let dir = tempfile::tempdir().unwrap();
    let mut bundle: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("docs/examples/import-bundle.json")).unwrap(),
    )
    .unwrap();
    bundle["network_passphrase"] = MAINNET.into();
    let bundle_path = dir.path().join("bundle.json");
    std::fs::write(&bundle_path, bundle.to_string()).unwrap();
    let imported = ozpb(&[
        "import".as_ref(),
        "--bundle".as_ref(),
        bundle_path.as_os_str(),
    ]);
    assert!(imported.status.success(), "{imported:?}");
    let recording = dir.path().join("recording.json");
    std::fs::write(&recording, &imported.stdout).unwrap();
    let snapshot = dir.path().join("registry.signed.json");
    std::fs::write(
        &snapshot,
        serde_json::to_string(&signed_mainnet_snapshot()).unwrap(),
    )
    .unwrap();
    let account: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("docs/examples/account.json")).unwrap(),
    )
    .unwrap();
    let output = ozpb(&[
        "synthesize".as_ref(),
        "--bundle".as_ref(),
        recording.as_os_str(),
        "--selected-authorizer".as_ref(),
        account["address"].as_str().unwrap().as_ref(),
        "--account".as_ref(),
        repo().join("docs/examples/account.json").as_os_str(),
        "--signed-registry".as_ref(),
        snapshot.as_os_str(),
        "--registry-roots".as_ref(),
        repo().join("docs/examples/registry-roots.json").as_os_str(),
        "--registry-min-version".as_ref(),
        "1".as_ref(),
        "--decisions".as_ref(),
        repo().join("docs/examples/decisions.json").as_os_str(),
        "--template-family".as_ref(),
        "policy-templates/scope@1".as_ref(),
    ]);
    assert_refused(&output, "synthesize");
}

/// The live-check request of `authority_cli.rs`, moved to mainnet.
fn mainnet_request(dir: &Path, command: &str) -> PathBuf {
    let signed = signed_mainnet_snapshot();
    let mut spec: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("docs/examples/subscription-spec.json")).unwrap(),
    )
    .unwrap();
    spec["network_id"] = mainnet().0.to_hex().into();
    spec["registry_snapshot"] = ozpb_registry::snapshot_root(&signed.snapshot)
        .unwrap()
        .to_hex()
        .into();
    let mut request = serde_json::json!({
        "spec": spec,
        "rule_index": 0,
        "binding_set": {"schema": "policy-binding-set/v1", "spec_hash": "00",
                        "network_id": spec["network_id"], "bindings": []},
        "signed_registry_snapshot": signed,
        "account_address": spec["smart_account"]["address"],
        "network_id": spec["network_id"],
        "rpc_source": "mainnet"
    });
    if command == "check-against-policy" {
        request["installed_context_rule_id"] = 42.into();
        request["candidate_signers"] = serde_json::json!([]);
        request["invocation"] = serde_json::json!({
            "contract": spec["rules"][0]["context"]["contract"],
            "fn_name": "transfer",
            "args": []
        });
    }
    let path = dir.join(format!("{command}.json"));
    std::fs::write(&path, request.to_string()).unwrap();
    path
}

#[test]
fn live_checks_refuse_the_development_root_for_mainnet_before_any_read() {
    let dir = tempfile::tempdir().unwrap();
    let sources = dir.path().join("sources.json");
    // An endpoint that cannot answer: the refusal must come before anything is read.
    std::fs::write(
        &sources,
        serde_json::json!({"mainnet": {"rpc_url": "https://rpc.invalid", "network_passphrase": MAINNET}})
            .to_string(),
    )
    .unwrap();
    for command in [
        "check-policy-call-surface",
        "prepare-install-intent",
        "check-against-policy",
    ] {
        let request = mainnet_request(dir.path(), command);
        let output = ozpb(&[
            command.as_ref(),
            "--request".as_ref(),
            request.as_os_str(),
            "--registry-roots".as_ref(),
            repo().join("docs/examples/registry-roots.json").as_os_str(),
            "--registry-min-version".as_ref(),
            "1".as_ref(),
            "--rpc-sources".as_ref(),
            sources.as_os_str(),
        ]);
        assert_refused(&output, command);
    }
}
