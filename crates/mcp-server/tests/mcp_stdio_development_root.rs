//! The public development registry root, configured as the server's pinned trust, is refused for
//! mainnet by every tool that pins registry trust — with `E_REGISTRY_ROOT_POLICY`, before any read.
//! Each request is otherwise consistent: the snapshot is correctly signed for mainnet and the spec
//! names its root, so the only thing wrong is a root anyone can sign with.

mod common;
use common::*;
use serde_json::{json, Value};

fn mainnet() -> ozpb_domain::NetworkId {
    ozpb_domain::NetworkId::from_passphrase(ozpb_domain::MAINNET_PASSPHRASE)
}

fn signed_mainnet_snapshot() -> ozpb_registry::SignedSnapshot {
    let snapshot = ozpb_registry::dev::account_advisory_successor(mainnet()).unwrap();
    ozpb_registry::sign_snapshot(&ozpb_registry::dev::dev_signing_key(), snapshot).unwrap()
}

/// Development roots, and a mainnet source whose endpoint cannot answer.
fn env() -> Vec<(&'static str, String)> {
    let root: String = ozpb_registry::dev::dev_root_verifying_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    vec![
        (
            "OZPB_REGISTRY_ROOTS_JSON",
            json!({"threshold": 1, "keys": {"legacy": root}}).to_string(),
        ),
        ("OZPB_REGISTRY_MIN_VERSION", "1".to_string()),
        (
            "OZPB_RPC_SOURCES_JSON",
            json!({"mainnet": {"rpc_url": "https://rpc.invalid",
                               "network_passphrase": ozpb_domain::MAINNET_PASSPHRASE}})
            .to_string(),
        ),
    ]
}

fn call(tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
           "params": {"name": tool, "arguments": arguments}})
}

fn refusal(responses: &[Value], tool: &str) {
    let result = &by_id(responses, 2)["result"];
    assert_eq!(result["isError"], true, "{tool}: {result}");
    assert_eq!(
        result["structuredContent"]["code"], "E_REGISTRY_ROOT_POLICY",
        "{tool}: {result}"
    );
}

#[test]
fn synthesis_refuses_the_development_root_for_mainnet() {
    let bundle = ozpb_synthesizer::fixtures::golden_bundle_on(ozpb_domain::MAINNET_PASSPHRASE);
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            call(
                "synthesize_policy",
                json!({
                    "bundles": [bundle],
                    "decisions": ozpb_synthesizer::fixtures::golden_decisions(),
                    "spending_limit_capability": "pinned",
                    "signed_registry_snapshot": signed_mainnet_snapshot(),
                }),
            ),
        ],
        &env(),
    );
    refusal(&responses, "synthesize_policy");
}

#[test]
fn live_checks_refuse_the_development_root_for_mainnet_before_any_read() {
    let signed = signed_mainnet_snapshot();
    let mut spec = subscription_spec();
    spec["network_id"] = mainnet().0.to_hex().into();
    spec["registry_snapshot"] = ozpb_registry::snapshot_root(&signed.snapshot)
        .unwrap()
        .to_hex()
        .into();
    let request = json!({
        "spec": spec,
        "rule_index": 0,
        "binding_set": {"schema": "policy-binding-set/v1", "spec_hash": "00",
                        "network_id": spec["network_id"], "bindings": []},
        "signed_registry_snapshot": signed,
        "account_address": spec["smart_account"]["address"],
        "network_id": spec["network_id"],
        "rpc_source": "mainnet"
    });
    let mut policy_check = request.clone();
    policy_check["installed_context_rule_id"] = 42.into();
    policy_check["candidate_signers"] = json!([]);
    policy_check["invocation"] = json!({
        "contract": spec["rules"][0]["context"]["contract"],
        "fn_name": "transfer",
        "args": []
    });
    for (tool, arguments) in [
        ("check_policy_call_surface", request.clone()),
        ("prepare_install_intent", request),
        ("check_against_policy", policy_check),
    ] {
        let responses = run_session_with_env(
            &[initialize(), initialized(), call(tool, arguments)],
            &env(),
        );
        refusal(&responses, tool);
    }
}
