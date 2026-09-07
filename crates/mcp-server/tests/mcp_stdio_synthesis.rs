//! `synthesize_policy` over stdio — the tool this milestone contracts, at the boundary that
//! serves it.
//!
//! The toolkit's own tests cover the derivation and the defaults; none of them starts this
//! binary. That gap is not hypothetical: `synthesize_policy` is refused unless the deployment
//! configures registry trust, and for a while nothing in the repository configured it, so a
//! fresh clone answered "disabled" while every toolkit test stayed green. What only a session
//! can check is the part between them — that the environment is read, that the optional fields
//! survive schema generation, and that the documented request shape is accepted as documented.

mod common;

use common::{by_id, initialize, initialized, run_session_with_env};

/// Roots, floor, and the snapshot a request may omit — the three an operator sets together.
fn configured_trust() -> Vec<(&'static str, String)> {
    let network = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
    let snapshot = ozpb_registry::dev::dev_snapshot(network, 1);
    let signed =
        ozpb_registry::sign_snapshot(&ozpb_registry::dev::dev_signing_key(), snapshot).unwrap();
    let root_hex = hex_of(
        ozpb_registry::dev::dev_signing_key()
            .verifying_key()
            .to_bytes(),
    );
    vec![
        (
            "OZPB_REGISTRY_ROOTS_JSON",
            serde_json::json!({"threshold": 1, "keys": {"legacy": root_hex}}).to_string(),
        ),
        ("OZPB_REGISTRY_MIN_VERSION", "1".to_string()),
        (
            "OZPB_REGISTRY_SNAPSHOT_JSON",
            serde_json::to_string(&signed).unwrap(),
        ),
    ]
}

fn hex_of(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn synthesize_call(arguments: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "synthesize_policy", "arguments": arguments}
    })
}

/// A recording of the shape `record_simulation` returns, carrying an observed account.
fn recorded_bundle() -> serde_json::Value {
    serde_json::to_value(ozpb_synthesizer::fixtures::golden_bundle()).unwrap()
}

fn decisions() -> serde_json::Value {
    serde_json::to_value(ozpb_synthesizer::fixtures::golden_decisions()).unwrap()
}

/// The request `docs/MCP-WALKTHROUGH.md` §3 documents: a recording, the decisions, and the
/// opt-in to composing the reviewed spending limit. Nothing else.
#[test]
fn the_documented_three_argument_request_returns_a_spec() {
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            synthesize_call(serde_json::json!({
                "bundles": [recorded_bundle()],
                "decisions": decisions(),
                "spending_limit_capability": "pinned",
            })),
        ],
        &configured_trust(),
    );
    let result = &by_id(&responses, 2)["result"];
    assert!(
        result["isError"] != serde_json::json!(true),
        "the documented call must not error: {result}"
    );
    let payload = &result["structuredContent"];
    assert_eq!(
        payload["spec_hash"].as_str().map(str::len),
        Some(64),
        "a spec hash is what this call is for: {payload}"
    );
    assert!(
        payload["spec"]["rules"].is_array(),
        "the spec has to come back with it: {payload}"
    );
}

/// Passing every field still works, and reaches the same artifact.
///
/// The fields were made optional, not replaced: a caller written against the earlier shape has
/// to keep getting the identical policy, or "wire-compatible" is a claim rather than a fact.
#[test]
fn the_explicit_request_reaches_the_same_spec() {
    let account = ozpb_synthesizer::fixtures::golden_input().account;
    let explicit = run_session_with_env(
        &[
            initialize(),
            initialized(),
            synthesize_call(serde_json::json!({
                "bundles": [recorded_bundle()],
                "selected_authorizer": ozpb_synthesizer::fixtures::golden_account_strkey(),
                "account": serde_json::to_value(&account).unwrap(),
                "decisions": decisions(),
                "spending_limit_capability": "pinned",
                "template_family": ozpb_api_types::DEFAULT_TEMPLATE_FAMILY,
            })),
        ],
        &configured_trust(),
    );
    let derived = run_session_with_env(
        &[
            initialize(),
            initialized(),
            synthesize_call(serde_json::json!({
                "bundles": [recorded_bundle()],
                "decisions": decisions(),
                "spending_limit_capability": "pinned",
            })),
        ],
        &configured_trust(),
    );
    assert_eq!(
        by_id(&explicit, 2)["result"]["structuredContent"]["spec_hash"],
        by_id(&derived, 2)["result"]["structuredContent"]["spec_hash"],
    );
}

/// With no trust configured the tool is refused, and says which variables are missing.
///
/// The behaviour that hid the whole problem, pinned so it cannot come back silently: if this
/// ever starts passing without configuration, a snapshot is being trusted that no operator
/// chose.
#[test]
fn synthesis_is_refused_until_the_deployment_is_configured() {
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            synthesize_call(serde_json::json!({
                "bundles": [recorded_bundle()],
                "decisions": decisions(),
                "spending_limit_capability": "pinned",
            })),
        ],
        &[],
    );
    let result = &by_id(&responses, 2)["result"];
    assert_eq!(result["isError"], serde_json::json!(true));
    let message = result["structuredContent"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains("OZPB_REGISTRY_ROOTS_JSON"),
        "the refusal has to name what to configure: {message}"
    );
}

/// A recording that observed no account code cannot be synthesized from, and the refusal
/// crosses the boundary with the documented code rather than as a transport error.
#[test]
fn a_recording_without_an_observed_account_is_refused() {
    let mut bundle = recorded_bundle();
    bundle["contract_executables"] = serde_json::json!({});
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            synthesize_call(serde_json::json!({
                "bundles": [bundle],
                "decisions": decisions(),
                "spending_limit_capability": "pinned",
            })),
        ],
        &configured_trust(),
    );
    let result = &by_id(&responses, 2)["result"];
    assert_eq!(result["isError"], serde_json::json!(true));
    assert_eq!(
        result["structuredContent"]["code"],
        serde_json::json!("E_AUTHORIZER_NOT_FOUND")
    );
}
