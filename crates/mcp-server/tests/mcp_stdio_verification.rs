//! Exercise the verification router through the real stdio protocol boundary.

mod common;
use common::*;

#[test]
fn verification_tools_are_listed_with_schemas() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]);
    let tools = by_id(&responses, 2)["result"]["tools"].as_array().unwrap();
    for name in VERIFICATION_TOOLS {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == *name)
            .unwrap_or_else(|| panic!("missing {name} tool"));
        assert!(
            tool["inputSchema"].is_object(),
            "{name} has no input schema"
        );
        assert!(
            tool["outputSchema"].is_object(),
            "{name} has no output schema"
        );
    }
    assert!(tools.iter().all(|tool| tool["name"] != "dry_run"));
}

#[test]
fn reference_suite_returns_labeled_layer_one_evidence() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "reference_suite", "arguments": {"spec": subscription_spec()}}
        }),
    ]);
    let call = by_id(&responses, 2);
    assert_ne!(call["result"]["isError"], true, "{call}");
    let output = &call["result"]["structuredContent"];
    assert_eq!(output["all_agree"], true, "{output}");
    assert_eq!(output["disagreements"], 0, "{output}");
    assert!(output["total"].as_u64().unwrap() > 10, "{output}");
    assert!(output["report"].is_object(), "{output}");
    assert!(output["coverage"].is_array(), "{output}");
}

#[test]
fn both_verification_tools_preserve_structured_spec_errors() {
    let bad_spec = serde_json::json!({"$schema": "policy-spec/v1"});
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "reference_suite", "arguments": {"spec": bad_spec}}
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "verify", "arguments": {
                "spec": bad_spec, "rule_index": 0, "claimed_generated_files": {}
            }}
        }),
    ]);
    for id in [2, 3] {
        let call = by_id(&responses, id);
        assert_eq!(call["result"]["isError"], true, "{call}");
        assert_eq!(
            call["result"]["structuredContent"]["code"], "E_SPEC_INVALID",
            "{call}"
        );
        assert!(call.get("error").is_none(), "{call}");
    }
}
