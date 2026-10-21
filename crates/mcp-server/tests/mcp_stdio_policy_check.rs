mod common;
use common::*;
use serde_json::{json, Value};

fn request(source: &str) -> Value {
    let spec = subscription_spec();
    json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_against_policy","arguments":{
        "spec":spec,"binding_set":{"schema":"policy-binding-set/v1","spec_hash":"00","network_id":spec["network_id"],"bindings":[]},
        "signed_registry_snapshot":{},"rule_index":0,"installed_context_rule_id":42,
        "account_address":spec["smart_account"]["address"],
        "network_id":ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE).0.to_hex(),
        "rpc_source":source,"candidate_signers":[],"invocation":{}}}})
}
fn trust() -> Vec<(&'static str, String)> {
    let root = ozpb_registry::dev::dev_root_verifying_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    vec![
        (
            "OZPB_REGISTRY_ROOTS_JSON",
            json!({"threshold":1,"keys":{"legacy":root}}).to_string(),
        ),
        ("OZPB_REGISTRY_MIN_VERSION", "1".into()),
    ]
}
fn code(responses: &[Value]) -> String {
    by_id(responses, 2)["result"]["structuredContent"]["code"]
        .as_str()
        .unwrap()
        .into()
}

#[test]
fn policy_check_schemas_and_conditional_stateful_description_are_served() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ]);
    let tool = by_id(&responses, 2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "check_against_policy")
        .unwrap();
    assert!(tool["inputSchema"].is_object() && tool["outputSchema"].is_object());
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
    assert_eq!(tool["annotations"]["destructiveHint"], false);
    assert_eq!(tool["annotations"]["idempotentHint"], true);
    let description = tool["description"].as_str().unwrap();
    assert!(description.contains("MUST successfully authenticate"));
    assert!(description.contains("before signing"));
    assert!(tool["inputSchema"]["properties"].get("rpc_url").is_none());
    assert!(tool["inputSchema"]["properties"].get("context").is_none());
}

#[test]
fn trust_and_named_network_sources_gate_work_before_any_build_or_read() {
    assert_eq!(
        code(&run_session(&[
            initialize(),
            initialized(),
            request("testnet")
        ])),
        "E_REGISTRY_EMPTY"
    );
    assert_eq!(
        code(&run_session_with_env(
            &[initialize(), initialized(), request("unknown")],
            &trust()
        )),
        "E_RPC"
    );
    let mut env = trust();
    env.push(("OZPB_RPC_SOURCES_JSON",json!({"mainnet":{"rpc_url":"https://rpc.invalid","network_passphrase":ozpb_domain::MAINNET_PASSPHRASE}}).to_string()));
    assert_eq!(
        code(&run_session_with_env(
            &[initialize(), initialized(), request("mainnet")],
            &env
        )),
        "E_NETWORK_MISMATCH"
    );
}

#[test]
fn caller_supplied_state_and_endpoint_are_rejected_by_wire_schema() {
    for field in [
        "rpc_url",
        "context",
        "call_count_so_far",
        "observed_ledger",
        "authenticated_signers",
    ] {
        let mut call = request("unknown");
        call["params"]["arguments"][field] = json!(0);
        let responses = run_session_with_env(&[initialize(), initialized(), call], &trust());
        let response = by_id(&responses, 2);
        assert_eq!(response["result"]["isError"], true, "{response}");
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains(&format!("unknown field `{field}`")),
            "{response}"
        );
    }
}
