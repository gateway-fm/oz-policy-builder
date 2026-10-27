//! The advisory account-authority tool through the real stdio boundary. Hermetic: every call
//! here is refused before any read, which is the point — the endpoint is the operator's, and
//! a request can only name one.

mod common;
use common::*;

fn trust_env() -> Vec<(&'static str, String)> {
    let root: String = ozpb_registry::dev::dev_root_verifying_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    vec![
        (
            "OZPB_REGISTRY_ROOTS_JSON",
            serde_json::json!({"threshold": 1, "keys": {"legacy": root}}).to_string(),
        ),
        ("OZPB_REGISTRY_MIN_VERSION", "1".to_string()),
    ]
}

fn request(rpc_source: &str) -> serde_json::Value {
    request_for("check_policy_call_surface", rpc_source)
}

fn request_for(tool: &str, rpc_source: &str) -> serde_json::Value {
    let testnet = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
    serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": tool, "arguments": {
            "spec": subscription_spec(),
            "rule_index": 0,
            "binding_set": {
                "schema": "policy-binding-set/v1",
                "spec_hash": "00",
                "network_id": testnet.0.to_hex(),
                "bindings": []
            },
            "signed_registry_snapshot": {},
            "account_address": subscription_spec()["smart_account"]["address"],
            "network_id": testnet.0.to_hex(),
            "rpc_source": rpc_source
        }}
    })
}

fn error_code(responses: &[serde_json::Value]) -> String {
    let call = by_id(responses, 2);
    assert_eq!(call["result"]["isError"], true, "{call}");
    call["result"]["structuredContent"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("no structured error code: {call}"))
        .to_string()
}

#[test]
fn the_tool_is_listed_as_an_advisory_read_with_schemas() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]);
    let tools = by_id(&responses, 2)["result"]["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "check_policy_call_surface")
        .expect("the authority tool is listed");
    assert!(tool["inputSchema"].is_object() && tool["outputSchema"].is_object());
    // It reads the network and may rebuild generated policies into the build cache, so it is
    // not advertised as read-only; it changes nothing on chain and repeats safely.
    assert_eq!(tool["annotations"]["readOnlyHint"], false, "{tool}");
    assert_eq!(tool["annotations"]["destructiveHint"], false, "{tool}");
    assert_eq!(tool["annotations"]["idempotentHint"], true, "{tool}");
    assert_eq!(tool["annotations"]["openWorldHint"], true, "{tool}");
    let description = tool["description"].as_str().unwrap().to_lowercase();
    assert!(description.contains("advisory") && description.contains("never says"));
    // The request names a source; it has no field for a URL.
    let properties = &tool["inputSchema"]["properties"];
    assert!(properties.get("rpc_source").is_some());
    assert!(properties.get("rpc_url").is_none());
}

#[test]
fn without_pinned_trust_nothing_is_read() {
    let responses = run_session(&[initialize(), initialized(), request("testnet")]);
    assert_eq!(error_code(&responses), "E_REGISTRY_EMPTY");
}

#[test]
fn assembly_is_unsigned_and_uses_operator_trust_and_rpc_sources() {
    let listed = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ]);
    let tool = by_id(&listed, 2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "assemble_install_transaction")
        .unwrap();
    assert!(tool["inputSchema"].is_object() && tool["outputSchema"].is_object());
    assert_eq!(tool["annotations"]["destructiveHint"], false);
    assert_eq!(tool["annotations"]["readOnlyHint"], false);
    assert!(tool["inputSchema"]["properties"].get("intent").is_none());
    assert!(tool["inputSchema"]["properties"].get("rpc_url").is_none());
    let mut call = request_for("assemble_install_transaction", "anywhere");
    let authority_request = call["params"]["arguments"].take();
    call["params"]["arguments"] = serde_json::json!({
        "intent_request":authority_request,
        "fee_payer":subscription_spec()["rules"][0]["authorization"]["signers"][0]["delegated"]["address"],
        "max_fee_stroops":100_000, "validity_ledgers":20
    });
    assert_eq!(
        error_code(&run_session(&[initialize(), initialized(), call.clone()])),
        "E_REGISTRY_EMPTY"
    );
    assert_eq!(
        error_code(&run_session_with_env(
            &[initialize(), initialized(), call],
            &trust_env()
        )),
        "E_RPC"
    );
}

#[test]
fn a_source_the_operator_did_not_configure_is_refused_before_any_read() {
    let responses = run_session_with_env(
        &[initialize(), initialized(), request("anywhere")],
        &trust_env(),
    );
    assert_eq!(error_code(&responses), "E_RPC");

    // A configured source for another network is refused the same way, before any read.
    let mut env = trust_env();
    env.push((
        "OZPB_RPC_SOURCES_JSON",
        serde_json::json!({"mainnet": {
            "rpc_url": "https://rpc.invalid",
            "network_passphrase": ozpb_domain::MAINNET_PASSPHRASE
        }})
        .to_string(),
    ));
    let responses = run_session_with_env(&[initialize(), initialized(), request("mainnet")], &env);
    assert_eq!(error_code(&responses), "E_NETWORK_MISMATCH");
}

#[test]
fn the_install_intent_runs_the_same_gates_before_any_read() {
    let listed = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]);
    let tool = by_id(&listed, 2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "prepare_install_intent")
        .cloned()
        .expect("the install intent is listed");
    // It takes exactly the check's request: there is no verdict for a caller to supply.
    assert!(tool["inputSchema"]["properties"]
        .get("call_surface_check")
        .is_none());
    assert_eq!(tool["annotations"]["readOnlyHint"], false, "{tool}");

    let responses = run_session(&[
        initialize(),
        initialized(),
        request_for("prepare_install_intent", "testnet"),
    ]);
    assert_eq!(error_code(&responses), "E_REGISTRY_EMPTY");
    let responses = run_session_with_env(
        &[
            initialize(),
            initialized(),
            request_for("prepare_install_intent", "anywhere"),
        ],
        &trust_env(),
    );
    assert_eq!(error_code(&responses), "E_RPC");
}
