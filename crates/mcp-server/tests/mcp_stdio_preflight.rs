//! Exercise the exact-envelope preflight tool at the stdio protocol boundary.

mod common;
use common::*;
#[path = "../../../tests/support/preflight_rpc.rs"]
mod preflight_rpc;

#[test]
fn preflight_has_a_schema_and_does_not_advertise_a_policy_verdict() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]);
    let tools = by_id(&responses, 2)["result"]["tools"].as_array().unwrap();
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "preflight_transaction")
        .expect("preflight tool must be advertised");
    for schema in ["inputSchema", "outputSchema"] {
        assert!(tool[schema].is_object(), "missing {schema}: {tool}");
    }
    let description = tool["description"].as_str().unwrap();
    assert!(description.contains("exact envelope"));
    assert!(description.contains("Does not identify an installed policy"));
}

#[test]
fn malformed_envelope_fails_before_an_rpc_request_with_a_structured_error() {
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "preflight_transaction", "arguments": {
                "rpc_url": "https://127.0.0.1:1",
                "network_passphrase": "Test SDF Network ; September 2015",
                "envelope_xdr_base64": "not-base64"
            }}
        }),
    ]);
    let call = by_id(&responses, 2);
    assert_eq!(call["result"]["isError"], true, "{call}");
    assert_eq!(
        call["result"]["structuredContent"]["code"], "E_RPC",
        "{call}"
    );
    assert!(call.get("error").is_none(), "{call}");
}

fn preflight_call(rpc_url: &str, envelope: &str) -> serde_json::Value {
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "preflight_transaction", "arguments": {
                "rpc_url": rpc_url,
                "network_passphrase": preflight_rpc::NETWORK,
                "envelope_xdr_base64": envelope
            }}
        }),
    ]);
    by_id(&responses, 2).clone()
}

#[test]
fn every_simulation_outcome_is_reported_without_endpoint_text() {
    let envelope = preflight_rpc::envelope();
    for case in preflight_rpc::outcome_cases(&envelope) {
        let (rpc_url, requests) = preflight_rpc::spawn(case.simulation);
        let call = preflight_call(&rpc_url, &envelope);
        // A reported outcome, failure included, is a result rather than a tool error.
        assert_ne!(call["result"]["isError"], true, "{}: {call}", case.name);
        let output = &call["result"]["structuredContent"];
        assert_eq!(output["outcome"], case.outcome, "{}: {call}", case.name);
        assert_eq!(
            output["insufficient_declared_resources"],
            serde_json::json!(case.insufficient_declared_resources),
            "{}: {call}",
            case.name
        );
        assert!(
            !call.to_string().contains(preflight_rpc::ENDPOINT_DETAIL),
            "{}: endpoint text reached the response",
            case.name
        );
        requests.join().expect("RPC fixture thread");
    }
}

#[test]
fn an_endpoint_refusal_is_an_rpc_error_without_endpoint_text() {
    let envelope = preflight_rpc::envelope();
    let (rpc_url, requests) = preflight_rpc::spawn(preflight_rpc::refusal());
    let call = preflight_call(&rpc_url, &envelope);
    assert_eq!(call["result"]["isError"], true, "{call}");
    let error = &call["result"]["structuredContent"];
    assert_eq!(error["code"], "E_RPC", "{call}");
    let message = error["message"].as_str().expect("error message");
    assert!(message.contains("rpc error"), "{call}");
    assert!(message.contains("withheld"), "{call}");
    assert!(
        !call.to_string().contains(preflight_rpc::ENDPOINT_DETAIL),
        "{call}"
    );
    requests.join().expect("RPC fixture thread");
}

#[test]
fn successful_preflight_reports_only_exact_envelope_rpc_evidence() {
    let envelope = preflight_rpc::envelope();
    let (rpc_url, requests) = preflight_rpc::spawn(preflight_rpc::success(&envelope));
    let responses = run_session(&[
        initialize(),
        initialized(),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "preflight_transaction", "arguments": {
                "rpc_url": rpc_url,
                "network_passphrase": preflight_rpc::NETWORK,
                "envelope_xdr_base64": envelope
            }}
        }),
    ]);
    let call = by_id(&responses, 2);
    assert_ne!(call["result"]["isError"], true, "{call}");
    let output = &call["result"]["structuredContent"];
    assert_eq!(output["outcome"], "simulated_success", "{call}");
    assert_eq!(
        output["insufficient_declared_resources"],
        serde_json::json!([]),
        "{call}"
    );
    assert_eq!(output["auth_mode"], "enforce", "{call}");
    assert_eq!(output["evidence_trust"], "rpc_reported", "{call}");
    assert_eq!(output["reported_ledger"], 4_104_380, "{call}");
    assert_eq!(output["state_dependent"], true, "{call}");
    assert_eq!(output["writes_committed"], false, "{call}");
    assert!(output.get("policy_verdict").is_none(), "{call}");
    let requests = requests.join().expect("RPC fixture thread");
    assert_eq!(requests[0]["method"], "getNetwork");
    assert_eq!(requests[1]["method"], "simulateTransaction");
    assert_eq!(requests[1]["params"]["authMode"], "enforce");
    assert_eq!(requests[1]["params"]["transaction"], envelope);
}
