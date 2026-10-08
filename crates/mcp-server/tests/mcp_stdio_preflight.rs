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
    // Preflight is not consequence-free: signed entries outlive the call that carried them.
    assert!(
        description.contains("Signed authorization entries are live authorizations"),
        "{description}"
    );
    assert!(
        description.contains("signatureExpirationLedger"),
        "{description}"
    );
    assert!(
        description.contains("A hosted server refuses signed envelopes"),
        "{description}"
    );
}

#[test]
fn malformed_envelope_fails_before_an_rpc_request_with_a_structured_error() {
    let endpoint = preflight_rpc::CountingEndpoint::bind();
    let call = preflight_call(&endpoint.url, "not-base64");
    assert_eq!(call["result"]["isError"], true, "{call}");
    assert!(call.get("error").is_none(), "{call}");
    let error = &call["result"]["structuredContent"];
    assert_eq!(error["code"], "E_ENVELOPE_PARSE", "{call}");
    let message = error["message"].as_str().expect("error message");
    assert!(message.contains("invalid transaction envelope"), "{call}");
    assert!(!message.contains("transport"), "{call}");
    assert_eq!(
        endpoint.connections(),
        0,
        "the envelope reached the network: {call}"
    );
}

#[test]
fn whitespace_inside_the_envelope_is_refused_before_the_network() {
    let envelope = preflight_rpc::envelope();
    for whitespace in preflight_rpc::ENVELOPE_WHITESPACE {
        let endpoint = preflight_rpc::CountingEndpoint::bind();
        let spaced = preflight_rpc::with_inner(&envelope, whitespace);
        let call = preflight_call(&endpoint.url, &spaced);
        let error = &call["result"]["structuredContent"];
        assert_eq!(call["result"]["isError"], true, "{whitespace:?}: {call}");
        let message = error["message"].as_str().expect("error message");
        assert!(
            format!("{}: {message}", error["code"].as_str().unwrap_or(""))
                .contains(preflight_rpc::WHITESPACE_REFUSAL),
            "{whitespace:?}: {call}"
        );
        assert_eq!(endpoint.connections(), 0, "{whitespace:?}: {call}");
    }
}

#[test]
fn an_oversized_envelope_is_a_resource_limit_before_the_network() {
    let endpoint = preflight_rpc::CountingEndpoint::bind();
    let oversized = "A".repeat(ozpb_source_rpc::MAX_XDR_BASE64_BYTES + 1);
    let call = preflight_call(&endpoint.url, &oversized);
    let error = &call["result"]["structuredContent"];
    assert_eq!(call["result"]["isError"], true, "{error}");
    assert_eq!(error["code"], "E_RESOURCE_LIMIT", "{error}");
    let message = error["message"].as_str().expect("error message");
    assert!(!message.contains("response"), "{error}");
    assert_eq!(endpoint.connections(), 0, "{error}");
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
