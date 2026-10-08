//! State-dependent simulation of one exact transaction envelope.
//!
//! This uses authorization enforcement, unlike record-mode acquisition. A successful
//! RPC simulation is evidence about that envelope at the endpoint's reported ledger;
//! it does not establish that an installed policy was selected, that a later ledger
//! will behave the same way, or that a transaction was submitted.

use crate::{
    ensure_base64_size, validate_simulation_envelope, verify_network, xdr_limits, RpcError,
    RpcTransport,
};
use ozpb_domain::{sha256, NetworkId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use stellar_xdr::{ReadXdr, ScVal, SorobanAuthorizationEntry, SorobanTransactionData, WriteXdr};

/// Result of an enforcement-mode trial of one transaction, never a policy verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightOutcome {
    SimulatedSuccess,
    SimulationFailed,
    RestorationRequired,
}

/// RPC-reported, state-dependent evidence for the exact envelope identified by its XDR hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightObservation {
    /// SHA-256 of the canonical envelope XDR bytes, not a transaction hash.
    pub envelope_xdr_sha256: String,
    pub network_id: String,
    pub reported_ledger: u32,
    pub outcome: PreflightOutcome,
    /// The request uses `authMode=enforce`; a record-mode result never reaches here.
    pub auth_mode: String,
    /// The endpoint's result is trusted only as far as the configured RPC endpoint.
    pub evidence_trust: String,
    /// A new ledger or restoration can change the result immediately.
    pub state_dependent: bool,
    /// Simulation discards writes, even when an invocation succeeds.
    pub writes_committed: bool,
}

/// Simulate the caller's one-operation envelope in authorization-enforcing mode.
///
/// The caller must provide the signed authorization entries it wants enforced inside
/// the envelope. RPC errors in a result become `SimulationFailed`; the endpoint's raw
/// error string is withheld because it can reflect confidential envelope contents.
/// An archived-entry preamble is `RestorationRequired`, not a successful invocation.
pub fn preflight_transaction<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    envelope_xdr_base64: &str,
) -> Result<PreflightObservation, RpcError> {
    let envelope = validate_simulation_envelope(envelope_xdr_base64)?;
    let envelope_xdr = envelope
        .to_xdr(xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("invalid transaction envelope: {error}")))?;
    let envelope_xdr_sha256 = sha256(&envelope_xdr).to_hex();
    verify_network(transport, network_passphrase)?;
    let result = transport
        .call(
            "simulateTransaction",
            json!({
                "transaction": envelope_xdr_base64,
                "authMode": "enforce",
                "xdrFormat": "base64"
            }),
        )
        .map_err(redact_simulation_error)?;
    parse_preflight(
        &result,
        envelope_xdr_sha256,
        NetworkId::from_passphrase(network_passphrase).0.to_hex(),
    )
}

fn redact_simulation_error(error: RpcError) -> RpcError {
    // The transport may include a plain-text HTTP error-body excerpt or a JSON-RPC
    // error that reflects the confidential envelope. Preserve the error category,
    // never endpoint-controlled text. Local envelope validation above retains its
    // useful, non-echoing diagnostics.
    match error {
        RpcError::Transport(_) => RpcError::Transport(
            "simulation transport failed (response detail withheld)".to_string(),
        ),
        RpcError::Malformed(_) => RpcError::Malformed(
            "simulation response is malformed (response detail withheld)".to_string(),
        ),
        _ => RpcError::Rpc(
            "simulation RPC refused the request (response detail withheld)".to_string(),
        ),
    }
}

fn parse_preflight(
    result: &Value,
    envelope_xdr_sha256: String,
    network_id: String,
) -> Result<PreflightObservation, RpcError> {
    let reported_ledger: u32 = result
        .get("latestLedger")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::Malformed("preflight lacks integer latestLedger".to_string()))?
        .try_into()
        .map_err(|_| RpcError::Malformed("preflight latestLedger exceeds u32".to_string()))?;
    if reported_ledger == 0 {
        return Err(RpcError::Malformed(
            "preflight latestLedger cannot be zero".to_string(),
        ));
    }
    let has_error = match result.get("error") {
        None => false,
        Some(Value::String(message)) if !message.is_empty() => true,
        Some(Value::String(_)) => {
            return Err(RpcError::Malformed(
                "preflight error field is empty".to_string(),
            ))
        }
        Some(_) => {
            return Err(RpcError::Malformed(
                "preflight error field is not a string".to_string(),
            ))
        }
    };
    let outcome = if has_error {
        if result.get("restorePreamble").is_some() || result.get("results").is_some() {
            return Err(RpcError::Malformed(
                "failed preflight also reports success or restoration".to_string(),
            ));
        }
        PreflightOutcome::SimulationFailed
    } else if let Some(restore) = result.get("restorePreamble") {
        validate_restoration(restore)?;
        PreflightOutcome::RestorationRequired
    } else {
        validate_success(result)?;
        PreflightOutcome::SimulatedSuccess
    };
    Ok(PreflightObservation {
        envelope_xdr_sha256,
        network_id,
        reported_ledger,
        outcome,
        auth_mode: "enforce".to_string(),
        evidence_trust: "rpc_reported".to_string(),
        state_dependent: true,
        writes_committed: false,
    })
}

fn validate_success(result: &Value) -> Result<(), RpcError> {
    let results = result
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::Malformed("successful preflight lacks results".to_string()))?;
    let [one] = results.as_slice() else {
        return Err(RpcError::Malformed(format!(
            "successful preflight has {} results for one operation",
            results.len()
        )));
    };
    let returned = one
        .get("xdr")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Malformed("preflight result lacks return XDR".to_string()))?;
    ensure_base64_size("preflight return XDR", returned)?;
    ScVal::from_xdr_base64(returned, xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("invalid preflight return XDR: {error}")))?;
    let auth = one
        .get("auth")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::Malformed("preflight result lacks auth array".to_string()))?;
    for (index, value) in auth.iter().enumerate() {
        let encoded = value.as_str().ok_or_else(|| {
            RpcError::Malformed(format!("preflight auth[{index}] is not XDR text"))
        })?;
        ensure_base64_size("preflight auth XDR", encoded)?;
        SorobanAuthorizationEntry::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            RpcError::Malformed(format!("invalid preflight auth[{index}] XDR: {error}"))
        })?;
    }
    let transaction_data = result
        .get("transactionData")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::Malformed("successful preflight lacks transactionData".to_string())
        })?;
    validate_transaction_data(transaction_data)?;
    let fee = result
        .get("minResourceFee")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::Malformed("successful preflight lacks minResourceFee".to_string())
        })?;
    fee.parse::<u64>()
        .map_err(|_| RpcError::Malformed("preflight minResourceFee is not a u64".to_string()))?;
    Ok(())
}

fn validate_restoration(restore: &Value) -> Result<(), RpcError> {
    let object = restore
        .as_object()
        .ok_or_else(|| RpcError::Malformed("restorePreamble is not an object".to_string()))?;
    let transaction_data = object
        .get("transactionData")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Malformed("restorePreamble lacks transactionData".to_string()))?;
    validate_transaction_data(transaction_data)?;
    let fee = object
        .get("minResourceFee")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Malformed("restorePreamble lacks minResourceFee".to_string()))?;
    fee.parse::<u64>().map_err(|_| {
        RpcError::Malformed("restorePreamble minResourceFee is not a u64".to_string())
    })?;
    Ok(())
}

fn validate_transaction_data(encoded: &str) -> Result<(), RpcError> {
    ensure_base64_size("preflight transactionData", encoded)?;
    SorobanTransactionData::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
        RpcError::Malformed(format!("invalid preflight transactionData: {error}"))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_recorder_core::{fixtures, record, RecordOptions};
    use std::cell::RefCell;

    const NETWORK: &str = "Test SDF Network ; September 2015";

    struct CannedTransport {
        result: Result<Value, RpcError>,
        calls: RefCell<Vec<(String, Value)>>,
    }

    impl CannedTransport {
        fn new(result: Value) -> Self {
            Self {
                result: Ok(result),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl RpcTransport for CannedTransport {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            self.calls.borrow_mut().push((method.to_string(), params));
            if method == "getNetwork" {
                Ok(json!({
                    "passphrase": NETWORK,
                    "protocolVersion": crate::MAX_SUPPORTED_PROTOCOL
                }))
            } else {
                self.result
                    .as_ref()
                    .map(Clone::clone)
                    .map_err(|error| match error {
                        RpcError::Transport(message) => RpcError::Transport(message.clone()),
                        RpcError::Malformed(message) => RpcError::Malformed(message.clone()),
                        _ => RpcError::Rpc(error.to_string()),
                    })
            }
        }
    }

    fn envelope() -> String {
        record(&fixtures::executed_snapshot(), RecordOptions::default())
            .unwrap()
            .raw
            .envelope_xdr_base64
    }

    fn transaction_data() -> String {
        SorobanTransactionData::default()
            .to_xdr_base64(xdr_limits())
            .unwrap()
    }

    fn success() -> Value {
        json!({
            "latestLedger": 4200101,
            "results": [{
                "xdr": ScVal::Void.to_xdr_base64(xdr_limits()).unwrap(),
                "auth": []
            }],
            "transactionData": transaction_data(),
            "minResourceFee": "100"
        })
    }

    #[test]
    fn requests_auth_enforcement_and_labels_exact_state_dependent_success() {
        let tx = envelope();
        let transport = CannedTransport::new(success());
        let observation = preflight_transaction(&transport, NETWORK, &tx).unwrap();
        assert_eq!(observation.outcome, PreflightOutcome::SimulatedSuccess);
        assert_eq!(observation.auth_mode, "enforce");
        assert_eq!(observation.evidence_trust, "rpc_reported");
        assert!(observation.state_dependent);
        assert_eq!(observation.reported_ledger, 4_200_101);
        assert!(!observation.writes_committed);
        assert_eq!(
            observation.network_id,
            NetworkId::from_passphrase(NETWORK).0.to_hex()
        );
        let encoded = stellar_xdr::TransactionEnvelope::from_xdr_base64(&tx, xdr_limits())
            .unwrap()
            .to_xdr(xdr_limits())
            .unwrap();
        assert_eq!(observation.envelope_xdr_sha256, sha256(&encoded).to_hex());
        let calls = transport.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, "simulateTransaction");
        assert_eq!(calls[1].1["authMode"], "enforce");
        assert_eq!(calls[1].1["transaction"], tx);
    }

    #[test]
    fn a_failed_simulation_is_not_a_success_or_a_policy_denial_claim() {
        let transport = CannedTransport::new(json!({
            "latestLedger": 4200101,
            "error": "private invocation and secret authorization data"
        }));
        let observation = preflight_transaction(&transport, NETWORK, &envelope()).unwrap();
        assert_eq!(observation.outcome, PreflightOutcome::SimulationFailed);
        let serialized = serde_json::to_string(&observation).unwrap();
        assert!(!serialized.contains("private invocation"));
        assert!(!serialized.contains("secret authorization"));
    }

    #[test]
    fn restoration_is_a_separate_non_success_outcome() {
        let mut result = success();
        result["restorePreamble"] = json!({
            "transactionData": transaction_data(),
            "minResourceFee": "200"
        });
        let observation =
            preflight_transaction(&CannedTransport::new(result), NETWORK, &envelope()).unwrap();
        assert_eq!(observation.outcome, PreflightOutcome::RestorationRequired);
    }

    #[test]
    fn malformed_or_contradictory_replies_cannot_claim_success() {
        let mut missing_auth = success();
        missing_auth["results"][0]
            .as_object_mut()
            .unwrap()
            .remove("auth");
        let mut invalid_xdr = success();
        invalid_xdr["results"][0]["xdr"] = json!("invalid");
        let mut invalid_auth = success();
        invalid_auth["results"][0]["auth"] = json!(["invalid"]);
        let mut many_results = success();
        many_results["results"] = json!([
            success()["results"][0].clone(),
            success()["results"][0].clone()
        ]);
        let mut failed_and_success = success();
        failed_and_success["error"] = json!("failed");
        for result in [
            json!({"results": success()["results"], "transactionData": transaction_data(), "minResourceFee": "100"}),
            json!({"latestLedger": 0, "error": "failed"}),
            missing_auth,
            invalid_xdr,
            invalid_auth,
            many_results,
            failed_and_success,
            json!({"latestLedger": 4200101, "error": ""}),
            json!({"latestLedger": 4200101, "results": success()["results"], "transactionData": "invalid", "minResourceFee": "100"}),
            json!({"latestLedger": 4200101, "restorePreamble": {"transactionData": "invalid", "minResourceFee": "100"}}),
            json!({"latestLedger": 4200101, "restorePreamble": {"transactionData": transaction_data(), "minResourceFee": "-1"}}),
        ] {
            assert!(
                matches!(
                    preflight_transaction(&CannedTransport::new(result), NETWORK, &envelope()),
                    Err(RpcError::Malformed(_))
                ),
                "malformed response must not be reported as a successful simulation"
            );
        }
    }

    #[test]
    fn malformed_envelope_stops_before_network_and_rpc_error_detail_is_withheld() {
        let transport = CannedTransport::new(success());
        assert!(preflight_transaction(&transport, NETWORK, "not XDR").is_err());
        assert!(transport.calls.borrow().is_empty());

        let refusing = CannedTransport {
            result: Err(RpcError::Rpc(
                "secret envelope echoed by endpoint".to_string(),
            )),
            calls: RefCell::new(Vec::new()),
        };
        let error = preflight_transaction(&refusing, NETWORK, &envelope())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret envelope"));

        let gateway = CannedTransport {
            result: Err(RpcError::Transport(
                "HTTP 400: secret envelope echoed as plain text".to_string(),
            )),
            calls: RefCell::new(Vec::new()),
        };
        let error = preflight_transaction(&gateway, NETWORK, &envelope())
            .unwrap_err()
            .to_string();
        assert!(error.contains("transport"));
        assert!(!error.contains("secret envelope"));
    }
}
