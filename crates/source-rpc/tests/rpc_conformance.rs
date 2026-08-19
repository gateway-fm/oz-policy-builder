//! Conformance of the acquisition layer against **captured real RPC responses**.
//!
//! Why this file exists, and why the unit tests in `lib.rs` are not enough.
//!
//! Those tests mock the transport with JSON we write ourselves. That validates our parsing
//! logic, but it cannot validate the assumption underneath it — *which JSON field carries
//! which XDR type*. When the mock encodes our assumption, the mock and the code agree and the
//! test is green no matter what the network actually sends.
//!
//! That is not hypothetical. `getLedgerEntries` puts `LedgerEntryData` in its `xdr` field, not
//! a whole `LedgerEntry`. The mocks encoded a `LedgerEntry`, so every unit test passed while
//! `ozpb record` failed against every real endpoint — for three weeks, because the live path is
//! not in any offline gate. The bug arrived one day after the live evidence was recorded, so
//! the evidence stayed stale and unchallenged.
//!
//! The fixtures in `captured-testnet/` are verbatim `result` objects from Stellar testnet
//! (protocol 27) via Gateway's public RPC. Replaying them through the real entry points is the
//! only thing that catches a wrong field/type assumption. All four are public-chain data, so
//! they are legitimate fixtures (§6.5 forbids private bundles, not public ledger reads).
//!
//! These are a snapshot, not a subscription: they prove we read *this* shape correctly, not
//! that the shape is still current. `nightly-live.yml` re-runs the live path so drift shows up
//! within a day rather than in a demo.

use ozpb_source_rpc::{get_transaction, simulate_transaction, RpcError, RpcTransport};
use std::cell::RefCell;
use stellar_xdr::ReadXdr;

const NETWORK: &str = "Test SDF Network ; September 2015";

fn captured(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/captured-testnet")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parsing {name}: {error}"))
}

/// Replays captured responses by method name, and records which methods were asked for so a
/// test can assert the acquisition actually made the calls it claims to.
struct Replay {
    calls: RefCell<Vec<String>>,
}

impl Replay {
    fn new() -> Self {
        Replay {
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl RpcTransport for Replay {
    fn call(
        &self,
        method: &str,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        self.calls.borrow_mut().push(method.to_string());
        Ok(captured(method))
    }
}

#[test]
fn a_captured_get_transaction_response_records() {
    let transport = Replay::new();
    let snapshot = get_transaction(
        &transport,
        NETWORK,
        "ccf2dbedac314b31aa0eed402991c941ee76b79e6defaa03a41af92a6c1f6d43",
    )
    .expect("a real getTransaction response must record");

    // The acquisition must have verified the network and fetched the referenced contract
    // instances — the step whose field/type assumption was wrong.
    let calls = transport.calls.borrow().clone();
    assert!(
        calls.contains(&"getNetwork".to_string()),
        "calls: {calls:?}"
    );
    assert!(
        calls.contains(&"getTransaction".to_string()),
        "calls: {calls:?}"
    );
    assert!(
        calls.contains(&"getLedgerEntries".to_string()),
        "the executable observation must be acquired, not skipped: {calls:?}"
    );

    let bundle =
        ozpb_recorder_core::record(&snapshot, ozpb_recorder_core::RecordOptions::default())
            .expect("the captured transaction must produce a bundle");
    assert_eq!(bundle.trust, ozpb_domain::TrustLevel::rpc_reported());
    assert_eq!(
        bundle.authorizations.len(),
        1,
        "the captured transfer has exactly one authorizer"
    );
    // The recorder observed the target's executable — this is what the broken decode dropped.
    assert!(
        !bundle.contract_executables.is_empty(),
        "no executable observed; the getLedgerEntries decode is wrong again"
    );
    assert_eq!(
        bundle.token_movements.len(),
        1,
        "the captured tx is one SEP-41 transfer"
    );
}

#[test]
fn a_captured_simulation_response_records() {
    let transport = Replay::new();
    // The envelope only has to be well-formed: the captured simulation response is what the
    // parser consumes.
    let envelope = captured("getTransaction")
        .get("envelopeXdr")
        .and_then(|v| v.as_str())
        .expect("captured envelopeXdr")
        .to_string();

    let snapshot = simulate_transaction(&transport, NETWORK, &envelope)
        .expect("a real simulateTransaction response must record");
    let bundle =
        ozpb_recorder_core::record(&snapshot, ozpb_recorder_core::RecordOptions::default())
            .expect("the captured simulation must produce a bundle");
    assert_eq!(bundle.trust, ozpb_domain::TrustLevel::rpc_reported());
    assert!(
        !bundle.authorizations.is_empty(),
        "record-mode simulation returns the auth entries it recorded"
    );
}

#[test]
fn the_captured_responses_carry_the_fields_the_parsers_read() {
    // A cheap guard against a fixture being trimmed or re-captured incorrectly: if a field a
    // parser depends on is missing, fail here with the field name rather than inside a parser.
    let tx = captured("getTransaction");
    for field in [
        "status",
        "envelopeXdr",
        // The success label is checked against this, not taken from `status` alone, so a
        // fixture trimmed of it would make the executed path untestable against real data.
        "resultXdr",
        "resultMetaXdr",
        "ledger",
        "createdAt",
    ] {
        assert!(
            tx.get(field).is_some(),
            "getTransaction fixture lacks {field}"
        );
    }
    // And it must still be a decodable TransactionResult whose outcome matches the captured
    // status: a re-capture that truncates or re-encodes it should fail here, by name, rather
    // than inside the parser's agreement check.
    let result_xdr = tx
        .get("resultXdr")
        .and_then(|v| v.as_str())
        .expect("resultXdr is base64 text");
    let decoded =
        stellar_xdr::TransactionResult::from_xdr_base64(result_xdr, ozpb_source_rpc::xdr_limits())
            .expect("the captured resultXdr must decode as a TransactionResult");
    let succeeded = matches!(
        decoded.result,
        stellar_xdr::TransactionResultResult::TxSuccess(_)
            | stellar_xdr::TransactionResultResult::TxFeeBumpInnerSuccess(_)
    );
    assert_eq!(
        succeeded,
        tx.get("status").and_then(|v| v.as_str()) == Some("SUCCESS"),
        "the captured resultXdr must agree with the captured status"
    );
    // `createdAt` is a *string* on the wire even though it is a unix timestamp. Recording that
    // here because a fixture "corrected" to a number would hide a real parsing requirement.
    assert!(
        tx.get("createdAt").and_then(|v| v.as_str()).is_some(),
        "createdAt is a string on the wire; the parser must accept that form"
    );

    assert!(captured("getNetwork").get("passphrase").is_some());

    let sim = captured("simulateTransaction");
    assert!(sim.get("stateChanges").is_some_and(|v| v.is_array()));
    assert!(sim
        .get("results")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("auth"))
        .is_some_and(|a| a.is_array()));

    let entries = captured("getLedgerEntries");
    let entry = entries
        .get("entries")
        .and_then(|e| e.get(0))
        .expect("a captured ledger entry");
    for field in ["key", "xdr", "lastModifiedLedgerSeq"] {
        assert!(
            entry.get(field).is_some(),
            "getLedgerEntries fixture lacks {field}"
        );
    }
}
