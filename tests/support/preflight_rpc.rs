//! Small local RPC responder shared by the CLI and MCP boundary tests.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use stellar_xdr::{
    Limits, ReadXdr, SorobanResourcesExtV0, SorobanTransactionData, SorobanTransactionDataExt,
    TransactionEnvelope, TransactionExt, WriteXdr,
};

pub const NETWORK: &str = "Test SDF Network ; September 2015";

/// The example invocation, assembled as a wallet would send it: declaring the Soroban
/// transaction data that the captured simulation of it reported. The example bundle's own
/// envelope declares none, which simulation would report as insufficient.
pub fn envelope() -> String {
    let bundle: Value =
        serde_json::from_str(include_str!("../../docs/examples/import-bundle.json"))
            .expect("example bundle JSON");
    let example = bundle["envelope_xdr_base64"]
        .as_str()
        .expect("example envelope");
    let mut envelope =
        TransactionEnvelope::from_xdr_base64(example, Limits::none()).expect("envelope XDR");
    let TransactionEnvelope::Tx(v1) = &mut envelope else {
        panic!("the example envelope is a v1 transaction");
    };
    let captured = captured_simulation()["transactionData"]
        .as_str()
        .map(|data| SorobanTransactionData::from_xdr_base64(data, Limits::none()))
        .expect("captured transaction data")
        .expect("transaction data XDR");
    v1.tx.ext = TransactionExt::V1(captured);
    envelope
        .to_xdr_base64(Limits::none())
        .expect("assembled envelope XDR")
}

fn captured_simulation() -> Value {
    serde_json::from_str(include_str!(
        "../../crates/source-rpc/tests/captured-testnet/simulateTransaction.json"
    ))
    .expect("captured simulation JSON")
}

/// Whitespace the XDR decoder would skip, each tried inside an envelope by both shells.
pub const ENVELOPE_WHITESPACE: [&str; 4] = [" ", "\t", "\n", "\r\n"];

/// What both shells say when an envelope contains whitespace.
pub const WHITESPACE_REFUSAL: &str =
    "E_ENVELOPE_PARSE: transaction envelope base64 contains whitespace";

/// `envelope` with `whitespace` inserted in the middle.
pub fn with_inner(envelope: &str, whitespace: &str) -> String {
    let (head, tail) = envelope.split_at(envelope.len() / 2);
    format!("{head}{whitespace}{tail}")
}

/// The Soroban transaction data `envelope` declares.
pub fn declared(envelope: &str) -> SorobanTransactionData {
    match TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).expect("envelope XDR") {
        TransactionEnvelope::Tx(v1) => match v1.tx.ext {
            TransactionExt::V1(data) => data,
            TransactionExt::V0 => panic!("the envelope declares no Soroban data"),
        },
        _ => panic!("the envelope is not a v1 transaction"),
    }
}

/// The captured testnet reply, reporting `simulated` as the transaction data it used.
pub fn simulation_using(simulated: &SorobanTransactionData) -> Value {
    let mut simulation = captured_simulation();
    simulation["transactionData"] = json!(simulated
        .to_xdr_base64(Limits::none())
        .expect("transaction data XDR"));
    simulation["minResourceFee"] = json!(simulated.resource_fee.to_string());
    simulation
}

/// A successful simulation that used exactly what `envelope` declares.
pub fn success(envelope: &str) -> Value {
    simulation_using(&declared(envelope))
}

/// Text an endpoint put in its reply. It stands in for anything the endpoint could echo from
/// the confidential envelope, so no shell output may contain it.
pub const ENDPOINT_DETAIL: &str = "endpoint-detail-echoing-the-envelope";

/// The endpoint read its ledger and then reported an error.
pub fn failure() -> Value {
    json!({
        "latestLedger": 4_104_380,
        "error": format!("HostError: Error(Auth, InvalidAction) {ENDPOINT_DETAIL}")
    })
}

/// The endpoint refused before reading its ledger: stellar-rpc answers with `latestLedger` 0.
pub fn refusal() -> Value {
    json!({
        "latestLedger": 0,
        "error": format!("cannot simulate this transaction: {ENDPOINT_DETAIL}")
    })
}

/// One simulation reply and what both shells must report for it.
pub struct OutcomeCase {
    pub name: &'static str,
    pub simulation: Value,
    pub outcome: &'static str,
    pub insufficient_declared_resources: Vec<&'static str>,
}

/// Every non-success outcome, each from a reply the endpoint can send for `envelope`.
pub fn outcome_cases(envelope: &str) -> Vec<OutcomeCase> {
    let declared = declared(envelope);

    let mut preamble = success(envelope);
    preamble["restorePreamble"] = json!({
        "transactionData": declared.to_xdr_base64(Limits::none()).expect("transaction data XDR"),
        "minResourceFee": "100"
    });

    // Since protocol 23 the endpoint restores archived entries inside the simulation and
    // lists them, by read-write footprint index, in the simulated transaction data.
    let mut restored = declared.clone();
    assert!(
        !restored.resources.footprint.read_write.is_empty(),
        "the example writes ledger state"
    );
    restored.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
        archived_soroban_entries: vec![0].try_into().expect("one archived index"),
    });

    let mut over = declared.clone();
    over.resources.instructions += 1;
    over.resource_fee += 1;

    vec![
        OutcomeCase {
            name: "failed simulation",
            simulation: failure(),
            outcome: "simulation_failed",
            insufficient_declared_resources: vec![],
        },
        OutcomeCase {
            name: "restoration preamble",
            simulation: preamble,
            outcome: "restoration_required",
            insufficient_declared_resources: vec![],
        },
        OutcomeCase {
            name: "entries restored inside the simulation",
            simulation: simulation_using(&restored),
            outcome: "restoration_required",
            insufficient_declared_resources: vec![],
        },
        OutcomeCase {
            name: "under-declared resources",
            simulation: simulation_using(&over),
            outcome: "declared_resources_insufficient",
            insufficient_declared_resources: vec!["instructions", "resource_fee"],
        },
    ]
}

/// Serve `getNetwork` and one `simulateTransaction` answered with `simulation`, returning
/// both exact requests.
pub fn spawn(simulation: Value) -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local RPC fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        for _ in 0..2 {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for RPC request"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept RPC request: {error}"),
                }
            };
            // A socket accepted from a non-blocking listener is itself non-blocking on BSD
            // and macOS, so a read could fail before the client has written its request.
            stream.set_nonblocking(false).expect("blocking RPC stream");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut stream);
            let method = request["method"].as_str().expect("RPC method");
            let result = match method {
                "getNetwork" => json!({"passphrase": NETWORK, "protocolVersion": 28}),
                "simulateTransaction" => simulation.clone(),
                other => panic!("unexpected RPC method: {other}"),
            };
            let response = json!({"jsonrpc": "2.0", "id": request["id"], "result": result});
            let body = serde_json::to_vec(&response).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            requests.push(request);
        }
        requests
    });
    (address, handle)
}

/// A local endpoint that accepts and drops every connection, counting them.
///
/// A command that must refuse its input before the network is pointed here, then shown to have
/// made no connection at all. A closed port cannot show that: an attempted connection to it and
/// a local refusal both end in `E_RPC`.
pub struct CountingEndpoint {
    pub url: String,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl CountingEndpoint {
    pub fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counting endpoint");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = thread::spawn({
            let (connections, stop) = (connections.clone(), stop.clone());
            move || loop {
                // Accept before checking `stop`, so a connection already queued when the
                // command under test exited is still counted.
                match listener.accept() {
                    Ok(_) => {
                        connections.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept on counting endpoint: {error}"),
                }
            }
        });
        Self {
            url,
            connections,
            stop,
            handle: Some(handle),
        }
    }

    /// Stop listening and return how many connections were made.
    pub fn connections(mut self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("counting endpoint thread");
        }
        self.connections.load(Ordering::SeqCst)
    }
}

fn read_request(stream: &mut TcpStream) -> Value {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("HTTP request header");
        header.push(byte[0]);
        assert!(header.len() <= 16_384, "oversized HTTP header");
    }
    let header = String::from_utf8(header).expect("ASCII HTTP header");
    let length: usize = header
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(key, value)| {
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().expect("content length"))
            })
        })
        .expect("content length");
    assert!(length <= 1_048_576, "oversized RPC request");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).expect("HTTP request body");
    serde_json::from_slice(&body).expect("RPC request JSON")
}
