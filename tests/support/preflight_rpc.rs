//! Small local RPC responder shared by the CLI and MCP boundary tests.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use stellar_xdr::{
    Limits, ReadXdr, SorobanTransactionData, TransactionEnvelope, TransactionExt, WriteXdr,
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
