//! Small local RPC responder shared by the CLI and MCP boundary tests.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const NETWORK: &str = "Test SDF Network ; September 2015";

pub fn envelope() -> String {
    let bundle: Value =
        serde_json::from_str(include_str!("../../docs/examples/import-bundle.json"))
            .expect("example bundle JSON");
    bundle["envelope_xdr_base64"]
        .as_str()
        .expect("example envelope")
        .to_string()
}

/// Serve `getNetwork` and one `simulateTransaction`, returning both exact requests.
pub fn spawn() -> (String, JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local RPC fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let simulation: Value = serde_json::from_str(include_str!(
            "../../crates/source-rpc/tests/captured-testnet/simulateTransaction.json"
        ))
        .expect("captured simulation JSON");
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
