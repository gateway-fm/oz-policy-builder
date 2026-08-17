//! Shared harness for the stdio protocol tests, plus the served tool set as data.
//!
//! Integration test files are separate crates and cannot `use` each other, so the harness lives
//! here and each test binary compiles its own copy. That is also why the module is
//! `#![allow(dead_code)]`: every binary uses a subset of it, and without the allow the unused
//! remainder would be a warning — fatal under the `-D warnings` gate.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// The MVP tool set: recording, synthesis, evaluation, codegen.
pub const MVP_TOOLS: &[&str] = &[
    "record_transaction",
    "record_simulation",
    "import_recording",
    "synthesize_policy",
    "evaluate_spec",
    "generate_code",
];

/// The tools contributed by the post-MVP module, which is not part of this milestone.
///
/// An empty list rather than no list, so the exact-count assertion stays exact: it is the
/// union of the two lists that must match the served set, and with the module absent that
/// union is the MVP set alone.
pub const POST_MVP_TOOLS: &[&str] = &[];

/// Drive the server over stdio with a batch of newline-delimited JSON-RPC requests,
/// close stdin (which ends the transport and exits the server), and return the parsed
/// responses keyed by id.
pub fn run_session(requests: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let bin = env!("CARGO_BIN_EXE_ozpb-mcp-server");
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mcp server");

    {
        let mut stdin = child.stdin.take().unwrap();
        for r in requests {
            writeln!(stdin, "{}", serde_json::to_string(r).unwrap()).unwrap();
        }
        // Dropping stdin closes it → server sees EOF and shuts down.
    }

    let out = child.stdout.take().unwrap();
    let mut responses = Vec::new();
    for line in BufReader::new(out).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            responses.push(v);
        }
    }
    let _ = child.wait();
    responses
}

pub fn initialize() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "itest", "version": "0"}}
    })
}

pub fn initialized() -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
}

pub fn by_id(responses: &[serde_json::Value], id: i64) -> &serde_json::Value {
    responses
        .iter()
        .find(|r| r.get("id").and_then(|v| v.as_i64()) == Some(id))
        .unwrap_or_else(|| panic!("no response with id {id}; got {responses:?}"))
}

pub fn subscription_spec() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/subscription-spec.json");
    let text = std::fs::read_to_string(&path).expect("read example spec");
    serde_json::from_str(&text).unwrap()
}
