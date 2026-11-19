//! A server configured with a disposable-build launcher asks it its protocol before serving, and
//! refuses to start when the launcher is from another revision: otherwise the mismatch would be
//! found only by the first build's frame, with that build's slot retained.

#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

/// Run the server over stdio with a launcher that answers `--protocol` with `protocol`, and send
/// it one `initialize` request.
fn start_with_launcher(protocol: &str) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap().join("launcher");
    std::fs::write(
        &path,
        format!(
            "#!/usr/bin/python3\nimport sys\nif sys.argv[1:] != ['--protocol']:\n    \
             sys.exit(1)\nsys.stdout.write({protocol:?})\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ozpb-mcp-server"));
    // A test states the operator configuration it needs; an exported one must not leak in.
    for key in [
        "OZPB_RPC_SOURCES_JSON",
        "OZPB_WALLET_HANDOFF_URL",
        "OZPB_BUILD_TIMEOUT_SECS",
        "OZPB_BUILD_JOBS",
    ] {
        command.env_remove(key);
    }
    let mut child = command
        .env("OZPB_BUILD_WORKER_LAUNCHER", &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run the MCP server");
    let initialize = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "itest", "version": "0"}}});
    // A server that refused has already exited and closed its input; that is not a failure here.
    let _ = writeln!(child.stdin.take().unwrap(), "{initialize}");
    child.wait_with_output().expect("wait for the MCP server")
}

#[test]
fn a_launcher_from_another_revision_stops_startup() {
    let refused = start_with_launcher("build-worker-job/v1 contained-build-result/v1\n");
    assert!(!refused.status.success(), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("same revision"), "{stderr}");
    assert!(refused.stdout.is_empty(), "it served nothing: {refused:?}");

    // Control: with a launcher of this revision the same server starts and answers.
    let started = start_with_launcher("build-worker-job/v1 contained-build-result/v2\n");
    let stdout = String::from_utf8_lossy(&started.stdout);
    assert!(stdout.contains("\"id\":1"), "{started:?}");
    assert!(stdout.contains("serverInfo"), "{started:?}");
}
