use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn process_refuses_unknown_start_fields_and_truncated_input() {
    for args in [
        vec!["--other"],
        vec!["--prepare", "extra"],
        vec!["extra", "--prepare"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ozpb-execution-runtime"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    for input in [b"{}\n".as_slice(), b"{\"schema\":1}", b"{}\n{}\n"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ozpb-execution-runtime"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn process_runs_the_complete_interactive_protocol() {
    use ed25519_dalek::{Signer, SigningKey};
    use ozpb_execution_runtime::{
        read_frame, verify_signature_response, SignRequest, SignatureResponse, MAX_FRAME_BYTES,
    };
    use std::io::BufReader;
    let key = SigningKey::from_bytes(&[42; 32]);
    let job: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap(),
    )
    .unwrap();
    let mut preparation = Command::new(env!("CARGO_BIN_EXE_ozpb-execution-runtime"))
        .arg("--prepare")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut prep_input = preparation.stdin.take().unwrap();
    serde_json::to_writer(&mut prep_input, &job).unwrap();
    prep_input.write_all(b"\n").unwrap();
    drop(prep_input);
    let prep_output = preparation.wait_with_output().unwrap();
    assert!(
        prep_output.status.success(),
        "{}",
        String::from_utf8_lossy(&prep_output.stderr)
    );
    assert_eq!(
        prep_output.stdout.iter().filter(|&&b| b == b'\n').count(),
        1
    );
    let retained: serde_json::Value = serde_json::from_slice(&prep_output.stdout).unwrap();
    assert_eq!(retained["type"], "prepared");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ozpb-execution-runtime"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    serde_json::to_writer(&mut input, &job).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let prepared: serde_json::Value =
        serde_json::from_slice(&read_frame(&mut output, MAX_FRAME_BYTES).unwrap()).unwrap();
    assert_eq!(prepared["type"], "prepared");
    assert_eq!(prepared, retained);
    let binding: ozpb_execution_runtime::OfflineBinding =
        serde_json::from_value(prepared["binding"].clone()).unwrap();
    assert_eq!(
        ozpb_execution_runtime::offline_network(&binding).unwrap(),
        prepared["execution_network_id"]
    );
    let mut count = 0;
    loop {
        let frame: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut output, MAX_FRAME_BYTES).unwrap()).unwrap();
        if frame["type"] == "result" {
            assert_eq!(frame["passed"], true);
            assert_eq!(frame["complete"], false);
            assert_eq!(frame["binding"], prepared["binding"]);
            assert!(count > 15);
            break;
        }
        let request: SignRequest = serde_json::from_value(frame).unwrap();
        count += 1;
        assert_eq!(request.request_id, count.to_string());
        assert_eq!(request.run_hash, binding.run_hash);
        assert_eq!(
            request.execution_network_id,
            prepared["execution_network_id"]
        );
        let response = SignatureResponse {
            frame_type: "signature".into(),
            request_id: request.request_id.clone(),
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: hex::encode(
                key.sign(&hex::decode(&request.digest_hex).unwrap())
                    .to_bytes(),
            ),
        };
        verify_signature_response(&request, &response).unwrap();
        serde_json::to_writer(&mut input, &response).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }
    drop(input);
    assert!(child.wait().unwrap().success());
}
