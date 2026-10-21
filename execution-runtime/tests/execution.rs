use ozpb_execution_runtime::{
    execute, prepare, DelegateSigner, NativeJob, SignRequest, SignatureResponse,
};

struct NoCapability;
impl DelegateSigner for NoCapability {
    fn sign(&mut self, _: &SignRequest) -> Result<SignatureResponse, String> {
        Err("no registered delegate capability".into())
    }
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn real_candidate_account_path_cannot_substitute_a_missing_delegate() {
    let job: NativeJob = serde_json::from_slice(
        &std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap(),
    )
    .unwrap();
    let prepared = prepare(job).unwrap();
    assert!(execute(&prepared, &mut NoCapability).is_err());
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn worker_rejects_protocol_identity_and_expansion_mismatches_before_signing() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let job: NativeJob = serde_json::from_slice(
        &std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap(),
    )
    .unwrap();
    for mutate in [
        |j: &mut NativeJob| j.ledger.protocol_version = 26,
        |j: &mut NativeJob| j.ledger.timestamp = "000100000".into(),
        |j: &mut NativeJob| j.request.candidate.network_id = "ff".repeat(32),
        |j: &mut NativeJob| j.request.artifact.rule_index = 1,
        |j: &mut NativeJob| {
            j.request.candidate.binding_set.bindings[0].observed_wasm_hash = "ff".repeat(32)
        },
    ] {
        let mut changed = job.clone();
        mutate(&mut changed);
        assert!(prepare(changed).is_err());
    }
    for account in [true, false] {
        let mut changed = job.clone();
        let encoded = if account {
            &mut changed.account_wasm_base64
        } else {
            changed
                .request
                .artifact
                .claimed_wasm_base64
                .as_mut()
                .unwrap()
        };
        let mut bytes = STANDARD.decode(&*encoded).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        *encoded = STANDARD.encode(bytes);
        assert!(matches!(prepare(changed), Err(e) if e.contains("byte hash mismatch")));
    }
    let mut unsupported = job.clone();
    let spec = &mut unsupported.request.candidate.spec;
    spec["rules"][0]["authorization"]["signers"].as_array_mut().unwrap().push(
        serde_json::json!({"delegated": {"address": stellar_strkey::ed25519::PublicKey([6;32]).to_string().as_str()}})
    );
    let validated: ozpb_policy_spec::PolicySpec = serde_json::from_value(spec.clone()).unwrap();
    unsupported.request.candidate.binding_set.spec_hash =
        validated.validate().unwrap().hash().to_hex();
    unsupported.request.artifact.spec = spec.clone();
    assert!(
        matches!(prepare(unsupported), Err(e) if e.contains("unsupported signer configuration"))
    );
    let mut expanded = job;
    let spec = &mut expanded.request.candidate.spec;
    let second = spec["rules"][0].clone();
    spec["rules"].as_array_mut().unwrap().push(second);
    let validated: ozpb_policy_spec::PolicySpec = serde_json::from_value(spec.clone()).unwrap();
    let validated = validated.validate().unwrap();
    expanded.request.candidate.binding_set.spec_hash = validated.hash().to_hex();
    expanded.request.artifact.spec = spec.clone();
    assert!(matches!(prepare(expanded), Err(e) if e.contains("unsupported native scope")));
}

#[test]
#[ignore = "requires freshly generated Wasm; run scripts/test-native-execution.sh"]
fn real_candidate_account_path_runs_the_derived_suite_and_commits_state() {
    use ed25519_dalek::{Signer, SigningKey};
    struct Capability(SigningKey);
    impl DelegateSigner for Capability {
        fn sign(&mut self, request: &SignRequest) -> Result<SignatureResponse, String> {
            Ok(SignatureResponse {
                frame_type: "signature".into(),
                request_id: request.request_id.clone(),
                public_key_hex: hex::encode(self.0.verifying_key().to_bytes()),
                signature_hex: hex::encode(
                    self.0
                        .sign(&hex::decode(&request.digest_hex).unwrap())
                        .to_bytes(),
                ),
            })
        }
    }
    let job: NativeJob = serde_json::from_slice(
        &std::fs::read(std::env::var("OZPB_NATIVE_TEST_JOB").unwrap()).unwrap(),
    )
    .unwrap();
    let prepared = prepare(job).unwrap();
    let out = execute(
        &prepared,
        &mut Capability(SigningKey::from_bytes(&[42; 32])),
    )
    .unwrap();
    assert!(out.passed, "{out:#?}");
    assert!(!out.complete);
    assert!(out.cases.len() > 15);
    assert!(out.cases.iter().any(|c| c.permitted && c.state_changed));
    assert!(out
        .cases
        .iter()
        .filter(|c| !c.permitted)
        .all(|c| !c.state_changed));
    let json = serde_json::to_value(&out).unwrap();
    let controls = json["controls"]
        .as_array()
        .expect("cryptographic controls are required");
    for name in [
        "signature_bit",
        "nonce_binding",
        "payload_binding",
        "context_rule_binding",
        "nonce_replay",
    ] {
        assert!(
            controls
                .iter()
                .any(|v| v["name"] == name && v["passed"] == true),
            "{name}"
        );
    }
    assert_eq!(json["stateful"]["successful_calls"], 12);
    assert_eq!(json["stateful"]["counter_before"], 0);
    assert_eq!(json["stateful"]["counter_after"], 12);
    assert_eq!(json["stateful"]["overflow_refused"], true);
    assert_eq!(json["stateful"]["overflow_rolled_back"], true);
    assert_eq!(json["stateful"]["partial_rollback_refused"], true);
    assert_eq!(json["stateful"]["partial_rollback_preserved_counter"], true);
    assert_eq!(json["stateful"]["passed"], true);
}
