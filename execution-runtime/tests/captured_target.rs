//! Actual SDK-29 native SAC, pinned account Wasm and freshly generated policy over a capture.
//! The capture here is built locally from a real SAC deployment; it is not an RPC observation.
#[path = "support/captured_fixture.rs"]
mod captured_fixture;

use captured_fixture::{enc, job, job_with_balance};
use ed25519_dalek::{Signer, SigningKey};
use ozpb_execution_runtime::{
    execute_captured, prepare_captured, CapturedTargetJob, DelegateSigner, SignRequest,
    SignatureResponse,
};
use soroban_sdk::xdr::{self, ReadXdr};

struct Capability;
impl DelegateSigner for Capability {
    fn sign(&mut self, r: &SignRequest) -> Result<SignatureResponse, String> {
        let key = SigningKey::from_bytes(&[42; 32]);
        Ok(SignatureResponse {
            frame_type: "signature".into(),
            request_id: r.request_id.clone(),
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: hex::encode(key.sign(&hex::decode(&r.digest_hex).unwrap()).to_bytes()),
        })
    }
}

#[test]
#[ignore = "requires source-built captured native SAC fixture; run scripts/test-captured-target.sh"]
fn captured_sac_executes_real_target_balances_and_policy_denial_rollback() {
    let prepared = prepare_captured(job()).unwrap();
    let report = execute_captured(&prepared, &mut Capability).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["passed"], true, "{value:#}");
    assert_eq!(value["complete"], false);
    assert_eq!(value["storage_mode"], "strict_snapshot_source");
    let cases = value["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    let original = &cases[0];
    assert_eq!(original["case_id"], "target:original:0");
    assert_eq!(original["sender_delta"], "-1000000");
    assert_eq!(original["recipient_delta"], "1000000");
    assert_eq!(original["counter_before"], 0);
    assert_eq!(original["counter_after"], 1);
    // Both captured writable entries changed; exactly the two new nonces appeared.
    assert_eq!(original["written_keys"].as_array().unwrap().len(), 3);
    assert_eq!(original["created_keys"].as_array().unwrap().len(), 2);
    assert_eq!(original["captured_reads"].as_array().unwrap().len(), 3);
    assert!(original["undeclared_reads"].as_array().unwrap().is_empty());
    assert_eq!(cases[1]["case_id"], "target:argument-denial:0");
    assert_eq!(cases[1]["refusal_code"], 6);
    assert_eq!(cases[2]["case_id"], "target:empty-signers:0");
    assert_eq!(cases[2]["refusal_code"], 1);
    for case in &cases[1..] {
        assert_eq!(case["refusal_contract"], value["policy_address"]);
        assert_eq!(case["state_before_hash"], case["state_after_hash"]);
        assert_eq!(case["sender_delta"], "0");
        assert_eq!(case["recipient_delta"], "0");
        assert_eq!(case["counter_after"], 0);
        assert!(case["created_keys"].as_array().unwrap().is_empty());
    }
}

#[test]
#[ignore = "requires source-built captured native SAC fixture; run scripts/test-captured-target.sh"]
fn captured_state_decides_the_target_outcome() {
    // The policy permits the call, but the captured sender cannot cover it: the target's own
    // refusal must fail the layer rather than read as a pass or as a policy denial.
    let prepared = prepare_captured(job_with_balance(999_999)).unwrap();
    let report = execute_captured(&prepared, &mut Capability).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["passed"], false);
    let original = &value["cases"][0];
    assert_eq!(original["permitted"], false);
    assert_eq!(original["agree"], false);
    assert!(original["refusal_code"].is_null());
    assert_eq!(original["state_before_hash"], original["state_after_hash"]);
}

#[test]
#[ignore = "requires source-built captured native SAC fixture; run scripts/test-captured-target.sh"]
fn captured_prepare_refuses_modified_header_config_scope_and_incomplete_closure() {
    type Mutation = fn(&mut CapturedTargetJob);
    let cases: [(Mutation, &str); 11] = [
        (
            |j| j.capture.observed_ledger += 1,
            "network or ledger differs",
        ),
        (
            |j| j.capture.network_id = "ff".repeat(32),
            "network or ledger differs",
        ),
        (
            |j| j.capture.header_xdr = "AAAAAA==".into(),
            "ledger header is not valid XDR",
        ),
        (
            |j| j.capture.state_archival.last_modified_ledger = u32::MAX,
            "state-archival configuration differs",
        ),
        (
            |j| {
                for entry in &mut j.capture.entries {
                    if entry.live_until_ledger.is_some() {
                        entry.live_until_ledger = Some(1);
                    }
                }
            },
            "not live",
        ),
        (
            |j| drop(j.capture.entries.pop()),
            "not exactly the native transfer closure",
        ),
        (
            |j| j.native.ledger.protocol_version = 26,
            "unsupported job schema or source protocol",
        ),
        (
            |j| j.capture.account_code_hash = "00".repeat(32),
            "pinned account Wasm",
        ),
        (
            |j| {
                let key = j.capture.read_only_keys[0].clone();
                j.capture.read_write_keys.push(key);
            },
            "not exactly the native transfer closure",
        ),
        (
            |j| {
                let mut call = xdr::InvokeContractArgs::from_xdr_base64(
                    &j.capture.invocation_xdr,
                    xdr::Limits::none(),
                )
                .unwrap();
                let mut args = call.args.to_vec();
                args[2] = xdr::ScVal::I128(xdr::Int128Parts {
                    hi: 0,
                    lo: 1_000_001,
                });
                call.args = args.try_into().unwrap();
                j.capture.invocation_xdr = enc(&call);
            },
            "not an exact-amount transfer",
        ),
        (
            |j| {
                let mut auth = xdr::SorobanAuthorizationEntry::from_xdr_base64(
                    &j.capture.recording_auth_xdr,
                    xdr::Limits::none(),
                )
                .unwrap();
                let child = auth.root_invocation.clone();
                auth.root_invocation.sub_invocations = vec![child].try_into().unwrap();
                j.capture.recording_auth_xdr = enc(&auth);
            },
            "recorded authorization root",
        ),
    ];
    let base = job();
    prepare_captured(base.clone()).unwrap();
    for (index, (mutate, reason)) in cases.into_iter().enumerate() {
        let mut input = base.clone();
        mutate(&mut input);
        match prepare_captured(input) {
            Err(error) => assert!(error.contains(reason), "mutation {index}: {error}"),
            Ok(_) => panic!("mutation {index} was accepted"),
        }
    }
}

#[test]
#[ignore = "requires the recorded testnet capture and its generated policy; run scripts/test-captured-target.sh"]
fn captured_recorded_testnet_state_executes() {
    // The job's ledger parameters come from the capture's own header and configuration;
    // preparation still checks the header hash and every binding independently.
    let read = |var: &str| std::fs::read(std::env::var(var).unwrap()).unwrap();
    let mut native: ozpb_execution_runtime::NativeJob =
        serde_json::from_slice(&read("OZPB_TESTNET_NATIVE_JOB")).unwrap();
    let capture: ozpb_domain::TargetCapture =
        serde_json::from_slice(&read("OZPB_TESTNET_CAPTURE")).unwrap();
    let header =
        xdr::LedgerHeaderHistoryEntry::from_xdr_base64(&capture.header_xdr, xdr::Limits::none())
            .unwrap();
    let xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(settings)) =
        xdr::LedgerEntryData::from_xdr_base64(
            &capture.state_archival.data_xdr,
            xdr::Limits::none(),
        )
        .unwrap()
    else {
        panic!("state-archival entry")
    };
    native.ledger.sequence = capture.observed_ledger;
    native.ledger.timestamp = header.header.scp_value.close_time.0.to_string();
    native.ledger.base_reserve = header.header.base_reserve;
    native.ledger.min_temp_entry_ttl = settings.min_temporary_ttl;
    native.ledger.min_persistent_entry_ttl = settings.min_persistent_ttl;
    native.ledger.max_entry_ttl = settings.max_entry_ttl;
    let prepared = prepare_captured(CapturedTargetJob {
        schema: 1,
        native,
        capture,
    })
    .unwrap();
    let value =
        serde_json::to_value(execute_captured(&prepared, &mut Capability).unwrap()).unwrap();
    assert_eq!(value["passed"], true, "{value:#}");
    if let Ok(path) = std::env::var("OZPB_TESTNET_CAPTURED_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
}
