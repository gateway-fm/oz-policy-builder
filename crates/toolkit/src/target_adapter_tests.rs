use super::*;
use crate::test_support::registry_trust;
use ozpb_domain::{sha256, target_adapters, Provenance, TESTNET_PASSPHRASE};
use ozpb_policy_spec::{Constraint, DriftResponse, TargetHashRole};
use ozpb_recorder_core::fixtures as raw;
use ozpb_registry::{dev, sign_snapshot, TargetAdapterCapability};
use ozpb_synthesizer::fixtures as spec;
use stellar_xdr::{Limits, SorobanAuthorizedFunction, WriteXdr};

fn request() -> (SynthesizeInput, Hash32) {
    let hash = sha256(b"synthetic registry adapter router");
    (request_for(hash), hash)
}

/// A swap-shaped recording whose target is observed running `hash`, with a development
/// registry that binds `hash` to the reviewed router descriptor.
fn request_for(hash: Hash32) -> SynthesizeInput {
    let mut authorization = raw::auth_entry(raw::address_credentials(1));
    let SorobanAuthorizedFunction::ContractFn(call) = &mut authorization.root_invocation.function
    else {
        unreachable!()
    };
    call.function_name = "swap_exact_tokens_for_tokens".try_into().unwrap();
    call.args = vec![
        raw::i128_val(1000),
        raw::i128_val(950),
        stellar_xdr::ScVal::Vec(Some(
            vec![
                stellar_xdr::ScVal::Address(raw::token_sc()),
                stellar_xdr::ScVal::Address(raw::account_sc()),
            ]
            .try_into()
            .unwrap(),
        )),
        stellar_xdr::ScVal::Address(raw::account_sc()),
        stellar_xdr::ScVal::U64(2000),
    ]
    .try_into()
    .unwrap();
    let mut envelope = raw::envelope_with(vec![]);
    let stellar_xdr::TransactionEnvelope::Tx(tx) = &mut envelope else {
        unreachable!()
    };
    let mut operations = tx.tx.operations.to_vec();
    let stellar_xdr::OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
        unreachable!()
    };
    op.host_function = stellar_xdr::HostFunction::InvokeContract(call.clone());
    tx.tx.operations = operations.try_into().unwrap();
    let mut observations = raw::observed_executables();
    observations
        .get_mut(&spec::golden_token_strkey())
        .unwrap()
        .executable = ObservedExecutable::Wasm { code_hash: hash };
    let snapshot = EvidenceSnapshot::from_rpc_simulation(
        TESTNET_PASSPHRASE,
        envelope.to_xdr_base64(Limits::none()).unwrap(),
        vec![authorization.to_xdr_base64(Limits::none()).unwrap()],
        Some(4_200_100),
    )
    .with_contract_executables(observations);
    let recording = record_snapshot(&snapshot, RecordOptions::default()).unwrap();
    let mut snapshot = dev::dev_snapshot(
        ozpb_domain::NetworkId::from_passphrase(TESTNET_PASSPHRASE),
        1,
    );
    snapshot.target_adapters.insert(
        hash.to_hex(),
        TargetAdapterCapability {
            implementation: "soroswap-router@1".into(),
            semantics_digest: target_adapters::soroswap_router().digest().unwrap(),
            review_reference: "https://example.invalid/synthetic-reviewed-router".into(),
        },
    );
    let mut decisions = spec::golden_decisions();
    decisions.spending_limit = None;
    decisions.widenings.clear();
    SynthesizeInput {
        bundles: vec![recording.bundle],
        selected_authorizer: None,
        account: None,
        signed_registry_snapshot: Some(
            serde_json::to_value(sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap())
                .unwrap(),
        ),
        decisions: serde_json::to_value(decisions).unwrap(),
        spending_limit_capability: None,
        template_family: "policy-templates/scope@1".into(),
    }
}

fn output(input: &SynthesizeInput) -> PolicySpec {
    serde_json::from_value(synthesize_policy(input, &registry_trust()).unwrap().spec).unwrap()
}

#[test]
fn signed_hash_binding_routes_semantics_without_inventing_a_quote() {
    let (input, hash) = request();
    let spec = output(&input);
    spec.clone().validate().unwrap();
    let rule = &spec.rules[0];
    let args = &rule.allowed_calls[0].args;
    assert!(matches!(&args[0].constraint, Constraint::LeI128 { max } if max == "1000"));
    assert!(matches!(&args[1].constraint, Constraint::EqI128 { value } if value == "950"));
    for i in [1, 2, 3] {
        assert_eq!(args[i].provenance, Provenance::ObservedExact);
    }
    assert!(matches!(args[4].constraint, Constraint::AnyValue));
    for i in [0, 4] {
        assert!(
            matches!(&args[i].provenance, Provenance::AdapterDerived { adapter, code_hash }
            if adapter == "soroswap-router@1" && *code_hash == hash)
        );
    }
    let target = rule.context.target_code_hash.as_ref().unwrap();
    assert_eq!(target.role, TargetHashRole::AdapterRequired);
    assert_eq!(target.on_drift, DriftResponse::Refuse);
    assert!(spec
        .evidence
        .recordings
        .iter()
        .all(|r| r.trust == ozpb_domain::TrustLevel::self_supplied()));
}

/// The committed development snapshot carries the router binding, so a call recorded against
/// the testnet router's code gets the adapter's input bound and unconstrained deadline, and
/// the rule refuses on drift. The minimum output stays the recorded value: the adapter does
/// not invent a floor.
#[test]
fn committed_development_registry_derives_the_testnet_router_bounds() {
    let router = target_adapters::SOROSWAP_ROUTER_TESTNET_WASM;
    let mut input = request_for(router);
    input.signed_registry_snapshot = Some(
        serde_json::from_str(include_str!("../../../docs/examples/registry.signed.json")).unwrap(),
    );
    let spec = output(&input);
    let rule = &spec.rules[0];
    let args = &rule.allowed_calls[0].args;
    assert!(matches!(&args[0].constraint, Constraint::LeI128 { max } if max == "1000"));
    assert!(matches!(&args[1].constraint, Constraint::EqI128 { value } if value == "950"));
    assert!(
        matches!(&args[4].constraint, Constraint::EqScval { xdr_base64 }
        if xdr_base64 == &stellar_xdr::ScVal::U64(2000).to_xdr_base64(Limits::none()).unwrap())
    );
    assert_eq!(args[4].provenance, Provenance::ObservedExact);
    assert!(
        matches!(&args[0].provenance, Provenance::AdapterDerived { adapter, code_hash }
        if adapter == "soroswap-router@2" && *code_hash == router)
    );
    let target = rule.context.target_code_hash.as_ref().unwrap();
    assert_eq!(
        (target.hash, target.role, target.on_drift),
        (
            router,
            TargetHashRole::AdapterRequired,
            DriftResponse::Refuse
        )
    );
}

#[test]
fn absent_or_different_binding_stays_exact_and_unverified_registry_never_widens() {
    let (input, _) = request();
    for mismatch in [false, true] {
        let mut input = input.clone();
        let mut signed: SignedSnapshot =
            serde_json::from_value(input.signed_registry_snapshot.clone().unwrap()).unwrap();
        let entry = signed
            .snapshot
            .target_adapters
            .values()
            .next()
            .unwrap()
            .clone();
        signed.snapshot.target_adapters.clear();
        if mismatch {
            signed
                .snapshot
                .target_adapters
                .insert(sha256(b"different target").to_hex(), entry);
        }
        input.signed_registry_snapshot = Some(
            serde_json::to_value(sign_snapshot(&dev::dev_signing_key(), signed.snapshot).unwrap())
                .unwrap(),
        );
        assert!(output(&input).rules[0].allowed_calls[0]
            .args
            .iter()
            .all(|a| a.provenance == Provenance::ObservedExact));
    }
    let mut tampered = input;
    tampered.signed_registry_snapshot.as_mut().unwrap()["snapshot"]["target_adapters"] =
        serde_json::json!({});
    assert_eq!(
        synthesize_policy(&tampered, &registry_trust())
            .unwrap_err()
            .code,
        EC::ERegistrySignature
    );
}

#[test]
fn explicit_user_widening_keeps_its_distinct_intent_and_provenance() {
    let (mut input, _) = request();
    let mut decisions: UserDecisions = serde_json::from_value(input.decisions.clone()).unwrap();
    decisions.widenings.push(ozpb_synthesizer::Widening {
        contract: spec::golden_token_strkey(),
        fn_name: "swap_exact_tokens_for_tokens".into(),
        arg_index: 1,
        bound: ozpb_synthesizer::WideningBound::GeI128 { min: "900".into() },
        intent: "Explicit absolute output floor for this synthetic scenario".into(),
        blast_radius: ozpb_domain::BlastRadius::High,
    });
    input.decisions = serde_json::to_value(decisions).unwrap();
    let result = output(&input);
    assert!(
        matches!(&result.rules[0].allowed_calls[0].args[1].constraint, Constraint::GeI128 { min } if min == "900")
    );
    assert!(matches!(
        result.rules[0].allowed_calls[0].args[1].provenance,
        Provenance::UserWidened { .. }
    ));
}

#[test]
fn unrelated_authorizers_revoked_adapter_does_not_affect_selected_authorizer() {
    let (mut input, _) = request();
    let mut bundle: RecordingBundle = serde_json::from_value(input.bundles[0].clone()).unwrap();
    let unrelated_hash = sha256(b"revoked target for a different authorizer");
    let unrelated_target = format!("{}", stellar_strkey::Contract([71; 32]));
    let mut auth = raw::auth_entry(raw::address_credentials(2));
    let stellar_xdr::SorobanCredentials::Address(credentials) = &mut auth.credentials else {
        unreachable!()
    };
    credentials.address = raw::merchant_sc();
    let SorobanAuthorizedFunction::ContractFn(call) = &mut auth.root_invocation.function else {
        unreachable!()
    };
    call.contract_address =
        stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([71; 32])));
    bundle
        .raw
        .simulated_auth_xdr_base64
        .push(auth.to_xdr_base64(Limits::none()).unwrap());
    bundle.contract_executables.insert(
        unrelated_target,
        ozpb_recorder_core::ExecutableObservation {
            executable: ObservedExecutable::Wasm {
                code_hash: unrelated_hash,
            },
            observed_ledger: ozpb_domain::LedgerSeq(4_200_100),
            last_modified_ledger: None,
            live_until_ledger: None,
        },
    );
    let snapshot = EvidenceSnapshot::from_rpc_simulation(
        TESTNET_PASSPHRASE,
        bundle.raw.envelope_xdr_base64,
        bundle.raw.simulated_auth_xdr_base64,
        Some(4_200_100),
    )
    .with_contract_executables(bundle.contract_executables);
    input.bundles = vec![
        record_snapshot(&snapshot, RecordOptions::default())
            .unwrap()
            .bundle,
    ];
    input.selected_authorizer = Some(spec::golden_account_strkey());
    let mut signed: SignedSnapshot =
        serde_json::from_value(input.signed_registry_snapshot.clone().unwrap()).unwrap();
    signed.snapshot.revocations.insert(
        format!("target_adapter/{unrelated_hash}"),
        ozpb_registry::Revocation {
            reason: "test revoked unrelated target".into(),
            effective_version: 1,
        },
    );
    input.signed_registry_snapshot = Some(
        serde_json::to_value(sign_snapshot(&dev::dev_signing_key(), signed.snapshot).unwrap())
            .unwrap(),
    );
    assert!(matches!(
        output(&input).rules[0].allowed_calls[0].args[0].provenance,
        Provenance::AdapterDerived { .. }
    ));
}
