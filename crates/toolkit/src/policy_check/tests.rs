use super::*;
use crate::test_support::{build_config, registry_trust};
use stellar_xdr::{
    AccountEntry, AccountEntryExt, ContractDataEntry, ExtensionPoint, Int128Parts,
    ScContractInstance, ScMapEntry, SequenceNumber, String32, Thresholds,
};

fn c(byte: u8) -> String {
    format!("{}", stellar_strkey::Contract([byte; 32]))
}
fn g(byte: u8) -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
}
fn symbol(value: &str) -> ScVal {
    ScVal::Symbol(value.try_into().unwrap())
}
fn vector(values: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(values.try_into().unwrap()))
}
fn record(fields: Vec<(&str, ScVal)>) -> ScVal {
    let mut fields: Vec<_> = fields
        .into_iter()
        .map(|(key, val)| ScMapEntry {
            key: symbol(key),
            val,
        })
        .collect();
    fields.sort_by(|a, b| a.key.cmp(&b.key));
    ScVal::Map(Some(fields.try_into().unwrap()))
}
fn amount(n: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}
fn store(capture: &mut PolicyStateCapture, key: LedgerKey, value: ScVal) {
    let LedgerKey::ContractData(data) = &key else {
        panic!("contract data required")
    };
    capture.entries.insert(
        key.clone(),
        Some(CapturedPolicyEntry {
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: data.contract.clone(),
                key: data.key.clone(),
                durability: data.durability,
                val: value,
            }),
            last_modified_ledger: 1,
            live_until_ledger: Some(5_000_000),
        }),
    );
}
fn instance(capture: &mut PolicyStateCapture, contract: &str, hash: Hash32) {
    store(
        capture,
        data_key(contract, ScVal::LedgerKeyContractInstance).unwrap(),
        ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(hash.0)),
            storage: None,
        }),
    );
}

fn fixture() -> (CheckAgainstPolicyInput, PolicyStateCapture) {
    let (authority, _) = crate::call_surface_live::tests::fixture();
    let spec: PolicySpec = serde_json::from_value(authority.spec.clone()).unwrap();
    let rule = &spec.rules[0];
    let SignerSpec::Delegated { address: delegate } = &rule.authorization.signers[0] else {
        panic!("classic fixture")
    };
    let input = CheckAgainstPolicyInput {
        spec: authority.spec.clone(),
        binding_set: authority.binding_set.clone(),
        signed_registry_snapshot: authority.signed_registry_snapshot,
        rule_index: 0,
        installed_context_rule_id: 42,
        account_address: authority.account_address.clone(),
        network_id: authority.network_id,
        rpc_source: authority.rpc_source,
        candidate_signers: vec![PolicyCheckSigner::Delegated {
            address: delegate.clone(),
        }],
        invocation: serde_json::to_value(Invocation {
            contract: rule.context.contract.clone(),
            fn_name: "transfer".into(),
            args: vec![
                ArgValue::Address(spec.smart_account.address.clone()),
                ArgValue::Address(ozpb_synthesizer::fixtures::golden_merchant_strkey()),
                ArgValue::I128(500_000_000),
            ],
        })
        .unwrap(),
    };
    let mut capture = PolicyStateCapture {
        network_id: spec.network_id,
        account_address: input.account_address.clone(),
        installed_context_rule_id: 42,
        observed_ledger: 4_200_000,
        ledger_hash: Hash32([0x11; 32]),
        entries: BTreeMap::new(),
    };
    instance(
        &mut capture,
        &input.account_address,
        spec.smart_account.observed_code_hash,
    );
    instance(
        &mut capture,
        &rule.context.contract,
        rule.context
            .target_code_hash
            .as_ref()
            .map(|target| target.hash)
            .unwrap_or(Hash32([3; 32])),
    );
    store(
        &mut capture,
        account_key(&input.account_address, "ContextRuleData", 42).unwrap(),
        record(vec![
            (
                "context_type",
                tagged(
                    "CallContract",
                    vec![ScVal::Address(address(&rule.context.contract).unwrap())],
                )
                .unwrap(),
            ),
            (
                "name",
                ScVal::String(stellar_xdr::ScString(
                    spec.name.as_str().try_into().unwrap(),
                )),
            ),
            (
                "valid_until",
                ScVal::U32(rule.valid_until.as_ref().unwrap().ledger.0),
            ),
            ("signer_ids", vector(vec![ScVal::U32(7)])),
            ("policy_ids", vector(vec![ScVal::U32(8), ScVal::U32(9)])),
        ]),
    );
    let delegate_bytes = delegate
        .parse::<stellar_strkey::ed25519::PublicKey>()
        .unwrap()
        .0;
    store(
        &mut capture,
        account_key(&input.account_address, "SignerData", 7).unwrap(),
        record(vec![
            (
                "signer",
                tagged(
                    "Delegated",
                    vec![ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256(delegate_bytes)),
                    )))],
                )
                .unwrap(),
            ),
            ("count", ScVal::U32(1)),
        ]),
    );
    let classic = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(delegate_bytes))),
        balance: 1,
        seq_num: SequenceNumber(1),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: Default::default(),
        ext: AccountEntryExt::V0,
    };
    let data = LedgerEntryData::Account(classic);
    capture.entries.insert(
        data.to_key(),
        Some(CapturedPolicyEntry {
            data,
            last_modified_ledger: 1,
            live_until_ledger: None,
        }),
    );
    for binding in &input.binding_set.bindings {
        instance(
            &mut capture,
            &binding.contract_address,
            Hash32::from_hex(&binding.observed_wasm_hash).unwrap(),
        );
        store(
            &mut capture,
            account_key(
                &input.account_address,
                "PolicyData",
                8 + binding.policy_index as u32,
            )
            .unwrap(),
            record(vec![
                (
                    "policy",
                    ScVal::Address(address(&binding.contract_address).unwrap()),
                ),
                ("count", ScVal::U32(1)),
            ]),
        );
        match &rule.policies[binding.policy_index] {
            PolicyRef::Generated { .. } => {
                store(
                    &mut capture,
                    policy_key(
                        &binding.contract_address,
                        "Installed",
                        &input.account_address,
                        42,
                    )
                    .unwrap(),
                    ScVal::Bool(true),
                );
                store(
                    &mut capture,
                    policy_key(
                        &binding.contract_address,
                        "CallCount",
                        &input.account_address,
                        42,
                    )
                    .unwrap(),
                    ScVal::U32(0),
                );
            }
            PolicyRef::Reviewed {
                params:
                    ReviewedParams::SpendingLimit {
                        limit,
                        period_ledgers,
                    },
                ..
            } => {
                store(
                    &mut capture,
                    policy_key(
                        &binding.contract_address,
                        "AccountContext",
                        &input.account_address,
                        42,
                    )
                    .unwrap(),
                    record(vec![
                        ("spending_limit", amount(limit.parse().unwrap())),
                        ("period_ledgers", ScVal::U32(*period_ledgers)),
                        ("cached_total_spent", amount(0)),
                        ("spending_history", vector(vec![])),
                    ]),
                );
            }
        }
    }
    (input, capture)
}

fn run(input: &CheckAgainstPolicyInput, capture: &PolicyStateCapture) -> CheckAgainstPolicyOutput {
    let plan = plan_policy_check_read(input, &registry_trust(), &build_config()).unwrap();
    finish_policy_check(&plan, capture).unwrap()
}

#[test]
fn stranger_in_otherwise_sufficient_candidates_must_deny() {
    let live = vec![SignerIdentity::Delegated(g(1))];
    let good = PolicyCheckSigner::Delegated { address: g(1) };
    assert!(candidates_belong_to_rule(
        std::slice::from_ref(&good),
        &live
    ));
    assert!(!candidates_belong_to_rule(
        &[good, PolicyCheckSigner::Delegated { address: g(2) }],
        &live
    ));
}

#[test]
fn complete_installed_rule_differs_from_spec_index_and_binds_conditional_evidence() {
    let (input, capture) = fixture();
    let CheckAgainstPolicyOutput::Permit { evidence } = run(&input, &capture) else {
        panic!("complete fixture must permit")
    };
    assert_eq!(evidence.installed_context_rule_id, 42);
    assert_eq!(evidence.rule_index, 0);
    assert!(evidence.matches_request(&input).unwrap());
    assert!(!evidence.storage_reads.is_empty());
    assert!(!evidence.configuration_reads.is_empty());
    assert_eq!(evidence.classic_account_reads.len(), 1);
    let wire = serde_json::to_value(evidence).unwrap();
    assert_eq!(
        wire["authentication_assumption"],
        "candidate_signers_must_authenticate"
    );
    assert_eq!(wire["evidence_trust"], "rpc_reported");
    assert_eq!(wire["recheck_before_signing"], "required");
}

#[test]
fn authorized_plus_stranger_is_denied_by_the_full_operation() {
    let (mut input, capture) = fixture();
    input
        .candidate_signers
        .push(PolicyCheckSigner::Delegated { address: g(98) });
    assert!(
        matches!(run(&input,&capture),CheckAgainstPolicyOutput::Deny{deny_reason,..} if deny_reason=="unauthorized_signer")
    );
}

#[test]
fn missing_or_archived_counter_never_resets_allowance() {
    let (input, capture) = fixture();
    let key = policy_key(
        &input.binding_set.bindings[1].contract_address,
        "CallCount",
        &input.account_address,
        42,
    )
    .unwrap();
    let mut missing = capture.clone();
    missing.entries.insert(key.clone(), None);
    let CheckAgainstPolicyOutput::Unsupported {
        evidence: Some(evidence),
        ..
    } = run(&input, &missing)
    else {
        panic!("missing is unsupported")
    };
    assert!(matches!(
        evidence.restoration,
        PolicyStateRestoration::Unknown
    ));
    let mut archived = capture;
    archived
        .entries
        .get_mut(&key)
        .unwrap()
        .as_mut()
        .unwrap()
        .live_until_ledger = Some(1);
    let CheckAgainstPolicyOutput::Unsupported {
        evidence: Some(evidence),
        ..
    } = run(&input, &archived)
    else {
        panic!("archive is unsupported")
    };
    assert!(matches!(
        evidence.restoration,
        PolicyStateRestoration::Required
    ));
}

#[test]
fn altered_policy_code_or_rule_id_cannot_permit() {
    let (input, mut capture) = fixture();
    instance(
        &mut capture,
        &input.binding_set.bindings[1].contract_address,
        Hash32([9; 32]),
    );
    assert!(matches!(
        run(&input, &capture),
        CheckAgainstPolicyOutput::Unsupported { .. }
    ));
    capture.installed_context_rule_id = 0;
    let plan = plan_policy_check_read(&input, &registry_trust(), &build_config()).unwrap();
    assert!(finish_policy_check(&plan, &capture).is_err());
}

#[test]
fn no_candidates_denies_but_unknown_authentication_is_unsupported() {
    let (mut input, capture) = fixture();
    input.candidate_signers.clear();
    assert!(matches!(
        run(&input, &capture),
        CheckAgainstPolicyOutput::Deny { .. }
    ));
    let plan = plan_policy_check_read(&input, &registry_trust(), &build_config()).unwrap();
    assert!(resolve_signer(&plan, &capture, &SignerIdentity::Delegated(c(98))).is_err());
}

#[test]
fn missing_code_with_present_instance_is_explicitly_unavailable() {
    let (input, mut capture) = fixture();
    let hash = code_hash(&capture, &input.account_address).unwrap();
    capture.entries.insert(
        LedgerKey::ContractCode(stellar_xdr::LedgerKeyContractCode { hash: Hash(hash.0) }),
        None,
    );
    let CheckAgainstPolicyOutput::Unsupported {
        evidence: Some(evidence),
        ..
    } = run(&input, &capture)
    else {
        panic!("missing code cannot permit")
    };
    assert!(matches!(
        evidence.restoration,
        PolicyStateRestoration::Unknown
    ));
    assert!(evidence
        .configuration_reads
        .iter()
        .any(|read| matches!(read.observation, PolicyStateObservation::Absent)));
}

#[test]
fn counter_and_inclusive_rule_expiry_boundaries_are_enforced() {
    let (input, capture) = fixture();
    let spec: PolicySpec = serde_json::from_value(input.spec.clone()).unwrap();
    let StateSpec::CallCountPerInstallation { max_calls } = spec.rules[0].state[0];
    let counter = policy_key(
        &input.binding_set.bindings[1].contract_address,
        "CallCount",
        &input.account_address,
        42,
    )
    .unwrap();
    for (count, permit) in [(max_calls - 1, true), (max_calls, false)] {
        let mut state = capture.clone();
        store(&mut state, counter.clone(), ScVal::U32(count));
        assert_eq!(
            matches!(run(&input, &state), CheckAgainstPolicyOutput::Permit { .. }),
            permit
        );
    }
    let expiry = spec.rules[0].valid_until.as_ref().unwrap().ledger.0;
    for (ledger, permit) in [(expiry, true), (expiry + 1, false)] {
        let mut state = capture.clone();
        state.observed_ledger = ledger;
        let output = run(&input, &state);
        assert_eq!(
            matches!(output, CheckAgainstPolicyOutput::Permit { .. }),
            permit
        );
        assert!(!matches!(
            output,
            CheckAgainstPolicyOutput::Unsupported { .. }
        ));
    }
}

#[test]
fn reviewed_history_and_installed_parameters_are_part_of_the_live_prediction() {
    let (input, capture) = fixture();
    let spec: PolicySpec = serde_json::from_value(input.spec.clone()).unwrap();
    let PolicyRef::Reviewed {
        params:
            ReviewedParams::SpendingLimit {
                limit,
                period_ledgers,
            },
        ..
    } = &spec.rules[0].policies[0]
    else {
        panic!("spending fixture")
    };
    let limit: i128 = limit.parse().unwrap();
    let key = policy_key(
        &input.binding_set.bindings[0].contract_address,
        "AccountContext",
        &input.account_address,
        42,
    )
    .unwrap();
    for (spent_at, permit) in [
        (capture.observed_ledger, false),
        (capture.observed_ledger - period_ledgers, true),
    ] {
        let mut state = capture.clone();
        store(
            &mut state,
            key.clone(),
            record(vec![
                ("spending_limit", amount(limit)),
                ("period_ledgers", ScVal::U32(*period_ledgers)),
                ("cached_total_spent", amount(limit)),
                (
                    "spending_history",
                    vector(vec![record(vec![
                        ("amount", amount(limit)),
                        ("ledger_sequence", ScVal::U32(spent_at)),
                    ])]),
                ),
            ]),
        );
        assert_eq!(
            matches!(run(&input, &state), CheckAgainstPolicyOutput::Permit { .. }),
            permit
        );
    }
    let mut altered = capture;
    store(
        &mut altered,
        key,
        record(vec![
            ("spending_limit", amount(limit + 1)),
            ("period_ledgers", ScVal::U32(*period_ledgers)),
            ("cached_total_spent", amount(0)),
            ("spending_history", vector(vec![])),
        ]),
    );
    assert!(matches!(
        run(&input, &altered),
        CheckAgainstPolicyOutput::Unsupported { .. }
    ));
}

fn change_spec(
    input: &mut CheckAgainstPolicyInput,
    capture: &mut PolicyStateCapture,
    change: impl FnOnce(&mut PolicySpec),
) {
    let mut spec: PolicySpec = serde_json::from_value(input.spec.clone()).unwrap();
    change(&mut spec);
    let spec = spec.validate().unwrap();
    input.spec = serde_json::to_value(spec.spec()).unwrap();
    input.binding_set.spec_hash = spec.hash().to_hex();
    let generated = crate::generate_code_with_build_config(
        &GenerateCodeInput {
            spec: input.spec.clone(),
            rule_index: 0,
        },
        &build_config(),
    )
    .unwrap();
    let binding = &mut input.binding_set.bindings[1];
    binding.observed_wasm_hash = generated.wasm_hash.clone();
    binding.recognition = PolicyRecognition::VerifiedGeneratedManifest {
        build_manifest: generated.build_manifest,
    };
    instance(
        capture,
        &binding.contract_address,
        Hash32::from_hex(&generated.wasm_hash).unwrap(),
    );
}

#[test]
fn a_complete_generated_only_installation_can_permit_without_reviewed_state() {
    let (mut input, mut capture) = fixture();
    let reviewed = input.binding_set.bindings[0].contract_address.clone();
    change_spec(&mut input, &mut capture, |spec| {
        spec.rules[0].policies.remove(0);
    });
    input.binding_set.bindings.remove(0);
    input.binding_set.bindings[0].policy_index = 0;
    capture
        .entries
        .remove(&account_key(&input.account_address, "PolicyData", 8).unwrap());
    let reviewed_address = address(&reviewed).unwrap();
    capture.entries.retain(
        |key, _| !matches!(key, LedgerKey::ContractData(data) if data.contract == reviewed_address),
    );
    let rule_key = account_key(&input.account_address, "ContextRuleData", 42).unwrap();
    let LedgerEntryData::ContractData(rule) = &mut capture
        .entries
        .get_mut(&rule_key)
        .unwrap()
        .as_mut()
        .unwrap()
        .data
    else {
        panic!("rule data")
    };
    let ScVal::Map(Some(fields)) = &mut rule.val else {
        panic!("rule fields")
    };
    let mut replacement: Vec<_> = fields.iter().cloned().collect();
    replacement
        .iter_mut()
        .find(|field| field.key == symbol("policy_ids"))
        .unwrap()
        .val = vector(vec![ScVal::U32(9)]);
    *fields = replacement.try_into().unwrap();
    assert!(matches!(
        run(&input, &capture),
        CheckAgainstPolicyOutput::Permit { .. }
    ));
}

#[test]
fn target_warning_and_required_refusal_do_not_get_conflated() {
    for response in [DriftResponse::Warn, DriftResponse::Refuse] {
        let (mut input, mut capture) = fixture();
        change_spec(&mut input, &mut capture, |spec| {
            spec.rules[0].context.target_code_hash = Some(ozpb_policy_spec::TargetCodeHash {
                hash: Hash32([90; 32]),
                role: TargetHashRole::EvidenceOnly,
                observed_ledger: LedgerSeq(1),
                on_drift: response,
            })
        });
        match run(&input, &capture) {
            CheckAgainstPolicyOutput::Permit { evidence } if response == DriftResponse::Warn => {
                assert!(!evidence.target_drift.unwrap().refusal_required)
            }
            CheckAgainstPolicyOutput::Unsupported {
                evidence: Some(evidence),
                ..
            } if response == DriftResponse::Refuse => {
                assert!(evidence.target_drift.unwrap().refusal_required)
            }
            other => panic!("wrong drift result {other:?}"),
        }
    }
}

#[test]
fn tampered_attestation_duplicate_candidate_and_invalid_argument_do_not_start_a_read() {
    let (mut input, _) = fixture();
    input
        .candidate_signers
        .push(input.candidate_signers[0].clone());
    assert!(plan_policy_check_read(&input, &registry_trust(), &build_config()).is_err());
    input.candidate_signers.pop();
    let PolicyRecognition::VerifiedGeneratedManifest { build_manifest } =
        &mut input.binding_set.bindings[1].recognition
    else {
        panic!("generated")
    };
    build_manifest["wasm_hash"] = serde_json::json!("00");
    let error = plan_policy_check_read(&input, &registry_trust(), &build_config())
        .err()
        .unwrap();
    assert!(matches!(
        policy_check_unavailable(error).unwrap(),
        CheckAgainstPolicyOutput::Unsupported { .. }
    ));
    input.invocation["args"][0] = serde_json::json!({"scval_xdr":"garbage"});
    assert!(plan_policy_check_read(&input, &registry_trust(), &build_config()).is_err());
}
