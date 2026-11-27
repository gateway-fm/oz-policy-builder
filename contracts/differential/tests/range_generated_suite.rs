//! Compiled evidence for the inclusive range constraint (`range_i128`), the one shape that bounds
//! an amount on both sides.
//!
//! The harness derives the boundary cases from the committed ranged-transfer fixture
//! (`contracts/range-transfer-policy`, regenerated and drift-checked by
//! `range_crate_matches_committed_output`). Each case runs through a registered smart account's
//! host-managed `__check_auth` and the generated policy, and its verdict must equal both the
//! harness's expectation and the reference evaluator's. The policy runs as the natively compiled
//! crate here, and as its Wasm build in the ignored test below, which `scripts/verify-phase2.sh`
//! runs after building it with `stellar contract build`. Native account-library 0.8 coverage; a
//! local environment, not a live network.

use generated_range_transfer_r0::contract::{GeneratedPolicy, PolicyStorageKey};
use ozpb_evaluator::{evaluate, ArgValue, Invocation, Verdict};
use ozpb_harness::{build_suite, Case, MutationClass};
use ozpb_policy_spec::{Constraint, SignerSpec, ValidatedSpec};
use ozpb_synthesizer::walkthroughs::{range_transfer_spec, RANGE_MAX, RANGE_MIN};
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::xdr::{Limits, ReadXdr, ScErrorType, ScVal};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec as SVec,
};
use std::collections::BTreeSet;
use stellar_accounts::smart_account::{
    add_context_rule, do_check_auth, AuthPayload, ContextRuleType, Signer, SmartAccount,
    SmartAccountError,
};

#[contract]
struct RangeAccount;

#[contractimpl]
impl SmartAccount for RangeAccount {}

#[contractimpl]
impl CustomAccountInterface for RangeAccount {
    type Signature = AuthPayload;
    type Error = SmartAccountError;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: soroban_sdk::Vec<Context>,
    ) -> Result<(), SmartAccountError> {
        do_check_auth(&env, &signature_payload, &signatures, &auth_contexts)
    }
}

/// The generated policy, as its natively compiled crate or as a Wasm build of it.
enum Policy {
    Native,
    Wasm(Vec<u8>),
}

fn address(env: &Env, spec: &ValidatedSpec, account: &Address, strkey: &str) -> Address {
    if strkey == spec.spec().smart_account.address {
        account.clone()
    } else {
        Address::from_str(env, strkey)
    }
}

fn signer(env: &Env, spec: &ValidatedSpec, account: &Address, value: &SignerSpec) -> Signer {
    match value {
        SignerSpec::Delegated { address: strkey } => {
            Signer::Delegated(address(env, spec, account, strkey))
        }
        SignerSpec::External { .. } => panic!("the range fixture requires delegated signers"),
    }
}

fn argument(env: &Env, spec: &ValidatedSpec, account: &Address, value: &ArgValue) -> Val {
    match value {
        ArgValue::Address(strkey) => address(env, spec, account, strkey).into_val(env),
        ArgValue::I128(number) => number.into_val(env),
        ArgValue::ScvalXdr(encoded) => {
            let scval = ScVal::from_xdr_base64(encoded, Limits::none())
                .expect("the harness must produce decodable ScVal XDR");
            Val::try_from_val(env, &scval).expect("a generated ScVal case must be replayable")
        }
    }
}

fn run_case(spec: &ValidatedSpec, case: &Case, policy: &Policy) -> Result<(), soroban_sdk::Error> {
    let [rule] = spec.spec().rules.as_slice() else {
        panic!("the range fixture must have exactly one rule");
    };
    let env = Env::default();
    // Management setup and delegated-signer authentication are both mocked. The account and the
    // generated policy still run; digest binding is not what this suite tests.
    env.mock_all_auths();
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = 1_000);
    let policy = match policy {
        Policy::Native => env.register(GeneratedPolicy, ()),
        Policy::Wasm(bytes) => env.register(bytes.as_slice(), ()),
    };
    let account = env.register(RangeAccount, ());
    let target = Address::from_str(&env, &rule.context.contract);
    let live_signers = SVec::from_iter(
        &env,
        case.context
            .rule_live_signers
            .iter()
            .map(|value| signer(&env, spec, &account, value)),
    );
    let mut policies = Map::new(&env);
    policies.set(policy.clone(), 0u32.into_val(&env));
    let stored_rule = env.as_contract(&account, || {
        add_context_rule(
            &env,
            &ContextRuleType::CallContract(target),
            &soroban_sdk::String::from_str(&env, "range-transfer"),
            rule.valid_until.as_ref().map(|until| until.ledger.0),
            &live_signers,
            &policies,
        )
    });
    env.as_contract(&policy, || {
        let key = PolicyStorageKey::CallCount(account.clone(), stored_rule.id);
        match case.context.call_count_so_far {
            Some(used) => env.storage().persistent().set(&key, &used),
            None => env.storage().persistent().remove(&key),
        }
    });
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = case.context.current_ledger.0);

    let mut authenticated = Map::new(&env);
    for value in &case.context.authenticated_signers {
        authenticated.set(signer(&env, spec, &account, value), Bytes::new(&env));
    }
    let payload = AuthPayload {
        signers: authenticated,
        context_rule_ids: SVec::from_array(&env, [stored_rule.id]),
    };
    let call = &case.invocation;
    let args = SVec::from_iter(
        &env,
        call.args
            .iter()
            .map(|arg| argument(&env, spec, &account, arg)),
    );
    let contexts = SVec::from_array(
        &env,
        [Context::Contract(ContractContext {
            contract: address(&env, spec, &account, &call.contract),
            fn_name: Symbol::new(&env, &call.fn_name),
            args,
        })],
    );
    // Placeholder digest: delegated authentication is mocked in this fixture.
    let digest = env.crypto().sha256(&Bytes::new(&env));
    match env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
        &account,
        &digest.to_bytes(),
        payload.into_val(&env),
        &contexts,
    ) {
        Ok(()) => Ok(()),
        Err(Ok(error)) if error.is_type(ScErrorType::Contract) => Err(error),
        Err(Ok(error)) => panic!("account invocation failed outside the contract: {error:?}"),
        Err(Err(error)) => panic!("account invocation failed without a contract error: {error:?}"),
    }
}

fn amount(invocation: &Invocation) -> Option<i128> {
    match invocation.args.get(2) {
        Some(ArgValue::I128(value)) => Some(*value),
        _ => None,
    }
}

/// Every derived case agrees three ways — compiled policy, harness expectation, evaluator — and
/// the range's own boundaries are among them: both ends permit, one past each end and the
/// signed minimum deny with the tuple refusal (contract error 6, as the single bounds deny).
fn range_cases_agree(policy: Policy) {
    let spec = range_transfer_spec();
    let [rule] = spec.spec().rules.as_slice() else {
        panic!("the range fixture must have one rule");
    };
    assert_eq!(
        rule.allowed_calls[0].args[2].constraint,
        Constraint::RangeI128 {
            min: RANGE_MIN.to_string(),
            max: RANGE_MAX.to_string()
        }
    );
    let suite = build_suite(&spec);
    let mut permitted = BTreeSet::new();
    let mut refused = BTreeSet::new();
    for case in &suite {
        let actual = run_case(&spec, case, &policy);
        let reference = matches!(
            evaluate(&spec, &case.context, &case.invocation),
            Verdict::Permit
        );
        assert_eq!(
            (actual.is_ok(), reference),
            (case.expect_permit, case.expect_permit),
            "{} ({:?}): expected permit={}, policy={actual:?}, evaluator permit={reference}",
            case.label,
            case.class,
            case.expect_permit,
        );
        if case.class == MutationClass::NumericBoundary {
            if let Some(value) = amount(&case.invocation) {
                if actual.is_ok() {
                    permitted.insert(value);
                } else {
                    assert_eq!(
                        actual,
                        Err(soroban_sdk::Error::from_contract_error(6)),
                        "{} must fail with NoTupleMatched",
                        case.label
                    );
                    refused.insert(value);
                }
            }
        }
    }
    assert!(
        permitted.is_superset(&BTreeSet::from([RANGE_MIN, RANGE_MAX])),
        "both ends must permit: {permitted:?}"
    );
    assert!(
        refused.is_superset(&BTreeSet::from([RANGE_MIN - 1, RANGE_MAX + 1, i128::MIN])),
        "one past each end and the signed minimum must deny: {refused:?}"
    );
}

#[test]
fn range_cases_agree_through_the_compiled_policy() {
    range_cases_agree(Policy::Native);
}

#[test]
#[ignore = "requires the range policy's Wasm: OZPB_RANGE_POLICY_WASM=<path>, built by stellar \
            contract build --manifest-path contracts/range-transfer-policy/Cargo.toml; run by \
            scripts/verify-phase2.sh"]
fn range_cases_agree_through_the_wasm_policy() {
    let path = std::env::var("OZPB_RANGE_POLICY_WASM")
        .expect("OZPB_RANGE_POLICY_WASM must name the built range policy");
    let wasm = std::fs::read(path).expect("read the range policy Wasm");
    assert_eq!(
        &wasm[..4],
        b"\0asm",
        "OZPB_RANGE_POLICY_WASM is not a Wasm module"
    );
    range_cases_agree(Policy::Wasm(wasm));
}
