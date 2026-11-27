//! Native account-library 0.8 coverage; pinned account-Wasm compatibility is a separate gate.
//! Partial contract-integration evidence that a generated policy accepting two tuples of one
//! function refuses their cross products.
//!
//! The fixture rule accepts `transfer(SELF, FIRST_PAYEE, 1_000)` and
//! `transfer(SELF, SECOND_PAYEE, 2_000)`, each from its own recording. A mix of the two matches
//! every position of some accepted call, so a policy that checked positions independently would
//! permit it. Each derived case runs through a registered smart account's host-managed
//! `__check_auth` and the compiled generated policy, and the cross products are also put to the
//! reference evaluator. Management setup and delegated authentication are mocked; this is not a
//! live network or the pinned account Wasm.

use generated_two_payments_r0::contract::{GeneratedPolicy, PolicyStorageKey};
use ozpb_evaluator::{
    evaluate, evaluate_generated_rule, ArgValue, DenyReason, Invocation, Verdict,
};
use ozpb_harness::{build_suite, Case, MutationClass};
use ozpb_policy_spec::{SignerSpec, ValidatedSpec};
use ozpb_synthesizer::walkthroughs::{two_payment_spec, FIRST_PAYEE, SECOND_PAYEE};
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::xdr::{Limits, ReadXdr, ScErrorType, ScVal};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec as SVec,
};
use stellar_accounts::smart_account::{
    add_context_rule, do_check_auth, AuthPayload, ContextRuleType, Signer, SmartAccount,
    SmartAccountError,
};

#[contract]
struct PaymentAccount;

#[contractimpl]
impl SmartAccount for PaymentAccount {}

#[contractimpl]
impl CustomAccountInterface for PaymentAccount {
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
        SignerSpec::External { .. } => panic!("payment fixture requires delegated signers"),
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

fn context(env: &Env, spec: &ValidatedSpec, account: &Address, call: &Invocation) -> Context {
    let args = SVec::from_iter(
        env,
        call.args
            .iter()
            .map(|arg| argument(env, spec, account, arg)),
    );
    Context::Contract(ContractContext {
        contract: address(env, spec, account, &call.contract),
        fn_name: Symbol::new(env, &call.fn_name),
        args,
    })
}

fn run_case(spec: &ValidatedSpec, case: &Case) -> Result<(), soroban_sdk::Error> {
    let [rule] = spec.spec().rules.as_slice() else {
        panic!("the payment fixture must have exactly one rule");
    };
    let env = Env::default();
    // Management setup and delegated-signer authentication are both mocked. The
    // account and generated policy still run, but digest binding is not tested here.
    env.mock_all_auths();
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = 1_000);
    let policy = env.register(GeneratedPolicy, ());
    let account = env.register(PaymentAccount, ());
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
            &soroban_sdk::String::from_str(&env, "two-payments"),
            rule.valid_until.as_ref().map(|until| until.ledger.0),
            &live_signers,
            &policies,
        )
    });

    // Generated boundary cases name their initial counter. Each gets a fresh installed
    // environment, so one case cannot consume another's allowance.
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
    let contexts = SVec::from_array(&env, [context(&env, spec, &account, &case.invocation)]);
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

const NO_TUPLE_MATCHED: u32 = 6;

fn with_args(case: &Case, args: Vec<ArgValue>) -> Case {
    let mut case = case.clone();
    case.invocation = Invocation {
        args,
        ..case.invocation
    };
    case
}

#[test]
fn cross_products_of_two_accepted_tuples_are_refused_by_the_compiled_policy_and_the_evaluator() {
    let spec = two_payment_spec();
    let [rule] = spec.spec().rules.as_slice() else {
        panic!("the payment fixture must have one rule");
    };
    assert_eq!(
        rule.allowed_calls.len(),
        2,
        "two accepted tuples of one function"
    );
    let suite = build_suite(&spec);
    let original = suite
        .iter()
        .find(|case| case.class == MutationClass::Original)
        .expect("the suite must include a recorded payment");
    let payer = original.invocation.args[0].clone();
    let payment = |payee: String, amount: i128| {
        vec![
            payer.clone(),
            ArgValue::Address(payee),
            ArgValue::I128(amount),
        ]
    };

    // Positive controls: each recorded payment, whole, is permitted by both.
    for args in [
        payment(FIRST_PAYEE(), 1_000),
        payment(SECOND_PAYEE(), 2_000),
    ] {
        let case = with_args(original, args);
        assert_eq!(
            evaluate(&spec, &case.context, &case.invocation),
            Verdict::Permit
        );
        assert_eq!(
            run_case(&spec, &case),
            Ok(()),
            "a recorded payment must permit"
        );
    }

    // The tuples differ in the payee and the amount, so there are exactly two mixes, and the
    // harness must derive both.
    let crossed: Vec<&Case> = suite
        .iter()
        .filter(|case| case.class == MutationClass::TupleCrossProduct)
        .collect();
    assert_eq!(crossed.len(), 2, "one cross product per differing position");
    for expected in [
        payment(FIRST_PAYEE(), 2_000),
        payment(SECOND_PAYEE(), 1_000),
    ] {
        assert!(
            crossed.iter().any(|case| case.invocation.args == expected),
            "missing cross product {expected:?}"
        );
    }
    for case in &crossed {
        assert!(
            !case.expect_permit,
            "{}: a cross product must be expected to deny",
            case.label
        );
        assert_eq!(
            evaluate_generated_rule(rule, &case.context, &case.invocation),
            Verdict::Deny(DenyReason::NoTupleMatched),
            "{}",
            case.label
        );
        assert_eq!(
            evaluate(&spec, &case.context, &case.invocation),
            Verdict::Deny(DenyReason::NoTupleMatched),
            "{}",
            case.label
        );
        assert_eq!(
            run_case(&spec, case),
            Err(soroban_sdk::Error::from_contract_error(NO_TUPLE_MATCHED)),
            "{}: the compiled policy must refuse the mix with NoTupleMatched",
            case.label
        );
    }

    // And the whole derived suite agrees with the compiled policy.
    for case in &suite {
        let actual = run_case(&spec, case);
        assert_eq!(
            actual.is_ok(),
            case.expect_permit,
            "{} ({:?}): expected permit={}, account result={actual:?}",
            case.label,
            case.class,
            case.expect_permit,
        );
    }
}
