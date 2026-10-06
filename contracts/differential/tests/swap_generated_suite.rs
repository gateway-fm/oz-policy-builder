//! Partial contract-integration evidence for the generated Soroswap swap fixture.
//!
//! The harness derives mutations from this fixture's constraints. Each case runs through
//! a registered smart account's host-managed `__check_auth` invocation and the compiled
//! generated policy. This checks the fixture's permit/deny boundary in an isolated local
//! environment; it does not exercise a live network or all four dry-run layers (§4.5).

use generated_soroswap_swap_r0::contract::{GeneratedPolicy, PolicyStorageKey};
use ozpb_evaluator::{ArgValue, Invocation};
use ozpb_harness::{build_suite, Case, MutationClass};
use ozpb_policy_spec::{AddressRef, Constraint, SignerSpec, ValidatedSpec};
use ozpb_synthesizer::walkthroughs::soroswap_swap_spec;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::xdr::{Limits, ReadXdr, ScVal};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec as SVec,
};
use std::collections::{BTreeMap, BTreeSet};
use stellar_accounts::smart_account::{
    add_context_rule, do_check_auth, AuthPayload, ContextRuleType, Signer, SmartAccount,
    SmartAccountError,
};

#[contract]
struct SwapAccount;

#[contractimpl]
impl SmartAccount for SwapAccount {}

#[contractimpl]
impl CustomAccountInterface for SwapAccount {
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
        SignerSpec::External { .. } => panic!("swap fixture requires delegated signers"),
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
        panic!("the swap fixture must have exactly one rule");
    };
    let env = Env::default();
    env.mock_all_auths(); // Install/setup only; the explicit account check below still runs.
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = 1_000);
    let policy = env.register(GeneratedPolicy, ());
    let account = env.register(SwapAccount, ());
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
            &soroban_sdk::String::from_str(&env, "soroswap-swap"),
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
    let digest = env.crypto().sha256(&Bytes::new(&env));
    match env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
        &account,
        &digest.to_bytes(),
        payload.into_val(&env),
        &contexts,
    ) {
        Ok(()) => Ok(()),
        Err(Ok(error)) => Err(error),
        Err(Err(error)) => panic!("account invocation failed without a contract error: {error:?}"),
    }
}

#[test]
fn swap_mutations_agree_through_the_smart_account() {
    let spec = soroswap_swap_spec();
    let [rule] = spec.spec().rules.as_slice() else {
        panic!("the swap fixture must have one rule");
    };
    let [call] = rule.allowed_calls.as_slice() else {
        panic!("the swap fixture must have one allowed call");
    };
    let [amount_in, out_min, path, recipient, deadline] = call.args.as_slice() else {
        panic!("the swap fixture must have five constrained positions");
    };
    assert!(matches!(amount_in.constraint, Constraint::LeI128 { .. }));
    assert!(matches!(out_min.constraint, Constraint::GeI128 { .. }));
    assert!(matches!(path.constraint, Constraint::EqScval { .. }));
    assert!(matches!(
        recipient.constraint,
        Constraint::EqAddress {
            value: AddressRef::SelfAccount(_)
        }
    ));
    assert!(matches!(deadline.constraint, Constraint::AnyValue));
    let suite = build_suite(&spec);
    assert!(
        suite.len() > 15,
        "the derived suite needs substantive coverage"
    );

    let original = suite
        .iter()
        .find(|case| case.class == MutationClass::Original)
        .expect("the suite must include the recorded swap");
    let mut verdicts = BTreeMap::<MutationClass, (usize, usize)>::new();
    let mut denied_numeric_positions = BTreeSet::new();
    let mut denied_path = false;
    let mut denied_recipient = false;
    let mut permitted_deadline = false;
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
        let counts = verdicts.entry(case.class).or_default();
        if actual.is_ok() {
            counts.0 += 1;
        } else {
            counts.1 += 1;
        }
        if case.invocation.args.len() == original.invocation.args.len() {
            let changed: Vec<usize> = case
                .invocation
                .args
                .iter()
                .zip(&original.invocation.args)
                .enumerate()
                .filter_map(|(index, (candidate, recorded))| {
                    (candidate != recorded).then_some(index)
                })
                .collect();
            if changed.len() == 1 {
                match (case.class, changed[0], actual.is_ok()) {
                    (MutationClass::NumericBoundary, index @ (0 | 1), false) => {
                        denied_numeric_positions.insert(index);
                    }
                    (MutationClass::ArgEquality, 2, false) => denied_path = true,
                    (MutationClass::DifferentAddressArg, 3, false) => denied_recipient = true,
                    (MutationClass::TypeConfusion, 4, true) => permitted_deadline = true,
                    _ => {}
                }
            }
        }
    }

    // The original and a widened numeric/deadline call are positive controls. The cap,
    // floor, exact route, recipient, and arity must each produce at least one denial.
    assert!(verdicts
        .get(&MutationClass::Original)
        .is_some_and(|v| v.0 > 0));
    assert!(verdicts
        .get(&MutationClass::NumericBoundary)
        .is_some_and(|v| v.0 > 0 && v.1 > 0));
    assert!(verdicts
        .get(&MutationClass::TypeConfusion)
        .is_some_and(|v| v.0 > 0 && v.1 > 0));
    for class in [
        MutationClass::ArgEquality,
        MutationClass::DifferentAddressArg,
        MutationClass::ArgArity,
    ] {
        assert!(
            verdicts.get(&class).is_some_and(|v| v.1 > 0),
            "{class:?} must have a denied case"
        );
    }
    assert_eq!(
        denied_numeric_positions,
        BTreeSet::from([0, 1]),
        "both the input cap and output floor need a denied boundary"
    );
    assert!(denied_path, "an altered exact route must deny");
    assert!(denied_recipient, "a non-account recipient must deny");
    assert!(
        permitted_deadline,
        "an alternate deadline value must permit"
    );
}
