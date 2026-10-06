//! Layer-2 differential for the golden transfer fixture's generated deny suite.
//!
//! `harness::build_suite` derives cases from this fixture's constraints. This test replays
//! every case through the compiled policy in a committed-state Soroban environment and
//! checks its permit/deny verdict against the harness expectation. Selected mutations also
//! check exact reasons against hand-stated fixture expectations. This covers one fixture,
//! not every policy or all four dry-run layers.
//!
//! This test alone in the contracts workspace uses the harness. The existing differential
//! tests retain their independent, hand-written cases.

use generated_sub_transfer_r0::contract::{GeneratedPolicy, PolicyStorageKey};
use ozpb_evaluator::{ArgValue, Invocation};
use ozpb_harness::{build_suite, Case, MutationClass};
use ozpb_policy_spec::{Constraint, PredicateKind, SignerSpec, StateSpec};
use ozpb_synthesizer::fixtures as fx;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, Env, IntoVal, Map, Symbol, Val, Vec as SVec,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use stellar_accounts::smart_account::{
    add_context_rule, do_check_auth, AuthPayload, ContextRuleType, Signer, SmartAccount,
    SmartAccountError,
};

#[contract]
struct HarnessAccount;

#[contractimpl]
impl SmartAccount for HarnessAccount {}

#[contractimpl]
impl CustomAccountInterface for HarnessAccount {
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

/// Maps harness address strings to real, valid soroban Addresses, preserving equality:
/// the spec's own fixture strkeys map to `Address::from_str` of that exact strkey (so the
/// contract's compiled-in literals match), and any other string gets a fresh generated
/// address (distinct, valid). Same string → same Address.
struct AddrMap<'a> {
    env: &'a Env,
    known: Vec<String>,
    cache: RefCell<BTreeMap<String, Address>>,
}

impl<'a> AddrMap<'a> {
    fn new(env: &'a Env, account: &Address) -> Self {
        let map = AddrMap {
            env,
            known: vec![
                fx::golden_token_strkey(),
                fx::golden_merchant_strkey(),
                fx::golden_delegate_strkey(),
            ],
            cache: RefCell::new(BTreeMap::new()),
        };
        map.cache
            .borrow_mut()
            .insert(fx::golden_account_strkey(), account.clone());
        map
    }
    fn get(&self, s: &str) -> Address {
        if let Some(a) = self.cache.borrow().get(s) {
            return a.clone();
        }
        let addr = if self.known.iter().any(|k| k == s) {
            Address::from_str(self.env, s)
        } else {
            // Unknown/mutated address string (stranger, other-contract) → fresh valid
            // address; distinctness preserves the string-inequality the evaluator uses.
            Address::generate(self.env)
        };
        self.cache.borrow_mut().insert(s.to_string(), addr.clone());
        addr
    }
}

fn arg_to_val(env: &Env, map: &AddrMap, a: &ArgValue) -> Val {
    match a {
        ArgValue::Address(s) => map.get(s).into_val(env),
        ArgValue::I128(v) => v.into_val(env),
        ArgValue::ScvalXdr(_) => {
            // The golden transfer fixture uses only Address/I128 arguments.
            panic!("generated_suite: ScvalXdr arguments need explicit translation");
        }
    }
}

fn signer(map: &AddrMap, s: &SignerSpec) -> Signer {
    match s {
        SignerSpec::Delegated { address } => Signer::Delegated(map.get(address)),
        SignerSpec::External { .. } => panic!("the golden transfer fixture uses delegated signers"),
    }
}

fn signers(env: &Env, map: &AddrMap, list: &[SignerSpec]) -> SVec<Signer> {
    let mut v = SVec::new(env);
    for s in list {
        v.push_back(signer(map, s));
    }
    v
}

fn context_of(env: &Env, map: &AddrMap, inv: &Invocation) -> Context {
    let mut args: SVec<Val> = SVec::new(env);
    for a in &inv.args {
        args.push_back(arg_to_val(env, map, a));
    }
    Context::Contract(ContractContext {
        contract: map.get(&inv.contract),
        fn_name: Symbol::new(env, &inv.fn_name),
        args,
    })
}

struct InstalledWorld {
    env: Env,
    policy: Address,
    account: Address,
    rule_id: u32,
}

fn installed_world(rule_live_signers: &[SignerSpec]) -> InstalledWorld {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = 1_000);
    let policy = env.register(GeneratedPolicy, ());
    let account = env.register(HarnessAccount, ());
    let target = Address::from_str(&env, &fx::golden_token_strkey());
    let live_signers = signers(&env, &AddrMap::new(&env, &account), rule_live_signers);
    let mut policies = Map::new(&env);
    policies.set(policy.clone(), 0u32.into_val(&env));
    let stored_rule = env.as_contract(&account, || {
        add_context_rule(
            &env,
            &ContextRuleType::CallContract(target),
            &soroban_sdk::String::from_str(&env, "sub-transfer"),
            Some(4_223_456),
            &live_signers,
            &policies,
        )
    });

    InstalledWorld {
        env,
        policy,
        account,
        rule_id: stored_rule.id,
    }
}

fn call_count(world: &InstalledWorld) -> Option<u32> {
    world.env.as_contract(&world.policy, || {
        world
            .env
            .storage()
            .persistent()
            .get(&PolicyStorageKey::CallCount(
                world.account.clone(),
                world.rule_id,
            ))
    })
}

fn set_call_count(world: &InstalledWorld, count: Option<u32>) {
    world.env.as_contract(&world.policy, || {
        let key = PolicyStorageKey::CallCount(world.account.clone(), world.rule_id);
        match count {
            None => world.env.storage().persistent().remove(&key),
            Some(value) => world.env.storage().persistent().set(&key, &value),
        }
    });
}

fn authorize(world: &InstalledWorld, cases: &[&Case]) -> Result<(), soroban_sdk::Error> {
    let first = cases.first().expect("authorization needs a context");
    let env = &world.env;
    env.ledger()
        .with_mut(|l| l.sequence_number = first.context.current_ledger.0);
    let map = AddrMap::new(env, &world.account);

    let mut authenticated = Map::new(env);
    for authenticated_signer in &first.context.authenticated_signers {
        authenticated.set(signer(&map, authenticated_signer), Bytes::new(env));
    }
    let payload = AuthPayload {
        signers: authenticated,
        context_rule_ids: SVec::from_iter(env, cases.iter().map(|_| world.rule_id)),
    };
    let auth_contexts = SVec::from_iter(
        env,
        cases
            .iter()
            .map(|case| context_of(env, &map, &case.invocation)),
    );
    let signature_payload: Hash<32> = env.crypto().sha256(&Bytes::new(env));
    // Use the host-managed account invocation. Calling `do_check_auth` inside
    // `as_contract` bypasses the invocation boundary, so a later policy panic can
    // leave an earlier counter write visible to the test even though a real failed
    // authorization would revert it.
    let result = env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
        &world.account,
        &signature_payload.to_bytes(),
        payload.into_val(env),
        &auth_contexts,
    );
    match result {
        Ok(()) => Ok(()),
        Err(Ok(error)) => Err(error),
        Err(Err(error)) => panic!("account invocation failed without a contract error: {error:?}"),
    }
}

fn run_case(case: &Case) -> Result<(), soroban_sdk::Error> {
    let world = installed_world(&case.context.rule_live_signers);
    // Each generated case starts from its named boundary state. The sequence test below
    // instead lets successful authorizations advance the same committed counter.
    set_call_count(&world, case.context.call_count_so_far);
    authorize(&world, &[case])
}

#[test]
fn generated_deny_suite_agrees_with_the_real_contract() {
    let spec = fx::golden_spec();
    assert_eq!(
        spec.spec().rules.len(),
        1,
        "this test replays one policy rule"
    );
    let suite = build_suite(&spec);
    assert!(
        suite.len() > 10,
        "suite should be substantial: {}",
        suite.len()
    );

    assert!(
        suite.iter().all(|case| case
            .invocation
            .args
            .iter()
            .all(|arg| !matches!(arg, ArgValue::ScvalXdr(_)))),
        "the golden fixture gained an ScvalXdr case; add translation before replaying it"
    );

    for case in &suite {
        let result = run_case(case);
        let permitted = result.is_ok();
        assert_eq!(
            permitted, case.expect_permit,
            "DIVERGENCE on '{}' ({:?}): real contract permitted={} but harness expected permit={} (deny code {:?})",
            case.label, case.class, permitted, case.expect_permit, result.err()
        );
    }
}

#[test]
fn generated_golden_denials_preserve_the_expected_reason() {
    let spec = fx::golden_spec();
    let [rule] = spec.spec().rules.as_slice() else {
        panic!("this reason oracle is scoped to the one-rule golden fixture");
    };
    let [call] = rule.allowed_calls.as_slice() else {
        panic!("this reason oracle requires one complete allowed tuple");
    };
    assert_eq!(call.fn_name, "transfer");
    assert!(call.args.iter().all(|arg| matches!(
        arg.constraint,
        Constraint::EqAddress { .. } | Constraint::EqI128 { .. }
    )));
    assert_eq!(rule.authorization.kind, PredicateKind::AnyOf);
    assert!(rule.authorization.strict_signer_set);
    assert_eq!(
        rule.authorization.signers,
        vec![SignerSpec::Delegated {
            address: fx::golden_delegate_strkey(),
        }]
    );
    let [StateSpec::CallCountPerInstallation { max_calls }] = rule.state.as_slice() else {
        panic!("this reason oracle requires one per-installation call cap");
    };

    let mut covered = BTreeSet::new();
    for case in build_suite(&spec) {
        // These expected codes follow from the fixed fixture and one mutation at a
        // time. They are hand-stated here, not obtained from the evaluator or the
        // generated policy. Target, expiry, and unknown-signer cases can be refused
        // by the account before the policy runs, so they are outside this oracle.
        let expected_code = match case.class {
            MutationClass::DifferentFunction => Some(5), // FunctionNotAllowed
            MutationClass::ArgEquality
            | MutationClass::NumericBoundary
            | MutationClass::DifferentAddressArg
            | MutationClass::ArgArity
            | MutationClass::TypeConfusion => Some(6), // NoTupleMatched
            MutationClass::ZeroSigners => Some(1),       // ZeroSigners
            MutationClass::StrictSetMutation => {
                let authenticated = case
                    .context
                    .authenticated_signers
                    .first()
                    .expect("strict-set cases retain the golden delegate");
                if case.context.rule_live_signers.contains(authenticated) {
                    Some(3) // SignerSetDiverged: the delegate still matches a grown live set.
                } else {
                    // The account rejects a swapped set's now-unknown signer first.
                    None
                }
            }
            MutationClass::MissingState => Some(8), // MissingState
            MutationClass::CallCountBoundary
                if case
                    .context
                    .call_count_so_far
                    .is_some_and(|used| used >= *max_calls) =>
            {
                Some(7) // CallCountExceeded
            }
            _ => None,
        };
        let Some(code) = expected_code else { continue };
        assert!(
            !case.expect_permit,
            "{} changed from a denial to a permit in the generated suite",
            case.label
        );
        assert_eq!(
            run_case(&case),
            Err(soroban_sdk::Error::from_contract_error(code)),
            "{} ({:?}) must return policy error {code}",
            case.label,
            case.class
        );
        covered.insert(case.class);
    }
    assert_eq!(
        covered,
        BTreeSet::from([
            MutationClass::DifferentFunction,
            MutationClass::ArgEquality,
            MutationClass::NumericBoundary,
            MutationClass::DifferentAddressArg,
            MutationClass::ArgArity,
            MutationClass::TypeConfusion,
            MutationClass::ZeroSigners,
            MutationClass::StrictSetMutation,
            MutationClass::MissingState,
            MutationClass::CallCountBoundary,
        ]),
        "a fixture change must not silently remove a reason-checked class"
    );
}

#[test]
fn generated_suite_commits_permits_and_rolls_back_a_later_denial() {
    let spec = fx::golden_spec();
    let suite = build_suite(&spec);
    let original = suite
        .iter()
        .find(|case| case.class == MutationClass::Original)
        .expect("the generated suite must contain the recorded call");
    let wrong_function = suite
        .iter()
        .find(|case| case.class == MutationClass::DifferentFunction && !case.expect_permit)
        .expect("the generated suite must contain a denied function mutation");
    let [StateSpec::CallCountPerInstallation { max_calls }] = spec.spec().rules[0].state.as_slice()
    else {
        panic!("the golden fixture must have one call cap");
    };
    assert!(
        *max_calls > 2,
        "the fixture needs room for the multi-context control"
    );

    let world = installed_world(&original.context.rule_live_signers);
    assert_eq!(
        call_count(&world),
        Some(0),
        "install initializes the counter"
    );

    // A successful authorization with two contexts must commit two policy writes. This
    // control also establishes that the second context is reached by the account path.
    assert_eq!(authorize(&world, &[original, original]), Ok(()));
    assert_eq!(call_count(&world), Some(2));

    // Both contexts pass account-side rule matching. The generated policy permits the
    // first, then rejects the changed function in the second. The whole authorization
    // must roll back the first counter increment, rather than consume one call.
    assert_eq!(
        authorize(&world, &[original, wrong_function]),
        Err(soroban_sdk::Error::from_contract_error(5)),
        "the changed function must reach the generated policy and return FunctionNotAllowed"
    );
    assert_eq!(
        call_count(&world),
        Some(2),
        "later denial must roll back prior writes"
    );

    for used in 2..*max_calls {
        assert_eq!(
            authorize(&world, &[original]),
            Ok(()),
            "call {used} must permit"
        );
        assert_eq!(call_count(&world), Some(used + 1));
    }
    assert_eq!(
        authorize(&world, &[original]),
        Err(soroban_sdk::Error::from_contract_error(7)),
        "call N+1 must return CallCountExceeded"
    );
    assert_eq!(
        call_count(&world),
        Some(*max_calls),
        "cap denial must not write"
    );
}
