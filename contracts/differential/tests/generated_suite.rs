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
use soroban_sdk::xdr::ScErrorType;
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, Env, IntoVal, Map, Symbol, Val, Vec as SVec,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use stellar_accounts::smart_account::{
    add_context_rule, add_policy, do_check_auth, get_context_rule, AuthPayload, ContextRuleType,
    Signer, SmartAccount, SmartAccountError,
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
struct AddrMap {
    env: Env,
    known: Vec<String>,
    cache: RefCell<BTreeMap<String, Address>>,
}

impl AddrMap {
    fn new(env: &Env, account: &Address) -> Self {
        let map = AddrMap {
            env: env.clone(),
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
            Address::from_str(&self.env, s)
        } else {
            // Unknown/mutated address string (stranger, other-contract) → fresh valid
            // address; distinctness preserves the string-inequality the evaluator uses.
            Address::generate(&self.env)
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
    addresses: AddrMap,
    policy: Address,
    account: Address,
    rule_id: u32,
}

fn installed_world(rule_live_signers: &[SignerSpec]) -> InstalledWorld {
    let env = Env::default();
    // The fixture mocks both management setup and delegated-signer authentication.
    // The account and generated policy still execute; digest binding is outside this test.
    env.mock_all_auths();
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = 1_000);
    let policy = env.register(GeneratedPolicy, ());
    let account = env.register(HarnessAccount, ());
    let target = Address::from_str(&env, &fx::golden_token_strkey());
    let addresses = AddrMap::new(&env, &account);
    let live_signers = signers(&env, &addresses, rule_live_signers);
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
        addresses,
        policy,
        account,
        rule_id: stored_rule.id,
    }
}

fn policy_call_count_for_rule(
    world: &InstalledWorld,
    policy: &Address,
    rule_id: u32,
) -> Option<u32> {
    world.env.as_contract(policy, || {
        world
            .env
            .storage()
            .persistent()
            .get(&PolicyStorageKey::CallCount(world.account.clone(), rule_id))
    })
}

fn policy_call_count(world: &InstalledWorld, policy: &Address) -> Option<u32> {
    policy_call_count_for_rule(world, policy, world.rule_id)
}

fn call_count(world: &InstalledWorld) -> Option<u32> {
    policy_call_count(world, &world.policy)
}

fn set_policy_call_count(world: &InstalledWorld, policy: &Address, count: Option<u32>) {
    world.env.as_contract(policy, || {
        let key = PolicyStorageKey::CallCount(world.account.clone(), world.rule_id);
        match count {
            None => world.env.storage().persistent().remove(&key),
            Some(value) => world.env.storage().persistent().set(&key, &value),
        }
    });
}

fn set_call_count(world: &InstalledWorld, count: Option<u32>) {
    set_policy_call_count(world, &world.policy, count);
}

fn authorize_on_rule(
    world: &InstalledWorld,
    cases: &[&Case],
    rule_id: u32,
) -> Result<(), soroban_sdk::Error> {
    let first = cases.first().expect("authorization needs a context");
    let env = &world.env;
    env.ledger()
        .with_mut(|l| l.sequence_number = first.context.current_ledger.0);
    let map = &world.addresses;

    let mut authenticated = Map::new(env);
    for authenticated_signer in &first.context.authenticated_signers {
        authenticated.set(signer(map, authenticated_signer), Bytes::new(env));
    }
    let payload = AuthPayload {
        signers: authenticated,
        context_rule_ids: SVec::from_iter(env, cases.iter().map(|_| rule_id)),
    };
    let auth_contexts = SVec::from_iter(
        env,
        cases
            .iter()
            .map(|case| context_of(env, map, &case.invocation)),
    );
    // Delegated authentication is mocked here, so this placeholder digest does not
    // exercise the signer's digest-bound authorization.
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
        Err(Ok(error)) if error.is_type(ScErrorType::Contract) => Err(error),
        Err(Ok(error)) => panic!("account invocation failed outside the contract: {error:?}"),
        Err(Err(error)) => panic!("account invocation failed without a contract error: {error:?}"),
    }
}

fn authorize(world: &InstalledWorld, cases: &[&Case]) -> Result<(), soroban_sdk::Error> {
    authorize_on_rule(world, cases, world.rule_id)
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
        // generated policy. Account refusals use the pinned account's error numbers.
        let expected_code = match case.class {
            MutationClass::DifferentContract => Some(3002), // UnvalidatedContext
            MutationClass::DifferentFunction => Some(5),    // FunctionNotAllowed
            MutationClass::ArgEquality
            | MutationClass::NumericBoundary
            | MutationClass::DifferentAddressArg
            | MutationClass::ArgArity
            | MutationClass::TypeConfusion => Some(6), // NoTupleMatched
            MutationClass::ZeroSigners => Some(1),          // ZeroSigners
            MutationClass::WrongSigner => Some(3016),       // UnauthorizedSigner
            MutationClass::SignerBoundary
                if !case.expect_permit
                    && case
                        .context
                        .authenticated_signers
                        .iter()
                        .any(|signer| !case.context.rule_live_signers.contains(signer)) =>
            {
                Some(3016) // UnauthorizedSigner for the extra unknown signer.
            }
            MutationClass::StrictSetMutation => {
                let authenticated = case
                    .context
                    .authenticated_signers
                    .first()
                    .expect("strict-set cases retain the golden delegate");
                if case.context.rule_live_signers.contains(authenticated) {
                    Some(3) // SignerSetDiverged: the delegate still matches a grown live set.
                } else {
                    Some(3016) // UnauthorizedSigner for a swapped live signer set.
                }
            }
            MutationClass::TimeBoundary if !case.expect_permit => Some(3002),
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
            MutationClass::DifferentContract,
            MutationClass::DifferentFunction,
            MutationClass::ArgEquality,
            MutationClass::NumericBoundary,
            MutationClass::DifferentAddressArg,
            MutationClass::ArgArity,
            MutationClass::TypeConfusion,
            MutationClass::ZeroSigners,
            MutationClass::WrongSigner,
            MutationClass::SignerBoundary,
            MutationClass::StrictSetMutation,
            MutationClass::TimeBoundary,
            MutationClass::MissingState,
            MutationClass::CallCountBoundary,
        ]),
        "a fixture change must not silently remove a reason-checked class"
    );
}

#[test]
fn unknown_signer_keeps_one_address_across_install_and_authorization() {
    let spec = fx::golden_spec();
    let mut case = build_suite(&spec)
        .into_iter()
        .find(|case| case.class == MutationClass::Original)
        .expect("golden original case");
    let unknown = SignerSpec::Delegated {
        address: format!("{}", stellar_strkey::ed25519::PublicKey([99; 32])),
    };
    case.context.rule_live_signers = vec![unknown.clone()];
    case.context.authenticated_signers = vec![unknown];
    // The account recognizes its installed signer. The generated policy then rejects
    // the predicate, rather than the account rejecting an unrelated address.
    assert_eq!(
        run_case(&case),
        Err(soroban_sdk::Error::from_contract_error(2))
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

#[test]
fn later_policy_denial_rolls_back_an_earlier_policy_counter() {
    // Two instances of the generated contract isolate account-side policy ordering and
    // transaction atomicity. Rule setup uses the upstream storage helper with mocked
    // authorization; this does not exercise management access control or a separate
    // reviewed policy artifact.
    let spec = fx::golden_spec();
    let original = build_suite(&spec)
        .into_iter()
        .find(|case| case.class == MutationClass::Original)
        .expect("the golden suite must contain a permitted recorded call");
    let [StateSpec::CallCountPerInstallation { max_calls }] = spec.spec().rules[0].state.as_slice()
    else {
        panic!("the golden fixture must have one call cap");
    };
    let world = installed_world(&original.context.rule_live_signers);
    let later_policy = world.env.register(GeneratedPolicy, ());
    world.env.as_contract(&world.account, || {
        add_policy(
            &world.env,
            world.rule_id,
            &later_policy,
            0u32.into_val(&world.env),
        )
    });
    let stored_rule = world.env.as_contract(&world.account, || {
        get_context_rule(&world.env, world.rule_id)
    });
    assert_eq!(
        stored_rule.policies,
        SVec::from_array(&world.env, [world.policy.clone(), later_policy.clone()]),
        "the generated policy must execute before the added policy"
    );

    // Control: both installed policy instances see and commit the same permitted call.
    assert_eq!(call_count(&world), Some(0));
    assert_eq!(policy_call_count(&world, &later_policy), Some(0));
    assert_eq!(authorize(&world, &[&original]), Ok(()));
    assert_eq!(call_count(&world), Some(1));
    assert_eq!(policy_call_count(&world, &later_policy), Some(1));

    // Only the later instance is exhausted. It must reject after the earlier one has
    // run, and the host must revert the earlier instance's otherwise-valid write.
    set_policy_call_count(&world, &later_policy, Some(*max_calls));
    assert_eq!(
        authorize(&world, &[&original]),
        Err(soroban_sdk::Error::from_contract_error(7)),
        "the later policy must return CallCountExceeded"
    );
    assert_eq!(
        call_count(&world),
        Some(1),
        "the earlier write must roll back"
    );
    assert_eq!(
        policy_call_count(&world, &later_policy),
        Some(*max_calls),
        "the refusing policy must also retain its committed count"
    );
}

#[test]
fn overlapping_counted_rules_multiply_aggregate_authority() {
    // Risk demonstration for §4.5 and §4.8: an account can carry two context rules
    // using the same generated policy instance. The per-installation cap is keyed
    // by rule ID, so both rule IDs must be considered together before allowing an
    // overlap. The setup bypasses management authorization; this test measures
    // account authorization, not whether the management operation should be allowed.
    let spec = fx::golden_spec();
    let original = build_suite(&spec)
        .into_iter()
        .find(|case| case.class == MutationClass::Original)
        .expect("the golden suite must contain its permitted recorded call");
    let [StateSpec::CallCountPerInstallation { max_calls }] = spec.spec().rules[0].state.as_slice()
    else {
        panic!("the golden fixture must have one per-installation call cap");
    };
    assert!(*max_calls > 0, "the fixture needs a usable counted grant");
    let world = installed_world(&original.context.rule_live_signers);
    let first_rule = world.env.as_contract(&world.account, || {
        get_context_rule(&world.env, world.rule_id)
    });
    let mut policies = Map::new(&world.env);
    policies.set(world.policy.clone(), 0u32.into_val(&world.env));
    let second_rule = world.env.as_contract(&world.account, || {
        add_context_rule(
            &world.env,
            &first_rule.context_type,
            &soroban_sdk::String::from_str(&world.env, "parallel-grant"),
            first_rule.valid_until,
            &first_rule.signers,
            &policies,
        )
    });
    assert_ne!(first_rule.id, second_rule.id);
    assert_eq!(first_rule.policies, second_rule.policies);
    assert_eq!(
        second_rule.policies,
        SVec::from_array(&world.env, [world.policy.clone()]),
        "the second rule must really bind the same generated policy"
    );
    assert_eq!(
        policy_call_count_for_rule(&world, &world.policy, first_rule.id),
        Some(0)
    );
    assert_eq!(
        policy_call_count_for_rule(&world, &world.policy, second_rule.id),
        Some(0)
    );

    // Both selectors authorize the same invocation while installed together. Calling
    // through the host-managed account path keeps rule-ID selection and policy writes
    // in the same transaction boundary.
    for used in 0..*max_calls {
        for id in [first_rule.id, second_rule.id] {
            assert_eq!(
                authorize_on_rule(&world, &[&original], id),
                Ok(()),
                "rule {id} must permit call {used} within its own cap"
            );
            assert_eq!(
                policy_call_count_for_rule(&world, &world.policy, id),
                Some(used + 1)
            );
        }
    }
    assert_eq!(
        u64::from(
            policy_call_count_for_rule(&world, &world.policy, first_rule.id)
                .expect("first counter remains installed")
        ) + u64::from(
            policy_call_count_for_rule(&world, &world.policy, second_rule.id)
                .expect("second counter remains installed")
        ),
        u64::from(*max_calls) * 2,
        "the aggregate permitted calls exceed one installation's cap"
    );
    for id in [first_rule.id, second_rule.id] {
        assert_eq!(
            authorize_on_rule(&world, &[&original], id),
            Err(soroban_sdk::Error::from_contract_error(7)),
            "rule {id} must independently deny call N+1"
        );
        assert_eq!(
            policy_call_count_for_rule(&world, &world.policy, id),
            Some(*max_calls),
        );
    }
}
