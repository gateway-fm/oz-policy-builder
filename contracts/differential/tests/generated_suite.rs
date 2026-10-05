//! Layer-2 differential for the golden transfer fixture's generated deny suite.
//!
//! `harness::build_suite` derives cases from this fixture's constraints. This test replays
//! every case through the compiled policy in a committed-state Soroban environment and
//! checks its permit/deny verdict against the harness expectation. It covers this fixture
//! and these generated mutations, not every policy or all four dry-run layers.
//!
//! This test alone in the contracts workspace uses the harness. The existing differential
//! tests retain their independent, hand-written cases.

use generated_sub_transfer_r0::contract::{GeneratedPolicy, PolicyStorageKey};
use ozpb_evaluator::{ArgValue, Invocation};
use ozpb_harness::{build_suite, Case};
use ozpb_policy_spec::SignerSpec;
use ozpb_synthesizer::fixtures as fx;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{
    contract, contractimpl, vec as svec, Address, Bytes, Env, IntoVal, Map, Symbol, Val,
    Vec as SVec,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
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

fn run_case(case: &Case) -> Result<(), String> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = 1_000);
    let policy = env.register(GeneratedPolicy, ());
    let account = env.register(HarnessAccount, ());
    let map = AddrMap::new(&env, &account);
    let target = map.get(&fx::golden_token_strkey());
    let live_signers = signers(&env, &map, &case.context.rule_live_signers);
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

    // The account installed the policy through the real add_context_rule path. Adjust
    // committed policy state to the case's boundary value after installation.
    env.as_contract(&policy, || {
        let key = PolicyStorageKey::CallCount(account.clone(), stored_rule.id);
        match case.context.call_count_so_far {
            None => env.storage().persistent().remove(&key),
            Some(n) => {
                env.storage().persistent().set(&key, &n);
            }
        }
    });

    env.ledger()
        .with_mut(|l| l.sequence_number = case.context.current_ledger.0);

    let ctx = context_of(&env, &map, &case.invocation);
    let mut authenticated = Map::new(&env);
    for authenticated_signer in &case.context.authenticated_signers {
        authenticated.set(signer(&map, authenticated_signer), Bytes::new(&env));
    }
    let payload = AuthPayload {
        signers: authenticated,
        context_rule_ids: svec![&env, stored_rule.id],
    };
    let auth_contexts = svec![&env, ctx];
    let signature_payload: Hash<32> = env.crypto().sha256(&Bytes::new(&env));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&account, || {
            do_check_auth(&env, &signature_payload, &payload, &auth_contexts)
        })
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("{error:?}")),
        Err(_) => Err("authorization trapped".to_string()),
    }
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
