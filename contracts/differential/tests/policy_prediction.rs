//! Compare the legacy prediction model with exact pinned 0.7.2 policy Wasm.
//! Native 0.8 library semantics are deliberately tested as a separate boundary.

use ozpb_evaluator::spending_limit::{
    evaluate_spending_limit, SpendingEntry as ModelEntry, SpendingLimitState, SpendingVerdict,
};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal, Symbol, Val, Vec};
use stellar_accounts::policies::spending_limit::{
    self, SpendingEntry, SpendingLimitData, SpendingLimitStorageKey,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

#[contract]
pub struct ReviewedWindow;
#[contractimpl]
impl ReviewedWindow {
    pub fn enforce(
        e: Env,
        context: Context,
        signers: Vec<Signer>,
        rule: ContextRule,
        account: Address,
    ) {
        spending_limit::enforce(&e, &context, &signers, &rule, &account);
    }
}

fn actual_with_policy(
    state: &SpendingLimitState,
    current: u32,
    amount: i128,
    wasm: Option<&[u8]>,
) -> Result<(), soroban_sdk::Error> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|info| info.sequence_number = current);
    env.cost_estimate().budget().reset_unlimited();
    // The 1,000-entry algorithm boundary exceeds the SDK's default data-entry
    // size limit. Compare policy semantics only; this is not a claim that this
    // synthetic state or its transaction fits network resource limits.
    if state.spending_history.len() == 1000 {
        env.host().set_invocation_resource_limits(None).unwrap();
    }
    let policy = match wasm {
        Some(wasm) => env.register(wasm, ()),
        None => env.register(ReviewedWindow, ()),
    };
    let account = Address::generate(&env);
    let target = Address::generate(&env);
    let delegate = Address::generate(&env);
    let mut history = Vec::new(&env);
    for entry in &state.spending_history {
        history.push_back(SpendingEntry {
            amount: entry.amount,
            ledger_sequence: entry.ledger_sequence,
        });
    }
    env.as_contract(&policy, || {
        env.storage().persistent().set(
            &SpendingLimitStorageKey::AccountContext(account.clone(), 42),
            &SpendingLimitData {
                spending_limit: state.spending_limit,
                period_ledgers: state.period_ledgers,
                spending_history: history,
                cached_total_spent: state.cached_total_spent,
            },
        )
    });
    let signers = soroban_sdk::vec![&env, Signer::Delegated(delegate)];
    let rule = ContextRule {
        id: 42,
        context_type: ContextRuleType::CallContract(target.clone()),
        name: soroban_sdk::String::from_str(&env, "prediction"),
        signers: signers.clone(),
        signer_ids: Vec::new(&env),
        policies: Vec::new(&env),
        policy_ids: Vec::new(&env),
        valid_until: None,
    };
    let args: Vec<Val> = soroban_sdk::vec![
        &env,
        account.clone().into_val(&env),
        target.clone().into_val(&env),
        amount.into_val(&env)
    ];
    let context = Context::Contract(ContractContext {
        contract: target,
        fn_name: Symbol::new(&env, "transfer"),
        args,
    });
    match ReviewedWindowClient::new(&env, &policy).try_enforce(&context, &signers, &rule, &account)
    {
        Ok(Ok(())) => Ok(()),
        Err(Ok(error)) if error.is_type(soroban_sdk::xdr::ScErrorType::Contract) => Err(error),
        other => panic!("policy oracle failed outside a contract refusal: {other:?}"),
    }
}

fn actual(state: &SpendingLimitState, current: u32, amount: i128) -> bool {
    use sha2::{Digest, Sha256};
    let path = std::env::var("OZPB_SPENDING_POLICY_WASM")
        .expect("the verified pinned spending policy Wasm is required");
    let wasm = std::fs::read(path).expect("read pinned spending policy");
    let hash: [u8; 32] = Sha256::digest(&wasm).into();
    assert_eq!(
        hash,
        ozpb_domain::pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM.0
    );
    actual_with_policy(state, current, amount, Some(&wasm)).is_ok()
}

#[test]
#[ignore = "requires exact pinned policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn rolling_window_and_amount_boundaries_agree_with_pinned_policy() {
    for history_ledger in [10, 11, 12] {
        for current in [20, 21, 22] {
            for amount in [-1, 0, 40, 41, 100, 101] {
                let state = SpendingLimitState {
                    spending_limit: 100,
                    period_ledgers: 10,
                    spending_history: vec![ModelEntry {
                        amount: 60,
                        ledger_sequence: history_ledger,
                    }],
                    cached_total_spent: 60,
                };
                let predicted = evaluate_spending_limit(&state, current, amount);
                assert_ne!(predicted, SpendingVerdict::Unsupported);
                assert_eq!(
                    predicted == SpendingVerdict::Permit,
                    actual(&state, current, amount),
                    "ledger {history_ledger}/{current}, amount {amount}"
                );
            }
        }
    }
}

#[test]
#[ignore = "requires exact pinned policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn history_capacity_is_applied_after_upstream_cleanup() {
    let state = SpendingLimitState {
        spending_limit: 100,
        period_ledgers: 10,
        spending_history: vec![
            ModelEntry {
                amount: 0,
                ledger_sequence: 11
            };
            1000
        ],
        cached_total_spent: 0,
    };
    for current in [20, 21] {
        assert_eq!(
            evaluate_spending_limit(&state, current, 0) == SpendingVerdict::Permit,
            actual(&state, current, 0)
        );
    }
}

#[test]
fn current_library_semantics_are_not_the_legacy_policy_model() {
    let state = SpendingLimitState {
        spending_limit: 100,
        period_ledgers: 10,
        spending_history: vec![
            ModelEntry {
                amount: 0,
                ledger_sequence: 11
            };
            815
        ],
        cached_total_spent: 0,
    };
    // 0.8 caps reachable history at 815; the recognized 0.7.2 policy caps at 1000.
    assert_eq!(
        evaluate_spending_limit(&state, 20, 1),
        SpendingVerdict::Permit
    );
    assert_eq!(
        actual_with_policy(&state, 20, 1, None),
        Err(soroban_sdk::Error::from_contract_error(3224)),
        "the native helper must return HistoryCapacityExceeded, not a host resource failure"
    );
    let state = SpendingLimitState {
        spending_history: vec![ModelEntry {
            amount: 101,
            ledger_sequence: 11,
        }],
        cached_total_spent: 101,
        ..state
    };
    // 0.8 permits zero transfers before checking a lowered, already exceeded budget.
    // Recognition of the old Wasm must continue using its own stricter prediction.
    assert_eq!(
        evaluate_spending_limit(&state, 20, 0),
        SpendingVerdict::Deny
    );
    assert!(actual_with_policy(&state, 20, 0, None).is_ok());
}
