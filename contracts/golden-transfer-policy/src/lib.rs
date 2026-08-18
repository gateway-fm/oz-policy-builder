//! GENERATED POLICY — template family `policy-templates/scope@1`.
//! Normalized codegen input hash: 662ad7a94de0d249461d9e8b2c6525a95ab64f4e46f5ca0abf78479cf6181260
//!
//! DO NOT EDIT BY HAND: any manual change switches this artifact to CUSTOM
//! SOURCE MODE (architecture §4.4) — spec conformance, differential testing,
//! and generated-mode guarantees no longer apply to an edited copy.
//!
//! Check order is the generated-code contract (§4.4): signer predicate first
//! (the OZ account defers signer validation to policies), then strict
//! signer-set, then target/function/tuple scoping, then stateful invariants
//! (missing state denies; the call cap never resets within an installation —
//! only `uninstall`, which the smart account alone can call, clears it).
//! No setters, no upgrade entry point.
//!
//! Storage lifetime is maintained **only while this policy is used**: a permitted
//! call, or `install`, extends the entries it depends on toward the rule's validity
//! window where one is set and the network maximum otherwise — never past either.
//! An installed but idle policy still drifts into archival, and so does one that
//! only ever denies, since a denial reverts the extension along with everything
//! else. First use after a long gap may therefore cost a restore. Once a call cap
//! is spent the policy stops extending entirely: it can never permit again, so it
//! stops paying rent.
#![no_std]

use soroban_sdk::auth::Context;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, panic_with_error};
use soroban_sdk::{Address, Env, Symbol, TryFromVal, Val, Vec};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{ContextRule, Signer};

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum PolicyError {
    ZeroSigners = 1,
    PredicateUnsatisfied = 2,
    SignerSetDiverged = 3,
    TargetMismatch = 4,
    FunctionNotAllowed = 5,
    NoTupleMatched = 6,
    CallCountExceeded = 7,
    MissingState = 8,
    RuleExpired = 9,
    AlreadyInstalled = 10,
}

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    /// Call count for one installation, segregated by (smart account, context rule id).
    /// Never resets while installed; `uninstall` removes it.
    CallCount(Address, u32),
}

const TARGET: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
/// Defense in depth: the account also enforces the rule's valid_until.
const VALID_UNTIL_LEDGER: u32 = 4223456;
const MAX_CALLS: u32 = 12;

fn expected_signers(e: &Env) -> Vec<Signer> {
    soroban_sdk::vec![
        e,
        Signer::Delegated(Address::from_str(
            e,
            "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI"
        )),
    ]
}

fn matched_count(authenticated: &Vec<Signer>, expected: &Vec<Signer>) -> u32 {
    let mut matched: u32 = 0;
    for exp in expected.iter() {
        for got in authenticated.iter() {
            if got == exp {
                matched += 1;
                break;
            }
        }
    }
    matched
}

fn check_call_0(e: &Env, args: &Vec<Val>, smart_account: &Address) -> bool {
    if args.len() != 3u32 {
        return false;
    }
    let Some(v0) = args.get(0u32) else {
        return false;
    };
    match Address::try_from_val(e, &v0) {
        Ok(a) => {
            if *smart_account != a {
                return false;
            }
        }
        Err(_) => return false,
    }
    let Some(v1) = args.get(1u32) else {
        return false;
    };
    match Address::try_from_val(e, &v1) {
        Ok(a) => {
            if a != Address::from_str(
                e,
                "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC",
            ) {
                return false;
            }
        }
        Err(_) => return false,
    }
    let Some(v2) = args.get(2u32) else {
        return false;
    };
    match i128::try_from_val(e, &v2) {
        Ok(x) => {
            if x != 500000000i128 {
                return false;
            }
        }
        Err(_) => return false,
    }
    true
}

#[contract]
pub struct GeneratedPolicy;

#[contractimpl]
impl Policy for GeneratedPolicy {
    type AccountParams = u32;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        if e.ledger().sequence() > VALID_UNTIL_LEDGER {
            panic_with_error!(e, PolicyError::RuleExpired);
        }

        if authenticated_signers.len() == 0 {
            panic_with_error!(e, PolicyError::ZeroSigners);
        }
        let expected = expected_signers(e);
        let matched = matched_count(&authenticated_signers, &expected);
        if matched < 1u32 {
            panic_with_error!(e, PolicyError::PredicateUnsatisfied);
        }

        if context_rule.signers.len() != expected.len() {
            panic_with_error!(e, PolicyError::SignerSetDiverged);
        }
        for exp in expected.iter() {
            let mut found = false;
            for live in context_rule.signers.iter() {
                if live == exp {
                    found = true;
                    break;
                }
            }
            if !found {
                panic_with_error!(e, PolicyError::SignerSetDiverged);
            }
        }

        let c = match context {
            Context::Contract(c) => c,
            _ => panic_with_error!(e, PolicyError::FunctionNotAllowed),
        };
        if c.contract != Address::from_str(e, TARGET) {
            panic_with_error!(e, PolicyError::TargetMismatch);
        }
        let fn_0_ok = c.fn_name == Symbol::new(e, "transfer");
        if !fn_0_ok {
            panic_with_error!(e, PolicyError::FunctionNotAllowed);
        }
        let tuple_ok = fn_0_ok && check_call_0(e, &c.args, &smart_account);
        if !tuple_ok {
            panic_with_error!(e, PolicyError::NoTupleMatched);
        }

        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);
        let count: u32 = match e.storage().persistent().get(&key) {
            Some(c) => c,
            None => panic_with_error!(e, PolicyError::MissingState),
        };
        if count >= MAX_CALLS {
            panic_with_error!(e, PolicyError::CallCountExceeded);
        }
        e.storage().persistent().set(&key, &(count + 1u32));
        let remaining = MAX_CALLS - (count + 1u32);

        // Not a permission check — every decision above is already made. This keeps the
        // entries the policy depends on out of archival while it can still permit something.
        if remaining > 0u32 {
            let ttl = ttl_target(e);
            if ttl > 0 {
                e.storage().instance().extend_ttl(ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);
            }
        }
    }

    fn install(e: &Env, _install_params: u32, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, PolicyError::AlreadyInstalled);
        }
        e.storage().persistent().set(&key, &0u32);
        let remaining = MAX_CALLS;

        // Not a permission check — every decision above is already made. This keeps the
        // entries the policy depends on out of archival while it can still permit something.
        if remaining > 0u32 {
            let ttl = ttl_target(e);
            if ttl > 0 {
                e.storage().instance().extend_ttl(ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);
            }
        }
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);
        e.storage().persistent().remove(&key);
    }
}

/// Ledgers this policy's own entries should be kept alive for.
///
/// Bounded twice. By the network's rolling `max_ttl()`, because a single extension can
/// never reach further — a distant window is approached across successive calls rather
/// than in one step. And by the rule's own window, because past VALID_UNTIL_LEDGER every
/// enforce denies, so extending beyond it would pay rent for an artifact that can no
/// longer permit anything.
///
/// `saturating_sub` is load-bearing: `enforce` rejects an expired rule before reaching
/// here, but `install` has no such check, and a wrapped subtraction would turn an
/// already-expired rule into the largest possible extension.
fn ttl_target(e: &Env) -> u32 {
    let remaining = VALID_UNTIL_LEDGER.saturating_sub(e.ledger().sequence());
    let max = e.storage().max_ttl();
    if remaining < max {
        remaining
    } else {
        max
    }
}
