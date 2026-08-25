//! The compiled rule. Its guarantees, its check order and the hash of the
//! codegen input it came from are stated in the crate root.

use soroban_sdk::{
    auth::Context, contract, contracterror, contractevent, contractimpl, contracttype,
    panic_with_error, Address, Env, Symbol, TryFromVal, Val, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ################## ERRORS ##################

/// Every reason this policy can refuse an authorization, an install or an
/// uninstall.
///
/// The numbering is the published deny-reason contract rather than a position
/// in a range: a code identifies one refusal, an independently written
/// reference evaluator asserts the same mapping, and every variant is declared
/// in every generated policy whatever its rule's shape — so a reader can read a
/// code the same way across artifacts.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum PolicyError {
    /// No signer authenticated this authorization. The account defers signer
    /// validation to its policies, so an empty set has to be refused here.
    ZeroSigners = 1,
    /// The authenticated signers do not satisfy the rule's signer predicate.
    PredicateUnsatisfied = 2,
    /// The context rule's live signer set is no longer the one compiled in, so
    /// the grant a reader approved is not the grant being exercised.
    SignerSetDiverged = 3,
    /// The invoked contract is not the one this policy is scoped to.
    TargetMismatch = 4,
    /// The invoked function is not one of the allowed calls, or the
    /// authorization is not a contract invocation at all.
    FunctionNotAllowed = 5,
    /// The arguments satisfy no allowed call tuple: arity, a constraint, or
    /// both.
    NoTupleMatched = 6,
    /// This installation has used every call its cap allows. The count never
    /// resets within an installation.
    CallCountExceeded = 7,
    /// State this policy owns for the (smart account, context rule) is absent.
    /// Missing state denies rather than reading as zero.
    MissingState = 8,
    /// The ledger is past the rule's validity window.
    RuleExpired = 9,
    /// The policy is already installed for this (smart account, context rule).
    AlreadyInstalled = 10,
    /// The policy is not installed for this (smart account, context rule).
    NotInstalled = 11,
}

// ################## STORAGE KEYS ##################

/// Keys for the state this policy owns.
///
/// Every variant is segregated by (smart account, context rule id), which is
/// what lets one deployment serve any number of accounts without their
/// installations observing each other.
#[contracttype]
#[derive(Clone, Debug)]
pub enum PolicyStorageKey {
    /// Installation marker, segregated by (smart account, context rule id).
    Installed(Address, u32),
    /// Call count for one installation. Never resets until `uninstall`.
    CallCount(Address, u32),
}

// ################## CONSTANTS ##################

const TARGET: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
/// Defense in depth: the account also enforces the rule's valid_until.
const VALID_UNTIL_LEDGER: u32 = 4223456;
const MAX_CALLS: u32 = 12;

// ################## EVENTS ##################

/// Emitted when this policy permits an authorization.
///
/// Derives `Clone` alone where the other two events also derive `Debug`, `Eq`
/// and `PartialEq`, because `Context` implements none of those — which is the
/// same reason `SimpleEnforced` and `SpendingLimitEnforced` derive `Clone`
/// alone upstream.
#[contractevent]
#[derive(Clone)]
pub struct GeneratedPolicyEnforced {
    /// The smart account whose authorization was permitted.
    #[topic]
    pub smart_account: Address,
    /// The authorization that was permitted.
    pub context: Context,
    /// The context rule this policy is attached to.
    pub context_rule_id: u32,
    /// Calls this installation may still permit after the one just spent. Zero
    /// means the installation can never permit again.
    pub remaining_calls: u32,
}

/// Emitted when this policy is installed for a context rule of a smart account.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedPolicyInstalled {
    /// The smart account this policy is installed for.
    #[topic]
    pub smart_account: Address,
    /// The context rule this policy is attached to.
    pub context_rule_id: u32,
}

/// Emitted when this policy is removed from a context rule of a smart account.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedPolicyUninstalled {
    /// The smart account this policy is installed for.
    #[topic]
    pub smart_account: Address,
    /// The context rule this policy is attached to.
    pub context_rule_id: u32,
}

// ################## QUERY STATE ##################

/// This rule, compiled to a policy contract.
///
/// One deployment serves any number of smart accounts: everything the rule
/// fixes is a constant in this file, and everything that varies per
/// installation is keyed by (smart account, context rule id). There are no
/// setters and no upgrade entry point, so reconfiguration is
/// remove-and-reinstall — which is what makes the wasm hash a statement about
/// behaviour rather than about a starting state.
#[contract]
pub struct GeneratedPolicy;

#[contractimpl]
impl GeneratedPolicy {
    /// Whether this policy is installed for one context rule of one smart
    /// account.
    ///
    /// `false` for an absent installation rather than a panic: this is a query,
    /// and a missing entry is an answer to it.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule_id` - The context rule to ask about.
    /// * `smart_account` - The smart account to ask about.
    ///
    /// # Notes
    ///
    /// * A successful read extends the lifetime of the entries this policy
    ///   depends on — the same entries, through the same `ttl_target`
    ///   computation, as a permitted call. Extending on read is the library's
    ///   rule for entries a contract owns, so this is a state-changing call,
    ///   cheap but not free, and any caller may make it. The only write it can
    ///   perform is an extension, so paying for one on another account's behalf
    ///   is the whole of what an unauthorized caller can do here.
    /// * The extension is withheld once the call cap is spent, and the counter
    ///   is read for no other reason: an installation that can never permit
    ///   again must stop paying rent, which is what the crate header promises
    ///   and what a read that extended unconditionally would quietly break.
    /// * The target is `ttl_target(e)`, so an unauthenticated read can no more
    ///   carry these entries past VALID_UNTIL_LEDGER than a permitted call can:
    ///   past that ledger every entry point denies, and the extension stops
    ///   there.
    pub fn is_installed(e: &Env, context_rule_id: u32, smart_account: Address) -> bool {
        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule_id);
        if !e.storage().persistent().has(&installed_key) {
            return false;
        }
        let key = PolicyStorageKey::CallCount(smart_account, context_rule_id);
        let remaining = match e.storage().persistent().get::<_, u32>(&key) {
            Some(used) => MAX_CALLS.saturating_sub(used),
            None => 0u32,
        };

        // The `remaining` gate is not a permission check — nothing here decides
        // anything. It is the rent rule: an installation that can never permit again
        // stops paying. Otherwise this keeps the entries the policy depends on, and the
        // contract instance, out of archival.
        if remaining > 0u32 {
            let ttl = ttl_target(e);
            if ttl > 0 {
                e.storage().instance().extend_ttl(ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&installed_key, ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);
            }
        }

        true
    }

    /// Calls this installation may still permit.
    ///
    /// Counts down from the compiled-in cap and never resets: only `uninstall`,
    /// which the smart account alone can call, clears the count.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule_id` - The context rule to ask about.
    /// * `smart_account` - The smart account to ask about.
    ///
    /// # Errors
    ///
    /// * [`PolicyError::MissingState`] - When no installation marker exists for
    ///   this smart account and context rule, or when the marker exists and the
    ///   call counter does not. A count is required setup data, so its absence
    ///   is an error rather than a zero.
    ///
    /// # Notes
    ///
    /// * Extends the same entries `is_installed` does, through the same
    ///   computation, and withholds the extension once the count is spent.
    pub fn remaining_calls(e: &Env, context_rule_id: u32, smart_account: Address) -> u32 {
        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule_id);
        if !e.storage().persistent().has(&installed_key) {
            panic_with_error!(e, PolicyError::MissingState);
        }
        let key = PolicyStorageKey::CallCount(smart_account, context_rule_id);
        let used: u32 = match e.storage().persistent().get(&key) {
            Some(used) => used,
            None => panic_with_error!(e, PolicyError::MissingState),
        };
        let remaining = MAX_CALLS.saturating_sub(used);

        // The `remaining` gate is not a permission check — nothing here decides
        // anything. It is the rent rule: an installation that can never permit again
        // stops paying. Otherwise this keeps the entries the policy depends on, and the
        // contract instance, out of archival.
        if remaining > 0u32 {
            let ttl = ttl_target(e);
            if ttl > 0 {
                e.storage().instance().extend_ttl(ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&installed_key, ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);
            }
        }

        remaining
    }
}

// ################## CHANGE STATE ##################

#[contractimpl]
impl Policy for GeneratedPolicy {
    /// Installation parameters. A generated policy has none — every limit is
    /// compiled in — so this is a placeholder the smart account's `install`
    /// call has to pass something for.
    type AccountParams = u32;

    /// Enforces this policy for one authorization attempt.
    ///
    /// Returning is the permit; every refusal is a panic carrying the code that
    /// names it.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context` - The authorization context being enforced.
    /// * `authenticated_signers` - The signers the smart account has already
    ///   verified. The account defers signer validation to its policies, so
    ///   this list is checked here rather than trusted.
    /// * `context_rule` - The context rule this policy is attached to.
    /// * `smart_account` - The smart account being authorized.
    ///
    /// # Errors
    ///
    /// * [`PolicyError::MissingState`] - When no installation marker exists for
    ///   this smart account and context rule, or when the marker exists and the
    ///   call counter this policy owns does not. Missing state denies rather
    ///   than reading as zero.
    /// * [`PolicyError::RuleExpired`] - When the ledger sequence is past the
    ///   rule's validity window.
    /// * [`PolicyError::ZeroSigners`] - When no signer authenticated this
    ///   authorization.
    /// * [`PolicyError::PredicateUnsatisfied`] - When the authenticated signers
    ///   do not satisfy the rule's signer predicate.
    /// * [`PolicyError::SignerSetDiverged`] - When the context rule's live
    ///   signer set is a different size from the one compiled in, or when a
    ///   compiled-in signer is absent from it. Either way the grant a reader
    ///   approved is not the grant being exercised.
    /// * [`PolicyError::FunctionNotAllowed`] - When the authorization is not a
    ///   contract invocation at all, or when it invokes a function outside the
    ///   allowed calls.
    /// * [`PolicyError::TargetMismatch`] - When the invoked contract is not the
    ///   one this policy is scoped to.
    /// * [`PolicyError::NoTupleMatched`] - When the arguments satisfy no
    ///   allowed call tuple.
    /// * [`PolicyError::CallCountExceeded`] - When this installation has
    ///   already used every call its cap allows.
    ///
    /// # Events
    ///
    /// * topics - `["generated_policy_enforced", smart_account: Address]`
    /// * data - `[context: Context, context_rule_id: u32, remaining_calls:
    ///   u32]`
    ///
    /// # Notes
    ///
    /// * Refusals are ordered: the code a caller sees is the first condition
    ///   that failed, in the order the crate header documents, not an arbitrary
    ///   one of several.
    /// * The call counter is advanced only on the permitting path, and a panic
    ///   anywhere later in the invocation reverts that increment along with
    ///   everything else.
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&installed_key) {
            panic_with_error!(e, PolicyError::MissingState);
        }

        if e.ledger().sequence() > VALID_UNTIL_LEDGER {
            panic_with_error!(e, PolicyError::RuleExpired);
        }

        if authenticated_signers.is_empty() {
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

        let c = match &context {
            Context::Contract(c) => c.clone(),
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

        let key = PolicyStorageKey::CallCount(smart_account.clone(), context_rule.id);
        let count: u32 = match e.storage().persistent().get(&key) {
            Some(c) => c,
            None => panic_with_error!(e, PolicyError::MissingState),
        };
        if count >= MAX_CALLS {
            panic_with_error!(e, PolicyError::CallCountExceeded);
        }
        e.storage().persistent().set(&key, &(count + 1u32));
        let remaining = MAX_CALLS - (count + 1u32);

        // The `remaining` gate is not a permission check — nothing here decides
        // anything. It is the rent rule: an installation that can never permit again
        // stops paying. Otherwise this keeps the entries the policy depends on, and the
        // contract instance, out of archival.
        if remaining > 0u32 {
            let ttl = ttl_target(e);
            if ttl > 0 {
                e.storage().instance().extend_ttl(ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&installed_key, ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);
            }
        }

        GeneratedPolicyEnforced {
            smart_account: smart_account.clone(),
            context,
            context_rule_id: context_rule.id,
            remaining_calls: remaining,
        }
        .publish(e);
    }

    /// Installs this policy for one context rule of one smart account.
    ///
    /// Writes the installation marker and the call counter and extends the
    /// lifetime of the entries this policy depends on. `_install_params` is
    /// accepted and ignored: every limit is compiled in, so there is nothing an
    /// installation could configure.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `_install_params` - Unused; see above.
    /// * `context_rule` - The context rule this policy is being attached to.
    /// * `smart_account` - The smart account installing this policy.
    ///
    /// # Errors
    ///
    /// * [`PolicyError::RuleExpired`] - When the ledger sequence is already
    ///   past the rule's validity window, so the installation could never
    ///   permit anything.
    /// * [`PolicyError::AlreadyInstalled`] - When this (smart account, context
    ///   rule) already carries an installation. Re-installing would be the one
    ///   way to reset the state a rule relies on, so it is refused rather than
    ///   made idempotent.
    ///
    /// # Events
    ///
    /// * topics - `["generated_policy_installed", smart_account: Address]`
    /// * data - `[context_rule_id: u32]`
    fn install(e: &Env, _install_params: u32, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        if e.ledger().sequence() > VALID_UNTIL_LEDGER {
            panic_with_error!(e, PolicyError::RuleExpired);
        }
        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&installed_key) {
            panic_with_error!(e, PolicyError::AlreadyInstalled);
        }
        let key = PolicyStorageKey::CallCount(smart_account.clone(), context_rule.id);
        e.storage().persistent().set(&installed_key, &true);
        e.storage().persistent().set(&key, &0u32);
        let remaining = MAX_CALLS;

        // The `remaining` gate is not a permission check — nothing here decides
        // anything. It is the rent rule: an installation that can never permit again
        // stops paying. Otherwise this keeps the entries the policy depends on, and the
        // contract instance, out of archival.
        if remaining > 0u32 {
            let ttl = ttl_target(e);
            if ttl > 0 {
                e.storage().instance().extend_ttl(ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&installed_key, ttl / 2, ttl);
                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);
            }
        }

        GeneratedPolicyInstalled {
            smart_account: smart_account.clone(),
            context_rule_id: context_rule.id,
        }
        .publish(e);
    }

    /// Removes this policy's own state for one context rule of one smart
    /// account — the installation marker and the call count.
    ///
    /// Extends nothing on the way out: buying rent for entries being removed,
    /// on behalf of an account detaching from this contract, is the one place
    /// where the extension would be spent for nobody.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule` - The context rule this policy is being removed from.
    /// * `smart_account` - The smart account uninstalling this policy.
    ///
    /// # Errors
    ///
    /// * [`PolicyError::NotInstalled`] - When this (smart account, context
    ///   rule) carries no installation.
    ///
    /// # Events
    ///
    /// * topics - `["generated_policy_uninstalled", smart_account: Address]`
    /// * data - `[context_rule_id: u32]`
    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&installed_key) {
            panic_with_error!(e, PolicyError::NotInstalled);
        }
        let key = PolicyStorageKey::CallCount(smart_account.clone(), context_rule.id);
        e.storage().persistent().remove(&key);
        e.storage().persistent().remove(&installed_key);

        GeneratedPolicyUninstalled {
            smart_account: smart_account.clone(),
            context_rule_id: context_rule.id,
        }
        .publish(e);
    }
}

// ################## HELPER FUNCTIONS ##################

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
            if a != Address::from_str(e, "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC")
            {
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

/// Ledgers this policy's own entries should be kept alive for.
///
/// Bounded twice. By the network's rolling `max_ttl()`, because a single
/// extension can never reach further — a distant window is approached across
/// successive calls rather than in one step. And by the rule's own window,
/// because past VALID_UNTIL_LEDGER every entry point denies, so extending
/// beyond it would pay rent for an artifact that can no longer permit anything.
///
/// `saturating_sub` is defense in depth after the explicit expiry checks: later
/// changes cannot turn an already-expired rule into the largest possible
/// extension.
fn ttl_target(e: &Env) -> u32 {
    let remaining = VALID_UNTIL_LEDGER.saturating_sub(e.ledger().sequence());
    let max = e.storage().max_ttl();
    if remaining < max {
        remaining
    } else {
        max
    }
}
