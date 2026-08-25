//! State-archival behaviour of the generated policy (architecture §3, conformance §3).
//!
//! A generated policy keeps its call counter in `persistent` storage, and that entry is what
//! makes the per-installation cap unforgeable. If the entry is archived the caller pays for a
//! restore, and a client that assembles a transaction without simulation fails outright — so the
//! policy extends the entry's TTL rather than waiting to be rescued.
//!
//! Two properties are easy to get wrong and both are asserted here.
//!
//! **The extension must be conditional.** `Persistent::extend_ttl(key, threshold, extend_to)` only
//! writes when the current TTL is **at or below** `threshold` — the host's comparison is `<=`
//! (`soroban-env-host` `src/storage.rs:570`), while the SDK's own doc comment says "below" and is
//! wrong. Passing a threshold of `extend_to` would make every authorization pay rent. The no-op
//! direction therefore needs its own test: a suite that only checks "the TTL went up" passes an
//! implementation that extends unconditionally.
//!
//! **The target must not outlive the policy.** Extending past `VALID_UNTIL_LEDGER` buys nothing —
//! every `enforce` past that ledger panics — so the entry is meant to expire with the rule it
//! guards. The target is the smaller of the remaining validity window and the network's rolling
//! `max_ttl()`, and both clamps are exercised.
//!
//! The tests that need a *repeatable* extension lower `max_entry_ttl` so the network limit binds.
//! The reason is worth stating precisely, because it is the justification for that setup. While
//! the validity window is the binding clamp, exactly one extension is due: a fresh entry starts at
//! `min_persistent_entry_ttl`, far below the threshold, so the first permitted call pins
//! `live_until` to `VALID_UNTIL_LEDGER`. After that the entry's TTL and the target decay in step,
//! the TTL never falls back below half the target, and no further extension is ever due. Only when
//! `max_ttl()` binds does the target hold constant while the TTL decays, which is what makes
//! extension recur — roughly once per half of `max_entry_ttl`, indefinitely.
//!
//! Real network values, from `stellar network settings`, since the numbers decide which paths are
//! live in production:
//!
//! | network  | `min_persistent_ttl` | `max_entry_ttl` | threshold | extends at `install`? |
//! |----------|---------------------:|----------------:|----------:|-----------------------|
//! | test env |                4,096 |       6,312,000 | 3,156,000 | yes                   |
//! | testnet  |              120,960 |       3,110,400 | 1,555,200 | yes                   |
//! | mainnet  |            2,073,600 |       3,110,400 | 1,555,200 | **no**                |
//!
//! On Mainnet a fresh persistent entry already exceeds the threshold, so `install`'s extension is a
//! no-op there and the first real extension happens on a permitted call about thirty days later.
//! That is correct rather than a gap — the entry needs nothing at install — but it does mean
//! `install_extends_the_counter_entry_and_the_instance` proves a testnet/test-env behaviour, not a
//! Mainnet one.

use generated_sub_transfer_r0::contract::{
    GeneratedPolicy, GeneratedPolicyClient, PolicyStorageKey,
};
use ozpb_synthesizer::fixtures as fx;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{vec as svec, Address, Env, IntoVal, Symbol, Val, Vec as SVec};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

/// Compiled into the golden policy; mirrored here so the tests can position the ledger
/// relative to the window the artifact actually enforces.
/// `PolicyError::CallCountExceeded` in the generated artifact. Named here so a test asserts the
/// reason a call was refused rather than merely that it was.
const CALL_COUNT_EXCEEDED: u32 = 7;

/// `PolicyError::MissingState`, likewise named so a refusal is asserted by its reason.
const MISSING_STATE: u32 = 8;

/// The per-installation call cap compiled into the golden policy. A constant rather than a local
/// per test: two spellings of the same compiled-in number is how a test starts passing against a
/// policy that no longer has that cap.
const MAX_CALLS: u32 = 12;

const VALID_UNTIL: u32 = 4_223_456;

/// Small enough that the network limit, not the validity window, is the binding clamp — which is
/// what makes a decayed TTL observable at all.
const NARROW_MAX_TTL: u32 = 100_000;

struct World {
    env: Env,
    policy: Address,
    client: GeneratedPolicyClient<'static>,
    account: Address,
    token: Address,
}

/// Registers the policy and installs it at ledger 0. `max_entry_ttl` is applied before install so
/// the first extension already sees the narrowed limit.
fn setup(max_entry_ttl: Option<u32>) -> World {
    let env = Env::default();
    env.mock_all_auths();
    if let Some(max) = max_entry_ttl {
        env.ledger().set_max_entry_ttl(max);
    }
    let policy = env.register(GeneratedPolicy, ());
    let client = GeneratedPolicyClient::new(&env, &policy);
    let account = Address::from_str(&env, &fx::golden_account_strkey());
    let token = Address::from_str(&env, &fx::golden_token_strkey());
    let w = World {
        env,
        policy,
        client,
        account,
        token,
    };
    w.client.install(&0u32, &w.rule(), &w.account);
    w
}

impl World {
    fn rule(&self) -> ContextRule {
        let mut signers = SVec::new(&self.env);
        signers.push_back(Signer::Delegated(Address::from_str(
            &self.env,
            &fx::golden_delegate_strkey(),
        )));
        ContextRule {
            id: 0,
            context_type: ContextRuleType::CallContract(self.token.clone()),
            name: soroban_sdk::String::from_str(&self.env, "sub-transfer"),
            signers,
            signer_ids: SVec::new(&self.env),
            policies: SVec::new(&self.env),
            policy_ids: SVec::new(&self.env),
            valid_until: Some(VALID_UNTIL),
        }
    }

    fn permitted_context(&self) -> Context {
        let to = Address::from_str(&self.env, &fx::golden_merchant_strkey());
        let args: SVec<Val> = svec![
            &self.env,
            self.account.into_val(&self.env),
            to.into_val(&self.env),
            500_000_000i128.into_val(&self.env),
        ];
        Context::Contract(ContractContext {
            contract: self.token.clone(),
            fn_name: Symbol::new(&self.env, "transfer"),
            args,
        })
    }

    fn enforce_once(&self) {
        let mut signers = SVec::new(&self.env);
        signers.push_back(Signer::Delegated(Address::from_str(
            &self.env,
            &fx::golden_delegate_strkey(),
        )));
        self.client.enforce(
            &self.permitted_context(),
            &signers,
            &self.rule(),
            &self.account,
        );
    }

    fn counter_key(&self) -> PolicyStorageKey {
        PolicyStorageKey::CallCount(self.account.clone(), 0)
    }

    fn installed_key(&self) -> PolicyStorageKey {
        PolicyStorageKey::Installed(self.account.clone(), 0)
    }

    fn counter_ttl(&self) -> u32 {
        let key = self.counter_key();
        self.env.as_contract(&self.policy, || {
            self.env.storage().persistent().get_ttl(&key)
        })
    }

    fn installed_ttl(&self) -> u32 {
        let key = self.installed_key();
        self.env.as_contract(&self.policy, || {
            self.env.storage().persistent().get_ttl(&key)
        })
    }

    fn instance_ttl(&self) -> u32 {
        self.env
            .as_contract(&self.policy, || self.env.storage().instance().get_ttl())
    }

    /// The target the policy should be extending to, computed the way the artifact computes it.
    fn expected_target(&self) -> u32 {
        let max = self
            .env
            .as_contract(&self.policy, || self.env.storage().max_ttl());
        let remaining = VALID_UNTIL.saturating_sub(self.env.ledger().sequence());
        remaining.min(max)
    }

    fn advance_to(&self, sequence: u32) {
        self.env.ledger().set_sequence_number(sequence);
    }

    /// A call with the **permitted** signer, returning the error instead of panicking. Needed to
    /// tell "the cap is spent" apart from "something refused this call": a helper that supplies
    /// the wrong signer fails on the signer-set check whatever the counter says.
    fn try_enforce_permitted(&self) -> Result<(), soroban_sdk::Error> {
        let mut signers = SVec::new(&self.env);
        signers.push_back(Signer::Delegated(Address::from_str(
            &self.env,
            &fx::golden_delegate_strkey(),
        )));
        self.client
            .try_enforce(
                &self.permitted_context(),
                &signers,
                &self.rule(),
                &self.account,
            )
            .map(|_| ())
            .map_err(|e| e.expect("a policy error, not a host error"))
    }

    /// A call the policy must refuse: the authenticated signer is not the expected one.
    fn enforce_denied(&self) -> Result<(), soroban_sdk::Error> {
        let mut signers = SVec::new(&self.env);
        signers.push_back(Signer::Delegated(Address::from_str(
            &self.env,
            &fx::golden_merchant_strkey(),
        )));
        self.client
            .try_enforce(
                &self.permitted_context(),
                &signers,
                &self.rule(),
                &self.account,
            )
            .map(|_| ())
            .map_err(|e| e.expect("a policy error, not a host error"))
    }

    /// The fresh-entry TTL this network hands out, read rather than assumed: a hard-coded 4,096
    /// would silently stop discriminating if the SDK default moved.
    fn min_persistent_entry_ttl(&self) -> u32 {
        let mut floor = 0u32;
        self.env.ledger().with_mut(|li| {
            floor = li.min_persistent_entry_ttl;
        });
        floor
    }
}

#[test]
fn install_extends_the_counter_entry_and_the_instance() {
    let w = setup(Some(NARROW_MAX_TTL));
    let target = w.expected_target();

    // A freshly written persistent entry starts at `min_persistent_entry_ttl`, so an unextended
    // install is only distinguishable from an extended one while the target exceeds that floor.
    let floor = w.min_persistent_entry_ttl();
    assert!(
        target > floor,
        "test setup no longer distinguishes a fresh entry from an extended one: \
         target {target}, fresh-entry floor {floor}"
    );
    assert_eq!(
        w.counter_ttl(),
        target,
        "install left the counter entry at its default TTL instead of extending it"
    );
    assert_eq!(
        w.installed_ttl(),
        target,
        "install left the lifecycle marker at its default TTL"
    );
    assert_eq!(
        w.instance_ttl(),
        target,
        "install did not extend the contract instance and code TTL"
    );
}

#[test]
fn enforce_extends_the_counter_when_the_ttl_is_below_the_threshold() {
    let w = setup(Some(NARROW_MAX_TTL));
    let installed = w.counter_ttl();

    // Past the half-window, so the SDK's threshold check must fire.
    w.advance_to(installed / 2 + 1_000);
    let before = w.counter_ttl();
    let target = w.expected_target();
    assert!(
        before < target / 2,
        "setup did not put the TTL below the threshold: {before} vs target {target}"
    );

    w.enforce_once();

    assert_eq!(
        w.counter_ttl(),
        target,
        "enforce did not extend a counter entry whose TTL had decayed below the threshold"
    );
    assert_eq!(
        w.instance_ttl(),
        target,
        "enforce did not extend the instance and code TTL"
    );
}

#[test]
fn enforce_leaves_the_ttl_alone_when_it_is_above_the_threshold() {
    let w = setup(Some(NARROW_MAX_TTL));
    let installed = w.counter_ttl();

    // Comfortably inside the window: above the threshold, below the target. An implementation
    // that extends unconditionally would raise this to the target and fail the assertion.
    w.advance_to(installed / 4);
    let before = w.counter_ttl();
    let target = w.expected_target();
    assert!(
        before > target / 2 && before < target,
        "setup did not put the TTL between the threshold and the target: \
         {before}, target {target}"
    );

    w.enforce_once();

    assert_eq!(
        w.counter_ttl(),
        before,
        "enforce paid for a TTL extension that was not due; every authorization would pay rent"
    );
}

#[test]
fn a_denied_call_extends_nothing() {
    // Pins the cost property: a refused call buys no rent. Worth stating what this does *not*
    // pin, since the obvious reading is wrong. It cannot detect the extension block being hoisted
    // to the top of `enforce`, because a panic reverts the whole invocation including any
    // extension bought before it — which is the same reason hoisting would be pointless. Placement
    // is pinned elsewhere and more strongly: in `install` the counter key does not exist until
    // `set`, and extending first fails with `Error(Storage, MissingValue)`.
    let w = setup(Some(NARROW_MAX_TTL));
    let installed = w.counter_ttl();
    w.advance_to(installed / 2 + 1_000);

    let before = w.counter_ttl();
    let instance_before = w.instance_ttl();
    let target = w.expected_target();
    assert!(
        before < target / 2,
        "setup did not put the TTL below the threshold, so this test cannot discriminate"
    );

    assert!(
        w.enforce_denied().is_err(),
        "the wrong signer must be refused; this test depends on the call reverting"
    );

    assert_eq!(
        w.counter_ttl(),
        before,
        "a denied call extended the counter entry"
    );
    assert_eq!(
        w.instance_ttl(),
        instance_before,
        "a denied call extended the instance and code TTL"
    );
}

#[test]
fn uninstall_extends_nothing() {
    // `uninstall` deliberately buys no rent: the counter is being removed and the account is
    // detaching from the contract. Asserted rather than assumed, because the entry disappears and
    // only the instance TTL is left to observe.
    let w = setup(Some(NARROW_MAX_TTL));
    let installed = w.counter_ttl();
    w.advance_to(installed / 2 + 1_000);
    let instance_before = w.instance_ttl();

    w.client.uninstall(&w.rule(), &w.account);

    assert_eq!(
        w.instance_ttl(),
        instance_before,
        "uninstall extended the instance and code TTL on the way out"
    );
}

#[test]
fn spending_the_last_permitted_call_stops_buying_rent() {
    // The cap is what makes this policy finite, and the extension must know about it. Without the
    // `remaining` gate the final permitted call extends the counter, the instance and the code to
    // the full target at exactly the moment the installation becomes permanently deny-only —
    // paying the largest possible rent for an artifact that can never permit again.
    let w = setup(Some(NARROW_MAX_TTL));
    w.advance_to(w.counter_ttl() / 2 + 1_000);

    // Spend every call but the last; each is still productive, so each may extend.
    for _ in 0..MAX_CALLS - 1 {
        w.enforce_once();
    }

    // Let the TTL decay below the threshold again so a final extension would be visible.
    let target_before_last = w.expected_target();
    w.advance_to(w.env.ledger().sequence() + target_before_last / 2 + 1_000);
    let before = w.counter_ttl();
    let instance_before = w.instance_ttl();
    assert!(
        before < w.expected_target() / 2,
        "setup did not put the TTL below the threshold before the final call"
    );

    w.enforce_once(); // the last permitted call

    assert_eq!(
        w.counter_ttl(),
        before,
        "the final permitted call bought rent for a counter that can never permit again"
    );
    assert_eq!(
        w.instance_ttl(),
        instance_before,
        "the final permitted call bought rent for a policy that can never permit again"
    );

    // And it really was the last one — asserted with the *permitted* signer and on the exact
    // reason. The earlier form called a helper that supplies a different signer, so it refused
    // on the signer set no matter what the counter held, and its disjunction restated an
    // assertion made four lines above: it could not fail.
    let refused = w
        .try_enforce_permitted()
        .expect_err("the cap is spent, so a permitted-signer call must still be refused");
    assert_eq!(
        refused,
        soroban_sdk::Error::from_contract_error(CALL_COUNT_EXCEEDED),
        "refused for some reason other than the spent cap"
    );
}

#[test]
fn the_ttl_target_never_outlives_the_policy_validity_window() {
    // Default `max_entry_ttl` (6_312_000) is larger than the remaining validity window, so the
    // window is the binding clamp and the entry is meant to expire with the rule it guards.
    let w = setup(None);
    let max = w.env.as_contract(&w.policy, || w.env.storage().max_ttl());
    assert!(
        max > VALID_UNTIL,
        "this test only means something while the network limit exceeds the validity window"
    );

    assert_eq!(
        w.counter_ttl(),
        VALID_UNTIL,
        "the counter entry was extended past the ledger after which every enforce panics"
    );
}

#[test]
fn installing_after_expiry_is_rejected_without_writing_state() {
    let env = Env::default();
    env.mock_all_auths();
    let policy = env.register(GeneratedPolicy, ());
    let client = GeneratedPolicyClient::new(&env, &policy);
    let account = Address::from_str(&env, &fx::golden_account_strkey());
    let token = Address::from_str(&env, &fx::golden_token_strkey());
    env.ledger().set_sequence_number(VALID_UNTIL + 10_000);

    let mut signers = SVec::new(&env);
    signers.push_back(Signer::Delegated(Address::from_str(
        &env,
        &fx::golden_delegate_strkey(),
    )));
    let rule = ContextRule {
        id: 0,
        context_type: ContextRuleType::CallContract(token),
        name: soroban_sdk::String::from_str(&env, "sub-transfer"),
        signers,
        signer_ids: SVec::new(&env),
        policies: SVec::new(&env),
        policy_ids: SVec::new(&env),
        valid_until: Some(VALID_UNTIL),
    };

    match client.try_install(&0u32, &rule, &account) {
        Err(Ok(error)) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(9),
            "expired installation must fail with RuleExpired"
        ),
        other => panic!("expired installation must be refused: {other:?}"),
    }
    for key in [
        PolicyStorageKey::Installed(account.clone(), 0),
        PolicyStorageKey::CallCount(account, 0),
    ] {
        assert!(
            !env.as_contract(&policy, || env.storage().persistent().has(&key)),
            "failed installation wrote {key:?}"
        );
    }
}

/// The read-only surface, against the real compiled contract.
///
/// The codegen tests say the two getters are emitted and that neither body extends a TTL; this
/// says what they answer. Both matter, and only this one would notice a getter that compiled,
/// exported, bought no rent and returned the wrong number.
#[test]
fn the_getters_report_the_installation_and_the_calls_left() {
    // Before install, in an env of its own: `setup` installs, and the absent answers are half of
    // what these two functions are for.
    let env = Env::default();
    env.mock_all_auths();
    let policy = env.register(GeneratedPolicy, ());
    let client = GeneratedPolicyClient::new(&env, &policy);
    let account = Address::from_str(&env, &fx::golden_account_strkey());
    assert!(
        !client.is_installed(&0u32, &account),
        "an uninstalled policy must report itself uninstalled"
    );
    // The count is an error rather than a zero — the same fail-closed reading of missing state
    // that `enforce` uses, and the reason `is_installed` exists to answer the boolean instead.
    match client.try_remaining_calls(&0u32, &account) {
        Err(Ok(error)) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(MISSING_STATE),
            "an absent counter must be MissingState, not a zero"
        ),
        other => panic!("remaining_calls on an uninstalled policy must refuse: {other:?}"),
    }

    let w = setup(None);
    assert!(
        w.client.is_installed(&0u32, &w.account),
        "an installed policy must report itself installed"
    );
    assert_eq!(
        w.client.remaining_calls(&0u32, &w.account),
        MAX_CALLS,
        "a fresh installation has its whole cap left"
    );

    // Each permitted call is one off the count, so the getter tracks the counter rather than
    // recomputing something adjacent to it.
    w.enforce_once();
    assert_eq!(w.client.remaining_calls(&0u32, &w.account), MAX_CALLS - 1);
    w.enforce_once();
    assert_eq!(w.client.remaining_calls(&0u32, &w.account), MAX_CALLS - 2);

    // Spend the cap. The count bottoms out at zero rather than wrapping.
    for _ in 2..MAX_CALLS {
        w.enforce_once();
    }
    assert_eq!(
        w.client.remaining_calls(&0u32, &w.account),
        0,
        "a spent installation has nothing left"
    );
    assert_eq!(
        w.try_enforce_permitted(),
        Err(soroban_sdk::Error::from_contract_error(CALL_COUNT_EXCEEDED)),
        "the cap must really be spent for this to be a test about a spent cap"
    );
    assert!(
        w.client.is_installed(&0u32, &w.account),
        "a spent installation is still installed — only uninstall clears it"
    );

    // After uninstall, both go back to their absent answers.
    w.client.uninstall(&w.rule(), &w.account);
    assert!(!w.client.is_installed(&0u32, &w.account));
    match w.client.try_remaining_calls(&0u32, &w.account) {
        Err(Ok(error)) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(MISSING_STATE),
            "uninstall removes the counter, so the count is missing again"
        ),
        other => panic!("remaining_calls after uninstall must refuse: {other:?}"),
    }
}

/// A read buys no rent, on the real compiled contract and at every point in an installation's life.
///
/// The emitter-scan test says neither getter contains `extend_ttl`. This says what that means on
/// the ledger: the three TTLs a permitted call moves are all unmoved by a query, whether the
/// installation is fresh, part-spent or exhausted.
///
/// Measured at a decay below **half** the target, not merely below it. The host extends only when
/// the current TTL has fallen to the threshold the caller passes, and the write paths pass
/// `ttl / 2`; at a shallower decay the host declines the extension on its own and this test would
/// pass whether or not the policy asked for one. That is not hypothetical — it is what happened at
/// 90,000 ledgers in an earlier version of this file, where the marker still had 60,000 of a
/// 100,000 target left: the emitter's guard could be removed with nothing observable changing.
///
/// Non-vacuity comes from the same world: after the reads, one permitted `enforce` moves all three
/// TTLs to the target. Without that, an assertion that nothing moved would hold just as well
/// against a contract that had lost the ability to extend at all.
#[test]
fn a_read_buys_no_rent() {
    // A fresh world per case. Sharing one would let an earlier case's extension reset the decay
    // the next case depends on — which it did: after a non-vacuity `enforce` the marker was five
    // ledgers old, and the threshold assertion below caught it.
    for (label, spent) in [
        ("a fresh installation", 0u32),
        ("a part-spent one", 5),
        ("an exhausted one", MAX_CALLS),
    ] {
        let w = setup(Some(NARROW_MAX_TTL));
        for _ in 0..spent {
            w.enforce_once();
        }
        w.advance_to(NARROW_MAX_TTL * 3 / 5);
        let before = (w.installed_ttl(), w.counter_ttl(), w.instance_ttl());
        assert!(
            before.0 > 0 && before.0 <= w.expected_target() / 2,
            "{label}: the marker must be live and at or below the extension threshold ({} of \
             {}), or the host declines an extension for its own reasons and this proves nothing",
            before.0,
            w.expected_target()
        );

        assert!(w.client.is_installed(&0u32, &w.account));
        assert_eq!(
            (w.installed_ttl(), w.counter_ttl(), w.instance_ttl()),
            before,
            "{label}: `is_installed` must move no TTL"
        );

        assert_eq!(
            w.client.remaining_calls(&0u32, &w.account),
            MAX_CALLS - spent
        );
        assert_eq!(
            (w.installed_ttl(), w.counter_ttl(), w.instance_ttl()),
            before,
            "{label}: `remaining_calls` must move no TTL"
        );

        // Non-vacuity, in the same world and at the same decay: the write path does move them —
        // except on the exhausted installation, which is the one case where the policy has
        // deliberately stopped paying rent and there is no permitted call left to make.
        if spent < MAX_CALLS {
            w.enforce_once();
            let target = w.expected_target();
            assert_eq!(
                (w.installed_ttl(), w.counter_ttl(), w.instance_ttl()),
                (target, target, target),
                "{label}: a permitted call must extend all three, or the reads above were \
                 compared against a contract that cannot extend anything"
            );
        } else {
            assert_eq!(
                w.try_enforce_permitted()
                    .expect_err("the cap is spent, so there is no permitted call left"),
                soroban_sdk::Error::from_contract_error(CALL_COUNT_EXCEEDED),
                "{label}: the non-vacuity check must fail for the cap and not for some other \
                 reason"
            );
        }
    }
}

/// `remaining_calls` refuses an installation whose marker is gone, and says so by its code.
///
/// The function documents `MissingState` for an absent installation; before this it documented
/// that and then read the counter without ever looking at the marker, so the refusal it promised
/// could not happen. The state below cannot arise through the contract's own entry points —
/// `install` writes both entries and `uninstall` removes both — which is the reason to write the
/// marker away by hand rather than the reason not to check for it: the check is what makes the
/// documented refusal real, and what lets the function extend the marker's lifetime without
/// having assumed it exists.
#[test]
fn remaining_calls_refuses_an_installation_whose_marker_is_gone() {
    let w = setup(None);
    assert_eq!(
        w.client.remaining_calls(&0u32, &w.account),
        MAX_CALLS,
        "the installation must answer before its marker is removed, or this proves nothing"
    );

    let installed_key = w.installed_key();
    w.env.as_contract(&w.policy, || {
        w.env.storage().persistent().remove(&installed_key);
    });

    match w.client.try_remaining_calls(&0u32, &w.account) {
        Err(Ok(error)) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(MISSING_STATE),
            "a counter without its marker must refuse as MissingState"
        ),
        other => panic!("reading a counter whose marker is gone must be refused: {other:?}"),
    }
}
