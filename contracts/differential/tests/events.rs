//! The generated policy's on-chain trace, against the real compiled contract.
//!
//! A policy that leaves no record of what it installed, permitted or removed is unusable as
//! evidence, which for a tool whose value is auditability is the gap a reviewer leads with. The
//! `Policy` trait's own documentation asks for two of these three events
//! (`stellar-accounts-0.7.2/src/policies/mod.rs:106-111` and `:144-149`) and all three library
//! policies emit on all three entry points, so `enforce` is included by their practice.
//!
//! What cannot be observed this way, stated here so it is not looked for: a **denial**.
//! `panic_with_error!` reverts the invocation, so an event published before it is reverted with it
//! and never becomes an ordinary on-chain event. Events are possible on a permit only, and a
//! denial reason reaches the caller through the error code instead. `a_refusal_publishes_nothing`
//! asserts that rather than leaving it as a remark.
//!
//! Assertions compare the emitted entry against the typed `#[contractevent]` struct through
//! `Event::to_xdr`, which is the form `code-quality.md` prescribes: hand-decoding topics and data
//! field by field is a violation there, and it would also let a wrong topic pass as long as the
//! fields matched.

use generated_sub_transfer_r0::{
    GeneratedPolicy, GeneratedPolicyClient, GeneratedPolicyEnforced, GeneratedPolicyInstalled,
    GeneratedPolicyUninstalled,
};
use ozpb_synthesizer::fixtures as fx;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Events as _;
use soroban_sdk::xdr::{ContractEvent, ContractEventBody, ScVal};
use soroban_sdk::{vec as svec, Address, Env, Event as _, IntoVal, Symbol, Val, Vec as SVec};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

const VALID_UNTIL: u32 = 4_223_456;
/// Compiled into the golden policy.
const MAX_CALLS: u32 = 12;

/// `PolicyError` codes, named so a refusal is asserted by its reason rather than by its failing.
const PREDICATE_UNSATISFIED: u32 = 2;
const ALREADY_INSTALLED: u32 = 10;
const NOT_INSTALLED: u32 = 11;

struct World {
    env: Env,
    policy: Address,
    client: GeneratedPolicyClient<'static>,
    account: Address,
    token: Address,
}

fn setup() -> World {
    let env = Env::default();
    env.mock_all_auths();
    let policy = env.register(GeneratedPolicy, ());
    let client = GeneratedPolicyClient::new(&env, &policy);
    let account = Address::from_str(&env, &fx::golden_account_strkey());
    let token = Address::from_str(&env, &fx::golden_token_strkey());
    World {
        env,
        policy,
        client,
        account,
        token,
    }
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

    /// The same rule under a different id, for asking about an installation that does not exist.
    fn rule_for(&self, id: u32) -> ContextRule {
        ContextRule { id, ..self.rule() }
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

    /// The events this policy emitted **during the most recent invocation**. The test
    /// environment resets its event buffer per top-level call, so this is per-call rather than
    /// cumulative — which is why every assertion below reads it immediately after one call, and
    /// why "a refusal publishes nothing" can be stated as an empty log rather than an unchanged
    /// one. Filtered by contract, so an event from another registered contract could never be
    /// mistaken for one of ours.
    fn emitted(&self) -> Vec<ContractEvent> {
        self.env
            .events()
            .all()
            .filter_by_contract(&self.policy)
            .events()
            .to_vec()
    }

    fn last(&self) -> ContractEvent {
        self.emitted()
            .pop()
            .expect("at least one event must have been emitted")
    }
}

/// The name topic of an event, as the macro derived it from the struct name.
fn topic_of(event: &ContractEvent) -> String {
    let ContractEventBody::V0(body) = &event.body;
    match body
        .topics
        .first()
        .expect("every event carries a name topic")
    {
        ScVal::Symbol(symbol) => symbol.to_string(),
        other => panic!("the first topic must be the event's name symbol, got {other:?}"),
    }
}

#[test]
fn install_permit_and_uninstall_each_leave_a_trace() {
    let w = setup();

    w.client.install(&0u32, &w.rule(), &w.account);
    assert_eq!(
        w.emitted().len(),
        1,
        "install must publish exactly one event"
    );
    assert_eq!(
        w.last(),
        GeneratedPolicyInstalled {
            smart_account: w.account.clone(),
            context_rule_id: 0,
        }
        .to_xdr(&w.env, &w.policy),
        "the installed event must carry the account and the context rule it was installed for"
    );

    w.enforce_once();
    assert_eq!(
        w.emitted().len(),
        1,
        "a permitted call must publish exactly one event"
    );
    assert_eq!(
        w.last(),
        GeneratedPolicyEnforced {
            smart_account: w.account.clone(),
            context: w.permitted_context(),
            context_rule_id: 0,
            // The count *after* the call just spent, which is what makes this a running number
            // rather than a restatement of the compiled-in cap.
            remaining_calls: MAX_CALLS - 1,
        }
        .to_xdr(&w.env, &w.policy),
        "the enforced event must carry the permitted context and the calls left after it"
    );

    w.client.uninstall(&w.rule(), &w.account);
    assert_eq!(
        w.emitted().len(),
        1,
        "uninstall must publish exactly one event"
    );
    assert_eq!(
        w.last(),
        GeneratedPolicyUninstalled {
            smart_account: w.account.clone(),
            context_rule_id: 0,
        }
        .to_xdr(&w.env, &w.policy),
        "the uninstalled event must carry the account and the context rule it was removed from"
    );
}

/// The enforcement event's count follows the counter, including down to zero.
///
/// A `remaining_calls` that reported the cap, or the number already used, would satisfy an
/// assertion about the first call and diverge afterwards — so the walk covers every call the
/// installation has, and the last one reports nothing left.
#[test]
fn the_enforced_event_counts_down_to_zero() {
    let w = setup();
    w.client.install(&0u32, &w.rule(), &w.account);
    for spent in 1..=MAX_CALLS {
        w.enforce_once();
        assert_eq!(
            w.emitted().len(),
            1,
            "call {spent} must publish exactly one event"
        );
        assert_eq!(
            w.last(),
            GeneratedPolicyEnforced {
                smart_account: w.account.clone(),
                context: w.permitted_context(),
                context_rule_id: 0,
                remaining_calls: MAX_CALLS - spent,
            }
            .to_xdr(&w.env, &w.policy),
            "after {spent} of {MAX_CALLS} calls the event must report {} left",
            MAX_CALLS - spent
        );
    }
}

/// A refusal leaves nothing behind, and that is a property rather than an omission.
///
/// "Publish on denial too" is the first thing a reader asks for, so this is the answer: every
/// refusal path is exercised and each one must leave the event log where it found it.
#[test]
fn a_refusal_publishes_nothing() {
    let w = setup();
    w.client.install(&0u32, &w.rule(), &w.account);
    // Non-vacuity: the permitting path *does* publish, so an empty log below means the refusal
    // suppressed it rather than that this policy never publishes anything.
    assert_eq!(w.emitted().len(), 1, "install must publish");

    // Each refusal is asserted by its reason, not merely by failing: a call refused for some
    // other cause would publish nothing either, and would prove nothing about the path meant.
    assert_eq!(
        w.enforce_denied()
            .expect_err("the wrong signer must be refused"),
        soroban_sdk::Error::from_contract_error(PREDICATE_UNSATISFIED),
        "the denied call must be refused for its signer predicate"
    );
    assert!(
        w.emitted().is_empty(),
        "a refused authorization must publish nothing: {:?}",
        w.emitted()
    );

    match w.client.try_install(&0u32, &w.rule(), &w.account) {
        Err(Ok(error)) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(ALREADY_INSTALLED)
        ),
        other => panic!("a second install must be refused: {other:?}"),
    }
    assert!(
        w.emitted().is_empty(),
        "a refused install must publish nothing: {:?}",
        w.emitted()
    );

    match w.client.try_uninstall(&w.rule_for(7), &w.account) {
        Err(Ok(error)) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(NOT_INSTALLED)
        ),
        other => panic!("uninstalling something never installed must be refused: {other:?}"),
    }
    assert!(
        w.emitted().is_empty(),
        "a refused uninstall must publish nothing: {:?}",
        w.emitted()
    );
}

/// The topic symbol each event is published under is the one the emitted docs quote.
///
/// `#[contractevent]` derives the topic from the struct name, and the generated `# Events`
/// sections quote the result. This is what holds those quotes to the artifact: a doc naming a
/// topic the contract does not publish is exactly the kind of prose this project cannot afford,
/// and nothing else in the tree would notice it.
#[test]
fn the_documented_topics_are_the_ones_published() {
    let w = setup();
    let mut topics = Vec::new();
    // Collected after each call, because the environment's event buffer is per-invocation.
    w.client.install(&0u32, &w.rule(), &w.account);
    topics.extend(w.emitted().iter().map(topic_of));
    w.enforce_once();
    topics.extend(w.emitted().iter().map(topic_of));
    w.client.uninstall(&w.rule(), &w.account);
    topics.extend(w.emitted().iter().map(topic_of));

    assert_eq!(
        topics,
        vec![
            "generated_policy_installed".to_string(),
            "generated_policy_enforced".to_string(),
            "generated_policy_uninstalled".to_string(),
        ],
        "the published topics must be the ones the emitted docs quote"
    );
}
