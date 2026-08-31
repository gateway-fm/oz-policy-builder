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

use generated_sub_transfer_r0::contract::{
    GeneratedPolicy, GeneratedPolicyClient, GeneratedPolicyEnforced, GeneratedPolicyInstalled,
    GeneratedPolicyUninstalled,
};
use ozpb_synthesizer::fixtures as fx;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Events as _;
use soroban_sdk::xdr::{ContractEvent, ContractEventBody, ScVal};
use soroban_sdk::{
    vec as svec, Address, BytesN, Env, Event as _, IntoVal, Symbol, Val, Vec as SVec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

const VALID_UNTIL: u32 = 4_223_456;
/// Compiled into the golden policy.
const MAX_CALLS: u32 = 12;

/// `PolicyError` codes, named so a refusal is asserted by its reason rather than by its failing.
const PREDICATE_UNSATISFIED: u32 = 2;
const CALL_COUNT_EXCEEDED: u32 = 7;
const MISSING_STATE: u32 = 8;
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

    /// The digest the enforcement event must carry for a permitted context.
    ///
    /// SHA-256 over the context's XDR, taken with the host workspace's `sha2`
    /// (`ozpb_domain::sha256`) rather than with the soroban host's `Crypto::sha256` that the
    /// contract calls. The contract's own function would make every assertion below a
    /// restatement of the thing under test; two implementations of the same claim is what makes
    /// it an assertion. The serialization is still the host's, because that is what the digest
    /// is *of* — `ToXdr` is spelled out rather than imported so that it cannot shadow
    /// `Event::to_xdr`, which this file also uses.
    fn expected_context_hash(&self, context: &Context) -> BytesN<32> {
        let xdr: Vec<u8> = soroban_sdk::xdr::ToXdr::to_xdr(context.clone(), &self.env)
            .iter()
            .collect();
        BytesN::from_array(&self.env, &ozpb_domain::sha256(&xdr).0)
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

    /// A call with the **permitted** signer, returning the error instead of panicking.
    ///
    /// Needed wherever the refusal under test is not the signer check: a helper that supplies the
    /// wrong signer refuses on the predicate whatever the counter or the marker says, so it would
    /// report an empty event log for the wrong reason.
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
            context_hash: w.expected_context_hash(&w.permitted_context()),
            context_rule_id: 0,
            // The count *after* the call just spent, which is what makes this a running number
            // rather than a restatement of the compiled-in cap.
            remaining_calls: MAX_CALLS - 1,
        }
        .to_xdr(&w.env, &w.policy),
        "the enforced event must name the permitted context and the calls left after it"
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
                context_hash: w.expected_context_hash(&w.permitted_context()),
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
/// "Publish on denial too" is the first thing a reader asks for, so this is the answer: a refusal
/// leaves the event log where it found it.
///
/// Five refusals, not the twelve `panic_with_error!` sites the artifact has, and the reason is
/// worth stating rather than leaving as an apparent gap. The mechanism is uniform and is the
/// host's, not ours: `panic_with_error!` reverts the invocation, so an event published before it
/// is reverted with it. What varies between sites is therefore not whether the log is cleared but
/// how much work preceded the panic — so the five are chosen along that axis. One per entry
/// point, each a different code, plus the two `enforce` refusals at the extremes of its check
/// order: `MissingState`, which is the first thing it tests, and `CallCountExceeded`, which is
/// the last check before the counter is written and the event published. The full deny-reason
/// coverage — every code, against an independently written reference evaluator — is
/// `differential.rs`; this file is about the event log.
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

    // The far end of `enforce`'s check order: the counter is read, compared against the cap and
    // found spent, so this is the refusal with the most work behind it — and the one immediately
    // before the write-and-publish pair. A revert that stopped short of the event would show up
    // here or nowhere.
    for _ in 0..MAX_CALLS {
        w.enforce_once();
    }
    assert_eq!(
        w.emitted().len(),
        1,
        "the last permitted call must still publish, or the cap was reached early"
    );
    match w.try_enforce_permitted() {
        Err(error) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(CALL_COUNT_EXCEEDED),
            "the call past the cap must be refused for the cap"
        ),
        Ok(()) => panic!("a call past the cap must be refused"),
    }
    assert!(
        w.emitted().is_empty(),
        "a call refused for the spent cap must publish nothing: {:?}",
        w.emitted()
    );

    // The near end: no installation at all, which `enforce` tests before anything else. A fresh
    // world, because the one above is installed.
    let fresh = setup();
    match fresh.try_enforce_permitted() {
        Err(error) => assert_eq!(
            error,
            soroban_sdk::Error::from_contract_error(MISSING_STATE),
            "an enforce with no installation must be refused for the missing state"
        ),
        Ok(()) => panic!("an enforce with no installation must be refused"),
    }
    assert!(
        fresh.emitted().is_empty(),
        "an enforce refused for missing state must publish nothing: {:?}",
        fresh.emitted()
    );
}

/// What one event costs on the wire, measured rather than described.
///
/// §6 of the conformance record answered "why publish at all" with the artifact's growth in
/// bytes, which is the wrong quantity: the objection it answers is about what every permitted
/// call pays, and a wasm is paid for once. The fee-relevant number is the serialized size of the
/// event that lands in the transaction's metadata, so that is what this records.
///
/// Recorded as an exact assertion, not a bound. These are three fixed structs — the sizes move
/// only if a field is added, removed or retyped, and then the number here has to move with it,
/// which is the point. The enforcement event is the one that recurs; the other two happen once
/// per installation.
///
/// One number is enough for the enforcement event because all four of its fields are
/// fixed-width: it names the authorization by a 32-byte digest rather than embedding it, so the
/// size does not depend on what the call was. Here that is assumed rather than swept: the sweep
/// over a range of argument sizes is `event_payload.rs`, which exercises a Soroswap call and is
/// therefore later-milestone evidence. That sweep is what validates the assumption this test
/// rests on; the two do not stand or fall together, because this one pins a single fixture. An
/// event that had become size-dependent could still measure 264 bytes for this fixture and pass
/// here while the sweep fails, and a new fixed-width field moves this number while leaving the
/// sweep green. Where only this test is present, the assumption is stated and not proven.
#[test]
fn an_event_costs_what_the_conformance_record_says_it_costs() {
    use soroban_sdk::xdr::WriteXdr as _;

    let w = setup();
    let size_of = |event: &ContractEvent| {
        event
            .to_xdr(soroban_sdk::xdr::Limits::none())
            .expect("an emitted event must serialize")
            .len()
    };

    w.client.install(&0u32, &w.rule(), &w.account);
    let installed = size_of(&w.last());
    w.enforce_once();
    let enforced = size_of(&w.last());
    w.client.uninstall(&w.rule(), &w.account);
    let uninstalled = size_of(&w.last());

    assert_eq!(
        (installed, enforced, uninstalled),
        (172, 264, 172),
        "the serialized size of an event is what a permitted call pays for observability; if this \
         moved, an event's shape changed and §6 of docs/ECOSYSTEM-CONFORMANCE.md is now quoting \
         the wrong number"
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
