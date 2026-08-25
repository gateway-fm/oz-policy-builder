//! One permitted call publishes one size of event, whatever it was called with.
//!
//! The enforcement event names the authorization it approved by a SHA-256 digest rather than
//! embedding it, which departs from all three library policies — `SpendingLimitEnforced`,
//! `SimpleEnforced` and `WeightedEnforced` each carry a `Context` field
//! (`stellar-accounts-0.7.2/src/policies/spending_limit.rs:49`, `simple_threshold.rs:62`,
//! `weighted_threshold.rs:78`). This file is why that departure is not cosmetic, and
//! `docs/ECOSYSTEM-CONFORMANCE.md` §15, divergence 9 is the written argument.
//!
//! A `Context::Contract` carries every invocation argument, and a rule that leaves an argument
//! unconstrained puts no ceiling on it. An event that embedded the context would therefore grow
//! without bound on the one path where an event is published at all — a permit — and the failure
//! that produces is the one this project exists to prevent rather than an inefficiency. Mainnet
//! meters the total size of a transaction's contract events at
//! `CONTRACT_EVENTS_SIZE_BYTES` below and the host checks it *after* the call returns, so the
//! publish does not refuse: the invocation the policy has already permitted aborts, carrying
//! `Error(Budget, ExceededLimit)` and no policy code, while the reference evaluator reports
//! permit. Evaluator and artifact disagree, which is the failure mode every gate in this
//! repository exists to make impossible.
//!
//! The Soroswap policy is the artifact under test because it is the committed crate with an
//! unconstrained argument: its `deadline` is a user-widened `AnyValue`
//! (`crates/synthesizer/src/walkthroughs.rs:166`). Only such a position can carry an argument
//! large enough to reach the limit — every other constraint the committed policies use, an exact
//! address, an exact `ScVal`, an `i128` bound, bounds its argument's size as a side effect of
//! bounding its value. This file therefore travels with that crate at the milestone boundary,
//! as `generated_suite.rs` travels with the harness.
//!
//! Written as a sweep over sizes rather than around one admissible value, because the absence of
//! exactly this assertion is what let the defect in. A single value proves the contract survives
//! that value; what is wanted is that the event's size does not depend on the argument's at all,
//! and only a range that crosses the limit says so. Three of the six sizes below are under it and
//! were already publishable — they are the control, and they are what tells a red run apart from
//! a run that fails for an unrelated reason.

use generated_soroswap_swap_r0::contract::{GeneratedPolicy, GeneratedPolicyClient};
use ozpb_evaluator::{ArgValue, EvalContext, Invocation, Verdict};
use ozpb_policy_spec::{Constraint, SignerSpec, ValidatedSpec};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Events as _, Ledger as _};
use soroban_sdk::xdr::{ContractEvent, Limits, ScVal, WriteXdr as _};
use soroban_sdk::{
    vec as svec, Address, Bytes, Env, IntoVal, Symbol, TryFromVal as _, Val, Vec as SVec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

/// Mainnet's ceiling on the total size of the contract events one transaction emits.
///
/// `Env::default()` enforces it without being asked: the SDK installs
/// `InvocationResourceLimits::mainnet()` on every test environment
/// (`soroban-sdk-26.1.0/src/env.rs:719`), where the value is 16,384
/// (`soroban-sdk-26.1.0/src/testutils/cost_estimate.rs:147`). The host compares the accumulated
/// event bytes against it once the top-level call has returned
/// (`soroban-env-host-26.1.3/src/host/invocation_metering.rs:435-439`) and panics with
/// `Error(Budget, ExceededLimit)` — a host error and not a `PolicyError`, which is exactly why a
/// breach cannot be read as a denial.
const CONTRACT_EVENTS_SIZE_BYTES: u32 = 16_384;

/// Serialized sizes of the caller-chosen `deadline`, spanning the limit.
///
/// The first three are publishable with the context embedded and the last three are not — 20,000
/// is the value the defect was first reproduced at, and 65,536 is the largest single value any
/// limit in this project names at all (§14's exact-`ScVal` ceiling, in
/// `docs/ECOSYSTEM-CONFORMANCE.md`). It is not a ceiling *here*: an `AnyValue` position has none,
/// which is the whole reason this file exists. Each number is the length of a `Bytes` argument, so
/// an event embedding it would exceed that length by the rest of the context.
const DEADLINE_SIZES: [u32; 6] = [0, 32, 4_096, 16_000, 20_000, 65_536];

/// Arguments 0 and 1 at the boundary the rule allows: `amount_in` at its cap, `amount_out_min` at
/// its floor. Both are read back from the spec below rather than trusted here.
const AMOUNT_IN: i128 = 1_000_000_000;
const OUT_MIN: i128 = 950_000_000;

/// Well inside the rule's validity window, which the spec states and `world` reads.
const LEDGER: u32 = 100;

struct World {
    env: Env,
    policy: Address,
    client: GeneratedPolicyClient<'static>,
    account: Address,
    router: Address,
    delegate: Address,
    spec: ValidatedSpec,
}

/// A fresh installed policy per size.
///
/// Fresh rather than shared, so nothing accumulates between sizes: the event limit is checked per
/// top-level invocation and the call counter advances per permit, and a single environment would
/// leave both as confounds in a measurement whose whole point is that only the argument changed.
fn world() -> World {
    let spec = ozpb_synthesizer::walkthroughs::soroswap_swap_spec();
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.sequence_number = LEDGER);
    let policy = env.register(GeneratedPolicy, ());
    let client = GeneratedPolicyClient::new(&env, &policy);
    let account = Address::from_str(&env, &spec.spec().smart_account.address);
    let router = Address::from_str(&env, &spec.spec().rules[0].context.contract);
    let delegate = match &spec.spec().rules[0].authorization.signers[0] {
        SignerSpec::Delegated { address } => Address::from_str(&env, address),
        other => panic!("the Soroswap rule authorizes a delegated signer, not {other:?}"),
    };
    let w = World {
        env,
        policy,
        client,
        account,
        router,
        delegate,
        spec,
    };
    assert!(
        LEDGER < w.valid_until(),
        "the sweep must run inside the rule's validity window, or every call denies as expired"
    );
    w.client.install(&0u32, &w.rule(), &w.account);
    w
}

impl World {
    fn valid_until(&self) -> u32 {
        self.spec.spec().rules[0]
            .valid_until
            .as_ref()
            .expect("the Soroswap rule carries a validity window")
            .ledger
            .0
    }

    fn rule(&self) -> ContextRule {
        let mut signers = SVec::new(&self.env);
        signers.push_back(Signer::Delegated(self.delegate.clone()));
        ContextRule {
            id: 0,
            context_type: ContextRuleType::CallContract(self.router.clone()),
            name: soroban_sdk::String::from_str(&self.env, "soroswap-swap"),
            signers,
            signer_ids: SVec::new(&self.env),
            policies: SVec::new(&self.env),
            policy_ids: SVec::new(&self.env),
            valid_until: Some(self.valid_until()),
        }
    }

    /// The whitelisted two-hop route, as a `Val`.
    ///
    /// Its XDR has to equal the constant the policy compares against byte for byte, or the call
    /// denies on `NoTupleMatched` — and then both sides would deny, agree, publish nothing, and
    /// this whole file would pass while measuring an empty event log. `the_swept_call_is_the_one_
    /// the_rule_admits` is the assertion that forbids that reading.
    fn path(&self) -> Val {
        svec![&self.env, 1u32, 2u32].into_val(&self.env)
    }

    /// A permitted swap whose caller-chosen `deadline` serializes to `size` bytes of payload.
    fn swap(&self, size: u32) -> Context {
        let deadline = Bytes::from_slice(&self.env, &vec![0u8; size as usize]);
        let args: SVec<Val> = svec![
            &self.env,
            AMOUNT_IN.into_val(&self.env),
            OUT_MIN.into_val(&self.env),
            self.path(),
            self.account.into_val(&self.env),
            deadline.into_val(&self.env),
        ];
        Context::Contract(ContractContext {
            contract: self.router.clone(),
            fn_name: Symbol::new(&self.env, "swap_exact_tokens_for_tokens"),
            args,
        })
    }

    /// The same call as the evaluator sees it. Every argument is carried across as the exact
    /// `ScVal` the contract will receive, so the two sides cannot be reading different calls.
    fn invocation(&self, context: &Context) -> Invocation {
        let Context::Contract(c) = context else {
            unreachable!("`swap` builds a contract context")
        };
        Invocation {
            contract: self.spec.spec().rules[0].context.contract.clone(),
            fn_name: "swap_exact_tokens_for_tokens".to_string(),
            args: vec![
                ArgValue::I128(AMOUNT_IN),
                ArgValue::I128(OUT_MIN),
                ArgValue::ScvalXdr(self.scval_base64(&self.path())),
                ArgValue::Address(self.spec.spec().smart_account.address.clone()),
                ArgValue::ScvalXdr(
                    self.scval_base64(
                        &c.args.get(4u32).expect("the swap tuple has five arguments"),
                    ),
                ),
            ],
        }
    }

    fn eval_context(&self, call_count_so_far: u32) -> EvalContext {
        let signer = self.spec.spec().rules[0].authorization.signers[0].clone();
        EvalContext {
            smart_account: self.spec.spec().smart_account.address.clone(),
            current_ledger: ozpb_domain::LedgerSeq(LEDGER),
            authenticated_signers: vec![signer.clone()],
            rule_live_signers: vec![signer],
            call_count_so_far: Some(call_count_so_far),
        }
    }

    fn enforce(&self, context: &Context) -> Result<(), soroban_sdk::Error> {
        let mut signers = SVec::new(&self.env);
        signers.push_back(Signer::Delegated(self.delegate.clone()));
        self.client
            .try_enforce(context, &signers, &self.rule(), &self.account)
            .map(|_| ())
            .map_err(|e| e.expect("a policy error, not a host error"))
    }

    fn scval_base64(&self, value: &Val) -> String {
        ScVal::try_from_val(&self.env, value)
            .expect("a Val this file builds converts to an ScVal")
            .to_xdr_base64(Limits::none())
            .expect("an ScVal this file builds serializes under unbounded limits")
    }

    fn emitted(&self) -> Vec<ContractEvent> {
        self.env
            .events()
            .all()
            .filter_by_contract(&self.policy)
            .events()
            .to_vec()
    }
}

fn size_of(event: &ContractEvent) -> u32 {
    event
        .to_xdr(Limits::none())
        .expect("an emitted event serializes")
        .len() as u32
}

/// The swept call is admissible, and by the rule rather than by luck.
///
/// Non-vacuity for both tests below. If the route, the bounds or the account did not match, every
/// size would be refused on `NoTupleMatched`, both implementations would agree on the refusal, and
/// nothing would ever be published — a green sweep over an empty event log. So the two arguments
/// with an exact shape are compared against the spec's own constraints, and the smallest size in
/// the sweep is run end to end and asserted to publish.
#[test]
fn the_swept_call_is_the_one_the_rule_admits() {
    let w = world();
    let args = &w.spec.spec().rules[0].allowed_calls[0].args;

    match &args[2].constraint {
        Constraint::EqScval { xdr_base64 } => assert_eq!(
            &w.scval_base64(&w.path()),
            xdr_base64,
            "the route this file builds must be the exact ScVal the rule whitelists"
        ),
        other => panic!("argument 2 of the Soroswap rule is an exact ScVal, not {other:?}"),
    }
    assert!(
        matches!(&args[4].constraint, Constraint::AnyValue),
        "the deadline must be the unconstrained position, or nothing here can grow: {:?}",
        args[4].constraint
    );
    match &args[0].constraint {
        Constraint::LeI128 { max } => assert_eq!(
            max.parse::<i128>().expect("a decimal i128 bound"),
            AMOUNT_IN,
            "amount_in is swept at its cap"
        ),
        other => panic!("argument 0 of the Soroswap rule is an upper bound, not {other:?}"),
    }
    match &args[1].constraint {
        Constraint::GeI128 { min } => assert_eq!(
            min.parse::<i128>().expect("a decimal i128 bound"),
            OUT_MIN,
            "amount_out_min is swept at its floor"
        ),
        other => panic!("argument 1 of the Soroswap rule is a lower bound, not {other:?}"),
    }

    let context = w.swap(DEADLINE_SIZES[0]);
    w.enforce(&context)
        .expect("the smallest swept call must be permitted");
    assert_eq!(
        w.emitted().len(),
        1,
        "a permitted call must publish exactly one event, or this file measures nothing"
    );
}

/// The invariant: for every argument size, the artifact and the reference evaluator agree.
///
/// This is the assertion whose absence let the defect in. It is not about events — it is the
/// project's central claim, that the compiled policy decides what the independently written
/// evaluator predicts — and an event large enough to breach the transaction's event limit breaks
/// it without touching a single permission check: the evaluator returns `Permit`, the policy
/// reaches its `publish`, and the host then fails the invocation. A verdict comparison is
/// therefore the right shape for this test even though the cause is an event.
#[test]
fn the_artifact_and_the_evaluator_agree_at_every_argument_size() {
    for size in DEADLINE_SIZES {
        let w = world();
        let context = w.swap(size);
        let contract = w.enforce(&context);
        let verdict = ozpb_evaluator::evaluate_generated_rule(
            &w.spec.spec().rules[0],
            &w.eval_context(0),
            &w.invocation(&context),
        );
        match (&verdict, &contract) {
            (Verdict::Permit, Ok(())) => {}
            (verdict, contract) => panic!(
                "deadline of {size} bytes: DIVERGENCE — evaluator {verdict:?}, contract \
                 {contract:?}. Both must permit: every constraint the rule states is satisfied \
                 and the position that grew is the one it leaves unconstrained."
            ),
        }
    }
}

/// The mechanism: the event is one size, and that size is under the limit.
///
/// The test above says the two implementations agree; this says why they can be relied on to keep
/// agreeing at a size nobody thought to sweep. Both halves matter. A constant size that happened
/// to sit above the ceiling would abort every permitted call rather than only the large ones, and
/// a size under the ceiling that still moved with the argument would only push the breach further
/// out.
#[test]
fn the_enforcement_event_is_one_size_whatever_the_call_was() {
    let mut sizes: Vec<(u32, u32)> = Vec::new();
    for size in DEADLINE_SIZES {
        let w = world();
        w.enforce(&w.swap(size))
            .unwrap_or_else(|e| panic!("deadline of {size} bytes must be permitted: {e:?}"));
        let emitted = w.emitted();
        assert_eq!(
            emitted.len(),
            1,
            "deadline of {size} bytes: a permitted call publishes exactly one event"
        );
        sizes.push((size, size_of(&emitted[0])));
    }

    let (_, first) = sizes[0];
    assert!(
        sizes.iter().all(|(_, published)| *published == first),
        "the enforcement event's size must not depend on the argument's: {sizes:?}"
    );
    assert!(
        first < CONTRACT_EVENTS_SIZE_BYTES,
        "a permitted call's event must fit the transaction's event budget: {first} of \
         {CONTRACT_EVENTS_SIZE_BYTES} bytes"
    );
    // The sweep has to be able to breach the limit, or a constant size proves nothing about it.
    // Read from the largest argument actually swept, so widening `DEADLINE_SIZES` cannot leave
    // this claim behind.
    let largest = DEADLINE_SIZES
        .iter()
        .copied()
        .max()
        .expect("the sweep is not empty");
    assert!(
        largest > CONTRACT_EVENTS_SIZE_BYTES,
        "the sweep must cross the event limit ({largest} of {CONTRACT_EVENTS_SIZE_BYTES} bytes), \
         or an event of constant size is constant only below it"
    );
}
