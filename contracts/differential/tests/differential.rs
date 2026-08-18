//! Differential suite (architecture §4.5): the independently implemented reference
//! evaluator and the REAL generated policy contract (compiled against the audited
//! `stellar-accounts` release, executed in a soroban test env with committed state)
//! must agree on every case — verdict AND deny reason.
//!
//! The evaluator crate never depends on codegen (CI-enforced), so agreement here is
//! evidence, not tautology.

use generated_sub_transfer_r0::{GeneratedPolicy, GeneratedPolicyClient};
use ozpb_evaluator as ev;
use ozpb_policy_spec::{SignerSpec, ValidatedSpec};
use ozpb_synthesizer::fixtures as fx;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{vec as svec, Address, Env, Error, IntoVal, Symbol, Val, Vec as SVec};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

const AMOUNT: i128 = 500_000_000;
const VALID_UNTIL: u32 = 4_223_456;
const MAX_CALLS: u32 = 12;

// --- deny-reason mapping: evaluator reason -> generated PolicyError code -------------

fn expected_code(reason: &ev::DenyReason) -> u32 {
    match reason {
        ev::DenyReason::ZeroSigners => 1,
        ev::DenyReason::PredicateUnsatisfied => 2,
        ev::DenyReason::SignerSetDiverged => 3,
        ev::DenyReason::NoMatchingRule => 4, // TargetMismatch at the policy level
        ev::DenyReason::FunctionNotAllowed => 5,
        ev::DenyReason::NoTupleMatched => 6,
        ev::DenyReason::CallCountExceeded => 7,
        ev::DenyReason::MissingState => 8,
        ev::DenyReason::RuleExpired => 9,
    }
}

// --- world setup ----------------------------------------------------------------------

struct World {
    env: Env,
    client: GeneratedPolicyClient<'static>,
    account: Address,
    token: Address,
    spec: ValidatedSpec,
}

fn setup(install: bool) -> World {
    let env = Env::default();
    env.mock_all_auths();
    let policy = env.register(GeneratedPolicy, ());
    let client = GeneratedPolicyClient::new(&env, &policy);
    let account = Address::from_str(&env, &fx::golden_account_strkey());
    let token = Address::from_str(&env, &fx::golden_token_strkey());
    let spec = fx::golden_spec();
    let w = World {
        env,
        client,
        account,
        token,
        spec,
    };
    if install {
        let rule = w.rule(&[&fx::golden_delegate_strkey()]);
        w.client.install(&0u32, &rule, &w.account);
    }
    w
}

impl World {
    fn signer(&self, strkey: &str) -> Signer {
        Signer::Delegated(Address::from_str(&self.env, strkey))
    }

    fn signers(&self, strkeys: &[&str]) -> SVec<Signer> {
        let mut v = SVec::new(&self.env);
        for s in strkeys {
            v.push_back(self.signer(s));
        }
        v
    }

    fn rule(&self, live_signers: &[&str]) -> ContextRule {
        ContextRule {
            id: 0,
            context_type: ContextRuleType::CallContract(self.token.clone()),
            name: soroban_sdk::String::from_str(&self.env, "sub-transfer"),
            signers: self.signers(live_signers),
            signer_ids: SVec::new(&self.env),
            policies: SVec::new(&self.env),
            policy_ids: SVec::new(&self.env),
            valid_until: Some(VALID_UNTIL),
        }
    }

    fn transfer_ctx(&self, from: &Address, to_strkey: &str, amount: i128) -> Context {
        let to = Address::from_str(&self.env, to_strkey);
        let args: SVec<Val> = svec![
            &self.env,
            from.into_val(&self.env),
            to.into_val(&self.env),
            amount.into_val(&self.env),
        ];
        Context::Contract(ContractContext {
            contract: self.token.clone(),
            fn_name: Symbol::new(&self.env, "transfer"),
            args,
        })
    }

    fn enforce(
        &self,
        ctx: &Context,
        auth_strkeys: &[&str],
        live_strkeys: &[&str],
    ) -> Result<(), u32> {
        let res = self.client.try_enforce(
            ctx,
            &self.signers(auth_strkeys),
            &self.rule(live_strkeys),
            &self.account,
        );
        match res {
            Ok(_) => Ok(()),
            Err(Ok(err)) => Err(code_of(err)),
            Err(Err(e)) => panic!("invoke failure (not a contract error): {e:?}"),
        }
    }
}

fn code_of(err: Error) -> u32 {
    for c in 1..=11u32 {
        if err == Error::from_contract_error(c) {
            return c;
        }
    }
    panic!("unexpected non-policy error: {err:?}");
}

// --- evaluator side -------------------------------------------------------------------

fn spec_signer(strkey: &str) -> SignerSpec {
    SignerSpec::Delegated {
        address: strkey.to_string(),
    }
}

fn eval_ctx(
    smart_account: &str,
    ledger: u32,
    auth: &[&str],
    live: &[&str],
    count: Option<u32>,
) -> ev::EvalContext {
    ev::EvalContext {
        smart_account: smart_account.to_string(),
        current_ledger: ozpb_domain::LedgerSeq(ledger),
        authenticated_signers: auth.iter().map(|s| spec_signer(s)).collect(),
        rule_live_signers: live.iter().map(|s| spec_signer(s)).collect(),
        call_count_so_far: count,
    }
}

fn transfer_inv(
    contract: &str,
    fn_name: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> ev::Invocation {
    ev::Invocation {
        contract: contract.to_string(),
        fn_name: fn_name.to_string(),
        args: vec![
            ev::ArgValue::Address(from.to_string()),
            ev::ArgValue::Address(to.to_string()),
            ev::ArgValue::I128(amount),
        ],
    }
}

/// The heart of the suite: both implementations must agree on verdict and reason.
fn assert_agreement(
    name: &str,
    verdict: ev::Verdict,
    contract_result: Result<(), u32>,
    expect_permit: bool,
) {
    match (&verdict, &contract_result) {
        (ev::Verdict::Permit, Ok(())) => {
            assert!(
                expect_permit,
                "{name}: both permitted but the case expected denial"
            );
        }
        (ev::Verdict::Deny(reason), Err(code)) => {
            assert!(
                !expect_permit,
                "{name}: both denied but the case expected permit"
            );
            assert_eq!(
                expected_code(reason),
                *code,
                "{name}: deny reasons diverged (evaluator: {reason:?}, contract code {code})"
            );
        }
        (ev::Verdict::Indeterminate(reason), _) => {
            panic!("{name}: generated-rule evaluation was indeterminate: {reason:?}")
        }
        (v, r) => panic!("{name}: DIVERGENCE — evaluator {v:?}, contract {r:?}"),
    }
}

// --- shared identities ------------------------------------------------------------------

fn delegate() -> String {
    fx::golden_delegate_strkey()
}
fn stranger() -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey([11u8; 32]))
}
fn account_str() -> String {
    fx::golden_account_strkey()
}
fn token_str() -> String {
    fx::golden_token_strkey()
}
fn merchant_str() -> String {
    fx::golden_merchant_strkey()
}

// ---------------------------------------------------------------------------------------
// The suite
// ---------------------------------------------------------------------------------------

#[test]
fn original_recorded_invocation_permits_in_both() {
    let w = setup(true);
    let d = delegate();
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("original", verdict, contract, true);
}

#[test]
fn zero_signers_denies_in_both() {
    // THE zero-signer hole: policy-bearing rules skip account-side signer validation.
    let w = setup(true);
    let d = delegate();
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("zero-signers", verdict, contract, false);
}

#[test]
fn unrecognized_signer_denies_in_both() {
    let w = setup(true);
    let (d, s) = (delegate(), stranger());
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[&s], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&s], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("stranger-signer", verdict, contract, false);
}

#[test]
fn strict_mode_denies_grown_and_swapped_signer_sets_in_both() {
    // Signer-mutation attack: add_signer must fail closed, not broaden.
    let w = setup(true);
    let (d, s) = (delegate(), stranger());
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);

    let contract = w.enforce(&ctx, &[&d], &[&d, &s]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d, &s], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("strict-grown", verdict, contract, false);

    // Swapped set: the delegate still signs, but the stored rule set changed.
    let w = setup(true);
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[&d], &[&s]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&s], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("strict-swapped", verdict, contract, false);
}

#[test]
fn amount_mutations_deny_in_both() {
    let d = delegate();
    for amount in [AMOUNT + 1, AMOUNT - 1, AMOUNT * 10, 1, 0] {
        let w = setup(true);
        let ctx = w.transfer_ctx(&w.account, &merchant_str(), amount);
        let contract = w.enforce(&ctx, &[&d], &[&d]);
        let verdict = ev::evaluate(
            &w.spec,
            &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
            &transfer_inv(
                &token_str(),
                "transfer",
                &account_str(),
                &merchant_str(),
                amount,
            ),
        );
        assert_agreement(&format!("amount-{amount}"), verdict, contract, false);
    }
}

#[test]
fn recipient_and_sender_mutations_deny_in_both() {
    let d = delegate();
    // Different recipient.
    let w = setup(true);
    let ctx = w.transfer_ctx(&w.account, &stranger(), AMOUNT);
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &stranger(),
            AMOUNT,
        ),
    );
    assert_agreement("recipient", verdict, contract, false);

    // from != SELF.
    let w = setup(true);
    let merchant_addr = Address::from_str(&w.env, &merchant_str());
    let ctx = w.transfer_ctx(&merchant_addr, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &merchant_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("from-not-self", verdict, contract, false);
}

#[test]
fn function_and_target_mutations_deny_in_both() {
    let d = delegate();
    // Different function on the permitted contract.
    let w = setup(true);
    let mut_ctx = {
        let args: SVec<Val> = svec![
            &w.env,
            w.account.into_val(&w.env),
            Address::from_str(&w.env, &merchant_str()).into_val(&w.env),
            AMOUNT.into_val(&w.env),
        ];
        Context::Contract(ContractContext {
            contract: w.token.clone(),
            fn_name: Symbol::new(&w.env, "approve"),
            args,
        })
    };
    let contract = w.enforce(&mut_ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "approve",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("function", verdict, contract, false);

    // Different target contract entirely.
    let w = setup(true);
    let other = format!("{}", stellar_strkey::Contract([13u8; 32]));
    let other_addr = Address::from_str(&w.env, &other);
    let ctx = {
        let args: SVec<Val> = svec![
            &w.env,
            w.account.into_val(&w.env),
            Address::from_str(&w.env, &merchant_str()).into_val(&w.env),
            AMOUNT.into_val(&w.env),
        ];
        Context::Contract(ContractContext {
            contract: other_addr,
            fn_name: Symbol::new(&w.env, "transfer"),
            args,
        })
    };
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
        &transfer_inv(&other, "transfer", &account_str(), &merchant_str(), AMOUNT),
    );
    assert_agreement("target", verdict, contract, false);
}

#[test]
fn arg_arity_and_type_confusion_deny_in_both() {
    let d = delegate();
    // Extra argument.
    let w = setup(true);
    let ctx = {
        let args: SVec<Val> = svec![
            &w.env,
            w.account.into_val(&w.env),
            Address::from_str(&w.env, &merchant_str()).into_val(&w.env),
            AMOUNT.into_val(&w.env),
            1i128.into_val(&w.env),
        ];
        Context::Contract(ContractContext {
            contract: w.token.clone(),
            fn_name: Symbol::new(&w.env, "transfer"),
            args,
        })
    };
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let mut inv = transfer_inv(
        &token_str(),
        "transfer",
        &account_str(),
        &merchant_str(),
        AMOUNT,
    );
    inv.args.push(ev::ArgValue::I128(1));
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
        &inv,
    );
    assert_agreement("extra-arg", verdict, contract, false);

    // i128 where an address is expected.
    let w = setup(true);
    let ctx = {
        let args: SVec<Val> = svec![
            &w.env,
            w.account.into_val(&w.env),
            42i128.into_val(&w.env),
            AMOUNT.into_val(&w.env),
        ];
        Context::Contract(ContractContext {
            contract: w.token.clone(),
            fn_name: Symbol::new(&w.env, "transfer"),
            args,
        })
    };
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let mut inv = transfer_inv(
        &token_str(),
        "transfer",
        &account_str(),
        &merchant_str(),
        AMOUNT,
    );
    inv.args[1] = ev::ArgValue::I128(42);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(0)),
        &inv,
    );
    assert_agreement("type-confusion", verdict, contract, false);
}

#[test]
fn expiry_boundary_agrees_in_both() {
    let d = delegate();
    // One past valid_until: deny.
    let w = setup(true);
    w.env
        .ledger()
        .with_mut(|l| l.sequence_number = VALID_UNTIL + 1);
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), VALID_UNTIL + 1, &[&d], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("expired", verdict, contract, false);

    // Exactly at the boundary: permit.
    let w = setup(true);
    w.env.ledger().with_mut(|l| l.sequence_number = VALID_UNTIL);
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), VALID_UNTIL, &[&d], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("boundary", verdict, contract, true);
}

#[test]
fn missing_state_denies_in_both() {
    // §4.4: enforce never treats missing state as zero (no install ran here).
    let w = setup(false);
    let d = delegate();
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], None),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("missing-state", verdict, contract, false);
}

#[test]
fn lifetime_call_cap_exhausts_in_both_with_committed_state() {
    // Committed-state check: 12 permits, the 13th denies. Stateless simulation could
    // never demonstrate this (§4.5 layer 2).
    let w = setup(true);
    let d = delegate();
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    for i in 0..MAX_CALLS {
        let r = w.enforce(&ctx, &[&d], &[&d]);
        assert_eq!(r, Ok(()), "call {i} within the cap must permit");
    }
    let contract = w.enforce(&ctx, &[&d], &[&d]);
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account_str(), 100, &[&d], &[&d], Some(MAX_CALLS)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account_str(),
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("call-cap", verdict, contract, false);
}

#[test]
fn install_is_the_only_initializer_and_double_install_fails() {
    let w = setup(true);
    let rule = w.rule(&[&delegate()]);
    let res = w.client.try_install(&0u32, &rule, &w.account);
    match res {
        Err(Ok(err)) => assert_eq!(code_of(err), 10, "AlreadyInstalled"),
        other => panic!("double install must fail: {other:?}"),
    }
}

#[test]
fn uninstall_obeys_upstream_lifecycle_and_reinstall_resets_state() {
    let w = setup(false);
    let rule = w.rule(&[&delegate()]);

    match w.client.try_uninstall(&rule, &w.account) {
        Err(Ok(err)) => assert_eq!(code_of(err), 11, "NotInstalled"),
        other => panic!("uninstall before install must fail: {other:?}"),
    }

    w.client.install(&0u32, &rule, &w.account);
    let ctx = w.transfer_ctx(&w.account, &merchant_str(), AMOUNT);
    assert_eq!(w.enforce(&ctx, &[&delegate()], &[&delegate()]), Ok(()));
    w.client.uninstall(&rule, &w.account);
    match w.client.try_uninstall(&rule, &w.account) {
        Err(Ok(err)) => assert_eq!(code_of(err), 11, "NotInstalled"),
        other => panic!("repeated uninstall must fail: {other:?}"),
    }

    // A new installation is allowed and receives a fresh counter.
    w.client.install(&0u32, &rule, &w.account);
    for call in 0..MAX_CALLS {
        assert_eq!(
            w.enforce(&ctx, &[&delegate()], &[&delegate()]),
            Ok(()),
            "reinstalled counter must permit call {call}"
        );
    }
    assert_eq!(
        w.enforce(&ctx, &[&delegate()], &[&delegate()]),
        Err(7),
        "the fresh installation still enforces its own cap"
    );
}

#[test]
fn installation_markers_are_isolated_by_account_and_rule() {
    let w = setup(false);
    let delegate = delegate();
    let rule0 = w.rule(&[&delegate]);
    let mut rule1 = rule0.clone();
    rule1.id = 1;
    let account2 = Address::from_str(&w.env, &format!("{}", stellar_strkey::Contract([9u8; 32])));

    w.client.install(&0u32, &rule0, &w.account);
    w.client.install(&0u32, &rule1, &w.account);
    w.client.install(&0u32, &rule0, &account2);

    // Removing one key must not make either independent installation appear absent.
    w.client.uninstall(&rule0, &w.account);
    for (rule, account) in [(&rule1, &w.account), (&rule0, &account2)] {
        match w.client.try_install(&0u32, rule, account) {
            Err(Ok(err)) => assert_eq!(code_of(err), 10, "AlreadyInstalled"),
            other => panic!("independent installation was disturbed: {other:?}"),
        }
    }
}

#[test]
fn self_marker_is_account_independent_in_both() {
    // The same wasm serves a different account: SELF follows the smart_account param.
    let w = setup(false);
    let d = delegate();
    let account2_str = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let account2 = Address::from_str(&w.env, &account2_str);
    let rule = w.rule(&[&d]);
    w.client.install(&0u32, &rule, &account2);

    let ctx = w.transfer_ctx(&account2, &merchant_str(), AMOUNT);
    let res = w
        .client
        .try_enforce(&ctx, &w.signers(&[&d]), &rule, &account2);
    let contract = match res {
        Ok(_) => Ok(()),
        Err(Ok(err)) => Err(code_of(err)),
        Err(Err(e)) => panic!("invoke failure: {e:?}"),
    };
    let verdict = ev::evaluate(
        &w.spec,
        &eval_ctx(&account2_str, 100, &[&d], &[&d], Some(0)),
        &transfer_inv(
            &token_str(),
            "transfer",
            &account2_str,
            &merchant_str(),
            AMOUNT,
        ),
    );
    assert_agreement("self-independence", verdict, contract, true);
}

/// Our spec limits are not independent choices — they are the account's own limits,
/// restated on the host side. The host workspace cannot depend on `stellar-accounts` (it
/// pins a different `stellar-xdr` line), so this is the only place the two can be compared,
/// and a duplicated digit that silently drifts from an upstream release is exactly the class
/// of bug a version bump introduces.
#[test]
fn spec_limits_match_the_upstream_account_limits() {
    assert_eq!(
        u32::try_from(ozpb_policy_spec::MAX_SIGNERS_PER_RULE).unwrap(),
        stellar_accounts::smart_account::MAX_SIGNERS,
        "MAX_SIGNERS_PER_RULE must equal stellar-accounts MAX_SIGNERS: a spec we accept but \
         the account rejects fails at install time, after the user has reviewed it"
    );
    assert_eq!(
        u32::try_from(ozpb_policy_spec::MAX_POLICIES_PER_RULE).unwrap(),
        stellar_accounts::smart_account::MAX_POLICIES,
        "MAX_POLICIES_PER_RULE must equal stellar-accounts MAX_POLICIES"
    );
}

#[test]
fn committed_golden_source_matches_codegen_output() {
    // The compiled crate in this workspace IS the codegen output — no drift allowed.
    let generated = ozpb_codegen::generate(&fx::golden_spec(), 0, &ozpb_codegen::Pins::default())
        .expect("codegen must succeed");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../golden-transfer-policy");
    for (rel, content) in &generated.files {
        let committed = std::fs::read_to_string(root.join(rel)).expect("golden file exists");
        assert_eq!(&committed, content, "{rel} drifted from codegen output");
    }
}
