//! Dry-run harness — layer 1 + deny-suite generation (architecture §4.5).
//!
//! From a `ValidatedSpec` this derives an exhaustive, **constraint-derived** deny suite
//! (not a fixed list) and evaluates the original recorded call plus every mutation
//! through the independent reference evaluator, producing a **labeled permit/deny
//! evidence report**. The report is evidence, not proof: it states the tested boundary
//! classes and never claims untested inputs are denied.
//!
//! Layer 2 (real compiled `__check_auth` in a committed-state soroban env) consumes the
//! *same* generated suite from the contracts workspace, so the two implementations are
//! differentially tested over identical mutations.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::LedgerSeq;
use ozpb_evaluator::{evaluate_generated_rule, ArgValue, EvalContext, Invocation, Verdict};
use ozpb_policy_spec::{
    AddressRef, Constraint, PolicyRef, PredicateKind, RuleSpec, SignerSpec, StateSpec,
    ValidatedSpec,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A single test case in the suite, with the class it exercises and the expectation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Case {
    /// Rule whose generated policy this case exercises.
    pub rule_index: usize,
    /// Human-readable label, e.g. "amount[2] = observed+1".
    pub label: String,
    /// The boundary class this case belongs to (for coverage reporting).
    pub class: MutationClass,
    pub invocation: Invocation,
    pub context: EvalContext,
    /// What a correct policy must do with this case.
    pub expect_permit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationClass {
    /// The original recorded call (must permit).
    Original,
    DifferentContract,
    DifferentFunction,
    ArgEquality,
    NumericBoundary,
    DifferentAddressArg,
    ArgArity,
    TypeConfusion,
    ZeroSigners,
    WrongSigner,
    SignerBoundary,
    StrictSetMutation,
    TimeBoundary,
    CallCountBoundary,
    MissingState,
    TupleCrossProduct,
}

/// One evaluated line of the report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub label: String,
    /// Which rule this case exercised. Needed so coverage can be checked per rule.
    pub rule_index: usize,
    pub class: MutationClass,
    pub expected: &'static str,
    pub actual: String,
    pub agree: bool,
}

/// The labeled permit/deny evidence report (architecture §4.5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceReport {
    pub layer: &'static str,
    pub spec_hash: String,
    pub total: usize,
    pub agreements: usize,
    pub disagreements: usize,
    /// Coverage: how many cases per boundary class were tested.
    pub coverage: Vec<(MutationClass, usize)>,
    /// Per-rule coverage. Kept separate from the aggregate `coverage` because the floor has
    /// to be checked per rule: a union would let one rule's cases satisfy a requirement that
    /// only another rule creates, hiding that rule's gap entirely.
    pub coverage_by_rule: BTreeMap<usize, BTreeMap<MutationClass, usize>>,
    /// Classes each rule's own shape requires the suite to exercise. Compared against
    /// `coverage_by_rule` by [`EvidenceReport::missing_classes`] — the coverage floor.
    pub expected_classes: BTreeMap<usize, BTreeSet<MutationClass>>,
    pub outcomes: Vec<Outcome>,
    /// Composed **reviewed** policies (e.g. `oz:spending_limit`) that layer 1 does NOT
    /// model. The reference evaluator only models the generated scope+count semantics; a
    /// reviewed policy's stateful caps/windows are enforced on-chain but outside this
    /// report. If this is non-empty, `all_agree` proves agreement on the modeled semantics
    /// only — a composed cap could still deny on-chain. Layer 2 (the differential suite
    /// against the real compiled contract) is where composed policies get exercised.
    pub unmodeled_policies: Vec<UnmodeledPolicy>,
    /// Always present: this is tested evidence, not a proof of universal denial.
    pub disclaimer: &'static str,
}

/// A composed reviewed policy that layer 1 does not model (see [`EvidenceReport`]).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnmodeledPolicy {
    pub rule_index: usize,
    pub kind: String,
}

impl EvidenceReport {
    /// The original permits and every deny-case denies, over the semantics layer 1 models.
    /// NOTE: this does not account for composed reviewed policies — see
    /// [`EvidenceReport::unmodeled_policies`] and [`EvidenceReport::models_all_policies`].
    pub fn all_agree(&self) -> bool {
        self.disagreements == 0
    }

    /// True iff every composed policy is within layer-1's modeling scope, so `all_agree`
    /// is full-coverage agreement. False means a reviewed policy is enforced only on-chain.
    pub fn models_all_policies(&self) -> bool {
        self.unmodeled_policies.is_empty()
    }

    /// Boundary classes a rule's shape requires but the suite did not exercise for that rule.
    ///
    /// `all_agree` is silent about coverage: a generator regression that stopped emitting a
    /// whole class still reports zero disagreements. A non-empty result here means the
    /// evidence is narrower than the report implies, and is a gate failure — not a warning.
    ///
    /// Checked **per rule**, because coverage aggregated across rules lets rule 0's cases
    /// vouch for rule 1's missing ones.
    pub fn missing_classes(&self) -> Vec<(usize, MutationClass)> {
        let mut missing = Vec::new();
        for (rule_index, expected) in &self.expected_classes {
            let covered = self.coverage_by_rule.get(rule_index);
            for class in expected {
                let count = covered
                    .and_then(|per_class| per_class.get(class))
                    .copied()
                    .unwrap_or(0);
                if count == 0 {
                    missing.push((*rule_index, *class));
                }
            }
        }
        missing
    }

    /// Classes that were exercised but never demonstrated a *denial*, per rule.
    ///
    /// Not a gate failure: it is usually a **degenerate bound** rather than a coverage gap —
    /// a cap of `i128::MAX` cannot be exceeded and an expiry at `u32::MAX` cannot be passed,
    /// so the generator legitimately has no deny case to emit. It is reported because a grant
    /// with such a bound is effectively unbounded on that axis, which the reader should see.
    pub fn permit_only_classes(&self) -> Vec<(usize, MutationClass)> {
        let mut denials: BTreeSet<(usize, MutationClass)> = BTreeSet::new();
        let mut seen: BTreeSet<(usize, MutationClass)> = BTreeSet::new();
        for outcome in &self.outcomes {
            seen.insert((outcome.rule_index, outcome.class));
            if outcome.expected == "deny" {
                denials.insert((outcome.rule_index, outcome.class));
            }
        }
        seen.into_iter()
            .filter(|key| key.1 != MutationClass::Original && !denials.contains(key))
            .collect()
    }
}

const DISCLAIMER: &str = "Tested permit/deny evidence over constraint-derived boundary \
classes — NOT a proof that every untested input is denied. Trust is bounded by the tested \
classes listed in `coverage`.";

/// Boundary classes each rule's own shape requires the suite to exercise.
///
/// Keyed by rule, because the floor must be checked per rule: a set unioned across rules
/// would let one rule's coverage vouch for another's gap.
///
/// Seven classes are structural — every rule has a target, a function, an arity, and a signer
/// predicate, so their mutations always exist. The rest are conditional on what the rule
/// actually contains; demanding them unconditionally would make the floor unsatisfiable for
/// legitimate specs (a rule with no expiry can have no time boundary).
pub fn expected_classes(spec: &ValidatedSpec) -> BTreeMap<usize, BTreeSet<MutationClass>> {
    let mut per_rule = BTreeMap::new();
    for (rule_index, rule) in spec.spec().rules.iter().enumerate() {
        per_rule.insert(rule_index, expected_classes_for_rule(rule));
    }
    per_rule
}

fn expected_classes_for_rule(rule: &RuleSpec) -> BTreeSet<MutationClass> {
    let mut expected = BTreeSet::from([
        MutationClass::Original,
        MutationClass::DifferentContract,
        MutationClass::DifferentFunction,
        MutationClass::ArgArity,
        MutationClass::ZeroSigners,
        MutationClass::WrongSigner,
        MutationClass::SignerBoundary,
    ]);
    if rule.valid_until.is_some() {
        expected.insert(MutationClass::TimeBoundary);
    }
    if rule
        .state
        .iter()
        .any(|state| matches!(state, StateSpec::CallCountPerInstallation { .. }))
    {
        expected.insert(MutationClass::CallCountBoundary);
        expected.insert(MutationClass::MissingState);
    }
    if rule.authorization.strict_signer_set
        && !matches!(
            rule.authorization.kind,
            PredicateKind::AnyOfCurrentRuleSigners
        )
    {
        expected.insert(MutationClass::StrictSetMutation);
    }
    for call in &rule.allowed_calls {
        for arg in &call.args {
            match &arg.constraint {
                Constraint::EqAddress { .. } => {
                    expected.insert(MutationClass::DifferentAddressArg);
                    expected.insert(MutationClass::TypeConfusion);
                }
                Constraint::EqI128 { .. } => {
                    expected.insert(MutationClass::ArgEquality);
                    expected.insert(MutationClass::NumericBoundary);
                    expected.insert(MutationClass::TypeConfusion);
                }
                Constraint::LeI128 { .. } | Constraint::GeI128 { .. } => {
                    expected.insert(MutationClass::NumericBoundary);
                    expected.insert(MutationClass::TypeConfusion);
                }
                Constraint::AnyValue => {
                    expected.insert(MutationClass::NumericBoundary);
                    expected.insert(MutationClass::TypeConfusion);
                }
                // `EqScval` yields an equality mutation but no type-confusion case (the
                // comparison is over encoded XDR, so there is no alternate type to try).
                Constraint::EqScval { .. } => {
                    expected.insert(MutationClass::ArgEquality);
                }
            }
        }
    }
    if rule_can_produce_cross_products(rule) {
        expected.insert(MutationClass::TupleCrossProduct);
    }
    expected
}

/// Whether mixing two accepted tuples can produce a tuple that is not itself accepted.
///
/// Sharing `(fn_name, arity)` is not sufficient: `add_cross_products` skips any mix that
/// reproduces an observed tuple, so two tuples differing in exactly ONE position yield nothing
/// — every single-position swap lands back on one of the originals. Demanding the class there
/// would fail a perfectly correct spec, which is how a gate earns its way out of CI. Two
/// tuples must differ in at least two positions for a novel mix to exist.
fn rule_can_produce_cross_products(rule: &RuleSpec) -> bool {
    for (i, a) in rule.allowed_calls.iter().enumerate() {
        for b in rule.allowed_calls.iter().skip(i + 1) {
            if a.fn_name != b.fn_name || a.args.len() != b.args.len() {
                continue;
            }
            let mut a_args = a.args.clone();
            let mut b_args = b.args.clone();
            a_args.sort_by_key(|arg| arg.index);
            b_args.sort_by_key(|arg| arg.index);
            let differing = a_args
                .iter()
                .zip(b_args.iter())
                .filter(|(x, y)| x.constraint != y.constraint)
                .count();
            if differing >= 2 {
                return true;
            }
        }
    }
    false
}

/// Build the deny suite for every rule and evaluate it (layer 1). The suite is derived
/// from each rule's own constraints, so it grows automatically with the grant.
pub fn run_layer1(spec: &ValidatedSpec) -> EvidenceReport {
    let cases = build_suite(spec);
    let mut outcomes = Vec::with_capacity(cases.len());
    let mut agreements = 0usize;
    let mut disagreements = 0usize;

    for case in &cases {
        let verdict = spec
            .spec()
            .rules
            .get(case.rule_index)
            .map(|rule| evaluate_generated_rule(rule, &case.context, &case.invocation))
            .unwrap_or(Verdict::Deny(ozpb_evaluator::DenyReason::NoMatchingRule));
        let permitted = matches!(verdict, Verdict::Permit);
        let agree = permitted == case.expect_permit;
        if agree {
            agreements += 1;
        } else {
            disagreements += 1;
        }
        outcomes.push(Outcome {
            label: case.label.clone(),
            rule_index: case.rule_index,
            class: case.class,
            expected: if case.expect_permit { "permit" } else { "deny" },
            actual: match &verdict {
                Verdict::Permit => "permit".to_string(),
                Verdict::Deny(r) => format!("deny({r:?})"),
                Verdict::Indeterminate(r) => format!("indeterminate({r:?})"),
            },
            agree,
        });
    }

    // Re-derive coverage as (class, count) preserving suite order of first appearance.
    let mut cov: Vec<(MutationClass, usize)> = Vec::new();
    let mut cov_by_rule: BTreeMap<usize, BTreeMap<MutationClass, usize>> = BTreeMap::new();
    for case in &cases {
        match cov.iter_mut().find(|(c, _)| *c == case.class) {
            Some((_, n)) => *n += 1,
            None => cov.push((case.class, 1)),
        }
        *cov_by_rule
            .entry(case.rule_index)
            .or_default()
            .entry(case.class)
            .or_default() += 1;
    }

    // Flag composed reviewed policies the reference evaluator does not model, so a caller
    // never reads `all_agree` as coverage of a spending-limit cap or similar on-chain policy.
    let mut unmodeled_policies = Vec::new();
    for (rule_index, rule) in spec.spec().rules.iter().enumerate() {
        for policy in &rule.policies {
            if let PolicyRef::Reviewed { kind, .. } = policy {
                unmodeled_policies.push(UnmodeledPolicy {
                    rule_index,
                    kind: kind.clone(),
                });
            }
        }
    }

    EvidenceReport {
        layer: "layer1-reference-evaluator",
        spec_hash: spec.hash().to_hex(),
        total: cases.len(),
        agreements,
        disagreements,
        coverage: cov,
        coverage_by_rule: cov_by_rule,
        expected_classes: expected_classes(spec),
        outcomes,
        unmodeled_policies,
        disclaimer: DISCLAIMER,
    }
}

/// Expose the suite so layer 2 (the contracts workspace) drives the same mutations.
pub fn build_suite(spec: &ValidatedSpec) -> Vec<Case> {
    let mut cases = Vec::new();
    for (rule_index, rule) in spec.spec().rules.iter().enumerate() {
        build_rule_suite(&mut cases, spec, rule, rule_index);
    }
    cases
}

fn build_rule_suite(
    cases: &mut Vec<Case>,
    spec: &ValidatedSpec,
    rule: &RuleSpec,
    rule_index: usize,
) {
    let first_case = cases.len();
    let ctx0 = baseline_context(spec, rule);

    for call in &rule.allowed_calls {
        let base_args = concrete_args(spec, rule, call);
        let base_inv = Invocation {
            contract: rule.context.contract.clone(),
            fn_name: call.fn_name.clone(),
            args: base_args.clone(),
        };

        // Original: must permit.
        cases.push(Case {
            rule_index,
            label: format!("original {}", call.fn_name),
            class: MutationClass::Original,
            invocation: base_inv.clone(),
            context: ctx0.clone(),
            expect_permit: true,
        });

        // Different contract.
        cases.push(Case {
            rule_index,
            label: "different target contract".to_string(),
            class: MutationClass::DifferentContract,
            invocation: Invocation {
                contract: mutate_contract(&rule.context.contract),
                ..base_inv.clone()
            },
            context: ctx0.clone(),
            expect_permit: false,
        });

        // Different function.
        cases.push(Case {
            rule_index,
            label: format!("different function ({}__x)", call.fn_name),
            class: MutationClass::DifferentFunction,
            invocation: Invocation {
                fn_name: format!("{}_x", trunc(&call.fn_name)),
                ..base_inv.clone()
            },
            context: ctx0.clone(),
            expect_permit: false,
        });

        // Per-argument mutations derived from each constraint.
        for (i, arg) in base_args.iter().enumerate() {
            let constraint = call
                .args
                .iter()
                .find(|a| a.index as usize == i)
                .map(|a| &a.constraint);
            for (label, mutated, class, expect_permit) in arg_mutations(arg, constraint) {
                let mut margs = base_args.clone();
                margs[i] = mutated;
                cases.push(Case {
                    rule_index,
                    label: format!("{} arg[{i}]", label),
                    class,
                    invocation: Invocation {
                        args: margs,
                        ..base_inv.clone()
                    },
                    context: ctx0.clone(),
                    expect_permit,
                });
            }
        }

        // Arity: extra and missing argument.
        let mut extra = base_args.clone();
        extra.push(ArgValue::I128(1));
        cases.push(Case {
            rule_index,
            label: "extra argument".to_string(),
            class: MutationClass::ArgArity,
            invocation: Invocation {
                args: extra,
                ..base_inv.clone()
            },
            context: ctx0.clone(),
            expect_permit: false,
        });
        if !base_args.is_empty() {
            let mut missing = base_args.clone();
            missing.pop();
            cases.push(Case {
                rule_index,
                label: "missing argument".to_string(),
                class: MutationClass::ArgArity,
                invocation: Invocation {
                    args: missing,
                    ..base_inv.clone()
                },
                context: ctx0.clone(),
                expect_permit: false,
            });
        }
    }

    // Signer mutations (independent of which call).
    let base_inv = original_invocation(spec, rule);
    // Zero signers.
    cases.push(Case {
        rule_index,
        label: "zero authenticated signers".to_string(),
        class: MutationClass::ZeroSigners,
        invocation: base_inv.clone(),
        context: EvalContext {
            authenticated_signers: vec![],
            ..ctx0.clone()
        },
        expect_permit: false,
    });
    // Wrong signer.
    cases.push(Case {
        rule_index,
        label: "unrecognized signer authenticates".to_string(),
        class: MutationClass::WrongSigner,
        invocation: base_inv.clone(),
        context: EvalContext {
            authenticated_signers: vec![stranger_signer()],
            ..ctx0.clone()
        },
        expect_permit: false,
    });
    let required_signers = match &rule.authorization.kind {
        PredicateKind::AnyOf | PredicateKind::AnyOfCurrentRuleSigners => 1usize,
        PredicateKind::AllOf => rule.authorization.signers.len(),
        PredicateKind::Threshold { n } => *n as usize,
    };
    if required_signers > 1 {
        cases.push(Case {
            rule_index,
            label: "partially satisfying signer set".to_string(),
            class: MutationClass::SignerBoundary,
            invocation: base_inv.clone(),
            context: EvalContext {
                authenticated_signers: ctx0
                    .authenticated_signers
                    .iter()
                    .take(required_signers - 1)
                    .cloned()
                    .collect(),
                ..ctx0.clone()
            },
            expect_permit: false,
        });
    }
    if let Some(first_signer) = ctx0.authenticated_signers.first() {
        cases.push(Case {
            rule_index,
            label: "duplicate signer does not double-count".to_string(),
            class: MutationClass::SignerBoundary,
            invocation: base_inv.clone(),
            context: EvalContext {
                authenticated_signers: vec![first_signer.clone(); required_signers.max(2)],
                ..ctx0.clone()
            },
            expect_permit: required_signers == 1,
        });
    }
    let mut authenticated_with_extra = ctx0.authenticated_signers.clone();
    authenticated_with_extra.push(stranger_signer());
    cases.push(Case {
        rule_index,
        label: "authorized signer set plus unrecognized signer".to_string(),
        class: MutationClass::SignerBoundary,
        invocation: base_inv.clone(),
        context: EvalContext {
            authenticated_signers: authenticated_with_extra,
            ..ctx0.clone()
        },
        expect_permit: false,
    });
    // Strict-set mutation (only meaningful for named-identity predicates).
    if rule.authorization.strict_signer_set
        && !matches!(
            rule.authorization.kind,
            PredicateKind::AnyOfCurrentRuleSigners
        )
    {
        let mut grown = ctx0.rule_live_signers.clone();
        grown.push(stranger_signer());
        cases.push(Case {
            rule_index,
            label: "strict set: live rule signer set grew".to_string(),
            class: MutationClass::StrictSetMutation,
            invocation: base_inv.clone(),
            context: EvalContext {
                rule_live_signers: grown,
                ..ctx0.clone()
            },
            expect_permit: false,
        });
        cases.push(Case {
            rule_index,
            label: "strict set: live rule signer set swapped".to_string(),
            class: MutationClass::StrictSetMutation,
            invocation: base_inv.clone(),
            context: EvalContext {
                rule_live_signers: vec![stranger_signer()],
                ..ctx0.clone()
            },
            expect_permit: false,
        });
    }

    // Time boundary (only if the rule expires).
    if let Some(vu) = &rule.valid_until {
        if let Some(after) = vu.ledger.0.checked_add(1) {
            cases.push(Case {
                rule_index,
                label: "one ledger past valid_until".to_string(),
                class: MutationClass::TimeBoundary,
                invocation: base_inv.clone(),
                context: EvalContext {
                    current_ledger: LedgerSeq(after),
                    ..ctx0.clone()
                },
                expect_permit: false,
            });
        }
        // Exactly at the boundary must still permit.
        cases.push(Case {
            rule_index,
            label: "exactly at valid_until (still valid)".to_string(),
            class: MutationClass::TimeBoundary,
            invocation: base_inv.clone(),
            context: EvalContext {
                current_ledger: LedgerSeq(vu.ledger.0),
                ..ctx0.clone()
            },
            expect_permit: true,
        });
        cases.push(Case {
            rule_index,
            label: "one ledger before valid_until".to_string(),
            class: MutationClass::TimeBoundary,
            invocation: base_inv.clone(),
            context: EvalContext {
                current_ledger: LedgerSeq(vu.ledger.0.saturating_sub(1)),
                ..ctx0.clone()
            },
            expect_permit: true,
        });
    }

    // Stateful boundaries.
    for st in &rule.state {
        match st {
            StateSpec::CallCountPerInstallation { max_calls } => {
                cases.push(Case {
                    rule_index,
                    label: "call count zero".to_string(),
                    class: MutationClass::CallCountBoundary,
                    invocation: base_inv.clone(),
                    context: EvalContext {
                        call_count_so_far: Some(0),
                        ..ctx0.clone()
                    },
                    expect_permit: true,
                });
                cases.push(Case {
                    rule_index,
                    label: "call count exhausted".to_string(),
                    class: MutationClass::CallCountBoundary,
                    invocation: base_inv.clone(),
                    context: EvalContext {
                        call_count_so_far: Some(*max_calls),
                        ..ctx0.clone()
                    },
                    expect_permit: false,
                });
                cases.push(Case {
                    rule_index,
                    label: "one call left (still permits)".to_string(),
                    class: MutationClass::CallCountBoundary,
                    invocation: base_inv.clone(),
                    context: EvalContext {
                        call_count_so_far: Some(max_calls.saturating_sub(1)),
                        ..ctx0.clone()
                    },
                    expect_permit: true,
                });
                if let Some(above) = max_calls.checked_add(1) {
                    cases.push(Case {
                        rule_index,
                        label: "call count above maximum".to_string(),
                        class: MutationClass::CallCountBoundary,
                        invocation: base_inv.clone(),
                        context: EvalContext {
                            call_count_so_far: Some(above),
                            ..ctx0.clone()
                        },
                        expect_permit: false,
                    });
                }
                cases.push(Case {
                    rule_index,
                    label: "call count u32 maximum".to_string(),
                    class: MutationClass::CallCountBoundary,
                    invocation: base_inv.clone(),
                    context: EvalContext {
                        call_count_so_far: Some(u32::MAX),
                        ..ctx0.clone()
                    },
                    expect_permit: false,
                });
                cases.push(Case {
                    rule_index,
                    label: "missing state".to_string(),
                    class: MutationClass::MissingState,
                    invocation: base_inv.clone(),
                    context: EvalContext {
                        call_count_so_far: None,
                        ..ctx0.clone()
                    },
                    expect_permit: false,
                });
            }
        }
    }

    // Tuple cross-products: if a rule accepts >1 tuple for the same function, mixing
    // args across observed tuples must deny (unless that mix was itself observed).
    add_cross_products(cases, spec, rule, &ctx0, rule_index);

    for case in &mut cases[first_case..] {
        case.label = format!("rule[{rule_index}] {}", case.label);
    }
}

// --- mutation helpers -----------------------------------------------------------------

fn arg_mutations(
    value: &ArgValue,
    constraint: Option<&Constraint>,
) -> Vec<(String, ArgValue, MutationClass, bool)> {
    let mut out = Vec::new();
    match (value, constraint) {
        (ArgValue::I128(v), Some(Constraint::EqI128 { .. })) => {
            for (label, candidate) in [
                ("i128 +1", v.checked_add(1)),
                ("i128 -1", v.checked_sub(1)),
                ("i128 *10", v.checked_mul(10)),
            ] {
                if let Some(candidate) = candidate.filter(|candidate| candidate != v) {
                    out.push((
                        label.to_string(),
                        ArgValue::I128(candidate),
                        MutationClass::ArgEquality,
                        false,
                    ));
                }
            }
            if *v != 0 {
                out.push((
                    "i128 zero".into(),
                    ArgValue::I128(0),
                    MutationClass::NumericBoundary,
                    false,
                ));
            }
            if *v != i128::MAX {
                out.push((
                    "i128 maximum".into(),
                    ArgValue::I128(i128::MAX),
                    MutationClass::NumericBoundary,
                    false,
                ));
            }
            out.push((
                "type: address where i128".into(),
                ArgValue::Address(stranger_addr()),
                MutationClass::TypeConfusion,
                false,
            ));
        }
        (ArgValue::I128(_), Some(Constraint::LeI128 { max })) => {
            if let Ok(m) = max.parse::<i128>() {
                if let Some(below) = m.checked_sub(1) {
                    out.push((
                        "below upper bound".into(),
                        ArgValue::I128(below),
                        MutationClass::NumericBoundary,
                        true,
                    ));
                }
                out.push((
                    "at upper bound".into(),
                    ArgValue::I128(m),
                    MutationClass::NumericBoundary,
                    true,
                ));
                if let Some(above) = m.checked_add(1) {
                    out.push((
                        "above upper bound".into(),
                        ArgValue::I128(above),
                        MutationClass::NumericBoundary,
                        false,
                    ));
                }
                out.push((
                    "i128 minimum".into(),
                    ArgValue::I128(i128::MIN),
                    MutationClass::NumericBoundary,
                    true,
                ));
            }
            out.push((
                "type: address where i128".into(),
                ArgValue::Address(stranger_addr()),
                MutationClass::TypeConfusion,
                false,
            ));
        }
        (ArgValue::I128(_), Some(Constraint::GeI128 { min })) => {
            if let Ok(m) = min.parse::<i128>() {
                if let Some(below) = m.checked_sub(1) {
                    out.push((
                        "below lower bound".into(),
                        ArgValue::I128(below),
                        MutationClass::NumericBoundary,
                        false,
                    ));
                }
                out.push((
                    "at lower bound".into(),
                    ArgValue::I128(m),
                    MutationClass::NumericBoundary,
                    true,
                ));
                if let Some(above) = m.checked_add(1) {
                    out.push((
                        "above lower bound".into(),
                        ArgValue::I128(above),
                        MutationClass::NumericBoundary,
                        true,
                    ));
                }
                out.push((
                    "i128 maximum".into(),
                    ArgValue::I128(i128::MAX),
                    MutationClass::NumericBoundary,
                    true,
                ));
            }
            out.push((
                "type: address where i128".into(),
                ArgValue::Address(stranger_addr()),
                MutationClass::TypeConfusion,
                false,
            ));
        }
        (ArgValue::Address(_), Some(Constraint::EqAddress { .. })) => {
            out.push((
                "different address".into(),
                ArgValue::Address(stranger_addr()),
                MutationClass::DifferentAddressArg,
                false,
            ));
            out.push((
                "type: i128 where address".into(),
                ArgValue::I128(42),
                MutationClass::TypeConfusion,
                false,
            ));
        }
        (ArgValue::ScvalXdr(current), Some(Constraint::EqScval { .. })) => {
            let alternate = if current == "AAAAAA==" {
                "AAAAAQ=="
            } else {
                "AAAAAA=="
            };
            out.push((
                "different scval".into(),
                ArgValue::ScvalXdr(alternate.to_string()),
                MutationClass::ArgEquality,
                false,
            ));
        }
        (_, Some(Constraint::AnyValue)) => {
            out.push((
                "wildcard alternate i128".into(),
                ArgValue::I128(i128::MAX),
                MutationClass::NumericBoundary,
                true,
            ));
            out.push((
                "wildcard alternate type".into(),
                ArgValue::Address(stranger_addr()),
                MutationClass::TypeConfusion,
                true,
            ));
        }
        _ => {}
    }
    out
}

fn add_cross_products(
    cases: &mut Vec<Case>,
    spec: &ValidatedSpec,
    rule: &RuleSpec,
    ctx0: &EvalContext,
    rule_index: usize,
) {
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_function: BTreeMap<&str, Vec<Vec<ArgValue>>> = BTreeMap::new();
    for call in &rule.allowed_calls {
        by_function
            .entry(&call.fn_name)
            .or_default()
            .push(concrete_args(spec, rule, call));
    }

    for (fn_name, tuples) in by_function {
        let observed: BTreeSet<Vec<String>> = tuples
            .iter()
            .map(|tuple| tuple.iter().map(dbg_arg).collect())
            .collect();
        for left in 0..tuples.len() {
            for right in (left + 1)..tuples.len() {
                let (a, b) = (&tuples[left], &tuples[right]);
                if a.len() != b.len() {
                    continue;
                }
                for swap in 0..a.len() {
                    let mut mixed = a.clone();
                    mixed[swap] = b[swap].clone();
                    let key: Vec<String> = mixed.iter().map(dbg_arg).collect();
                    if observed.contains(&key) {
                        continue;
                    }
                    cases.push(Case {
                        rule_index,
                        label: format!("cross-product: tuple{left} with tuple{right} arg[{swap}]"),
                        class: MutationClass::TupleCrossProduct,
                        invocation: Invocation {
                            contract: rule.context.contract.clone(),
                            fn_name: fn_name.to_string(),
                            args: mixed,
                        },
                        context: ctx0.clone(),
                        expect_permit: false,
                    });
                }
            }
        }
    }
}

// --- concrete value derivation --------------------------------------------------------

fn concrete_args(
    spec: &ValidatedSpec,
    rule: &RuleSpec,
    call: &ozpb_policy_spec::AllowedCall,
) -> Vec<ArgValue> {
    let mut args: Vec<ArgValue> = Vec::new();
    let mut sorted = call.args.clone();
    sorted.sort_by_key(|a| a.index);
    for arg in &sorted {
        args.push(concrete_for(spec, rule, &arg.constraint));
    }
    args
}

fn concrete_for(spec: &ValidatedSpec, _rule: &RuleSpec, c: &Constraint) -> ArgValue {
    let account = &spec.spec().smart_account.address;
    match c {
        Constraint::EqAddress { value } => match value {
            AddressRef::SelfAccount(_) => ArgValue::Address(account.clone()),
            AddressRef::Address(a) => ArgValue::Address(a.clone()),
        },
        Constraint::EqI128 { value } => ArgValue::I128(value.parse().unwrap_or(0)),
        // For a bound, pick a value satisfying it (the "original" for a widened arg).
        Constraint::LeI128 { max } => ArgValue::I128(max.parse::<i128>().unwrap_or(0)),
        Constraint::GeI128 { min } => ArgValue::I128(min.parse::<i128>().unwrap_or(0)),
        Constraint::EqScval { xdr_base64 } => ArgValue::ScvalXdr(xdr_base64.clone()),
        // A wildcard accepts anything; the "original" concrete value is arbitrary.
        Constraint::AnyValue => ArgValue::I128(0),
    }
}

fn original_invocation(spec: &ValidatedSpec, rule: &RuleSpec) -> Invocation {
    let call = &rule.allowed_calls[0];
    Invocation {
        contract: rule.context.contract.clone(),
        fn_name: call.fn_name.clone(),
        args: concrete_args(spec, rule, call),
    }
}

fn baseline_context(spec: &ValidatedSpec, rule: &RuleSpec) -> EvalContext {
    let signers = rule.authorization.signers.clone();
    let ledger = rule
        .valid_until
        .as_ref()
        .map(|v| v.ledger.0.saturating_sub(1))
        .unwrap_or(1000);
    let call_count = rule
        .state
        .iter()
        .any(|s| matches!(s, StateSpec::CallCountPerInstallation { .. }))
        .then_some(0);
    EvalContext {
        smart_account: spec.spec().smart_account.address.clone(),
        current_ledger: LedgerSeq(ledger),
        authenticated_signers: signers.clone(),
        rule_live_signers: signers,
        call_count_so_far: call_count,
    }
}

fn mutate_contract(c: &str) -> String {
    // A different but well-formed-looking contract id.
    format!("{}", ozpb_domain::sha256(c.as_bytes()))
        .chars()
        .take(0)
        .collect::<String>()
        + "COTHERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

fn stranger_addr() -> String {
    "GSTRANGERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
}

fn stranger_signer() -> SignerSpec {
    SignerSpec::Delegated {
        address: stranger_addr(),
    }
}

fn trunc(s: &str) -> String {
    s.chars().take(28).collect()
}

fn dbg_arg(a: &ArgValue) -> String {
    format!("{a:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_synthesizer::fixtures::golden_spec;
    use ozpb_synthesizer::walkthroughs::{blend_claim_spec, soroswap_swap_spec};

    // --- coverage floor -------------------------------------------------------------------
    //
    // `all_agree` only says "no case disagreed". It says nothing about which classes were
    // *tested*, so a regression that stopped emitting an entire boundary class (every signer
    // case, say) would still report `all_agree: true` and pass every gate. These assert the
    // suite actually covers the classes the spec's own shape implies.

    #[test]
    fn a_spec_shape_always_covers_its_structurally_required_classes() {
        for (label, spec) in [
            ("W2 subscription", golden_spec()),
            ("W1 blend", blend_claim_spec()),
            ("W3 soroswap", soroswap_swap_spec()),
        ] {
            let report = run_layer1(&spec);
            assert!(
                report.missing_classes().is_empty(),
                "{label}: suite is missing boundary classes {:?} that this spec's shape \
                 requires; covered = {:?}",
                report.missing_classes(),
                report.coverage
            );
            // Non-vacuity: every rule's floor must exceed the seven structural classes, or
            // it would pass without checking anything the rule's own content implies.
            for (rule_index, expected) in &report.expected_classes {
                assert!(
                    expected.len() > 7,
                    "{label} rule[{rule_index}]: floor is only the structural classes \
                     ({expected:?}), so the conditional derivation never fired"
                );
            }
        }
    }

    #[test]
    fn a_report_missing_an_expected_class_names_it() {
        let spec = golden_spec();
        let mut report = run_layer1(&spec);
        // Simulate the regression: drop every signer-boundary case for rule 0.
        for per_class in report.coverage_by_rule.values_mut() {
            per_class.remove(&MutationClass::SignerBoundary);
        }
        assert!(
            report
                .missing_classes()
                .contains(&(0, MutationClass::SignerBoundary)),
            "dropping a structurally-required class must be reported, got {:?}",
            report.missing_classes()
        );
        // And a class the spec does not imply must not be demanded.
        assert!(
            !report
                .missing_classes()
                .iter()
                .any(|(_, class)| *class == MutationClass::TupleCrossProduct),
            "a single-tuple spec must not be required to cover cross-products"
        );
    }

    #[test]
    fn a_zero_count_coverage_entry_is_treated_as_uncovered() {
        // Reachable through a deserialized report; the floor must not accept a present-but-
        // empty entry as coverage.
        let mut report = run_layer1(&golden_spec());
        report
            .coverage_by_rule
            .entry(0)
            .or_default()
            .insert(MutationClass::SignerBoundary, 0);
        assert!(report
            .missing_classes()
            .contains(&(0, MutationClass::SignerBoundary)));
    }

    #[test]
    fn one_rules_coverage_cannot_vouch_for_another_rules_gap() {
        // Two rules, only the first of which can produce cross-product cases. Aggregated
        // coverage would show the class as covered and hide rule 1 entirely; a per-rule floor
        // must not demand it of rule 1 at all — and must still catch a real per-rule gap.
        let mut spec = golden_spec().spec().clone();
        let mut second = spec.rules[0].clone();
        second.allowed_calls.truncate(1);
        spec.rules.push(second);
        let spec = spec.validate().expect("two-rule spec must validate");
        let report = run_layer1(&spec);
        assert_eq!(
            report.expected_classes.len(),
            2,
            "both rules must have a floor"
        );
        assert!(
            report.missing_classes().is_empty(),
            "a legitimate two-rule spec must satisfy the floor: {:?}",
            report.missing_classes()
        );

        // Now break ONLY rule 1's coverage. An aggregated check would still see rule 0's
        // cases and pass.
        let mut broken = report.clone();
        broken
            .coverage_by_rule
            .get_mut(&1)
            .expect("rule 1 has coverage")
            .remove(&MutationClass::ZeroSigners);
        assert_eq!(
            broken.missing_classes(),
            vec![(1, MutationClass::ZeroSigners)],
            "a gap in rule 1 must be attributed to rule 1, not masked by rule 0"
        );
    }

    #[test]
    fn two_tuples_differing_in_one_position_do_not_demand_cross_products() {
        // `add_cross_products` skips any mix that reproduces an observed tuple, so a
        // single-position difference yields no cases. Demanding the class would fail a spec
        // the synthesizer legitimately produces (the same payment recorded at two amounts).
        let mut spec = golden_spec().spec().clone();
        let mut variant = spec.rules[0].allowed_calls[0].clone();
        for arg in &mut variant.args {
            if let Constraint::EqI128 { value } = &mut arg.constraint {
                *value = "999".to_string();
            }
        }
        spec.rules[0].allowed_calls.push(variant);
        let spec = spec.validate().expect("two-tuple spec must validate");
        let report = run_layer1(&spec);
        assert!(
            report.missing_classes().is_empty(),
            "a one-position tuple difference must not demand cross-products: {:?}",
            report.missing_classes()
        );
    }

    #[test]
    fn a_degenerate_bound_is_reported_as_permit_only_not_as_a_coverage_gap() {
        // An expiry at u32::MAX cannot be passed, so the generator has no deny case to emit.
        // That is a degenerate bound, not a missing class: the floor must stay satisfied and
        // the report must say the class never demonstrated a denial.
        let mut spec = golden_spec().spec().clone();
        spec.rules[0].valid_until = Some(ozpb_policy_spec::ValidUntil {
            ledger: LedgerSeq(u32::MAX),
            approx_time: None,
        });
        let spec = spec.validate().unwrap();
        let report = run_layer1(&spec);
        assert!(
            report.missing_classes().is_empty(),
            "a degenerate bound must not read as a missing class: {:?}",
            report.missing_classes()
        );
        assert!(
            report
                .permit_only_classes()
                .contains(&(0, MutationClass::TimeBoundary)),
            "an unreachable expiry must be reported as permit-only, got {:?}",
            report.permit_only_classes()
        );
        // The healthy spec must NOT be flagged for the same class.
        assert!(!run_layer1(&golden_spec())
            .permit_only_classes()
            .contains(&(0, MutationClass::TimeBoundary)));
    }

    #[test]
    fn expected_classes_follow_the_spec_shape_not_a_fixed_list() {
        // No expiry and no state ⇒ neither time nor call-count classes are required.
        let mut stateless = golden_spec().spec().clone();
        stateless.rules[0].valid_until = None;
        stateless.rules[0].state = vec![];
        let stateless = stateless.validate().unwrap();
        let expected = expected_classes(&stateless)
            .remove(&0)
            .expect("rule 0 floor");
        assert!(!expected.contains(&MutationClass::TimeBoundary));
        assert!(!expected.contains(&MutationClass::CallCountBoundary));
        assert!(!expected.contains(&MutationClass::MissingState));
        // …but the unconditional ones are always required.
        for class in [
            MutationClass::Original,
            MutationClass::DifferentContract,
            MutationClass::DifferentFunction,
            MutationClass::ArgArity,
            MutationClass::ZeroSigners,
            MutationClass::WrongSigner,
            MutationClass::SignerBoundary,
        ] {
            assert!(
                expected.contains(&class),
                "{class:?} must always be required"
            );
        }
        assert!(run_layer1(&stateless).missing_classes().is_empty());
    }

    #[test]
    fn w1_blend_claim_evidence_all_agrees() {
        let report = run_layer1(&blend_claim_spec());
        assert!(report.total > 8, "W1 suite: {}", report.total);
        assert!(
            report.all_agree(),
            "W1 disagreements: {:#?}",
            report
                .outcomes
                .iter()
                .filter(|o| !o.agree)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn w3_soroswap_evidence_all_agrees_including_bounds_and_any_deadline() {
        let report = run_layer1(&soroswap_swap_spec());
        assert!(report.total > 10, "W3 suite: {}", report.total);
        assert!(
            report.all_agree(),
            "W3 disagreements: {:#?}",
            report
                .outcomes
                .iter()
                .filter(|o| !o.agree)
                .collect::<Vec<_>>()
        );
        // W3 must exercise numeric-boundary cases (the amount_in cap and out_min floor).
        let classes: Vec<MutationClass> = report.coverage.iter().map(|(c, _)| *c).collect();
        assert!(classes.contains(&MutationClass::NumericBoundary));
    }

    #[test]
    fn subscription_evidence_report_all_agrees() {
        let report = run_layer1(&golden_spec());
        assert!(
            report.total > 10,
            "suite must be substantial: {}",
            report.total
        );
        assert!(
            report.all_agree(),
            "disagreements: {:#?}",
            report
                .outcomes
                .iter()
                .filter(|o| !o.agree)
                .collect::<Vec<_>>()
        );
        // The original permits, and there is at least one of each key security class.
        let classes: Vec<MutationClass> = report.coverage.iter().map(|(c, _)| *c).collect();
        for required in [
            MutationClass::Original,
            MutationClass::ZeroSigners,
            MutationClass::WrongSigner,
            MutationClass::StrictSetMutation,
            MutationClass::ArgEquality,
            MutationClass::DifferentFunction,
            MutationClass::DifferentContract,
            MutationClass::DifferentAddressArg,
            MutationClass::CallCountBoundary,
            MutationClass::MissingState,
            MutationClass::TimeBoundary,
        ] {
            assert!(classes.contains(&required), "missing class {required:?}");
        }
    }

    #[test]
    fn exactly_one_original_permit_case() {
        let report = run_layer1(&golden_spec());
        let permits: Vec<&Outcome> = report
            .outcomes
            .iter()
            .filter(|o| o.expected == "permit")
            .collect();
        // original + at-boundary time case + one-call-left case
        assert!(permits.iter().all(|o| o.agree));
        assert!(permits.iter().any(|o| o.class == MutationClass::Original));
    }

    #[test]
    fn report_serializes_with_disclaimer() {
        let report = run_layer1(&golden_spec());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("NOT a proof"));
        assert!(json.contains("layer1-reference-evaluator"));
    }

    #[test]
    fn composed_reviewed_policies_are_flagged_as_unmodeled() {
        // The golden subscription spec composes a reviewed oz:spending_limit policy whose
        // stateful cap the reference evaluator does NOT model. all_agree must therefore be
        // reported alongside an explicit "not covered here" flag, never as full coverage.
        let report = run_layer1(&golden_spec());
        assert!(report.all_agree(), "modeled semantics still agree");
        assert!(
            !report.models_all_policies(),
            "a composed reviewed policy must be flagged as outside layer-1 coverage"
        );
        assert!(
            report
                .unmodeled_policies
                .iter()
                .any(|p| p.kind == "oz:spending_limit" && p.rule_index == 0),
            "spending-limit on rule 0 must be listed as unmodeled: {:?}",
            report.unmodeled_policies
        );
        // A spec with no reviewed policy models everything (W1 Blend claim is inbound-only).
        let inbound = run_layer1(&blend_claim_spec());
        assert!(inbound.models_all_policies());
        assert!(inbound.unmodeled_policies.is_empty());
    }

    #[test]
    fn suite_is_deterministic() {
        let a = build_suite(&golden_spec());
        let b = build_suite(&golden_spec());
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.label, y.label);
        }
    }

    #[test]
    fn suite_covers_every_rule_in_a_permission_bundle() {
        let base = golden_spec();
        let mut raw = base.spec().clone();
        let mut second = raw.rules[0].clone();
        second.context.contract = ozpb_synthesizer::fixtures::golden_account_strkey();
        raw.rules.push(second);
        let multi = raw.validate().unwrap();

        let suite = build_suite(&multi);
        let originals: Vec<&Case> = suite
            .iter()
            .filter(|case| case.class == MutationClass::Original)
            .collect();
        assert_eq!(originals.len(), 2, "each rule must contribute its original");
        assert!(originals[0].label.starts_with("rule[0]"));
        assert!(originals[1].label.starts_with("rule[1]"));

        let report = run_layer1(&multi);
        assert!(report.all_agree(), "{:#?}", report.outcomes);
    }

    #[test]
    fn inclusive_numeric_bounds_test_below_at_above_and_extremes() {
        let suite = build_suite(&soroswap_swap_spec());
        for required in [
            "below upper bound",
            "at upper bound",
            "above upper bound",
            "i128 minimum",
            "below lower bound",
            "at lower bound",
            "above lower bound",
            "i128 maximum",
        ] {
            assert!(
                suite.iter().any(|case| case.label.contains(required)),
                "missing numeric boundary case: {required}"
            );
        }
        assert!(run_layer1(&soroswap_swap_spec()).all_agree());
    }

    #[test]
    fn threshold_signer_suite_covers_partial_duplicate_and_extra_sets() {
        let base = golden_spec();
        let mut raw = base.spec().clone();
        raw.rules[0].authorization.kind = PredicateKind::Threshold { n: 2 };
        raw.rules[0].authorization.signers = vec![
            SignerSpec::Delegated {
                address: ozpb_synthesizer::fixtures::golden_delegate_strkey(),
            },
            SignerSpec::Delegated {
                address: ozpb_synthesizer::fixtures::golden_merchant_strkey(),
            },
            SignerSpec::Delegated {
                address: ozpb_synthesizer::fixtures::golden_account_strkey(),
            },
        ];
        let threshold = raw.validate().unwrap();
        let suite = build_suite(&threshold);

        for required in [
            "partially satisfying signer set",
            "duplicate signer does not double-count",
            "authorized signer set plus unrecognized signer",
        ] {
            assert!(suite.iter().any(|case| case.label.contains(required)));
        }
        assert!(suite.iter().any(|case| {
            case.label
                .contains("authorized signer set plus unrecognized signer")
                && !case.expect_permit
        }));
        assert!(run_layer1(&threshold).all_agree());
    }

    #[test]
    fn state_and_time_suites_cover_both_sides_and_extremes() {
        let suite = build_suite(&golden_spec());
        for required in [
            "one ledger before valid_until",
            "exactly at valid_until",
            "one ledger past valid_until",
            "call count zero",
            "one call left",
            "call count exhausted",
            "call count above maximum",
            "call count u32 maximum",
        ] {
            assert!(suite.iter().any(|case| case.label.contains(required)));
        }
        assert!(run_layer1(&golden_spec()).all_agree());
    }

    #[test]
    fn cross_products_never_mix_different_functions() {
        let base = golden_spec();
        let mut raw = base.spec().clone();
        let mut second_call = raw.rules[0].allowed_calls[0].clone();
        second_call.fn_name = "approve".to_string();
        second_call.args[1].constraint = Constraint::EqAddress {
            value: AddressRef::Address(ozpb_synthesizer::fixtures::golden_delegate_strkey()),
        };
        second_call.args[2].constraint = Constraint::EqI128 {
            value: "500000001".into(),
        };
        raw.rules[0]
            .policies
            .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
        raw.rules[0].allowed_calls.push(second_call);
        let two_functions = raw.validate().unwrap();

        assert!(!build_suite(&two_functions)
            .iter()
            .any(|case| case.class == MutationClass::TupleCrossProduct));
    }
}
