//! Synthesizer v1 (architecture §4.3): RecordingBundle(s) + explicit user decisions →
//! PolicySpec. Pure, deterministic, **fail-closed**.
//!
//! Exact-by-default: every observed argument becomes a deep exact-equality constraint on
//! the complete tuple. Widening is never heuristic — it enters only through an explicit
//! [`Widening`] decision carrying intent and blast radius, or a reviewed adapter bound to
//! the observed target code hash and complete argument signature. The delegate signer set and
//! predicate cannot be inferred from a recording and are required decisions. Sequences
//! produce a *permission bundle* (independent rules, one per contract), never a workflow.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::pinned_upstream;
use ozpb_domain::{BlastRadius, Hash32, LedgerSeq, Provenance};
use ozpb_policy_spec::{
    AddressRef, AllowedCall, ArgConstraint, AuthorizationSpec, Constraint, ContextSpec,
    ContextType, DriftResponse, Evidence, PolicyRef, PolicySpec, PredicateKind, RecordingRef,
    ReviewedParams, RuleSpec, SignerSpec, SmartAccountRecord, StateSpec, TargetCodeHash,
    TargetHashRole, ValidUntil, GENERATED_POLICY_KIND, SPEC_SCHEMA,
};
use ozpb_recorder_core::{
    ArgSummary, AuthorizedCall, Execution, InvocationNode, MovementKind, ObservedExecutable,
    RecordingBundle, TokenMovement,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stellar_xdr::{Limits, WriteXdr};

pub mod adapters;
// Test-support walkthrough builders (W1, W3, two payments), shared across crates' tests; `expect` on
// known-good fixtures is intentional here.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod walkthroughs;

// ---------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SynthesisInput {
    pub bundles: Vec<RecordingBundle>,
    /// Which authorizer the grant is for — a transaction may contain several (§4.1).
    pub selected_authorizer: String,
    /// Account compatibility record. The toolkit constructs this only after resolving the
    /// observed Wasm hash in the authenticated capability registry.
    pub account: SmartAccountRecord,
    pub registry_snapshot: Hash32,
    /// Reviewed spending-limit wasm hash from the policy capability registry, if any.
    pub spending_limit_capability: Option<Hash32>,
    /// Audited template-family identity for the generated scope policy.
    pub template_family: String,
    pub template_capability_schema: Hash32,
    /// Reviewed, code-hash-bound contract adapters resolved by the caller (§4.3 / §6.1).
    /// An adapter applies to a rule only when its `target_code_hash` matches the target's
    /// observed on-chain code hash; it is the only path besides an explicit user decision by
    /// which a widening may enter a spec. Empty by default → pure exact-by-default synthesis.
    pub adapters: Vec<adapters::Adapter>,
}

/// Explicit user decisions. Everything here is a judgment call the synthesizer must not
/// make on its own.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDecisions {
    pub grant_name: String,
    /// Who may act under this grant (REQUIRED — not inferrable from the recording).
    pub delegate_signers: Vec<SignerSpec>,
    pub predicate: PredicateChoice,
    /// Grant lifetime as a ledger sequence; `None` requires the explicit unlimited ack.
    pub valid_until_ledger: Option<u32>,
    /// Explicit, high-blast-radius acknowledgment that the grant never expires.
    pub no_expiry_acknowledged: bool,
    /// Per-installation call cap; `None` requires the explicit unlimited-calls ack.
    pub max_calls: Option<u32>,
    /// Explicit, high-blast-radius acknowledgment that the grant has no call cap. Absent reads
    /// as `false`, so a caller that drops it gets a question, never an uncapped grant.
    #[serde(default)]
    pub unlimited_calls_acknowledged: bool,
    /// Explicit widenings (the only path to non-exact constraints).
    pub widenings: Vec<Widening>,
    /// Compose the reviewed OZ spending-limit policy (SEP-41 transfer rules only).
    pub spending_limit: Option<SpendingLimitChoice>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PredicateChoice {
    AnyOf,
    AllOf,
    Threshold { n: u32 },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Widening {
    /// Target contract (strkey) of the rule this widening applies to.
    pub contract: String,
    pub fn_name: String,
    pub arg_index: u32,
    pub bound: WideningBound,
    /// Explicit acknowledgement that a cap (`le_i128`) sets no floor: the argument is a signed
    /// integer, so every smaller value passes, negative amounts included, and only the target can
    /// refuse one. The way to bound both ends is a range (`WideningBound::RangeI128`), which needs
    /// no acknowledgement; without either, a cap is an open question. It answers nothing on a
    /// range, a floor or `any_value`, where it is refused. Absent reads as `false`, like
    /// `unlimited_calls_acknowledged`.
    #[serde(default)]
    pub no_floor_acknowledged: bool,
    /// The user's stated semantic intent ("amount is a cap, allow headroom to 100").
    pub intent: String,
    pub blast_radius: BlastRadius,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WideningBound {
    LeI128 {
        max: String,
    },
    GeI128 {
        min: String,
    },
    /// Both ends, inclusive: `min..=max`. The way to say "spend up to X" without leaving the
    /// amount open below: `{"range_i128": {"min": "0", "max": "X"}}`.
    RangeI128 {
        min: String,
        max: String,
    },
    /// Accept any value at this argument (maximal widening; only via an explicit,
    /// high-blast-radius user decision — e.g. a caller-chosen `deadline`).
    AnyValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendingLimitChoice {
    pub limit: String,
    pub period_ledgers: u32,
}

// ---------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SynthesisOutput {
    pub spec: PolicySpec,
    /// Per-constraint reasoning, for the wallet/skill to display.
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SynthError {
    #[error("E_NO_EVIDENCE: no recording bundles supplied")]
    NoEvidence,
    #[error("E_EVIDENCE_TRUST: bundle {0} has trust level '{1}' which cannot drive synthesis")]
    EvidenceTrust(usize, String),
    #[error(
        "E_TX_FAILED: bundle {0} records a failed execution; failed executions are not \
         behavior examples"
    )]
    FailedExecution(usize),
    #[error("E_NETWORK_MISMATCH: bundles span different networks")]
    NetworkMismatch,
    #[error("E_AUTHORIZER_NOT_FOUND: no authorization by {0} in the supplied recordings")]
    AuthorizerNotFound(String),
    #[error("E_INCOMPATIBLE_ACCOUNT: {0}")]
    IncompatibleAccount(String),
    #[error(
        "E_UNSUPPORTED_PATTERN: {0} (fail-closed: this observation cannot be turned into \
         a minimal grant by this toolkit version)"
    )]
    UnsupportedPattern(String),
    #[error("E_AMBIGUOUS_ARG_SEMANTICS: widening {contract}/{fn_name} arg {arg_index}: {reason}")]
    AmbiguousArgSemantics {
        contract: String,
        fn_name: String,
        arg_index: u32,
        reason: String,
    },
    #[error("E_UNREGISTERED_POLICY: {0}")]
    UnregisteredPolicy(String),
    #[error("E_NEEDS_DECISION: {0}")]
    NeedsDecision(String),
    #[error("E_INVALID_DECISION: {0}")]
    InvalidDecision(String),
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------------------
// synthesize(): the pure core
// ---------------------------------------------------------------------------------------

pub fn synthesize(
    input: &SynthesisInput,
    decisions: &UserDecisions,
) -> Result<SynthesisOutput, Vec<SynthError>> {
    let mut errors = Vec::new();

    // --- evidence gates (fail-closed) ---------------------------------------------
    if input.bundles.is_empty() {
        return Err(vec![SynthError::NoEvidence]);
    }
    for (i, b) in input.bundles.iter().enumerate() {
        if !b.trust.allows_synthesis() {
            errors.push(SynthError::EvidenceTrust(i, b.trust.as_str().to_string()));
        }
        // Failure-analysis recordings (record --allow-failed) are for understanding a
        // denial, never behavior examples: what a failed transaction attempted is not
        // evidence of what a policy should permit.
        //
        // Scope, stated exactly: this stops an *honestly recorded* failure from becoming a
        // policy. It is not an anti-forgery check and cannot be one — `execution` is an
        // admission-time claim carried in the artifact (no part of the raw evidence encodes
        // the result code), so an edited `executed_success` remains coherent here. The
        // forgery is refused where the outcome is provable: E_RESULT_MISMATCH against the
        // import's transaction result, and the resultXdr/status agreement check in the RPC
        // adapter.
        if b.execution == Execution::ExecutedFailed {
            errors.push(SynthError::FailedExecution(i));
        }
    }
    let network = input.bundles[0].network_id;
    if input.bundles.iter().any(|b| b.network_id != network) {
        errors.push(SynthError::NetworkMismatch);
    }
    if input.account.address != input.selected_authorizer {
        errors.push(SynthError::IncompatibleAccount(format!(
            "resolved smart account {} does not match selected authorizer {}",
            input.account.address, input.selected_authorizer
        )));
    }
    for (index, bundle) in input.bundles.iter().enumerate() {
        let has_selected_authorizer = bundle
            .authorizations
            .iter()
            .any(|authorization| authorization.authorizer == input.selected_authorizer);
        if !has_selected_authorizer {
            continue;
        }
        match bundle.contract_executables.get(&input.selected_authorizer) {
            Some(observation) => match observation.executable {
                ObservedExecutable::Wasm { code_hash }
                    if code_hash == input.account.observed_code_hash => {}
                ObservedExecutable::Wasm { code_hash } => {
                    errors.push(SynthError::IncompatibleAccount(format!(
                        "bundle {index} observed account wasm hash {code_hash}, but the registry-resolved account record claims {}",
                        input.account.observed_code_hash
                    )));
                }
                ObservedExecutable::StellarAsset => {
                    errors.push(SynthError::IncompatibleAccount(format!(
                        "bundle {index} observed the selected authorizer as a Stellar Asset contract, not a compatible smart account"
                    )));
                }
            },
            None => errors.push(SynthError::IncompatibleAccount(format!(
                "bundle {index} has no recorder-observed executable for the selected smart account"
            ))),
        }
    }

    // --- required decisions ---------------------------------------------------------
    if decisions.delegate_signers.is_empty() {
        errors.push(SynthError::NeedsDecision(
            "who is this grant for? delegate signer set is required and cannot be \
             inferred from the recording"
                .to_string(),
        ));
    }
    for signer in &decisions.delegate_signers {
        if matches!(signer, SignerSpec::External { .. }) {
            errors.push(SynthError::UnsupportedPattern(
                "external verifiers are unavailable in Phase 1: the smart-account signer value \
                 does not carry the claimed verifier Wasm hash, so this toolkit cannot yet \
                 enforce the required address-to-code binding"
                    .to_string(),
            ));
        }
    }
    match (
        decisions.valid_until_ledger,
        decisions.no_expiry_acknowledged,
    ) {
        (None, false) => errors.push(SynthError::NeedsDecision(
            "grant lifetime: provide valid_until_ledger, or explicitly acknowledge a \
             non-expiring grant (high blast radius)"
                .to_string(),
        )),
        // Two answers to one question: picking either would decide for the user.
        (Some(ledger), true) => errors.push(SynthError::InvalidDecision(format!(
            "grant lifetime: valid_until_ledger {ledger} contradicts no_expiry_acknowledged; \
             choose one"
        ))),
        _ => {}
    }
    match (decisions.max_calls, decisions.unlimited_calls_acknowledged) {
        (None, false) => errors.push(SynthError::NeedsDecision(
            "call cap: provide max_calls, or explicitly acknowledge unlimited calls \
             (unlimited_calls_acknowledged, high blast radius)"
                .to_string(),
        )),
        (Some(max_calls), true) => errors.push(SynthError::InvalidDecision(format!(
            "call cap: max_calls {max_calls} contradicts unlimited_calls_acknowledged; \
             choose one"
        ))),
        _ => {}
    }
    if let PredicateChoice::Threshold { n } = decisions.predicate {
        let count = decisions.delegate_signers.len();
        if n == 0 || (n as usize) > count {
            errors.push(SynthError::NeedsDecision(format!(
                "threshold {n} is not within 1..={count} delegate signers"
            )));
        }
    }
    // One argument carries one constraint, and `exact_constraints` applies the first widening
    // that names it. A second would be dropped without a word — a cap and a floor meant as a
    // range would quietly become the cap alone — so the document is refused and the argument
    // named instead.
    let mut widenings_per_argument = BTreeMap::<(&str, &str, u32), usize>::new();
    for w in &decisions.widenings {
        *widenings_per_argument
            .entry((w.contract.as_str(), w.fn_name.as_str(), w.arg_index))
            .or_default() += 1;
    }
    for ((contract, fn_name, arg_index), count) in widenings_per_argument {
        if count > 1 {
            errors.push(SynthError::InvalidDecision(format!(
                "widening {contract}/{fn_name} arg {arg_index}: {count} widenings name this \
                 argument, and an argument takes one bound; keep the one the user chose"
            )));
        }
    }
    // The open-floor acknowledgement answers the question a bound with no floor asks (below) and
    // no other: a cap, or a range from i128::MIN, which renders the same check. On a stated
    // floor it contradicts the bound beside it; on any_value it qualifies nothing. Either way the
    // user's answer is unclear, so the document is refused rather than the field ignored.
    for w in decisions
        .widenings
        .iter()
        .filter(|w| w.no_floor_acknowledged)
    {
        let (contract, fn_name, arg_index) = (&w.contract, &w.fn_name, w.arg_index);
        match &w.bound {
            WideningBound::LeI128 { .. } => {}
            WideningBound::RangeI128 { min, .. } if starts_at_the_type_minimum(min) => {}
            WideningBound::RangeI128 { min, max } => {
                errors.push(SynthError::InvalidDecision(format!(
                    "widening {contract}/{fn_name} arg {arg_index}: the range {min}..={max} has \
                     its floor at {min}, which contradicts no_floor_acknowledged; choose one"
                )))
            }
            WideningBound::GeI128 { min } => errors.push(SynthError::InvalidDecision(format!(
                "widening {contract}/{fn_name} arg {arg_index}: the floor at {min} contradicts \
                 no_floor_acknowledged; choose one"
            ))),
            WideningBound::AnyValue => errors.push(SynthError::InvalidDecision(format!(
                "widening {contract}/{fn_name} arg {arg_index}: no_floor_acknowledged qualifies \
                 a bound with no floor alone (a cap, le_i128, or a range from i128::MIN); \
                 any_value has no bound for it to qualify"
            ))),
        }
    }

    // --- evidence: canonical ordering + dedup (multi-recording provenance, §4.2) ----
    let mut recording_hashes: Vec<(Hash32, &RecordingBundle)> = Vec::new();
    for b in &input.bundles {
        let h = b
            .recording_hash()
            .map_err(|e| vec![SynthError::Internal(e.to_string())])?;
        if !recording_hashes.iter().any(|(existing, _)| *existing == h) {
            recording_hashes.push((h, b));
        }
    }
    recording_hashes.sort_by_key(|(h, _)| *h);

    // --- collect authorized calls by the selected authorizer -------------------------
    // Every node of the authorized invocation tree is an authorized call (§4.1).
    let mut observed: Vec<Observed> = Vec::new();
    let mut found_authorizer = false;

    for (rec_idx, (_, bundle)) in recording_hashes.iter().enumerate() {
        for (auth_idx, auth) in bundle.authorizations.iter().enumerate() {
            if auth.authorizer != input.selected_authorizer {
                continue;
            }
            found_authorizer = true;
            let base = format!("recordings[{rec_idx}]/auth[{auth_idx}]");
            let mut stack: Vec<(&InvocationNode, String)> = vec![(&auth.root, base)];
            while let Some((node, path)) = stack.pop() {
                match &node.call {
                    AuthorizedCall::Contract {
                        contract,
                        fn_name,
                        args,
                    } => observed.push(Observed {
                        contract: contract.clone(),
                        fn_name: fn_name.clone(),
                        args,
                        evidence_path: path.clone(),
                        recording_index: rec_idx,
                    }),
                    AuthorizedCall::CreateContract => {
                        errors.push(SynthError::UnsupportedPattern(
                            "authorized contract creation cannot be scoped by a \
                             CallContract rule"
                                .to_string(),
                        ));
                    }
                }
                for (i, sub) in node.sub_invocations.iter().enumerate() {
                    stack.push((sub, format!("{path}/sub[{i}]")));
                }
            }
        }
    }
    if !found_authorizer {
        errors.push(SynthError::AuthorizerNotFound(
            input.selected_authorizer.clone(),
        ));
    }
    if observed.is_empty() && found_authorizer {
        errors.push(SynthError::UnsupportedPattern(
            "the selected authorizer authorized no contract calls".to_string(),
        ));
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // --- build rules: one CallContract rule per target contract (permission bundle) --
    let mut rationale: Vec<String> = Vec::new();

    // Evidence about which argument carries value, gathered before any rule exists and consumed
    // only as text — see `value_movement_evidence` for why it cannot be anything else.
    rationale.extend(value_movement_evidence(&observed, &recording_hashes));
    let mut per_contract: BTreeMap<String, Vec<&Observed>> = BTreeMap::new();
    for o in &observed {
        per_contract.entry(o.contract.clone()).or_default().push(o);
    }
    if per_contract.len() > 1 {
        rationale.push(format!(
            "permission bundle: {} independent rules (one per contract); ordering and \
             dependency between them are NOT enforced",
            per_contract.len()
        ));
    }

    let authorization = AuthorizationSpec {
        kind: match decisions.predicate {
            PredicateChoice::AnyOf => PredicateKind::AnyOf,
            PredicateChoice::AllOf => PredicateKind::AllOf,
            PredicateChoice::Threshold { n } => PredicateKind::Threshold { n },
        },
        // Named identities are strict by default and mandatory in verified mode (D1).
        strict_signer_set: true,
        signers: decisions.delegate_signers.clone(),
    };

    let mut rules = Vec::new();
    for (contract, calls) in &per_contract {
        let mut target_code_hash =
            resolve_target_code_hash(contract, &recording_hashes, &mut errors, &mut rationale);
        // A reviewed adapter applies to this rule only when it is bound to the target's
        // observed on-chain code hash (§6.1). If the target was upgraded/unobserved, no
        // adapter claim is permitted and synthesis stays exact-by-default.
        let adapter = target_code_hash
            .as_ref()
            .and_then(|t| input.adapters.iter().find(|a| a.target_code_hash == t.hash));
        // Dedup identical tuples; merge their evidence paths.
        let mut tuples: Vec<(AllowedCall, Vec<String>)> = Vec::new();
        for o in calls {
            let matched_adapter =
                adapter.filter(|adapter| adapter.matches_call(&o.fn_name, o.args));
            let args = exact_constraints(
                o,
                input,
                decisions,
                matched_adapter,
                &mut errors,
                &mut rationale,
            );
            let call = AllowedCall {
                fn_name: o.fn_name.clone(),
                args,
                justified_by: vec![],
            };
            match tuples.iter_mut().find(|(existing, _)| {
                existing.fn_name == call.fn_name && existing.args == call.args
            }) {
                Some((_, paths)) => paths.push(o.evidence_path.clone()),
                None => tuples.push((call, vec![o.evidence_path.clone()])),
            }
        }
        let allowed_calls: Vec<AllowedCall> = tuples
            .into_iter()
            .map(|(mut c, mut paths)| {
                paths.sort();
                c.justified_by = paths;
                c
            })
            .collect();

        // If the reviewed adapter introduced any code-hash-bound constraint, the rule's
        // effect-minimality claim is valid only while the target's code hash holds — escalate
        // the drift policy from evidence-only/warn to adapter-required/refuse (§6.1).
        let adapter_derived = allowed_calls.iter().any(|c| {
            c.args
                .iter()
                .any(|a| matches!(a.provenance, Provenance::AdapterDerived { .. }))
        });
        if adapter_derived {
            if let Some(t) = target_code_hash.as_mut() {
                t.role = TargetHashRole::AdapterRequired;
                t.on_drift = DriftResponse::Refuse;
            }
        }

        // Compose-first: reviewed spending limit only where its semantics fit (§4.3) —
        // it understands SEP-41 `transfer` and nothing else.
        let mut policies = Vec::new();
        if let Some(sl) = &decisions.spending_limit {
            let transfer_count = allowed_calls
                .iter()
                .filter(|call| call.fn_name == "transfer")
                .count();
            if transfer_count == allowed_calls.len() {
                match input.spending_limit_capability {
                    Some(capability) => {
                        match validate_spending_limit_shape(sl, &allowed_calls, calls) {
                            Ok(()) => {
                                policies.push(PolicyRef::Reviewed {
                                    kind: "oz:spending_limit".to_string(),
                                    capability,
                                    params: ReviewedParams::SpendingLimit {
                                        limit: sl.limit.clone(),
                                        period_ledgers: sl.period_ledgers,
                                    },
                                });
                                rationale.push(format!(
                                    "composed reviewed oz:spending_limit on {contract} \
                                     (defense-in-depth cumulative cap over arg 2 of SEP-41 \
                                     transfer; it does not constrain the recipient — the generated \
                                     scope policy does)"
                                ));
                            }
                            Err(reason) => errors.push(SynthError::InvalidDecision(reason)),
                        }
                    }
                    None => errors.push(SynthError::UnregisteredPolicy(
                        "spending-limit composition requested but no reviewed \
                         spending-limit capability is registered for this network"
                            .to_string(),
                    )),
                }
            } else if transfer_count == 0 {
                errors.push(SynthError::UnsupportedPattern(format!(
                    "spending-limit composition requested for {contract}, but the rule \
                     grants no SEP-41 `transfer` — the reviewed policy only understands \
                     transfer"
                )));
            } else {
                errors.push(SynthError::UnsupportedPattern(format!(
                    "spending-limit composition requested for {contract}, but the rule mixes \
                     transfer with other functions; the reviewed policy supports only SEP-41 \
                     `transfer`, so attach it only to a transfer-only rule"
                )));
            }
        }
        // The generated scope(+count) policy always carries the signer predicate and
        // tuple scoping; identified pre-build by template family (§4.10).
        policies.push(PolicyRef::Generated {
            kind: GENERATED_POLICY_KIND.to_string(),
            template_family: input.template_family.clone(),
            capability_schema: input.template_capability_schema,
        });

        let state = match decisions.max_calls {
            Some(max_calls) => {
                let largest_observed_sequence = calls
                    .iter()
                    .fold(BTreeMap::<usize, u32>::new(), |mut counts, call| {
                        *counts.entry(call.recording_index).or_default() += 1;
                        counts
                    })
                    .into_values()
                    .max()
                    .unwrap_or(0);
                if max_calls < largest_observed_sequence {
                    errors.push(SynthError::InvalidDecision(format!(
                        "max_calls {max_calls} is below the {largest_observed_sequence} calls \
                         observed for {contract} in one representative recording"
                    )));
                }
                vec![StateSpec::CallCountPerInstallation { max_calls }]
            }
            None => {
                rationale.push(format!(
                    "{contract}: NO CALL CAP — the user explicitly acknowledged unlimited calls \
                     (high blast radius)"
                ));
                vec![]
            }
        };

        rules.push(RuleSpec {
            context: ContextSpec {
                context_type: ContextType::CallContract,
                contract: contract.clone(),
                target_code_hash,
            },
            valid_until: decisions.valid_until_ledger.map(|l| ValidUntil {
                ledger: LedgerSeq(l),
                approx_time: None,
            }),
            authorization: authorization.clone(),
            allowed_calls,
            policies,
            state,
        });
    }

    // Unused widenings are decisions that matched nothing — surface them, fail closed. Asking
    // only whether the argument ended up widened is sound because no two widenings name the
    // same argument (refused above), so a widened argument is this decision's.
    for w in &decisions.widenings {
        let Some(rule) = rules.iter().find(|r| {
            r.context.contract == w.contract
                && r.allowed_calls.iter().any(|c| {
                    c.fn_name == w.fn_name
                        && c.args
                            .iter()
                            .any(|a| a.index == w.arg_index && a.constraint.is_widening())
                })
        }) else {
            errors.push(SynthError::AmbiguousArgSemantics {
                contract: w.contract.clone(),
                fn_name: w.fn_name.clone(),
                arg_index: w.arg_index,
                reason: "widening matched no observed numeric argument".to_string(),
            });
            continue;
        };
        // Decisions name an argument, not a recorded call. Where the function was recorded as
        // several distinct calls, this one widening would loosen the argument in each — the
        // second payment's amount raised along with the first's. One argument of one recorded
        // call is what a widening claims, and nothing in a decision can say which call, so it is
        // refused. Calls that differ only in this argument collapse into one tuple: one call's.
        let widened_calls = rule
            .allowed_calls
            .iter()
            .filter(|c| {
                c.fn_name == w.fn_name
                    && c.args.iter().any(|a| {
                        a.index == w.arg_index
                            && matches!(a.provenance, Provenance::UserWidened { .. })
                    })
            })
            .count();
        if widened_calls > 1 {
            let (contract, fn_name, arg_index) = (&w.contract, &w.fn_name, w.arg_index);
            errors.push(SynthError::InvalidDecision(format!(
                "widening {contract}/{fn_name} arg {arg_index}: this widening would apply to \
                 {widened_calls} distinct recorded calls of {fn_name} on {contract}, loosening \
                 argument {arg_index} of each; a widening loosens one argument of one recorded \
                 call, and a decision cannot name which. Keep the argument exact, or synthesize \
                 from recordings in which {fn_name} is one distinct call"
            )));
        }
        // An applied numeric bound sits on an i128 (any other argument is refused above), and an
        // i128 is signed: a cap renders only `x > max → deny`, so the generated policy passes
        // every negative amount (cf. OpenZeppelin's v0.7.0 audit, L-06). A range from i128::MIN
        // renders exactly that check too, since a comparison against the type's own minimum is
        // left out. A floor of zero would infer a direction from the XDR type alone, and one
        // argument carries one bound, so the open floor is a decision the user states or
        // synthesis asks for.
        let open_floor = match &w.bound {
            WideningBound::LeI128 { max } => Some((
                format!("the cap at {max}"),
                format!(
                    "a range (range_i128, such as 0..={max}; needs development registry version 7 \
                     or later)"
                ),
            )),
            WideningBound::RangeI128 { min, max } if starts_at_the_type_minimum(min) => Some((
                format!(
                    "the range {min}..={max}, which starts at i128::MIN and so is the cap at \
                     {max},"
                ),
                format!("a floor above i128::MIN (such as 0..={max})"),
            )),
            _ => None,
        };
        // A widening already refused as stated is not asked about its floor as well: the
        // acknowledgement the question invites would not make it acceptable.
        let refused = errors.iter().any(|e| {
            matches!(e, SynthError::InvalidDecision(message) if message.starts_with(&format!(
                "widening {}/{} arg {}:",
                w.contract, w.fn_name, w.arg_index
            )))
        });
        if let Some((subject, instead)) = open_floor.filter(|_| !refused) {
            let (contract, fn_name, arg_index) = (&w.contract, &w.fn_name, w.arg_index);
            let refusal = negative_amount_refusal(rule, arg_index);
            if w.no_floor_acknowledged {
                rationale.push(format!(
                    "{contract}/{fn_name} arg {arg_index}: NO FLOOR — the user acknowledged that \
                     {subject} admits every smaller value, negative amounts included; {refusal}"
                ));
            } else {
                errors.push(SynthError::NeedsDecision(format!(
                    "widening {contract}/{fn_name} arg {arg_index}: floor: {subject} on this \
                     signed amount sets no floor, so every smaller value passes it, negative \
                     amounts included; {refusal}. Bound both ends instead with {instead}, or \
                     acknowledge the open floor (no_floor_acknowledged, only on the user's \
                     explicit acceptance), or keep the argument exact"
                )));
            }
        } else if let WideningBound::RangeI128 { min, max } = &w.bound {
            // A range's floor is the user's explicit decision, so nothing is asked; but a floor
            // below zero still admits negative amounts, and the report says how far.
            let (contract, fn_name, arg_index) = (&w.contract, &w.fn_name, w.arg_index);
            if let Ok(low) = min.parse::<i128>() {
                if low < 0 {
                    rationale.push(format!(
                        "{contract}/{fn_name} arg {arg_index}: NEGATIVE FLOOR — the user's range \
                         {low}..={max} admits negative amounts down to {low}; the generated scope \
                         policy refuses only below that"
                    ));
                }
            }
        }
    }
    // An adapter's cap sets no floor either. It is the adapter's reviewed claim, not a question
    // for the user, but the report states the open floor as plainly as for a user's cap.
    for rule in &rules {
        for call in &rule.allowed_calls {
            for arg in &call.args {
                if let (Constraint::LeI128 { max }, Provenance::AdapterDerived { adapter, .. }) =
                    (&arg.constraint, &arg.provenance)
                {
                    rationale.push(format!(
                        "{}/{} arg {}: NO FLOOR — adapter '{adapter}' caps this argument at {max} \
                         from its reviewed maximum-input role and sets no floor, so every smaller \
                         value passes, negative amounts included; {}",
                        rule.context.contract,
                        call.fn_name,
                        arg.index,
                        negative_amount_refusal(rule, arg.index)
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let spec = PolicySpec {
        schema: SPEC_SCHEMA.to_string(),
        name: decisions.grant_name.clone(),
        network_id: network,
        registry_snapshot: input.registry_snapshot,
        smart_account: input.account.clone(),
        rules,
        evidence: Evidence {
            recordings: recording_hashes
                .iter()
                .map(|(h, b)| RecordingRef {
                    hash: *h,
                    trust: b.trust,
                })
                .collect(),
        },
    };

    // The pure synthesizer is a public library boundary, not just an implementation detail
    // behind the toolkit facade. Never return a spec that fails its own security typestate:
    // malformed user decisions (duplicate logical signers, non-canonical numeric bounds,
    // invalid tuple shapes, etc.) fail here before codegen can observe them.
    if let Err(spec_errors) = spec.clone().validate() {
        return Err(spec_errors
            .into_iter()
            .map(|error| SynthError::InvalidDecision(error.to_string()))
            .collect());
    }

    Ok(SynthesisOutput { spec, rationale })
}

/// Validate the exact semantic assumptions made by the pinned OZ spending-limit policy.
///
/// Calls within one recording (one transaction) are treated as a single representative sequence
/// inside the rolling window and must fit cumulatively. Separate recordings are not added
/// together: they carry no durable fact about their relative order or distance in ledgers, so
/// treating them as one session would invent workflow semantics. At runtime the reviewed policy
/// still enforces the configured cumulative window across every call.
fn validate_spending_limit_shape(
    choice: &SpendingLimitChoice,
    allowed_calls: &[AllowedCall],
    observed_calls: &[&Observed<'_>],
) -> Result<(), String> {
    let limit = choice.limit.parse::<i128>().map_err(|_| {
        "spending limit must be the canonical decimal representation of an i128".to_string()
    })?;
    if limit <= 0 || choice.limit != limit.to_string() || choice.period_ledgers == 0 {
        return Err(
            "spending limit requires a canonical positive i128 limit and a nonzero period"
                .to_string(),
        );
    }

    for call in allowed_calls {
        let amount = call.args.iter().find(|arg| arg.index == 2).ok_or_else(|| {
            "oz:spending_limit requires SEP-41 transfer amount at argument 2".to_string()
        })?;
        match &amount.constraint {
            Constraint::EqI128 { value } => {
                let value = value.parse::<i128>().map_err(|_| {
                    "transfer argument 2 must be constrained as a canonical i128".to_string()
                })?;
                if !(0..=limit).contains(&value) {
                    return Err(format!(
                        "exact transfer amount {value} is outside the spending-limit range \
                         0..={limit}"
                    ));
                }
            }
            Constraint::LeI128 { max } => {
                let max = max.parse::<i128>().map_err(|_| {
                    "transfer argument 2 must be constrained as a canonical i128".to_string()
                })?;
                if max < 0 {
                    return Err(
                        "transfer amount upper bound admits no nonnegative amount".to_string()
                    );
                }
            }
            Constraint::GeI128 { min } => {
                let min = min.parse::<i128>().map_err(|_| {
                    "transfer argument 2 must be constrained as a canonical i128".to_string()
                })?;
                if min > limit {
                    return Err(format!(
                        "transfer amount lower bound {min} exceeds spending limit {limit}; the \
                         composed policies would deny every matching amount"
                    ));
                }
            }
            Constraint::RangeI128 { min, max } => {
                let (Ok(min), Ok(max)) = (min.parse::<i128>(), max.parse::<i128>()) else {
                    return Err(
                        "transfer argument 2 must be constrained as a canonical i128".to_string(),
                    );
                };
                if max < 0 || min > limit {
                    return Err(format!(
                        "transfer amount range {min}..={max} shares no amount with the spending \
                         limit's 0..={limit}; the composed policies would deny every matching \
                         amount"
                    ));
                }
            }
            Constraint::EqAddress { .. } | Constraint::EqScval { .. } | Constraint::AnyValue => {
                return Err(
                    "oz:spending_limit requires every transfer argument 2 to be constrained as \
                     i128"
                        .to_string(),
                );
            }
        }
    }

    let mut representative_totals = BTreeMap::<usize, i128>::new();
    for call in observed_calls {
        let Some(ArgSummary::I128(amount)) = call.args.get(2) else {
            return Err(format!(
                "observed {} argument 2 is not an i128 transfer amount",
                call.fn_name
            ));
        };
        if *amount < 0 || *amount > limit {
            return Err(format!(
                "observed transfer amount {amount} is outside the spending-limit range \
                 0..={limit}"
            ));
        }
        let total = representative_totals
            .entry(call.recording_index)
            .or_default();
        *total = total.checked_add(*amount).ok_or_else(|| {
            "representative transfer amounts overflow i128 when accumulated".to_string()
        })?;
    }
    if let Some(total) = representative_totals
        .into_values()
        .find(|total| *total > limit)
    {
        return Err(format!(
            "one representative transaction's transfer sequence totals {total}, above spending \
             limit {limit}; calls in one recording necessarily share the rolling window"
        ));
    }
    Ok(())
}

/// What refuses a negative value at a capped argument of `rule`. Never the generated scope policy:
/// a cap renders only `x > max → deny`. The reviewed spending limit refuses a negative transfer
/// amount, and it reads argument 2 of the transfer-only rule it is composed into (composition
/// refuses any other rule shape); anywhere else only the target contract is left.
fn negative_amount_refusal(rule: &RuleSpec, arg_index: u32) -> &'static str {
    let spending_limit = rule.policies.iter().any(
        |policy| matches!(policy, PolicyRef::Reviewed { kind, .. } if kind == "oz:spending_limit"),
    );
    if spending_limit && arg_index == 2 {
        "the generated scope policy refuses no negative amount; the composed spending limit does"
    } else {
        "the generated scope policy refuses no negative amount, so only the target contract can \
         refuse one"
    }
}

fn resolve_target_code_hash(
    contract: &str,
    recordings: &[(Hash32, &RecordingBundle)],
    errors: &mut Vec<SynthError>,
    rationale: &mut Vec<String>,
) -> Option<TargetCodeHash> {
    let mut wasm: Option<(Hash32, LedgerSeq)> = None;
    let mut saw_stellar_asset = false;
    for (_, bundle) in recordings {
        let Some(observation) = bundle.contract_executables.get(contract) else {
            continue;
        };
        match observation.executable {
            ObservedExecutable::Wasm { code_hash } => match wasm {
                Some((existing, _)) if existing != code_hash => {
                    errors.push(SynthError::UnsupportedPattern(format!(
                        "target {contract} had conflicting observed wasm hashes {existing} and {code_hash}"
                    )));
                    return None;
                }
                Some((existing, ledger)) => {
                    wasm = Some((existing, ledger.max(observation.observed_ledger)));
                }
                None => wasm = Some((code_hash, observation.observed_ledger)),
            },
            ObservedExecutable::StellarAsset => saw_stellar_asset = true,
        }
    }
    if saw_stellar_asset && wasm.is_some() {
        errors.push(SynthError::UnsupportedPattern(format!(
            "target {contract} was observed as both a Wasm and Stellar Asset contract"
        )));
        return None;
    }
    match wasm {
        Some((hash, observed_ledger)) => Some(TargetCodeHash {
            hash,
            role: TargetHashRole::EvidenceOnly,
            observed_ledger,
            on_drift: DriftResponse::Warn,
        }),
        None => {
            if saw_stellar_asset {
                rationale.push(format!(
                    "target {contract} is the built-in Stellar Asset contract; it has no Wasm code hash"
                ));
            } else {
                rationale.push(format!(
                    "target {contract} has no executable observation; no code-specific adapter claims are permitted"
                ));
            }
            None
        }
    }
}

/// Exact-by-default constraint derivation for one observed call, with explicit widenings
/// applied where the user decided them.
fn exact_constraints(
    o: &Observed<'_>,
    input: &SynthesisInput,
    decisions: &UserDecisions,
    adapter: Option<&adapters::Adapter>,
    errors: &mut Vec<SynthError>,
    rationale: &mut Vec<String>,
) -> Vec<ArgConstraint> {
    let mut out = Vec::new();
    for (i, arg) in o.args.iter().enumerate() {
        let index = i as u32;
        let widening = decisions
            .widenings
            .iter()
            .find(|w| w.contract == o.contract && w.fn_name == o.fn_name && w.arg_index == index);

        let (constraint, provenance) = match (arg, widening) {
            // AnyValue is a type-agnostic maximal widening (e.g. a caller-chosen
            // deadline); it applies regardless of the observed arg type.
            (
                _,
                Some(
                    w @ Widening {
                        bound: WideningBound::AnyValue,
                        ..
                    },
                ),
            ) => {
                if let Some(finding) = adapter.and_then(|ad| against_adapter_role(o, index, w, ad))
                {
                    if !errors.contains(&finding) {
                        errors.push(finding);
                    }
                }
                rationale.push(format!(
                    "{}/{} arg {index}: user-widened to ACCEPT ANY VALUE ({}), blast \
                     radius {:?} — this argument is unconstrained",
                    o.contract, o.fn_name, w.intent, w.blast_radius
                ));
                (
                    Constraint::AnyValue,
                    Provenance::UserWidened {
                        intent: w.intent.clone(),
                        blast_radius: w.blast_radius,
                    },
                )
            }
            // Numeric bounds are only meaningful for i128 amounts; anything else is
            // ambiguous semantics and fails closed.
            (ArgSummary::I128(observed), Some(w)) => {
                rationale.push(format!(
                    "{}/{} arg {index}: user-widened ({}), blast radius {:?}",
                    o.contract, o.fn_name, w.intent, w.blast_radius
                ));
                // A widening loosens the recorded call. A bound that excludes the recorded value
                // would refuse the call the grant was built from, so it is not a widening at all.
                if let Some(bound) = excluding_bound(&w.bound, *observed) {
                    let finding = SynthError::InvalidDecision(format!(
                        "widening {}/{} arg {index}: {bound} excludes the recorded value \
                         {observed}; a widening loosens the recorded call and cannot refuse it",
                        o.contract, o.fn_name
                    ));
                    if !errors.contains(&finding) {
                        errors.push(finding);
                    }
                }
                // A bound against an adapter's reviewed role is refused for that alone: asking
                // for a higher rating as well would suggest the rating could repair it.
                if let Some(finding) = adapter
                    .and_then(|ad| against_adapter_role(o, index, w, ad))
                    .or_else(|| uncapped_below_high(o, index, w, adapter))
                {
                    if !errors.contains(&finding) {
                        errors.push(finding);
                    }
                }
                (
                    match &w.bound {
                        WideningBound::LeI128 { max } => Constraint::LeI128 { max: max.clone() },
                        WideningBound::GeI128 { min } => Constraint::GeI128 { min: min.clone() },
                        WideningBound::RangeI128 { min, max } => Constraint::RangeI128 {
                            min: min.clone(),
                            max: max.clone(),
                        },
                        WideningBound::AnyValue => unreachable!("handled above"),
                    },
                    Provenance::UserWidened {
                        intent: w.intent.clone(),
                        blast_radius: w.blast_radius,
                    },
                )
            }
            (other, Some(w)) => {
                errors.push(SynthError::AmbiguousArgSemantics {
                    contract: o.contract.clone(),
                    fn_name: o.fn_name.clone(),
                    arg_index: index,
                    reason: format!(
                        "cannot apply a numeric bound to a non-i128 argument ({}); the XDR \
                         type alone never determines bound direction (use any_value to \
                         explicitly leave it unconstrained)",
                        arg_kind(other)
                    ),
                });
                let _ = w;
                (exact_for(other, input), Provenance::ObservedExact)
            }
            // No user decision for this arg: a reviewed adapter bound to the target's code
            // hash may derive a safe-direction widening (the only non-user widening path).
            (arg, None) => {
                let observed_i128 = match arg {
                    ArgSummary::I128(v) => Some(*v),
                    _ => None,
                };
                match adapter.and_then(|ad| {
                    ad.role(&o.fn_name, i)
                        .and_then(|role| role.widening(observed_i128))
                        .map(|bound| (ad, bound))
                }) {
                    Some((ad, bound)) => {
                        rationale.push(if matches!(bound, WideningBound::AnyValue) {
                            // As open as a user's any-value decision, which validation holds to
                            // high blast radius; no user chose it, so the report must say so.
                            format!(
                                "{}/{} arg {index}: adapter '{}' leaves this argument \
                                 UNCONSTRAINED (any value) from its reviewed caller-chosen role \
                                 — a high blast radius widening no user decided; valid only \
                                 while the target's code hash holds",
                                o.contract, o.fn_name, ad.name
                            )
                        } else {
                            format!(
                                "{}/{} arg {index}: adapter '{}' derived a code-hash-bound \
                                 widening from its reviewed argument role (valid only while the \
                                 target's code hash holds)",
                                o.contract, o.fn_name, ad.name
                            )
                        });
                        let constraint = match bound {
                            WideningBound::LeI128 { max } => Constraint::LeI128 { max },
                            WideningBound::GeI128 { min } => Constraint::GeI128 { min },
                            WideningBound::RangeI128 { min, max } => {
                                Constraint::RangeI128 { min, max }
                            }
                            WideningBound::AnyValue => Constraint::AnyValue,
                        };
                        (
                            constraint,
                            Provenance::AdapterDerived {
                                adapter: ad.name.clone(),
                                code_hash: ad.target_code_hash,
                            },
                        )
                    }
                    None => (exact_for(arg, input), Provenance::ObservedExact),
                }
            }
        };
        out.push(ArgConstraint {
            index,
            constraint,
            provenance,
        });
    }
    out
}

/// How `bound` reads in a refusal, when it excludes the recorded `observed` value. A bound that
/// does not parse is left to the spec's own canonical-value check, which names it.
fn excluding_bound(bound: &WideningBound, observed: i128) -> Option<String> {
    let parse = |value: &str| value.parse::<i128>().ok();
    match bound {
        WideningBound::LeI128 { max } => parse(max)
            .filter(|max| observed > *max)
            .map(|max| format!("the cap <= {max}")),
        WideningBound::GeI128 { min } => parse(min)
            .filter(|min| observed < *min)
            .map(|min| format!("the floor >= {min}")),
        WideningBound::RangeI128 { min, max } => match (parse(min), parse(max)) {
            (Some(low), Some(high)) if observed < low || observed > high => {
                Some(format!("the range {low}..={high}"))
            }
            _ => None,
        },
        WideningBound::AnyValue => None,
    }
}

/// Whether a range's stated floor is the type's own minimum, which the generated check leaves
/// out: such a range has no floor, the same check as a cap at its maximum.
fn starts_at_the_type_minimum(min: &str) -> bool {
    min.parse::<i128>() == Ok(i128::MIN)
}

/// How a user's bound reads in a finding: the decision's own values, as written.
fn bound_text(bound: &WideningBound) -> String {
    match bound {
        WideningBound::LeI128 { max } => format!("the cap <= {max}"),
        WideningBound::GeI128 { min } => format!("the floor >= {min}"),
        WideningBound::RangeI128 { min, max } => format!("the range {min}..={max}"),
        WideningBound::AnyValue => "any_value".to_string(),
    }
}

/// The ends a bound enforces, as the generated check renders it: `(floor, cap)`, where `None` on
/// a side means every value on that side passes. An end at the type's own limit refuses nothing
/// and the generated check leaves it out, so it is no end. `None` overall means a stated end does
/// not parse; the spec's canonical-value check names that, and no finding here rests on it.
fn enforced_ends(bound: &WideningBound) -> Option<(Option<i128>, Option<i128>)> {
    let parse = |value: &str| value.parse::<i128>().ok();
    let floor = |value: i128| (value != i128::MIN).then_some(value);
    let cap = |value: i128| (value != i128::MAX).then_some(value);
    Some(match bound {
        WideningBound::LeI128 { max } => (None, cap(parse(max)?)),
        WideningBound::GeI128 { min } => (floor(parse(min)?), None),
        WideningBound::RangeI128 { min, max } => (floor(parse(min)?), cap(parse(max)?)),
        WideningBound::AnyValue => (None, None),
    })
}

/// The refusal of a user bound that loosens the unsafe side of an argument a reviewed adapter
/// declares, if it does. A minimum output is the target's own check on the result, so a bound
/// admitting anything below the recorded value weakens it — lowering it to zero removes it. A
/// maximum input is what the call may spend, so a bound with no cap lets it spend any amount. A
/// rating cannot restore either check, so neither is a question of blast radius: the decision
/// contradicts the reviewed role and is refused. Raising a minimum output, or capping an input at
/// a finite amount, stays the user's value decision.
fn against_adapter_role(
    o: &Observed<'_>,
    index: u32,
    w: &Widening,
    adapter: &adapters::Adapter,
) -> Option<SynthError> {
    let Some(ArgSummary::I128(observed)) = o.args.get(index as usize) else {
        return None;
    };
    let (floor, cap) = enforced_ends(&w.bound)?;
    let (contract, fn_name, name) = (&o.contract, &o.fn_name, &adapter.name);
    let bound = bound_text(&w.bound);
    match adapter.role(fn_name, index as usize)? {
        adapters::ArgRole::MinOutput if floor.is_none_or(|floor| floor < *observed) => {
            Some(SynthError::InvalidDecision(format!(
                "widening {contract}/{fn_name} arg {index}: adapter '{name}' reviews this \
                 argument as a minimum output, below which the target refuses the call; {bound} \
                 admits values below the recorded {observed}, which weakens that check. A \
                 decision may only raise a minimum output: keep it exact, or bound it from below \
                 at {observed} or higher"
            )))
        }
        adapters::ArgRole::MaxInput if cap.is_none() => Some(SynthError::InvalidDecision(format!(
            "widening {contract}/{fn_name} arg {index}: adapter '{name}' reviews this argument as \
             a maximum input; {bound} sets no cap on it, so the call may spend any amount. Bound \
             it from above with a cap or a range, or leave it undecided for the adapter's cap at \
             the recorded {observed}"
        ))),
        _ => None,
    }
}

/// The refusal of a user bound with no cap that rates itself below high, if it is one. Every
/// larger value passes it, which on an amount is any amount — on that side the reach of
/// `any_value`, which validation holds to high. The XDR type never says whether an argument is
/// an amount, so synthesis assumes it may be, with one exception: a minimum output a reviewed
/// adapter declares, where the open top only tightens the target's own check.
fn uncapped_below_high(
    o: &Observed<'_>,
    index: u32,
    w: &Widening,
    adapter: Option<&adapters::Adapter>,
) -> Option<SynthError> {
    if w.blast_radius == BlastRadius::High {
        return None;
    }
    let (_, cap) = enforced_ends(&w.bound)?;
    let min_output = adapter.and_then(|ad| ad.role(&o.fn_name, index as usize))
        == Some(&adapters::ArgRole::MinOutput);
    if cap.is_some() || min_output {
        return None;
    }
    let rating = format!("{:?}", w.blast_radius).to_lowercase();
    Some(SynthError::InvalidDecision(format!(
        "widening {}/{} arg {index}: {} sets no cap, so the generated policy admits every larger \
         value, which on an amount is any amount: a high blast radius, and this decision rates it \
         {rating}. Rate it high, or give it a finite maximum",
        o.contract,
        o.fn_name,
        bound_text(&w.bound)
    )))
}

fn exact_for(arg: &ArgSummary, input: &SynthesisInput) -> Constraint {
    match arg {
        ArgSummary::Address(a) if *a == input.selected_authorizer => Constraint::EqAddress {
            // SELF resolves at runtime, keeping generated wasm account-independent (§4.4).
            value: AddressRef::self_account(),
        },
        ArgSummary::Address(a) => Constraint::EqAddress {
            value: AddressRef::address(a.clone()),
        },
        ArgSummary::I128(v) => Constraint::EqI128 {
            value: v.to_string(),
        },
        ArgSummary::U64(v) => Constraint::EqScval {
            xdr_base64: scval_b64(stellar_xdr::ScVal::U64(*v)),
        },
        ArgSummary::U32(v) => Constraint::EqScval {
            xdr_base64: scval_b64(stellar_xdr::ScVal::U32(*v)),
        },
        ArgSummary::Symbol(s) => Constraint::EqScval {
            xdr_base64: s
                .as_bytes()
                .to_vec()
                .try_into()
                .map(|sym| scval_b64(stellar_xdr::ScVal::Symbol(stellar_xdr::ScSymbol(sym))))
                .unwrap_or_else(|_| String::new()),
        },
        ArgSummary::Other { xdr_base64 } => Constraint::EqScval {
            xdr_base64: xdr_base64.clone(),
        },
    }
}

fn scval_b64(v: stellar_xdr::ScVal) -> String {
    v.to_xdr_base64(Limits::none()).unwrap_or_default()
}

fn arg_kind(a: &ArgSummary) -> &'static str {
    match a {
        ArgSummary::Address(_) => "address",
        ArgSummary::I128(_) => "i128",
        ArgSummary::U64(_) => "u64",
        ArgSummary::U32(_) => "u32",
        ArgSummary::Symbol(_) => "symbol",
        ArgSummary::Other { .. } => "opaque scval",
    }
}

/// Describe a movement's parties the way its kind actually defines them.
///
/// A mint has no sender and a burn no recipient — by construction, not by omission — and an
/// approval's counterparty is the spender rather than a `to`. One generic from/to sentence
/// reports all three as missing evidence, which is a defect claim about a well-formed event.
///
/// `locate` turns an address into the argument holding it, so the direction stays checkable by
/// eye; an address the vector does not hold is worth saying rather than hiding.
fn movement_parties(movement: &TokenMovement, locate: &dyn Fn(&str) -> String) -> String {
    let named = |who: &Option<String>| -> String {
        match who {
            Some(address) => locate(address),
            // Reachable only when the decoder found no address in a topic position its kind
            // defines, so here the absence really is missing evidence.
            None => "a party the event did not record".to_string(),
        }
    };
    match movement.kind {
        MovementKind::Transfer => {
            format!("from {} to {}", named(&movement.from), named(&movement.to))
        }
        MovementKind::Mint => format!("minted to {}", named(&movement.to)),
        MovementKind::Burn => format!("burned from {}", named(&movement.from)),
        MovementKind::Approve => format!(
            "approved by {} for spender {}",
            named(&movement.from),
            named(&movement.spender)
        ),
    }
}

/// Which observed argument carries the value a recorded token movement reports.
///
/// **This returns text and nothing else, and that is the design.** A token movement is a
/// post-execution *effect*: the policy runs inside `__check_auth`, which sees authorization
/// contexts and no events at all, so a constraint predicated on a movement would be
/// unenforceable at the moment it is evaluated — only the authorization tree is an enforcement
/// fact (§4.1). Returning `Vec<String>` makes that structural: no movement can produce or alter
/// a constraint, because nothing here can reach a `PolicySpec`.
///
/// That is the guarantee, and it is narrower than "movements cannot move the spec hash" — which
/// is false. A bundle is hashed whole and the spec pins that hash in `evidence.recordings`, so
/// editing a movement does change the spec hash. It should: the spec then came from a different
/// recording, and saying so is the evidence chain working.
///
/// It exists because the toolkit refuses, by design, to guess an argument's direction — the XDR
/// type alone never determines it, and `SynthError::AmbiguousArgSemantics` fails closed rather
/// than assume. A movement carries the amount and the parties, which is exactly the evidence a
/// human needs to settle that question, so it is presented rather than applied.
///
/// Every movement produces a line, including one whose amount could not be decoded and one that
/// matches no argument. Silence is the failure mode worth avoiding here: a movement that fits
/// nothing is precisely the case a reader needs to see.
fn value_movement_evidence(
    observed: &[Observed],
    recordings: &[(Hash32, &RecordingBundle)],
) -> Vec<String> {
    let mut lines = Vec::new();
    for (rec_idx, (_, bundle)) in recordings.iter().enumerate() {
        // A movement is evidence about the transaction that emitted it. Matching it against
        // calls from other recordings lets an integer coincidence attribute value across
        // unrelated transactions — a confident claim about the wrong call, which is worse than
        // no claim at all.
        let from_this_recording: Vec<&Observed> = observed
            .iter()
            .filter(|o| o.recording_index == rec_idx)
            .collect();

        for (mv_idx, movement) in bundle.token_movements.iter().enumerate() {
            let where_it_moved = format!("recordings[{rec_idx}]/movements[{mv_idx}]");
            let Some(amount) = movement.amount else {
                // `decode_token_event` keeps a recognized transfer, mint or burn whose data
                // carries no decodable amount, so this is not an approval-only shape. There is
                // nothing to match on, but the movement is still evidence that something moved.
                lines.push(format!(
                    "evidence — token movement {where_it_moved} ({:?}) was recorded with no \
                     decodable amount, so it cannot be matched to an argument. Its parties: {}.",
                    movement.kind,
                    movement_parties(movement, &|address| address.to_string()),
                ));
                continue;
            };

            let mut matched = false;
            for o in &from_this_recording {
                // Equal amounts in two arguments are ordinary — an input and an output that
                // coincide, a fee equal to a principal. Taking the first would name an argument
                // the evidence does not single out.
                let candidates: Vec<usize> = o
                    .args
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| matches!(a, ArgSummary::I128(v) if *v == amount))
                    .map(|(i, _)| i)
                    .collect();
                if candidates.is_empty() {
                    continue;
                }
                matched = true;

                let locate = |address: &str| -> String {
                    o.args
                        .iter()
                        .position(|a| matches!(a, ArgSummary::Address(x) if x == address))
                        .map(|i| format!("arg {i}"))
                        .unwrap_or_else(|| format!("{address}, which no argument holds"))
                };
                let parties = movement_parties(movement, &locate);
                let verdict = match candidates.as_slice() {
                    [only] => format!("so arg {only} is the one carrying value"),
                    many => format!(
                        "but {} match that amount, so it does not single one out",
                        many.iter()
                            .map(|i| format!("arg {i}"))
                            .collect::<Vec<_>>()
                            .join(" and ")
                    ),
                };
                lines.push(format!(
                    "{}/{}: evidence — token movement {where_it_moved} ({:?}) moves {amount} \
                     {parties}, {verdict}. Evidence for your decision, never applied on its \
                     own: the policy cannot see events, so this constrains nothing.",
                    o.contract, o.fn_name, movement.kind,
                ));
            }

            if !matched {
                // Worth reporting, but not worth asserting a cause. A recording holds
                // transaction-wide events that cannot be reliably attributed to one
                // authorization, so this movement may belong to another call or another
                // authorizer entirely — or the call may indeed have executed with a vector the
                // authorization did not pin. The evidence does not distinguish those.
                lines.push(format!(
                    "evidence — token movement {where_it_moved} ({:?}) moves {amount} \
                     {}, and no authorized argument in this recording holds that value. It may \
                     belong to another call or authorizer in the same transaction, or the call \
                     may have executed with a vector the authorization did not pin; this \
                     evidence does not say which.",
                    movement.kind,
                    movement_parties(movement, &|address| address.to_string()),
                ));
            }
        }
    }
    lines
}

/// One observed authorized call (private working view).
struct Observed<'a> {
    contract: String,
    fn_name: String,
    args: &'a [ArgSummary],
    evidence_path: String,
    /// Which recording observed this call. Carried as an index rather than parsed back out of
    /// `evidence_path`, so evidence that belongs to one transaction cannot be attributed to a
    /// call from another.
    recording_index: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_domain::sha256;
    use ozpb_recorder_core::{
        fixtures, record, ExecutableObservation, ObservedExecutable, RecordOptions,
    };

    fn transfer_bundle() -> RecordingBundle {
        let mut bundle = record(&fixtures::executed_snapshot(), RecordOptions::default()).unwrap();
        bundle.contract_executables.insert(
            account_strkey(),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm {
                    code_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                },
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );
        bundle.contract_executables.insert(
            format!("{}", stellar_strkey::Contract([2u8; 32])),
            ExecutableObservation {
                executable: ObservedExecutable::StellarAsset,
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );
        bundle
    }

    fn account_strkey() -> String {
        // The fixture smart account is the contract id [1u8; 32].
        format!("{}", stellar_strkey::Contract([1u8; 32]))
    }

    fn merchant_strkey() -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([3u8; 32]))
    }

    fn delegate_strkey(byte: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
    }

    fn account_record() -> SmartAccountRecord {
        SmartAccountRecord {
            address: account_strkey(),
            observed_code_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            registry_resolution: "stellar-accounts@0.7.x (test)".to_string(),
        }
    }

    fn input() -> SynthesisInput {
        SynthesisInput {
            bundles: vec![transfer_bundle()],
            selected_authorizer: account_strkey(),
            account: account_record(),
            registry_snapshot: sha256(b"registry"),
            spending_limit_capability: Some(pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM),
            template_family: "policy-templates/scope@1".to_string(),
            template_capability_schema: sha256(b"policy-templates/scope@1:capability-algebra"),
            adapters: vec![],
        }
    }

    fn delegate() -> SignerSpec {
        SignerSpec::Delegated {
            address: delegate_strkey(7),
        }
    }

    fn decisions() -> UserDecisions {
        UserDecisions {
            grant_name: "sub-transfer".to_string(),
            delegate_signers: vec![delegate()],
            predicate: PredicateChoice::AnyOf,
            valid_until_ledger: Some(4_223_456),
            no_expiry_acknowledged: false,
            max_calls: Some(12),
            unlimited_calls_acknowledged: false,
            widenings: vec![],
            spending_limit: Some(SpendingLimitChoice {
                limit: "500000000".to_string(),
                period_ledgers: 120_960,
            }),
        }
    }

    #[test]
    fn happy_path_synthesizes_a_validating_exact_spec() {
        let out = synthesize(&input(), &decisions()).unwrap();
        let validated = out.spec.clone().validate().expect("spec must validate");
        let spec = validated.spec();

        assert_eq!(spec.rules.len(), 1);
        let rule = &spec.rules[0];
        assert!(rule.context.contract.starts_with('C'));
        assert_eq!(rule.allowed_calls.len(), 1);
        let call = &rule.allowed_calls[0];
        assert_eq!(call.fn_name, "transfer");
        assert_eq!(call.args.len(), 3);

        // Exact-by-default + SELF resolution.
        assert_eq!(
            call.args[0].constraint,
            Constraint::EqAddress {
                value: AddressRef::self_account()
            },
            "the observed from == selected authorizer must become SELF"
        );
        assert_eq!(
            call.args[1].constraint,
            Constraint::EqAddress {
                value: AddressRef::address(merchant_strkey())
            }
        );
        assert_eq!(
            call.args[2].constraint,
            Constraint::EqI128 {
                value: "500000000".to_string()
            }
        );
        for a in &call.args {
            assert_eq!(a.provenance, Provenance::ObservedExact);
        }

        // Strict signer set is the default for named identities.
        assert!(rule.authorization.strict_signer_set);

        // Composition: reviewed spending limit + generated scope policy.
        assert_eq!(rule.policies.len(), 2);
        assert!(
            matches!(&rule.policies[0], PolicyRef::Reviewed { kind, .. } if kind == "oz:spending_limit")
        );
        assert!(
            matches!(&rule.policies[1], PolicyRef::Generated { template_family, .. } if template_family == "policy-templates/scope@1")
        );

        // Evidence mapping present.
        assert_eq!(call.justified_by, vec!["recordings[0]/auth[0]".to_string()]);
        assert_eq!(spec.evidence.recordings.len(), 1);
    }

    #[test]
    fn synthesis_rejects_an_account_hash_not_observed_by_the_recorder() {
        let mut input = input();
        input.bundles[0].contract_executables.insert(
            account_strkey(),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm {
                    code_hash: sha256(b"different-account-wasm"),
                },
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );

        let errors = synthesize(&input, &decisions()).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SynthError::IncompatibleAccount(_))));
    }

    #[test]
    fn synthesis_carries_observed_target_hash_into_the_rule_context() {
        let mut input = input();
        let target_hash = sha256(b"reviewed-target-wasm");
        input.bundles[0].contract_executables.insert(
            format!("{}", stellar_strkey::Contract([2u8; 32])),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm {
                    code_hash: target_hash,
                },
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );

        let output = synthesize(&input, &decisions()).unwrap();
        let target = output.spec.rules[0]
            .context
            .target_code_hash
            .as_ref()
            .expect("Wasm targets must retain their observed hash");
        assert_eq!(target.hash, target_hash);
        assert_eq!(target.observed_ledger, LedgerSeq(4_200_100));
    }

    // --- target code-hash agreement across recordings ------------------------------------
    //
    // `resolve_target_code_hash` folds every recording's observation of the target into one
    // hash, and refuses when two recordings disagree — the target's code changed between
    // them, so constraints derived from one may not describe the other. Mutation testing
    // found the whole guard could be forced true or false, and its `!=` inverted, without
    // any test noticing, because no test fed the same target twice.

    /// Two recordings of the same target. `code_hash` decides what each observed; the ledger
    /// differs so the bundles hash differently and are not deduplicated into one.
    fn two_recordings_of_target(first: Hash32, second: Hash32) -> Vec<RecordingBundle> {
        let target = format!("{}", stellar_strkey::Contract([2u8; 32]));
        [(first, 4_200_100u32), (second, 4_200_200u32)]
            .into_iter()
            .map(|(code_hash, ledger)| {
                let mut bundle = transfer_bundle();
                bundle.contract_executables.insert(
                    target.clone(),
                    ExecutableObservation {
                        executable: ObservedExecutable::Wasm { code_hash },
                        observed_ledger: LedgerSeq(ledger),
                        last_modified_ledger: None,
                        live_until_ledger: None,
                    },
                );
                bundle
            })
            .collect()
    }

    #[test]
    fn recordings_that_agree_on_the_target_hash_are_accepted() {
        let agreed = sha256(b"reviewed-target-wasm");
        let mut input = input();
        input.bundles = two_recordings_of_target(agreed, agreed);

        let output = synthesize(&input, &decisions())
            .expect("recordings that agree on the target must not be refused");
        let target = output.spec.rules[0]
            .context
            .target_code_hash
            .as_ref()
            .expect("a Wasm target keeps its observed hash");
        assert_eq!(target.hash, agreed);
        assert_eq!(
            target.observed_ledger,
            LedgerSeq(4_200_200),
            "the latest observation of the same code wins"
        );
    }

    #[test]
    fn recordings_that_disagree_on_the_target_hash_are_refused() {
        let mut input = input();
        input.bundles =
            two_recordings_of_target(sha256(b"target-wasm-v1"), sha256(b"target-wasm-v2"));

        let errors = synthesize(&input, &decisions())
            .expect_err("a target whose code changed between recordings must fail closed");
        assert!(
            errors.iter().any(|error| matches!(
                error,
                SynthError::UnsupportedPattern(message) if message.contains("conflicting observed wasm hashes")
            )),
            "expected a conflicting-hash refusal, got {errors:?}"
        );
    }

    // --- threshold bounds -----------------------------------------------------------------
    //
    // `n == 0 || (n as usize) > count` rejects a threshold outside 1..=count. Both halves
    // were untested: no case used a threshold predicate at all, so `||` could become `&&`
    // and `>` could become `<` unnoticed.

    fn threshold_decisions(n: u32, signers: usize) -> UserDecisions {
        UserDecisions {
            predicate: PredicateChoice::Threshold { n },
            delegate_signers: (0..signers)
                .map(|i| SignerSpec::Delegated {
                    address: delegate_strkey(u8::try_from(i + 7).unwrap()),
                })
                .collect(),
            ..decisions()
        }
    }

    #[test]
    fn a_threshold_within_the_signer_count_is_accepted() {
        // 1-of-2: valid, so neither bound may reject it. Catches a lower bound that rejects
        // any threshold below the signer count.
        let output =
            synthesize(&input(), &threshold_decisions(1, 2)).expect("1-of-2 is a valid threshold");
        assert_eq!(
            output.spec.rules[0].authorization.kind,
            PredicateKind::Threshold { n: 1 }
        );
    }

    #[test]
    fn a_threshold_of_zero_or_above_the_signer_count_is_refused() {
        for (n, signers, why) in [
            (
                0u32,
                2usize,
                "a threshold of zero would authorize with no signatures",
            ),
            (
                3,
                2,
                "a threshold above the signer count can never be satisfied",
            ),
        ] {
            let errors = synthesize(&input(), &threshold_decisions(n, signers)).expect_err(why);
            assert!(
                errors.iter().any(|error| matches!(
                    error,
                    SynthError::NeedsDecision(message) if message.contains("threshold")
                )),
                "{why}: expected a threshold refusal for {n}-of-{signers}, got {errors:?}"
            );
        }
    }

    #[test]
    fn adapter_never_widens_a_call_with_the_wrong_whole_argument_shape() {
        use ozpb_recorder_core::{ArgSummary, AuthorizedCall, ObservedExecutable};
        let mut input = crate::fixtures::golden_input();
        let code_hash = ozpb_domain::sha256(b"synthetic-swap-shape");
        input.bundles[0]
            .contract_executables
            .get_mut(&crate::fixtures::golden_token_strkey())
            .unwrap()
            .executable = ObservedExecutable::Wasm { code_hash };
        input.adapters = vec![adapters::soroswap_router_adapter(code_hash)];
        input.spending_limit_capability = None;
        let mut decisions = crate::fixtures::golden_decisions();
        decisions.spending_limit = None;
        let path = stellar_xdr::ScVal::Vec(Some(
            vec![stellar_xdr::ScVal::Address(
                stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(
                    [2; 32],
                ))),
            )]
            .try_into()
            .unwrap(),
        ));
        let args = vec![
            ArgSummary::I128(1000),
            ArgSummary::I128(950),
            ArgSummary::Other {
                xdr_base64: path.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
            },
            ArgSummary::Address(crate::fixtures::golden_account_strkey()),
            ArgSummary::U64(2000),
        ];
        for mutation in 0..5 {
            let mut input = input.clone();
            let AuthorizedCall::Contract {
                fn_name,
                args: observed,
                ..
            } = &mut input.bundles[0].authorizations[0].root.call
            else {
                unreachable!()
            };
            *fn_name = "swap_exact_tokens_for_tokens".into();
            *observed = args.clone();
            match mutation {
                0 => observed.push(ArgSummary::U32(1)),
                1 => {
                    observed.pop();
                }
                2 => observed[2] = ArgSummary::U32(1),
                3 => observed[4] = ArgSummary::I128(2000),
                _ => {
                    observed[2] = ArgSummary::Other {
                        xdr_base64: stellar_xdr::ScVal::Vec(Some(
                            vec![stellar_xdr::ScVal::U32(1)].try_into().unwrap(),
                        ))
                        .to_xdr_base64(stellar_xdr::Limits::none())
                        .unwrap(),
                    }
                }
            }
            let output = synthesize(&input, &decisions).unwrap();
            assert!(
                output
                    .spec
                    .rules
                    .iter()
                    .flat_map(|r| &r.allowed_calls)
                    .flat_map(|c| &c.args)
                    .all(|a| !matches!(
                        a.provenance,
                        ozpb_domain::Provenance::AdapterDerived { .. }
                    )),
                "malformed call shape {mutation} was widened"
            );
        }
    }

    /// An argument the adapter leaves open is as unconstrained as a user's any-value decision,
    /// so the rationale must say so in the same terms, not as a routine derived bound.
    #[test]
    fn adapter_any_value_rationale_flags_high_blast_radius() {
        use ozpb_recorder_core::{ArgSummary, AuthorizedCall, ObservedExecutable};
        let mut input = crate::fixtures::golden_input();
        let code_hash = ozpb_domain::sha256(b"synthetic-swap-shape");
        input.bundles[0]
            .contract_executables
            .get_mut(&crate::fixtures::golden_token_strkey())
            .unwrap()
            .executable = ObservedExecutable::Wasm { code_hash };
        input.adapters = vec![adapters::Adapter::from_semantics(
            code_hash,
            ozpb_domain::target_adapters::soroswap_router(),
        )];
        input.spending_limit_capability = None;
        let mut decisions = crate::fixtures::golden_decisions();
        decisions.spending_limit = None;
        let path = stellar_xdr::ScVal::Vec(Some(
            vec![stellar_xdr::ScVal::Address(
                stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(
                    [2; 32],
                ))),
            )]
            .try_into()
            .unwrap(),
        ));
        let AuthorizedCall::Contract { fn_name, args, .. } =
            &mut input.bundles[0].authorizations[0].root.call
        else {
            unreachable!()
        };
        *fn_name = "swap_exact_tokens_for_tokens".into();
        *args = vec![
            ArgSummary::I128(1000),
            ArgSummary::I128(950),
            ArgSummary::Other {
                xdr_base64: path.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
            },
            ArgSummary::Address(crate::fixtures::golden_account_strkey()),
            ArgSummary::U64(2000),
        ];
        let output = synthesize(&input, &decisions).unwrap();
        let line = |arg: &str| {
            output
                .rationale
                .iter()
                .find(|line| line.contains(&format!("swap_exact_tokens_for_tokens arg {arg}:")))
                .cloned()
                .unwrap_or_default()
        };
        let deadline = line("4");
        assert!(
            deadline.contains("UNCONSTRAINED") && deadline.contains("high blast radius"),
            "the open deadline is reported as a routine bound: {deadline:?}"
        );
        assert!(deadline.contains("soroswap-router@1"));
        let input_bound = line("0");
        assert!(
            !input_bound.contains("high blast radius"),
            "a bounded input is not flagged as open: {input_bound:?}"
        );
    }

    #[test]
    fn a_reviewed_adapter_bound_to_the_observed_code_hash_derives_widenings() {
        use adapters::{Adapter, ArgRole, FnRoles};

        let target = format!("{}", stellar_strkey::Contract([2u8; 32]));
        let code_hash = sha256(b"reviewed-token-wasm");

        let mut input = input();
        // The recorder observed the target's on-chain code hash — the adapter binds to it.
        input.bundles[0].contract_executables.insert(
            target.clone(),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm { code_hash },
                observed_ledger: LedgerSeq(4_200_100),
                last_modified_ledger: None,
                live_until_ledger: None,
            },
        );
        // `amount` (arg 2) is a MaxInput → the reviewed adapter caps it from above; from/to
        // keep their exact roles. This is a non-user widening path: provenance is adapter-derived.
        let mut functions = std::collections::BTreeMap::new();
        functions.insert(
            "transfer".to_string(),
            FnRoles {
                fn_name: "transfer".to_string(),
                arg_types: vec![
                    ozpb_domain::target_adapters::ArgumentType::Address,
                    ozpb_domain::target_adapters::ArgumentType::Address,
                    ozpb_domain::target_adapters::ArgumentType::I128,
                ],
                arg_roles: vec![ArgRole::ExactOnly, ArgRole::ExactOnly, ArgRole::MaxInput],
            },
        );
        input.adapters = vec![Adapter {
            name: "reviewed-token@1".to_string(),
            target_code_hash: code_hash,
            functions,
        }];

        let mut d = decisions();
        d.widenings = vec![]; // no user widening — the adapter is the only widening source
        let out = synthesize(&input, &d).unwrap();
        let rule = &out.spec.rules[0];
        let call = &rule.allowed_calls[0];

        // arg 2 is adapter-derived: LeI128 capped at the observed amount, code-hash-bound.
        assert_eq!(
            call.args[2].constraint,
            Constraint::LeI128 {
                max: "500000000".to_string()
            }
        );
        assert!(
            matches!(
                &call.args[2].provenance,
                Provenance::AdapterDerived { adapter, code_hash: h }
                    if adapter == "reviewed-token@1" && *h == code_hash
            ),
            "arg 2 must carry AdapterDerived provenance, got {:?}",
            call.args[2].provenance
        );
        // ExactOnly-role args stay exact.
        assert_eq!(call.args[0].provenance, Provenance::ObservedExact);
        assert_eq!(call.args[1].provenance, Provenance::ObservedExact);

        // A code-hash-bound adapter claim escalates the drift policy to refuse-on-drift (§6.1).
        let target_hash = rule.context.target_code_hash.as_ref().unwrap();
        assert_eq!(target_hash.role, TargetHashRole::AdapterRequired);
        assert_eq!(target_hash.on_drift, DriftResponse::Refuse);

        // The adapter's cap sets no floor either. No user acknowledges it, so the rationale says
        // it, with what refuses a negative amount: here the composed spending limit, which reads
        // this transfer amount; without it, only the target.
        let open_floor = |refusal: &str| {
            format!(
                "{target}/transfer arg 2: NO FLOOR — adapter 'reviewed-token@1' caps this \
                 argument at 500000000 from its reviewed maximum-input role and sets no floor, so \
                 every smaller value passes, negative amounts included; {refusal}"
            )
        };
        assert!(
            out.rationale.contains(&open_floor(
                "the generated scope policy refuses no negative amount; the composed spending \
                 limit does"
            )),
            "{:#?}",
            out.rationale
        );
        d.spending_limit = None;
        let uncomposed = synthesize(&input, &d).unwrap();
        assert!(
            uncomposed.rationale.contains(&open_floor(
                "the generated scope policy refuses no negative amount, so only the target \
                 contract can refuse one"
            )),
            "{:#?}",
            uncomposed.rationale
        );

        // The adapter-derived spec still validates.
        assert!(out.spec.validate().is_ok());
    }

    #[test]
    fn synthesis_is_deterministic() {
        let a = synthesize(&input(), &decisions()).unwrap();
        let b = synthesize(&input(), &decisions()).unwrap();
        let ha = a.spec.validate().unwrap().hash();
        let hb = b.spec.validate().unwrap().hash();
        assert_eq!(ha, hb);
    }

    #[test]
    fn missing_delegates_is_an_open_question() {
        let mut d = decisions();
        d.delegate_signers.clear();
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::NeedsDecision(m) if m.contains("delegate"))));
    }

    #[test]
    fn duplicate_delegate_identities_fail_during_synthesis() {
        let mut d = decisions();
        d.delegate_signers.push(delegate());
        d.predicate = PredicateChoice::Threshold { n: 2 };
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_INVALID_DECISION:")),
            "synthesis must reject a threshold over duplicate logical signers: {errs:?}"
        );
    }

    #[test]
    fn hostile_numeric_widening_fails_during_synthesis() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let mut d = decisions();
        d.widenings = vec![Widening {
            contract,
            fn_name: "transfer".to_string(),
            arg_index: 2,
            bound: WideningBound::LeI128 {
                max: "({ return true; 0 } as i128) + 0".to_string(),
            },
            no_floor_acknowledged: true,
            intent: "hostile source token".to_string(),
            blast_radius: BlastRadius::High,
        }];
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_INVALID_DECISION:")),
            "synthesis must reject non-canonical i128 decisions before building a spec: {errs:?}"
        );
    }

    #[test]
    fn external_verifiers_are_rejected_without_a_runtime_code_binding() {
        let mut decisions = decisions();
        decisions.delegate_signers = vec![SignerSpec::External {
            verifier: format!("{}", stellar_strkey::Contract([8u8; 32])),
            verifier_code_hash: sha256(b"registered-but-not-runtime-bound-verifier"),
            key_hex: "11".repeat(32),
        }];
        let errors = synthesize(&input(), &decisions).unwrap_err();
        assert!(errors.iter().any(
            |error| matches!(error, SynthError::UnsupportedPattern(message)
                if message.contains("external verifiers are unavailable in Phase 1"))
        ));
    }

    #[test]
    fn missing_lifetime_needs_explicit_ack() {
        let mut d = decisions();
        d.valid_until_ledger = None;
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::NeedsDecision(m) if m.contains("lifetime"))));

        d.no_expiry_acknowledged = true;
        let out = synthesize(&input(), &d).unwrap();
        assert!(out.spec.rules[0].valid_until.is_none());
        assert!(out.spec.validate().is_ok());
    }

    #[test]
    fn decisions_without_cap_or_unlimited_ack_need_decision() {
        let mut d = decisions();
        d.max_calls = None;
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::NeedsDecision(m) if m.contains("call cap"))));

        d.unlimited_calls_acknowledged = true;
        let out = synthesize(&input(), &d).unwrap();
        assert!(out.spec.rules[0].state.is_empty());
        assert!(out
            .rationale
            .iter()
            .any(|line| line.contains("NO CALL CAP")));
        assert!(out.spec.validate().is_ok());
    }

    #[test]
    fn an_expiry_with_the_no_expiry_ack_is_contradictory() {
        let mut d = decisions();
        d.no_expiry_acknowledged = true;
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::InvalidDecision(m) if m.contains("lifetime"))));
    }

    #[test]
    fn a_call_cap_with_the_unlimited_ack_is_contradictory() {
        let mut d = decisions();
        d.unlimited_calls_acknowledged = true;
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::InvalidDecision(m) if m.contains("call cap"))));
    }

    #[test]
    fn wrong_authorizer_fails_closed() {
        let mut i = input();
        i.selected_authorizer = merchant_strkey();
        // The merchant never authorized anything in this recording.
        let errs = synthesize(&i, &decisions()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::AuthorizerNotFound(_))));
    }

    #[test]
    fn selected_authorizer_must_be_the_resolved_smart_account() {
        let mut i = input();
        i.account.address = merchant_strkey();
        let errs = synthesize(&i, &decisions()).unwrap_err();
        assert!(
            errs.iter()
                .any(|error| error.to_string().starts_with("E_INCOMPATIBLE_ACCOUNT:")),
            "SELF constraints and install metadata must refer to the selected authorizer: {errs:?}"
        );
    }

    #[test]
    fn widening_applies_only_with_explicit_decision_and_only_to_amounts() {
        // Applied to the i128 amount: becomes a bound with user_widened provenance.
        let mut d = decisions();
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        d.widenings = vec![Widening {
            contract: contract.clone(),
            fn_name: "transfer".to_string(),
            arg_index: 2,
            bound: WideningBound::LeI128 {
                max: "1000000000".to_string(),
            },
            no_floor_acknowledged: true,
            intent: "allow headroom".to_string(),
            blast_radius: BlastRadius::Medium,
        }];
        let out = synthesize(&input(), &d).unwrap();
        let arg = &out.spec.rules[0].allowed_calls[0].args[2];
        assert!(matches!(arg.constraint, Constraint::LeI128 { .. }));
        assert!(matches!(arg.provenance, Provenance::UserWidened { .. }));
        assert!(out.spec.validate().is_ok());

        // Widening an address argument is ambiguous semantics: fail closed.
        let mut d = decisions();
        d.widenings = vec![Widening {
            contract,
            fn_name: "transfer".to_string(),
            arg_index: 1,
            bound: WideningBound::LeI128 {
                max: "10".to_string(),
            },
            no_floor_acknowledged: false,
            intent: "nonsense".to_string(),
            blast_radius: BlastRadius::High,
        }];
        let errs = synthesize(&input(), &d).unwrap_err();
        // The reason names the arg kind ("address") — guards arg_kind().
        assert!(errs.iter().any(|e| matches!(
            e,
            SynthError::AmbiguousArgSemantics { reason, .. } if reason.contains("address")
        )));
        // The unused-widening applied-check ALSO fires: a non-i128 arg is never a numeric
        // match, so `is_widening()` stays false at that index and the widening "matched
        // nothing". This distinct reason guards the `&& a.constraint.is_widening()` gate —
        // an `||` there would spuriously mark the widening applied and suppress this error.
        assert!(
            errs.iter().any(|e| matches!(
                e,
                SynthError::AmbiguousArgSemantics { reason, .. }
                    if reason.contains("matched no observed numeric argument")
            )),
            "expected the applied-check 'matched nothing' error, got {errs:?}"
        );
    }

    // A bundle whose selected authorizer authorizes `root` plus each entry in `subs` (as
    // sub-invocations), for exercising multi-contract bundling and tuple dedup.
    fn bundle_with_subs(
        root: (&str, &str, Vec<ArgSummary>),
        subs: Vec<(&str, &str, Vec<ArgSummary>)>,
    ) -> RecordingBundle {
        use ozpb_recorder_core::{AuthorizationRecord, CredentialRecord, Execution, RawEvidence};
        let node = |c: &str, f: &str, a: Vec<ArgSummary>| InvocationNode {
            call: AuthorizedCall::Contract {
                contract: c.to_string(),
                fn_name: f.to_string(),
                args: a,
            },
            sub_invocations: vec![],
        };
        let mut root_node = node(root.0, root.1, root.2);
        root_node.sub_invocations = subs.into_iter().map(|(c, f, a)| node(c, f, a)).collect();
        RecordingBundle {
            schema: ozpb_recorder_core::RECORDING_SCHEMA.to_string(),
            canonicalization_version: ozpb_domain::CANONICALIZATION_VERSION,
            network_id: ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
            trust: ozpb_domain::TrustLevel::rpc_reported(),
            execution: Execution::ExecutedSuccess,
            ledger: Some(ozpb_domain::LedgerSeq(1)),
            created_at_unix: Some(1),
            operation_index: 0,
            authorizations: vec![AuthorizationRecord {
                authorizer: account_strkey(),
                credential: CredentialRecord::Address {
                    nonce: 1,
                    signature_expiration_ledger: 2,
                },
                fingerprint: sha256(b"multi"),
                root: root_node,
            }],
            token_movements: vec![],
            state_changes: vec![],
            contract_executables: input().bundles[0].contract_executables.clone(),
            evidence_notes: vec![],
            acquisition: None,
            raw: RawEvidence {
                result_xdr_base64: None,
                envelope_xdr_base64: "x".to_string(),
                result_meta_xdr_base64: None,
                simulated_auth_xdr_base64: vec![],
            },
        }
    }

    /// A failure-analysis recording must never silently become a behavior example: the
    /// recorder refuses failed executions without --allow-failed, and synthesis refuses
    /// them always.
    #[test]
    fn failed_executions_are_not_behavior_examples_for_synthesis() {
        let mut i = input();
        i.bundles[0].execution = Execution::ExecutedFailed;
        let errs = synthesize(&i, &decisions()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, SynthError::FailedExecution(0))),
            "expected FailedExecution, got {errs:?}"
        );
    }

    #[test]
    fn threshold_boundary_validation() {
        let addr = |b: u8| SignerSpec::Delegated {
            address: delegate_strkey(b),
        };
        let mut d = decisions();
        d.spending_limit = None;
        d.delegate_signers = vec![addr(1), addr(2)];
        // n == count is valid (guards `>` vs `>=`).
        d.predicate = PredicateChoice::Threshold { n: 2 };
        assert!(
            synthesize(&input(), &d).is_ok(),
            "threshold == signer count must be valid"
        );
        // n > count fails.
        d.predicate = PredicateChoice::Threshold { n: 3 };
        assert!(synthesize(&input(), &d).is_err());
        // n == 0 fails.
        d.predicate = PredicateChoice::Threshold { n: 0 };
        assert!(synthesize(&input(), &d).is_err());
    }

    #[test]
    fn multiple_contracts_yield_a_permission_bundle() {
        let a = format!("{}", stellar_strkey::Contract([10u8; 32]));
        let b = format!("{}", stellar_strkey::Contract([11u8; 32]));
        let bundle = bundle_with_subs(
            (&a, "poke", vec![ArgSummary::U32(1)]),
            vec![(&b, "prod", vec![ArgSummary::U32(2)])],
        );
        let mut i = input();
        i.bundles = vec![bundle];
        let mut d = decisions();
        d.spending_limit = None;
        let out = synthesize(&i, &d).unwrap();
        // One rule per contract, and the rationale flags the permission bundle (guards the
        // `per_contract.len() > 1` branch).
        assert_eq!(out.spec.rules.len(), 2);
        assert!(out
            .rationale
            .iter()
            .any(|r| r.contains("permission bundle")));

        // A single-contract grant must NOT emit the permission-bundle rationale.
        let single = synthesize(&input(), &{
            let mut d = decisions();
            d.spending_limit = None;
            d
        })
        .unwrap();
        assert!(!single
            .rationale
            .iter()
            .any(|r| r.contains("permission bundle")));
    }

    #[test]
    fn spending_limit_rejects_mixed_function_rules() {
        let token = transfer_bundle().authorizations[0].root.call_contract();
        let bundle = bundle_with_subs(
            (
                &token,
                "transfer",
                vec![
                    ArgSummary::Address(account_strkey()),
                    ArgSummary::Address(merchant_strkey()),
                    ArgSummary::I128(500_000_000),
                ],
            ),
            vec![(&token, "approve", vec![ArgSummary::I128(1)])],
        );
        let mut i = input();
        i.bundles = vec![bundle];

        let errs = synthesize(&i, &decisions()).unwrap_err();
        assert!(
            errs.iter().any(
                |error| matches!(error, SynthError::UnsupportedPattern(message) if message.contains("only SEP-41 `transfer`"))
            ),
            "the reviewed spending-limit policy denies non-transfer functions, so it cannot be attached to a mixed rule: {errs:?}"
        );
    }

    #[test]
    fn tuple_dedup_merges_identical_and_keeps_distinct() {
        let c = format!("{}", stellar_strkey::Contract([12u8; 32]));
        // Identical (fn,args) twice → one tuple with two justifying paths (guards the
        // dedup `==` and `&&`).
        let merged = {
            let bundle = bundle_with_subs(
                (&c, "ping", vec![ArgSummary::U32(1)]),
                vec![(&c, "ping", vec![ArgSummary::U32(1)])],
            );
            let mut i = input();
            i.bundles = vec![bundle];
            let mut d = decisions();
            d.spending_limit = None;
            synthesize(&i, &d).unwrap()
        };
        assert_eq!(merged.spec.rules[0].allowed_calls.len(), 1);
        assert_eq!(merged.spec.rules[0].allowed_calls[0].justified_by.len(), 2);

        // Same fn, DIFFERENT args → two distinct tuples (not merged).
        let distinct = {
            let bundle = bundle_with_subs(
                (&c, "ping", vec![ArgSummary::U32(1)]),
                vec![(&c, "ping", vec![ArgSummary::U32(2)])],
            );
            let mut i = input();
            i.bundles = vec![bundle];
            let mut d = decisions();
            d.spending_limit = None;
            synthesize(&i, &d).unwrap()
        };
        assert_eq!(distinct.spec.rules[0].allowed_calls.len(), 2);
    }

    #[test]
    fn spending_limit_invalid_params_fail_closed() {
        // Zero period must error (guards the `period == 0 || limit <= 0` disjunction).
        let mut d = decisions();
        d.spending_limit = Some(SpendingLimitChoice {
            limit: "500000000".to_string(),
            period_ledgers: 0,
        });
        assert!(synthesize(&input(), &d)
            .unwrap_err()
            .iter()
            .any(|e| matches!(e, SynthError::InvalidDecision(_))));
        // Non-positive limit must error.
        let mut d = decisions();
        d.spending_limit = Some(SpendingLimitChoice {
            limit: "0".to_string(),
            period_ledgers: 120_960,
        });
        assert!(synthesize(&input(), &d)
            .unwrap_err()
            .iter()
            .any(|e| matches!(e, SynthError::InvalidDecision(_))));
    }

    #[test]
    fn spending_limit_parameter_checks_are_independent_of_call_shape() {
        for (limit, period_ledgers) in [("0", 1), ("-1", 1), ("0500000000", 1), ("500000000", 0)] {
            let choice = SpendingLimitChoice {
                limit: limit.to_string(),
                period_ledgers,
            };
            assert!(
                validate_spending_limit_shape(&choice, &[], &[]).is_err(),
                "invalid limit={limit:?}, period={period_ledgers} must fail before call-shape checks"
            );
        }
        let valid = SpendingLimitChoice {
            limit: "500000000".to_string(),
            period_ledgers: 1,
        };
        assert!(validate_spending_limit_shape(&valid, &[], &[]).is_ok());
    }

    #[test]
    fn spending_limit_constraint_intersections_include_only_their_boundaries() {
        fn transfer_with_amount(constraint: Constraint) -> AllowedCall {
            AllowedCall {
                fn_name: "transfer".to_string(),
                args: vec![ArgConstraint {
                    index: 2,
                    provenance: if constraint.is_widening() {
                        Provenance::UserWidened {
                            intent: "semantic boundary test".to_string(),
                            blast_radius: BlastRadius::Medium,
                        }
                    } else {
                        Provenance::ObservedExact
                    },
                    constraint,
                }],
                justified_by: vec!["recordings[0]/auth[0]/root".to_string()],
            }
        }

        let choice = SpendingLimitChoice {
            limit: "10".to_string(),
            period_ledgers: 1,
        };
        let range = |min: &str, max: &str| Constraint::RangeI128 {
            min: min.to_string(),
            max: max.to_string(),
        };
        for (constraint, accepted) in [
            (Constraint::EqI128 { value: "-1".into() }, false),
            (Constraint::EqI128 { value: "0".into() }, true),
            (Constraint::EqI128 { value: "10".into() }, true),
            (Constraint::EqI128 { value: "11".into() }, false),
            (Constraint::LeI128 { max: "-1".into() }, false),
            (Constraint::LeI128 { max: "0".into() }, true),
            (Constraint::GeI128 { min: "10".into() }, true),
            (Constraint::GeI128 { min: "11".into() }, false),
            // A range meets 0..=10 unless it ends below 0 or starts above 10.
            (range("-5", "-1"), false),
            (range("-5", "0"), true),
            (range("10", "15"), true),
            (range("11", "15"), false),
            (range("-5", "15"), true),
            // Unparsable at either end; a non-canonical but parsable one is the spec's to refuse.
            (range("x", "5"), false),
            (range("0", "5 "), false),
        ] {
            let call = transfer_with_amount(constraint.clone());
            assert_eq!(
                validate_spending_limit_shape(&choice, &[call], &[]).is_ok(),
                accepted,
                "unexpected spending-limit intersection for {constraint:?}"
            );
        }
    }

    #[test]
    fn spending_limit_observed_amount_boundaries_and_cumulative_totals() {
        let allowed = vec![AllowedCall {
            fn_name: "transfer".to_string(),
            args: vec![ArgConstraint {
                index: 2,
                constraint: Constraint::EqI128 { value: "0".into() },
                provenance: Provenance::ObservedExact,
            }],
            justified_by: vec!["recordings[0]/auth[0]/root".to_string()],
        }];
        let choice = SpendingLimitChoice {
            limit: "10".to_string(),
            period_ledgers: 1,
        };

        for (amount, accepted) in [(-1, false), (0, true), (10, true), (11, false)] {
            let args = vec![
                ArgSummary::U32(0),
                ArgSummary::U32(0),
                ArgSummary::I128(amount),
            ];
            let observed = Observed {
                contract: "contract".to_string(),
                fn_name: "transfer".to_string(),
                args: &args,
                evidence_path: "recordings[0]/auth[0]/root".to_string(),
                recording_index: 0,
            };
            assert_eq!(
                validate_spending_limit_shape(&choice, &allowed, &[&observed]).is_ok(),
                accepted,
                "unexpected verdict for observed amount {amount}"
            );
        }

        let args_a = vec![ArgSummary::U32(0), ArgSummary::U32(0), ArgSummary::I128(4)];
        let args_b = vec![ArgSummary::U32(0), ArgSummary::U32(0), ArgSummary::I128(6)];
        let args_c = vec![ArgSummary::U32(0), ArgSummary::U32(0), ArgSummary::I128(7)];
        let observed = |args| Observed {
            contract: "contract".to_string(),
            fn_name: "transfer".to_string(),
            args,
            evidence_path: "recordings[0]/auth[0]/root".to_string(),
            recording_index: 0,
        };
        let four = observed(&args_a);
        let six = observed(&args_b);
        let seven = observed(&args_c);
        assert!(validate_spending_limit_shape(&choice, &allowed, &[&four, &six]).is_ok());
        assert!(validate_spending_limit_shape(&choice, &allowed, &[&four, &seven]).is_err());

        let max_choice = SpendingLimitChoice {
            limit: i128::MAX.to_string(),
            period_ledgers: 1,
        };
        let max_args = vec![
            ArgSummary::U32(0),
            ArgSummary::U32(0),
            ArgSummary::I128(i128::MAX),
        ];
        let one_args = vec![ArgSummary::U32(0), ArgSummary::U32(0), ArgSummary::I128(1)];
        let max = observed(&max_args);
        let one = observed(&one_args);
        assert!(validate_spending_limit_shape(&max_choice, &allowed, &[&max, &one]).is_err());
    }

    #[test]
    fn spending_limit_rejects_untyped_and_wildcard_amounts() {
        let token = transfer_bundle().authorizations[0].root.call_contract();
        let bundle = bundle_with_subs(
            (
                &token,
                "transfer",
                vec![
                    ArgSummary::Address(account_strkey()),
                    ArgSummary::Address(merchant_strkey()),
                    ArgSummary::Address(merchant_strkey()),
                ],
            ),
            vec![],
        );
        let mut synthesis_input = input();
        synthesis_input.bundles = vec![bundle];
        let errors = synthesize(&synthesis_input, &decisions()).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SynthError::InvalidDecision(message)
                if message.contains("constrained as i128"))));

        let mut user_decisions = decisions();
        user_decisions.widenings = vec![Widening {
            contract: token,
            fn_name: "transfer".to_string(),
            arg_index: 2,
            bound: WideningBound::AnyValue,
            no_floor_acknowledged: false,
            intent: "caller chooses any amount".to_string(),
            blast_radius: BlastRadius::High,
        }];
        let errors = synthesize(&input(), &user_decisions).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SynthError::InvalidDecision(message)
                if message.contains("constrained as i128"))));
    }

    #[test]
    fn spending_limit_covers_each_amount_and_the_representative_sequence() {
        let mut too_small = decisions();
        too_small.spending_limit = Some(SpendingLimitChoice {
            limit: "499999999".to_string(),
            period_ledgers: 120_960,
        });
        let errors = synthesize(&input(), &too_small).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SynthError::InvalidDecision(message)
                if message.contains("outside the spending-limit range"))));

        let token = transfer_bundle().authorizations[0].root.call_contract();
        let transfer_args = || {
            vec![
                ArgSummary::Address(account_strkey()),
                ArgSummary::Address(merchant_strkey()),
                ArgSummary::I128(300_000_000),
            ]
        };
        let bundle = bundle_with_subs(
            (&token, "transfer", transfer_args()),
            vec![(&token, "transfer", transfer_args())],
        );
        let mut synthesis_input = input();
        synthesis_input.bundles = vec![bundle];
        let errors = synthesize(&synthesis_input, &decisions()).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SynthError::InvalidDecision(message)
                if message.contains("calls in one recording necessarily share"))));
    }

    #[test]
    fn call_cap_cannot_be_below_a_representative_contract_sequence() {
        let token = transfer_bundle().authorizations[0].root.call_contract();
        let args = || {
            vec![
                ArgSummary::Address(account_strkey()),
                ArgSummary::Address(merchant_strkey()),
                ArgSummary::I128(100_000_000),
            ]
        };
        let bundle = bundle_with_subs(
            (&token, "transfer", args()),
            vec![(&token, "transfer", args())],
        );
        let mut synthesis_input = input();
        synthesis_input.bundles = vec![bundle];
        let mut user_decisions = decisions();
        user_decisions.max_calls = Some(1);
        let errors = synthesize(&synthesis_input, &user_decisions).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SynthError::InvalidDecision(message)
                if message.contains("below the 2 calls observed"))));

        user_decisions.max_calls = Some(2);
        let output = synthesize(&synthesis_input, &user_decisions)
            .expect("a cap equal to the representative sequence must permit replay");
        assert_eq!(
            output.spec.rules[0].state,
            vec![StateSpec::CallCountPerInstallation { max_calls: 2 }]
        );
    }

    #[test]
    fn widening_wrong_fn_or_index_fails_closed() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        // Right contract + arg, WRONG fn → not applied → fail closed (guards the fn `&&`).
        let mut d = decisions();
        d.widenings = vec![Widening {
            contract: contract.clone(),
            fn_name: "not_transfer".to_string(),
            arg_index: 2,
            bound: WideningBound::LeI128 {
                max: "10".to_string(),
            },
            no_floor_acknowledged: false,
            intent: "wrong fn".to_string(),
            blast_radius: BlastRadius::Low,
        }];
        assert!(synthesize(&input(), &d)
            .unwrap_err()
            .iter()
            .any(|e| matches!(e, SynthError::AmbiguousArgSemantics { .. })));
        // Right contract + fn, WRONG index → not applied → fail closed (guards the index `&&`).
        let mut d = decisions();
        d.widenings = vec![Widening {
            contract,
            fn_name: "transfer".to_string(),
            arg_index: 9,
            bound: WideningBound::LeI128 {
                max: "10".to_string(),
            },
            no_floor_acknowledged: false,
            intent: "wrong index".to_string(),
            blast_radius: BlastRadius::Low,
        }];
        assert!(synthesize(&input(), &d)
            .unwrap_err()
            .iter()
            .any(|e| matches!(e, SynthError::AmbiguousArgSemantics { .. })));
    }

    #[test]
    fn u64_argument_encodes_to_a_nonempty_scval_constraint() {
        // A U64 arg becomes an EqScval with real XDR bytes (guards scval_b64()).
        let c = format!("{}", stellar_strkey::Contract([13u8; 32]));
        let bundle = bundle_with_subs((&c, "tick", vec![ArgSummary::U64(42)]), vec![]);
        let mut i = input();
        i.bundles = vec![bundle];
        let mut d = decisions();
        d.spending_limit = None;
        let out = synthesize(&i, &d).unwrap();
        match &out.spec.rules[0].allowed_calls[0].args[0].constraint {
            Constraint::EqScval { xdr_base64 } => {
                assert!(!xdr_base64.is_empty(), "U64 must encode to non-empty XDR");
            }
            other => panic!("expected EqScval, got {other:?}"),
        }
    }

    #[test]
    fn widening_that_matches_nothing_fails_closed() {
        let mut d = decisions();
        d.widenings = vec![Widening {
            contract: "CNOSUCHCONTRACT".to_string(),
            fn_name: "transfer".to_string(),
            arg_index: 2,
            bound: WideningBound::LeI128 {
                max: "10".to_string(),
            },
            no_floor_acknowledged: false,
            intent: "typo'd target".to_string(),
            blast_radius: BlastRadius::Low,
        }];
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::AmbiguousArgSemantics { .. })));
    }

    /// One argument carries one constraint. A user who caps the amount and then floors it means
    /// a range; synthesis used to apply the first widening that named the argument, and the
    /// unused-widening check only asks whether the argument ended up widened at all, so the
    /// floor was neither applied nor refused and the spec quietly said less than the user did.
    #[test]
    fn a_second_widening_of_the_same_argument_is_refused() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let widen =
            |contract: &str, fn_name: &str, arg_index: u32, bound: WideningBound| Widening {
                contract: contract.to_string(),
                fn_name: fn_name.to_string(),
                arg_index,
                bound,
                no_floor_acknowledged: false,
                intent: "a decision about one argument".to_string(),
                blast_radius: BlastRadius::High,
            };
        let cap = || WideningBound::LeI128 {
            max: "1000000000".to_string(),
        };
        let floor = || WideningBound::GeI128 {
            min: "1".to_string(),
        };
        let duplicate_findings = |errors: &[SynthError]| -> Vec<String> {
            errors
                .iter()
                .filter_map(|error| match error {
                    SynthError::InvalidDecision(message) if message.contains("widenings name") => {
                        Some(message.clone())
                    }
                    _ => None,
                })
                .collect()
        };

        let mut d = decisions();
        d.widenings = vec![
            widen(&contract, "transfer", 2, cap()),
            widen(&contract, "transfer", 2, floor()),
        ];
        let errors = synthesize(&input(), &d).unwrap_err();
        assert_eq!(
            duplicate_findings(&errors),
            vec![format!(
                "widening {contract}/transfer arg 2: 2 widenings name this argument, and an \
                 argument takes one bound; keep the one the user chose"
            )],
            "{errors:?}"
        );
        assert!(errors[0].to_string().starts_with("E_INVALID_DECISION:"));

        // Three widenings of one argument are one finding, counted.
        d.widenings.push(widen(&contract, "transfer", 2, cap()));
        let errors = synthesize(&input(), &d).unwrap_err();
        let findings = duplicate_findings(&errors);
        assert_eq!(findings.len(), 1, "{errors:?}");
        assert!(findings[0].contains(": 3 widenings name"), "{findings:?}");

        // The same function and index on another contract, and another function or index on
        // this one, are other arguments: they fail for what they are, never as duplicates.
        for other in [
            widen("CNOSUCHCONTRACT", "transfer", 2, floor()),
            widen(&contract, "transfer_from", 2, floor()),
            widen(&contract, "transfer", 1, WideningBound::AnyValue),
        ] {
            let mut d = decisions();
            d.widenings = vec![widen(&contract, "transfer", 2, floor()), other.clone()];
            match synthesize(&input(), &d) {
                Ok(_) => assert_eq!(
                    other.arg_index, 1,
                    "only the any_value widening of the recipient, arg 1, synthesizes"
                ),
                Err(errors) => {
                    assert!(
                        duplicate_findings(&errors).is_empty(),
                        "{other:?}: {errors:?}"
                    );
                    assert!(
                        errors
                            .iter()
                            .all(|e| matches!(e, SynthError::AmbiguousArgSemantics { .. })),
                        "{other:?}: {errors:?}"
                    );
                }
            }
        }
    }

    /// A widening of the recorded transfer's amount, argument 2: an i128, a signed integer.
    fn amount_widening(bound: WideningBound, no_floor_acknowledged: bool) -> Widening {
        Widening {
            contract: transfer_bundle().authorizations[0].root.call_contract(),
            fn_name: "transfer".to_string(),
            arg_index: 2,
            bound,
            no_floor_acknowledged,
            intent: "an amount decision".to_string(),
            blast_radius: BlastRadius::High,
        }
    }

    /// The analogue of OpenZeppelin's v0.7.0 audit finding L-06. A cap renders only
    /// `x > max → deny`, so on a signed amount every negative value passes the generated policy
    /// and only the target can refuse it. Adding a floor of zero would infer a direction from the
    /// XDR type, which synthesis never does, and one argument cannot carry a cap and a floor. So a
    /// cap is a question until the user accepts the open floor in so many words.
    #[test]
    fn a_cap_on_a_signed_amount_needs_its_open_floor_acknowledged() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let cap = WideningBound::LeI128 {
            max: "1000000000".to_string(),
        };
        // What refuses a negative amount here. Never the generated scope policy; the reviewed
        // spending limit does, for the transfer amount (argument 2) of a rule it is composed into.
        const COMPOSED: &str =
            "the generated scope policy refuses no negative amount; the composed spending limit does";
        const TARGET_ONLY: &str = "the generated scope policy refuses no negative amount, so only \
                                   the target contract can refuse one";
        let question = |contract: &str, arg: u32, refusal: &str| {
            SynthError::NeedsDecision(format!(
                "widening {contract}/transfer arg {arg}: floor: the cap at 1000000000 on this \
                 signed amount sets no floor, so every smaller value passes it, negative amounts \
                 included; {refusal}. Bound both ends instead with a range (range_i128, such as \
                 0..=1000000000; needs development registry version 7 or later), or acknowledge \
                 the open floor (no_floor_acknowledged, only on the user's explicit acceptance), \
                 or keep the argument exact"
            ))
        };
        let acknowledged = |contract: &str, arg: u32, refusal: &str| {
            format!(
                "{contract}/transfer arg {arg}: NO FLOOR — the user acknowledged that the cap at \
                 1000000000 admits every smaller value, negative amounts included; {refusal}"
            )
        };

        let mut d = decisions();
        d.widenings = vec![amount_widening(cap.clone(), false)];
        assert_eq!(
            synthesize(&input(), &d).unwrap_err(),
            vec![question(&contract, 2, COMPOSED)]
        );

        d.widenings = vec![amount_widening(cap.clone(), true)];
        let out = synthesize(&input(), &d).unwrap();
        let amount = &out.spec.rules[0].allowed_calls[0].args[2];
        assert_eq!(
            amount.constraint,
            Constraint::LeI128 {
                max: "1000000000".to_string()
            }
        );
        assert!(matches!(amount.provenance, Provenance::UserWidened { .. }));
        assert!(
            out.rationale
                .contains(&acknowledged(&contract, 2, COMPOSED)),
            "{:#?}",
            out.rationale
        );

        // Without the spending limit only the target is left to refuse a negative amount.
        d.spending_limit = None;
        let out = synthesize(&input(), &d).unwrap();
        assert!(
            out.rationale
                .contains(&acknowledged(&contract, 2, TARGET_ONLY)),
            "{:#?}",
            out.rationale
        );
        d.widenings = vec![amount_widening(cap.clone(), false)];
        assert_eq!(
            synthesize(&input(), &d).unwrap_err(),
            vec![question(&contract, 2, TARGET_ONLY)]
        );

        // The composed spending limit reads argument 2 alone: a cap on another signed argument
        // of the same composed rule is still the target's to refuse.
        let two_amounts = bundle_with_subs(
            (
                &contract,
                "transfer",
                vec![
                    ArgSummary::Address(account_strkey()),
                    ArgSummary::I128(7),
                    ArgSummary::I128(500_000_000),
                ],
            ),
            vec![],
        );
        let mut synthesis_input = input();
        synthesis_input.bundles = vec![two_amounts];
        let mut d = decisions();
        let mut second = amount_widening(cap, false);
        second.arg_index = 1;
        d.widenings = vec![second.clone()];
        assert_eq!(
            synthesize(&synthesis_input, &d).unwrap_err(),
            vec![question(&contract, 1, TARGET_ONLY)]
        );
        second.no_floor_acknowledged = true;
        d.widenings = vec![second];
        let out = synthesize(&synthesis_input, &d).unwrap();
        assert!(
            matches!(out.spec.rules[0].policies[0], PolicyRef::Reviewed { .. }),
            "the rule composes the spending limit"
        );
        assert!(
            out.rationale
                .contains(&acknowledged(&contract, 1, TARGET_ONLY)),
            "{:#?}",
            out.rationale
        );

        // The question is about an argument the cap bounds. A cap that applies to nothing, or to
        // an address, is refused for that; asking about its floor would be a question about
        // nothing.
        for (contract, arg_index) in [("CNOSUCHCONTRACT".to_string(), 2), (contract, 1)] {
            let mut unapplied = amount_widening(
                WideningBound::LeI128 {
                    max: "10".to_string(),
                },
                false,
            );
            unapplied.contract = contract;
            unapplied.arg_index = arg_index;
            let mut d = decisions();
            d.widenings = vec![unapplied];
            let errors = synthesize(&input(), &d).unwrap_err();
            assert!(
                errors
                    .iter()
                    .all(|e| matches!(e, SynthError::AmbiguousArgSemantics { .. })),
                "{errors:?}"
            );
        }
    }

    /// The acknowledgement answers the question a cap asks — or a range from `i128::MIN`, which is
    /// one — and no other. On a floor it says the opposite of the bound beside it; on `any_value`
    /// there is no bound for it to qualify.
    /// Either way the user's decision is unclear, so it is refused rather than ignored.
    #[test]
    fn the_no_floor_acknowledgement_belongs_to_a_cap_alone() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let floor = WideningBound::GeI128 {
            min: "1".to_string(),
        };
        let mut d = decisions();
        d.spending_limit = None; // the reviewed spending limit refuses an any_value amount
        for (bound, finding) in [
            (
                floor.clone(),
                format!(
                    "widening {contract}/transfer arg 2: the floor at 1 contradicts \
                     no_floor_acknowledged; choose one"
                ),
            ),
            (
                WideningBound::AnyValue,
                format!(
                    "widening {contract}/transfer arg 2: no_floor_acknowledged qualifies a bound \
                     with no floor alone (a cap, le_i128, or a range from i128::MIN); any_value \
                     has no bound for it to qualify"
                ),
            ),
            (
                WideningBound::RangeI128 {
                    min: "0".to_string(),
                    max: "1000000000".to_string(),
                },
                format!(
                    "widening {contract}/transfer arg 2: the range 0..=1000000000 has its floor \
                     at 0, which contradicts no_floor_acknowledged; choose one"
                ),
            ),
        ] {
            d.widenings = vec![amount_widening(bound.clone(), true)];
            assert_eq!(
                synthesize(&input(), &d).unwrap_err(),
                vec![SynthError::InvalidDecision(finding)]
            );
            // Without it, neither asks anything about a floor.
            d.widenings = vec![amount_widening(bound, false)];
            synthesize(&input(), &d).unwrap();
        }
    }

    /// "Spend up to X" stated safely: a range closes the cap from below, so it is the answer to
    /// the floor question rather than a reason to ask it. The bounds go into the spec as given.
    #[test]
    fn a_range_on_a_signed_amount_asks_no_floor_question() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let mut d = decisions();
        d.widenings = vec![amount_widening(
            WideningBound::RangeI128 {
                min: "0".to_string(),
                max: "1000000000".to_string(),
            },
            false,
        )];
        let out = synthesize(&input(), &d).unwrap();
        let amount = &out.spec.rules[0].allowed_calls[0].args[2];
        assert_eq!(
            amount.constraint,
            Constraint::RangeI128 {
                min: "0".to_string(),
                max: "1000000000".to_string()
            }
        );
        assert!(matches!(amount.provenance, Provenance::UserWidened { .. }));
        assert!(
            !out.rationale.iter().any(|line| line.contains("FLOOR")),
            "{:#?}",
            out.rationale
        );
        assert!(out.rationale.contains(&format!(
            "{contract}/transfer arg 2: user-widened (an amount decision), blast radius High"
        )));
        assert!(out.spec.validate().is_ok());

        // A floor below zero is a decision too, and the report says what it admits. A range from
        // i128::MIN has no floor at all and asks a cap's question
        // (`a_range_from_i128_min_asks_the_floor_question_a_cap_asks`).
        let ranged = |min: String| {
            let mut d = decisions();
            d.widenings = vec![amount_widening(
                WideningBound::RangeI128 {
                    min,
                    max: "1000000000".to_string(),
                },
                false,
            )];
            synthesize(&input(), &d).unwrap().rationale
        };
        let below_zero = ranged("-5".to_string());
        assert!(
            below_zero.contains(&format!(
                "{contract}/transfer arg 2: NEGATIVE FLOOR — the user's range -5..=1000000000 \
                 admits negative amounts down to -5; the generated scope policy refuses only \
                 below that"
            )),
            "{below_zero:#?}"
        );
        assert!(!ranged("1".to_string())
            .iter()
            .any(|line| line.contains("FLOOR")));

        // One argument, one widening: a range and a cap on it are two decisions, refused.
        d.widenings.push(amount_widening(
            WideningBound::LeI128 {
                max: "1000000000".to_string(),
            },
            true,
        ));
        assert!(synthesize(&input(), &d).unwrap_err().iter().any(|e| matches!(
            e,
            SynthError::InvalidDecision(message) if message.contains("2 widenings name this argument")
        )));
    }

    /// A widening loosens the recorded call; a bound that excludes the recorded value would turn
    /// the grant against the very call it was built from. Each numeric bound is held to it, at
    /// the boundary inclusive (the transfer recorded 500000000).
    #[test]
    fn a_numeric_bound_must_admit_the_recorded_value() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let excludes = |bound: &str| {
            vec![SynthError::InvalidDecision(format!(
                "widening {contract}/transfer arg 2: {bound} excludes the recorded value \
                 500000000; a widening loosens the recorded call and cannot refuse it"
            ))]
        };
        let range = |min: &str, max: &str| WideningBound::RangeI128 {
            min: min.to_string(),
            max: max.to_string(),
        };
        let mut d = decisions();
        d.spending_limit = None;
        for (bound, acknowledged, refusal) in [
            (
                WideningBound::LeI128 {
                    max: "499999999".to_string(),
                },
                true,
                "the cap <= 499999999",
            ),
            (
                WideningBound::GeI128 {
                    min: "500000001".to_string(),
                },
                false,
                "the floor >= 500000001",
            ),
            (range("0", "499999999"), false, "the range 0..=499999999"),
            (
                range("500000001", "600000000"),
                false,
                "the range 500000001..=600000000",
            ),
        ] {
            d.widenings = vec![amount_widening(bound, acknowledged)];
            assert_eq!(synthesize(&input(), &d).unwrap_err(), excludes(refusal));
        }
        for (bound, acknowledged) in [
            (
                WideningBound::LeI128 {
                    max: "500000000".to_string(),
                },
                true,
            ),
            (
                WideningBound::GeI128 {
                    min: "500000000".to_string(),
                },
                false,
            ),
            (range("500000000", "500000000"), false),
        ] {
            d.widenings = vec![amount_widening(bound.clone(), acknowledged)];
            assert!(synthesize(&input(), &d).is_ok(), "{bound:?}");
        }

        // Two recordings of the same call are one finding, not two. (Two distinct calls would
        // draw a second finding: one widening cannot apply to both.)
        let call = || {
            (
                contract.as_str(),
                "transfer",
                vec![
                    ArgSummary::Address(account_strkey()),
                    ArgSummary::Address(merchant_strkey()),
                    ArgSummary::I128(500_000_000),
                ],
            )
        };
        let mut two = input();
        two.bundles = vec![bundle_with_subs(call(), vec![call()])];
        d.widenings = vec![amount_widening(range("0", "1"), false)];
        assert_eq!(
            synthesize(&two, &d).unwrap_err(),
            excludes("the range 0..=1")
        );
    }

    /// A swap recorded as `swap_exact_tokens_for_tokens(1000, 950, path, SELF, 2000)` on a target
    /// whose observed code the reviewed router adapter (`soroswap-router@2`) is bound to, unless
    /// `bound` is false. Returns the input, the router address and the decisions to widen.
    fn adapted_swap(bound: bool) -> (SynthesisInput, String, UserDecisions) {
        let mut input = crate::fixtures::golden_input();
        let router = crate::fixtures::golden_token_strkey();
        let code_hash = sha256(b"reviewed-router-wasm");
        input.bundles[0]
            .contract_executables
            .get_mut(&router)
            .unwrap()
            .executable = ObservedExecutable::Wasm { code_hash };
        if bound {
            input.adapters = vec![adapters::soroswap_router_adapter(code_hash)];
        }
        input.spending_limit_capability = None;
        let path = stellar_xdr::ScVal::Vec(Some(
            vec![stellar_xdr::ScVal::Address(
                stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(
                    [2; 32],
                ))),
            )]
            .try_into()
            .unwrap(),
        ));
        let AuthorizedCall::Contract { fn_name, args, .. } =
            &mut input.bundles[0].authorizations[0].root.call
        else {
            unreachable!()
        };
        *fn_name = "swap_exact_tokens_for_tokens".into();
        *args = vec![
            ArgSummary::I128(1000),
            ArgSummary::I128(950),
            ArgSummary::Other {
                xdr_base64: path.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
            },
            ArgSummary::Address(crate::fixtures::golden_account_strkey()),
            ArgSummary::U64(2000),
        ];
        let mut decisions = crate::fixtures::golden_decisions();
        decisions.spending_limit = None;
        (input, router, decisions)
    }

    fn swap_widening(router: &str, arg_index: u32, bound: WideningBound) -> Widening {
        Widening {
            contract: router.to_string(),
            fn_name: "swap_exact_tokens_for_tokens".to_string(),
            arg_index,
            no_floor_acknowledged: matches!(bound, WideningBound::LeI128 { .. }),
            bound,
            intent: "a swap decision".to_string(),
            blast_radius: BlastRadius::High,
        }
    }

    /// A reviewed adapter knows which direction of an argument is the unsafe one. A user bound
    /// that loosens it there contradicts the reviewed role: lowering a swap's minimum output
    /// removes the router's only slippage check, and a maximum input without a cap lets the call
    /// spend any amount. Each is refused — whatever blast radius it is rated, because the label
    /// would not restore the check — while a bound that only tightens the unsafe side applies.
    #[test]
    fn a_user_bound_against_an_adapter_role_is_refused() {
        let range = |min: &str, max: &str| WideningBound::RangeI128 {
            min: min.to_string(),
            max: max.to_string(),
        };
        let (input, router, decisions) = adapted_swap(true);
        let min_output = |bound: &str| {
            SynthError::InvalidDecision(format!(
                "widening {router}/swap_exact_tokens_for_tokens arg 1: adapter \
                 'soroswap-router@2' reviews this argument as a minimum output, below which the \
                 target refuses the call; {bound} admits values below the recorded 950, which \
                 weakens that check. A decision may only raise a minimum output: keep it exact, \
                 or bound it from below at 950 or higher"
            ))
        };
        let max_input = |bound: &str| {
            SynthError::InvalidDecision(format!(
                "widening {router}/swap_exact_tokens_for_tokens arg 0: adapter \
                 'soroswap-router@2' reviews this argument as a maximum input; {bound} sets no \
                 cap on it, so the call may spend any amount. Bound it from above with a cap or a \
                 range, or leave it undecided for the adapter's cap at the recorded 1000"
            ))
        };
        for (widening, finding) in [
            // The reviewer's case: a low-rated range that reaches zero drops the slippage check.
            (
                {
                    let mut w = swap_widening(&router, 1, range("0", "950"));
                    w.blast_radius = BlastRadius::Low;
                    w
                },
                min_output("the range 0..=950"),
            ),
            (
                swap_widening(
                    &router,
                    1,
                    WideningBound::LeI128 {
                        max: "950".to_string(),
                    },
                ),
                min_output("the cap <= 950"),
            ),
            (
                swap_widening(
                    &router,
                    1,
                    WideningBound::GeI128 {
                        min: "949".to_string(),
                    },
                ),
                min_output("the floor >= 949"),
            ),
            (
                swap_widening(&router, 1, WideningBound::AnyValue),
                min_output("any_value"),
            ),
            (
                swap_widening(
                    &router,
                    0,
                    WideningBound::GeI128 {
                        min: "0".to_string(),
                    },
                ),
                max_input("the floor >= 0"),
            ),
            (
                swap_widening(&router, 0, range("0", &i128::MAX.to_string())),
                max_input(&format!("the range 0..={}", i128::MAX)),
            ),
            (
                swap_widening(&router, 0, WideningBound::AnyValue),
                max_input("any_value"),
            ),
        ] {
            let mut d = decisions.clone();
            d.widenings = vec![widening.clone()];
            assert_eq!(
                synthesize(&input, &d).unwrap_err(),
                vec![finding],
                "{widening:?}"
            );
        }
        // The refusal is the only finding. A cap with no floor acknowledgement is not also asked
        // about its floor, nor a low-rated open top about its rating: neither answer would make
        // it acceptable.
        for (widening, finding) in [
            (
                {
                    let mut w = swap_widening(
                        &router,
                        1,
                        WideningBound::LeI128 {
                            max: "950".to_string(),
                        },
                    );
                    w.no_floor_acknowledged = false;
                    w
                },
                min_output("the cap <= 950"),
            ),
            (
                {
                    let mut w = swap_widening(
                        &router,
                        0,
                        WideningBound::GeI128 {
                            min: "0".to_string(),
                        },
                    );
                    w.blast_radius = BlastRadius::Low;
                    w
                },
                max_input("the floor >= 0"),
            ),
        ] {
            let mut d = decisions.clone();
            d.widenings = vec![widening.clone()];
            assert_eq!(
                synthesize(&input, &d).unwrap_err(),
                vec![finding],
                "{widening:?}"
            );
        }

        // Raising the minimum output, or capping the input at any finite amount, is the user's
        // value decision and applies with their provenance.
        for widening in [
            {
                let mut w = swap_widening(
                    &router,
                    1,
                    WideningBound::GeI128 {
                        min: "950".to_string(),
                    },
                );
                w.blast_radius = BlastRadius::Low;
                w
            },
            swap_widening(&router, 1, range("950", "2000")),
            swap_widening(&router, 0, range("0", "2000")),
        ] {
            let mut d = decisions.clone();
            d.widenings = vec![widening.clone()];
            let out = synthesize(&input, &d).unwrap();
            let arg = &out.spec.rules[0].allowed_calls[0].args[widening.arg_index as usize];
            assert!(
                matches!(arg.provenance, Provenance::UserWidened { .. }),
                "{widening:?}: {arg:?}"
            );
        }

        // Without the binding nothing declares the role, so the decision is the user's alone.
        let (unbound, _, _) = adapted_swap(false);
        let mut d = decisions;
        d.widenings = vec![swap_widening(&router, 1, range("0", "950"))];
        assert!(synthesize(&unbound, &d).is_ok());
    }

    /// A bound with no finite cap admits every larger value, which on an amount is any amount:
    /// the same reach as `any_value` on that side, so it carries the same high blast radius
    /// whatever the decision rates it. The one argument where the open top is the safe side is a
    /// minimum output a reviewed adapter declares; there a floor only tightens the target's check.
    #[test]
    fn an_open_above_bound_requires_high_blast_radius() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let rated = |bound: WideningBound, blast_radius: BlastRadius| {
            let mut w = amount_widening(bound, false);
            w.no_floor_acknowledged = matches!(w.bound, WideningBound::LeI128 { .. });
            w.blast_radius = blast_radius;
            w
        };
        let finding = |bound: &str, rating: &str| {
            vec![SynthError::InvalidDecision(format!(
                "widening {contract}/transfer arg 2: {bound} sets no cap, so the generated \
                 policy admits every larger value, which on an amount is any amount: a high \
                 blast radius, and this decision rates it {rating}. Rate it high, or give it a \
                 finite maximum"
            ))]
        };
        let max = i128::MAX.to_string();
        let mut d = decisions();
        d.spending_limit = None;
        for (bound, text) in [
            (
                WideningBound::GeI128 {
                    min: "0".to_string(),
                },
                "the floor >= 0".to_string(),
            ),
            (
                WideningBound::RangeI128 {
                    min: "0".to_string(),
                    max: max.clone(),
                },
                format!("the range 0..={max}"),
            ),
        ] {
            for (radius, rating) in [(BlastRadius::Low, "low"), (BlastRadius::Medium, "medium")] {
                d.widenings = vec![rated(bound.clone(), radius)];
                assert_eq!(
                    synthesize(&input(), &d).unwrap_err(),
                    finding(&text, rating)
                );
            }
            d.widenings = vec![rated(bound, BlastRadius::High)];
            assert!(synthesize(&input(), &d).is_ok());
        }
        // A cap at i128::MAX is no cap. Without the floor acknowledgement it is still refused once,
        // for its open top: acknowledging the floor would not make it acceptable.
        d.widenings = vec![amount_widening(
            WideningBound::LeI128 { max: max.clone() },
            false,
        )];
        d.widenings[0].blast_radius = BlastRadius::Medium;
        assert_eq!(
            synthesize(&input(), &d).unwrap_err(),
            finding(&format!("the cap <= {max}"), "medium")
        );
        // A finite cap is the user's own assessment, any rating included.
        d.widenings = vec![rated(
            WideningBound::RangeI128 {
                min: "0".to_string(),
                max: "1000000000".to_string(),
            },
            BlastRadius::Low,
        )];
        assert!(synthesize(&input(), &d).is_ok());

        // On a minimum output the reviewed router adapter declares, the open top is the safe side.
        let (input, router, mut decisions) = adapted_swap(true);
        let mut floor = swap_widening(
            &router,
            1,
            WideningBound::GeI128 {
                min: "950".to_string(),
            },
        );
        floor.blast_radius = BlastRadius::Medium;
        decisions.widenings = vec![floor.clone()];
        assert!(synthesize(&input, &decisions).is_ok());
        // Without the adapter nothing says it is a minimum output.
        let (unbound, _, _) = adapted_swap(false);
        assert_eq!(
            synthesize(&unbound, &decisions).unwrap_err(),
            vec![SynthError::InvalidDecision(format!(
                "widening {router}/swap_exact_tokens_for_tokens arg 1: the floor >= 950 sets no \
                 cap, so the generated policy admits every larger value, which on an amount is \
                 any amount: a high blast radius, and this decision rates it medium. Rate it \
                 high, or give it a finite maximum"
            ))]
        );
    }

    /// A range from `i128::MIN` renders the same check as a cap: the generated policy leaves out a
    /// comparison against the type's own minimum. So it asks the cap's floor question and takes
    /// the cap's acknowledgement, rather than passing as a range that needs none.
    #[test]
    fn a_range_from_i128_min_asks_the_floor_question_a_cap_asks() {
        let contract = transfer_bundle().authorizations[0].root.call_contract();
        let min = i128::MIN.to_string();
        let bound = WideningBound::RangeI128 {
            min: min.clone(),
            max: "1000000000".to_string(),
        };
        let mut d = decisions();
        d.spending_limit = None;
        d.widenings = vec![amount_widening(bound.clone(), false)];
        assert_eq!(
            synthesize(&input(), &d).unwrap_err(),
            vec![SynthError::NeedsDecision(format!(
                "widening {contract}/transfer arg 2: floor: the range {min}..=1000000000, which \
                 starts at i128::MIN and so is the cap at 1000000000, on this signed amount sets \
                 no floor, so every smaller value passes it, negative amounts included; the \
                 generated scope policy refuses no negative amount, so only the target contract \
                 can refuse one. Bound both ends instead with a floor above i128::MIN (such as \
                 0..=1000000000), or acknowledge the open floor (no_floor_acknowledged, only on \
                 the user's explicit acceptance), or keep the argument exact"
            ))]
        );
        d.widenings = vec![amount_widening(bound, true)];
        let out = synthesize(&input(), &d).unwrap();
        assert!(
            out.rationale.contains(&format!(
                "{contract}/transfer arg 2: NO FLOOR — the user acknowledged that the range \
                 {min}..=1000000000, which starts at i128::MIN and so is the cap at 1000000000, \
                 admits every smaller value, negative amounts included; the generated scope \
                 policy refuses no negative amount, so only the target contract can refuse one"
            )),
            "{:#?}",
            out.rationale
        );
    }

    /// Decisions name an argument by contract, function and index — not by recorded call. When
    /// the function was recorded as several distinct calls, one widening would loosen the
    /// argument in each of them: widening the first payment's amount to `0..=2000` would raise
    /// the second payment's too. Until a decision can name its call, that is refused. Calls that
    /// differ only in the widened argument become one tuple, so a widening there is one call's.
    #[test]
    fn a_widening_on_a_multi_tuple_function_is_refused_unless_scoped() {
        let token = transfer_bundle().authorizations[0].root.call_contract();
        let payment = |payee: String, amount: i128| {
            bundle_with_subs(
                (
                    &token,
                    "transfer",
                    vec![
                        ArgSummary::Address(account_strkey()),
                        ArgSummary::Address(payee),
                        ArgSummary::I128(amount),
                    ],
                ),
                vec![],
            )
        };
        let range = WideningBound::RangeI128 {
            min: "0".to_string(),
            max: "2000".to_string(),
        };
        let mut d = decisions();
        d.spending_limit = None;
        let mut two_payees = input();
        two_payees.bundles = vec![
            payment(merchant_strkey(), 2000),
            payment(delegate_strkey(9), 1000),
        ];
        // Exact, the two payments are two tuples.
        assert_eq!(
            synthesize(&two_payees, &d).unwrap().spec.rules[0]
                .allowed_calls
                .len(),
            2
        );
        d.widenings = vec![amount_widening(range.clone(), false)];
        assert_eq!(
            synthesize(&two_payees, &d).unwrap_err(),
            vec![SynthError::InvalidDecision(format!(
                "widening {token}/transfer arg 2: this widening would apply to 2 distinct \
                 recorded calls of transfer on {token}, loosening argument 2 of each; a widening \
                 loosens one argument of one recorded call, and a decision cannot name which. \
                 Keep the argument exact, or synthesize from recordings in which transfer is one \
                 distinct call"
            ))]
        );

        let mut one_payee = input();
        one_payee.bundles = vec![
            payment(merchant_strkey(), 2000),
            payment(merchant_strkey(), 1000),
        ];
        let out = synthesize(&one_payee, &d).unwrap();
        let calls = &out.spec.rules[0].allowed_calls;
        assert_eq!(calls.len(), 1, "{calls:#?}");
        assert_eq!(calls[0].justified_by.len(), 2);

        // The count is per function: one rule with a widened call of each of two functions holds
        // one call per widening.
        let args = || {
            vec![
                ArgSummary::Address(account_strkey()),
                ArgSummary::Address(merchant_strkey()),
                ArgSummary::I128(2000),
            ]
        };
        let mut two_functions = input();
        two_functions.bundles = vec![bundle_with_subs(
            (&token, "transfer", args()),
            vec![(&token, "approve", args())],
        )];
        let mut approve = amount_widening(range, false);
        approve.fn_name = "approve".to_string();
        d.widenings.push(approve);
        let out = synthesize(&two_functions, &d).unwrap();
        assert_eq!(out.spec.rules[0].allowed_calls.len(), 2);

        // And per argument: it counts the calls carrying this widening, not those carrying
        // another. Recorded as `pay(SELF, payee, 2000)` and a shorter `pay(SELF, payee)`, the
        // amount widening reaches one call and is that call's; the recipient widening reaches
        // both and is refused, alone.
        let mut two_arities = input();
        two_arities.bundles = vec![bundle_with_subs(
            (&token, "pay", args()),
            vec![(&token, "pay", args()[..2].to_vec())],
        )];
        let mut amount = amount_widening(
            WideningBound::RangeI128 {
                min: "0".to_string(),
                max: "2000".to_string(),
            },
            false,
        );
        amount.fn_name = "pay".to_string();
        let mut recipient = amount.clone();
        recipient.arg_index = 1;
        recipient.bound = WideningBound::AnyValue;
        d.widenings = vec![amount, recipient];
        assert_eq!(
            synthesize(&two_arities, &d).unwrap_err(),
            vec![SynthError::InvalidDecision(format!(
                "widening {token}/pay arg 1: this widening would apply to 2 distinct recorded \
                 calls of pay on {token}, loosening argument 1 of each; a widening loosens one \
                 argument of one recorded call, and a decision cannot name which. Keep the \
                 argument exact, or synthesize from recordings in which pay is one distinct call"
            ))]
        );
    }

    #[test]
    fn spending_limit_requires_registry_capability() {
        let mut i = input();
        i.spending_limit_capability = None;
        let errs = synthesize(&i, &decisions()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::UnregisteredPolicy(_))));
    }

    #[test]
    fn duplicate_recordings_dedup_and_merge_evidence() {
        let mut i = input();
        i.bundles = vec![transfer_bundle(), transfer_bundle()]; // identical
        let out = synthesize(&i, &decisions()).unwrap();
        assert_eq!(
            out.spec.evidence.recordings.len(),
            1,
            "identical bundles dedup to one canonical recording ref"
        );
    }

    #[test]
    fn create_contract_authorization_fails_closed() {
        let mut bundle = transfer_bundle();
        bundle.authorizations[0].root.call = AuthorizedCall::CreateContract;
        let mut i = input();
        i.bundles = vec![bundle];
        let errs = synthesize(&i, &decisions()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::UnsupportedPattern(_))));
    }

    proptest::proptest! {
        /// Property: whenever synthesis succeeds, the produced spec validates and every
        /// constraint is observed_exact unless an explicit widening decision produced it.
        #[test]
        fn synthesized_specs_always_validate(max_calls in 1u32..1000, ledger in 1u32..u32::MAX) {
            let mut d = decisions();
            d.max_calls = Some(max_calls);
            d.valid_until_ledger = Some(ledger);
            if let Ok(out) = synthesize(&input(), &d) {
                let validated = out.spec.validate();
                proptest::prop_assert!(validated.is_ok());
                for rule in &validated.unwrap().spec().rules {
                    for call in &rule.allowed_calls {
                        for arg in &call.args {
                            proptest::prop_assert_eq!(&arg.provenance, &Provenance::ObservedExact);
                        }
                    }
                }
            }
        }
    }

    // Small helper to pull the observed contract strkey out of a bundle.
    trait CallContractExt {
        fn call_contract(&self) -> String;
    }
    impl CallContractExt for InvocationNode {
        fn call_contract(&self) -> String {
            match &self.call {
                AuthorizedCall::Contract { contract, .. } => contract.clone(),
                _ => panic!("not a contract call"),
            }
        }
    }
    // --- token-movement value hints (evidence only, never a constraint) -------------------

    /// The recorded transfer moves `AMOUNT` from the account to the merchant, and the authorized
    /// argument vector is `[account, merchant, AMOUNT]`. The hint must name the index that
    /// carries the value and the two that carry the parties, because that is the evidence a user
    /// needs to answer the one question the toolkit refuses to answer for them.
    #[test]
    fn a_token_movement_names_the_argument_that_carries_value() {
        let out = synthesize(&input(), &decisions()).unwrap();
        let hint = out
            .rationale
            .iter()
            .find(|r| r.contains("token movement"))
            .unwrap_or_else(|| {
                panic!(
                    "no token-movement evidence in rationale: {:#?}",
                    out.rationale
                )
            });

        assert!(
            hint.contains("arg 2"),
            "the value is argument 2 of transfer(from, to, amount); hint said: {hint}"
        );
        assert!(
            hint.contains("500000000"),
            "the hint must quote the moved amount so it can be checked: {hint}"
        );
        assert!(
            hint.contains("arg 0") && hint.contains("arg 1"),
            "the payer and payee arguments are what make the direction checkable: {hint}"
        );
        assert!(
            hint.contains("evidence"),
            "the line must say it is evidence, not a decision: {hint}"
        );
    }

    /// A movement that matches no authorized argument is the signal that the call executed with a
    /// different vector than the one authorized — `require_auth_for_args` permits exactly that.
    /// Saying nothing would hide it.
    #[test]
    fn a_movement_matching_no_argument_is_reported_rather_than_dropped() {
        let mut i = input();
        for movement in &mut i.bundles[0].token_movements {
            movement.amount = Some(999);
        }
        let out = synthesize(&i, &decisions()).unwrap();
        assert!(
            out.rationale
                .iter()
                .any(|r| r.contains("token movement") && r.contains("999") && r.contains("no")),
            "an unmatched movement must be reported: {:#?}",
            out.rationale
        );
    }

    /// The property most worth protecting and the easiest to lose in a refactor: a movement is a
    /// post-execution effect, so it must never *derive a constraint*. Editing a movement does
    /// change the spec hash — the bundle it belongs to is hashed whole and the spec pins that
    /// hash — so the guarantee is about what movements produce, not about the hash staying put.
    #[test]
    fn the_value_hint_never_reaches_the_spec() {
        let plain = synthesize(&input(), &decisions()).unwrap();

        let mut altered = input();
        for movement in &mut altered.bundles[0].token_movements {
            movement.amount = Some(1);
            movement.to = Some(merchant_strkey());
        }
        let hinted = synthesize(&altered, &decisions()).unwrap();

        // Compared per rule rather than whole-spec, and the reason is worth stating: editing a
        // bundle changes that bundle's own hash, which the spec pins in `evidence.recordings`.
        // That difference is the evidence chain working — it says the spec came from a different
        // recording — so a whole-spec assertion would fail for a reason that is not the property
        // under test. What must not move is anything derived.
        assert_eq!(
            plain.spec.rules, hinted.spec.rules,
            "token movements changed a rule; they are evidence, not a constraint"
        );
        assert_eq!(
            plain.spec.smart_account, hinted.spec.smart_account,
            "token movements changed the account record; they are evidence, not a decision"
        );
        assert_ne!(
            plain.rationale, hinted.rationale,
            "if the rationale is identical too, this test proves nothing about where the \
             evidence went"
        );
    }

    /// A movement belongs to the recording that observed it. Comparing it against calls from
    /// every recording lets an integer coincidence attribute value across unrelated transactions,
    /// which is worse than saying nothing: it is a confident claim about the wrong call.
    #[test]
    fn a_movement_is_not_attributed_to_a_call_from_another_recording() {
        let mut i = input();
        // Two recordings. The first keeps the transfer's movements; the second has none of its
        // own but authorizes the same call, so any line naming it can only have come from the
        // first recording's movements.
        let mut second = transfer_bundle();
        second.token_movements.clear();
        i.bundles.push(second);

        let out = synthesize(&i, &decisions()).unwrap();
        let attributions = out
            .rationale
            .iter()
            .filter(|r| r.contains("token movement") && r.contains("arg 2"))
            .count();

        assert_eq!(
            attributions, 1,
            "a movement recorded once was attributed {attributions} times, so a call from a \
             recording that observed no movement was credited with one: {:#?}",
            out.rationale
        );
    }

    /// Equal amounts in two arguments are ordinary — an input and an output that happen to match,
    /// a fee equal to a principal. The movement then identifies no unique index, and naming one
    /// anyway is evidence pointing at the wrong argument.
    #[test]
    fn equal_amounts_in_two_arguments_are_reported_as_ambiguous() {
        let mut i = input();
        // Make argument 1 carry the same i128 as argument 2 so exactly two candidates exist.
        for bundle in &mut i.bundles {
            for auth in &mut bundle.authorizations {
                if let AuthorizedCall::Contract { args, .. } = &mut auth.root.call {
                    let amount = args.iter().find_map(|a| match a {
                        ArgSummary::I128(v) => Some(*v),
                        _ => None,
                    });
                    if let Some(v) = amount {
                        args[1] = ArgSummary::I128(v);
                    }
                }
            }
        }

        let out = synthesize(&i, &decisions()).unwrap();
        let hint = out
            .rationale
            .iter()
            .find(|r| r.contains("token movement"))
            .unwrap_or_else(|| panic!("no movement evidence: {:#?}", out.rationale));

        assert!(
            hint.contains("arg 1") && hint.contains("arg 2"),
            "both candidate indices must be named when the amount does not single one out: {hint}"
        );
        assert!(
            !hint.contains("is the one carrying value"),
            "with two candidates the line must not claim a unique index: {hint}"
        );
    }

    /// `decode_token_event` keeps a recognized transfer, mint or burn whose data carries no
    /// decodable amount, so `amount: None` is not an approval-only shape. Dropping those is the
    /// silence this evidence exists to prevent.
    #[test]
    fn a_movement_without_an_amount_is_reported_rather_than_dropped() {
        let mut i = input();
        for movement in &mut i.bundles[0].token_movements {
            movement.amount = None;
        }
        let out = synthesize(&i, &decisions()).unwrap();

        assert!(
            out.rationale
                .iter()
                .any(|r| r.contains("token movement") && r.contains("amount")),
            "a movement whose amount could not be decoded must still be reported: {:#?}",
            out.rationale
        );
    }

    /// Mint has no sender and burn no recipient by construction, and an approval's counterparty
    /// is the spender. A generic from/to sentence makes all three look like missing evidence.
    #[test]
    fn evidence_is_worded_for_the_movement_kind() {
        let mut i = input();
        for movement in &mut i.bundles[0].token_movements {
            movement.kind = MovementKind::Mint;
            movement.from = None;
        }
        let out = synthesize(&i, &decisions()).unwrap();
        let hint = out
            .rationale
            .iter()
            .find(|r| r.contains("token movement"))
            .unwrap_or_else(|| panic!("no movement evidence: {:#?}", out.rationale));

        assert!(
            hint.contains("minted to"),
            "a mint moves value to a recipient and has no sender; the line must say so: {hint}"
        );
        assert!(
            !hint.contains("did not record"),
            "a mint has no sender by construction, so reporting one as unrecorded claims a \
             defect in a well-formed event: {hint}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Golden fixtures: the end-to-end Phase 1 pipeline spec (recorder fixture → synthesize).
// Shared by codegen tests and the contracts differential suite.
// ---------------------------------------------------------------------------------------

// Deterministic test-support builders shared across crates. `unwrap`/`panic` on
// known-good literals is intentional; the core-logic lint stays in force elsewhere.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod fixtures {
    use super::*;
    use ozpb_domain::sha256;
    use ozpb_policy_spec::ValidatedSpec;
    use ozpb_recorder_core::{fixtures as rec, record, RecordOptions};

    pub fn golden_account_strkey() -> String {
        format!("{}", stellar_strkey::Contract([1u8; 32]))
    }

    pub fn golden_token_strkey() -> String {
        format!("{}", stellar_strkey::Contract([2u8; 32]))
    }

    pub fn golden_merchant_strkey() -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([3u8; 32]))
    }

    pub fn golden_delegate_strkey() -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([7u8; 32]))
    }

    pub fn golden_bundle() -> RecordingBundle {
        golden_bundle_on(ozpb_domain::TESTNET_PASSPHRASE)
    }

    /// [`golden_bundle`] recorded on another network.
    pub fn golden_bundle_on(network_passphrase: &str) -> RecordingBundle {
        match record(
            &rec::executed_snapshot_on(network_passphrase),
            RecordOptions::default(),
        ) {
            Ok(mut bundle) => {
                bundle.contract_executables.insert(
                    golden_account_strkey(),
                    ozpb_recorder_core::ExecutableObservation {
                        executable: ozpb_recorder_core::ObservedExecutable::Wasm {
                            code_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                        },
                        observed_ledger: LedgerSeq(4_200_100),
                        last_modified_ledger: None,
                        live_until_ledger: None,
                    },
                );
                bundle.contract_executables.insert(
                    golden_token_strkey(),
                    ozpb_recorder_core::ExecutableObservation {
                        executable: ozpb_recorder_core::ObservedExecutable::StellarAsset,
                        observed_ledger: LedgerSeq(4_200_100),
                        last_modified_ledger: None,
                        live_until_ledger: None,
                    },
                );
                bundle
            }
            Err(e) => panic!("golden recording must succeed: {e}"),
        }
    }

    pub fn golden_input() -> SynthesisInput {
        SynthesisInput {
            bundles: vec![golden_bundle()],
            selected_authorizer: golden_account_strkey(),
            account: SmartAccountRecord {
                address: golden_account_strkey(),
                observed_code_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                registry_resolution: "stellar-accounts@0.7.x (dev registry)".to_string(),
            },
            registry_snapshot: sha256(b"dev-registry-snapshot"),
            spending_limit_capability: Some(pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM),
            template_family: "policy-templates/scope@1".to_string(),
            template_capability_schema: sha256(b"policy-templates/scope@1:capability-algebra"),
            adapters: vec![],
        }
    }

    pub fn golden_decisions() -> UserDecisions {
        UserDecisions {
            grant_name: "sub-transfer".to_string(),
            delegate_signers: vec![SignerSpec::Delegated {
                address: golden_delegate_strkey(),
            }],
            predicate: PredicateChoice::AnyOf,
            valid_until_ledger: Some(4_223_456),
            no_expiry_acknowledged: false,
            max_calls: Some(12),
            unlimited_calls_acknowledged: false,
            widenings: vec![],
            spending_limit: Some(SpendingLimitChoice {
                limit: "500000000".to_string(),
                period_ledgers: 120_960,
            }),
        }
    }

    /// The golden validated spec: the full Phase 1 pipeline output for the recorded
    /// testnet-style transfer.
    pub fn golden_spec() -> ValidatedSpec {
        let out = match synthesize(&golden_input(), &golden_decisions()) {
            Ok(o) => o,
            Err(e) => panic!("golden synthesis must succeed: {e:?}"),
        };
        match out.spec.validate() {
            Ok(v) => v,
            Err(e) => panic!("golden spec must validate: {e:?}"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn golden_strkeys_are_stable_fixture_inputs_not_self_referential_expectations() {
            assert_eq!(
                golden_account_strkey(),
                "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526"
            );
            assert_eq!(
                golden_token_strkey(),
                "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ"
            );
            assert_eq!(
                golden_merchant_strkey(),
                "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC"
            );
            assert_eq!(
                golden_delegate_strkey(),
                "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI"
            );
        }
    }
}
