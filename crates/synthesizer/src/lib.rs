//! Synthesizer v1 (architecture §4.3): RecordingBundle(s) + explicit user decisions →
//! PolicySpec. Pure, deterministic, **fail-closed**.
//!
//! Exact-by-default: every observed argument becomes a deep exact-equality constraint on
//! the complete tuple. Widening is never heuristic — it enters only through an explicit
//! [`Widening`] decision carrying intent and blast radius. The delegate signer set and
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
    TargetHashRole, ValidUntil, SPEC_SCHEMA,
};
use ozpb_recorder_core::{
    ArgSummary, AuthorizedCall, InvocationNode, MovementKind, ObservedExecutable, RecordingBundle,
    TokenMovement,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stellar_xdr::{Limits, WriteXdr};

pub mod adapters;
// Test-support walkthrough builders (W1/W3), shared across crates' tests; `expect` on
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
    /// Optional per-installation call cap.
    pub max_calls: Option<u32>,
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
    if decisions.valid_until_ledger.is_none() && !decisions.no_expiry_acknowledged {
        errors.push(SynthError::NeedsDecision(
            "grant lifetime: provide valid_until_ledger, or explicitly acknowledge a \
             non-expiring grant (high blast radius)"
                .to_string(),
        ));
    }
    if let PredicateChoice::Threshold { n } = decisions.predicate {
        let count = decisions.delegate_signers.len();
        if n == 0 || (n as usize) > count {
            errors.push(SynthError::NeedsDecision(format!(
                "threshold {n} is not within 1..={count} delegate signers"
            )));
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
            let args = exact_constraints(o, input, decisions, adapter, &mut errors, &mut rationale);
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
            kind: "gen:scope+count".to_string(),
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
            None => vec![],
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

    // Unused widenings are decisions that matched nothing — surface them, fail closed.
    for w in &decisions.widenings {
        let applied = rules.iter().any(|r| {
            r.context.contract == w.contract
                && r.allowed_calls.iter().any(|c| {
                    c.fn_name == w.fn_name
                        && c.args
                            .iter()
                            .any(|a| a.index == w.arg_index && a.constraint.is_widening())
                })
        });
        if !applied {
            errors.push(SynthError::AmbiguousArgSemantics {
                contract: w.contract.clone(),
                fn_name: w.fn_name.clone(),
                arg_index: w.arg_index,
                reason: "widening matched no observed numeric argument".to_string(),
            });
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
            (ArgSummary::I128(_), Some(w)) => {
                rationale.push(format!(
                    "{}/{} arg {index}: user-widened ({}), blast radius {:?}",
                    o.contract, o.fn_name, w.intent, w.blast_radius
                ));
                (
                    match &w.bound {
                        WideningBound::LeI128 { max } => Constraint::LeI128 { max: max.clone() },
                        WideningBound::GeI128 { min } => Constraint::GeI128 { min: min.clone() },
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
                        rationale.push(format!(
                            "{}/{} arg {index}: adapter '{}' derived a code-hash-bound widening \
                             from its reviewed argument role (valid only while the target's code \
                             hash holds)",
                            o.contract, o.fn_name, ad.name
                        ));
                        let constraint = match bound {
                            WideningBound::LeI128 { max } => Constraint::LeI128 { max },
                            WideningBound::GeI128 { min } => Constraint::GeI128 { min },
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
            },
        );
        bundle.contract_executables.insert(
            format!("{}", stellar_strkey::Contract([2u8; 32])),
            ExecutableObservation {
                executable: ObservedExecutable::StellarAsset,
                observed_ledger: LedgerSeq(4_200_100),
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
    fn a_reviewed_adapter_bound_to_the_observed_code_hash_derives_widenings() {
        use adapters::{Adapter, ArgRole, FnRoles};

        let target = format!("{}", stellar_strkey::Contract([2u8; 32]));
        let code_hash = sha256(b"reviewed-token-wasm");

        let mut input = input();
        // The recorder observed the target's on-chain code hash — the adapter binds to it.
        input.bundles[0].contract_executables.insert(
            target,
            ExecutableObservation {
                executable: ObservedExecutable::Wasm { code_hash },
                observed_ledger: LedgerSeq(4_200_100),
            },
        );
        // `amount` (arg 2) is a MaxInput → the reviewed adapter caps it from above; from/to
        // keep their exact roles. This is a non-user widening path: provenance is adapter-derived.
        let mut functions = std::collections::BTreeMap::new();
        functions.insert(
            "transfer".to_string(),
            FnRoles {
                fn_name: "transfer".to_string(),
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
            raw: RawEvidence {
                envelope_xdr_base64: "x".to_string(),
                result_meta_xdr_base64: None,
                simulated_auth_xdr_base64: vec![],
            },
        }
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
        for (constraint, accepted) in [
            (Constraint::EqI128 { value: "-1".into() }, false),
            (Constraint::EqI128 { value: "0".into() }, true),
            (Constraint::EqI128 { value: "10".into() }, true),
            (Constraint::EqI128 { value: "11".into() }, false),
            (Constraint::LeI128 { max: "-1".into() }, false),
            (Constraint::LeI128 { max: "0".into() }, true),
            (Constraint::GeI128 { min: "10".into() }, true),
            (Constraint::GeI128 { min: "11".into() }, false),
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
            intent: "typo'd target".to_string(),
            blast_radius: BlastRadius::Low,
        }];
        let errs = synthesize(&input(), &d).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SynthError::AmbiguousArgSemantics { .. })));
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

    pub fn golden_bundle() -> RecordingBundle {
        match record(&rec::executed_snapshot(), RecordOptions::default()) {
            Ok(mut bundle) => {
                bundle.contract_executables.insert(
                    golden_account_strkey(),
                    ozpb_recorder_core::ExecutableObservation {
                        executable: ozpb_recorder_core::ObservedExecutable::Wasm {
                            code_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                        },
                        observed_ledger: LedgerSeq(4_200_100),
                    },
                );
                bundle.contract_executables.insert(
                    golden_token_strkey(),
                    ozpb_recorder_core::ExecutableObservation {
                        executable: ozpb_recorder_core::ObservedExecutable::StellarAsset,
                        observed_ledger: LedgerSeq(4_200_100),
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
}
