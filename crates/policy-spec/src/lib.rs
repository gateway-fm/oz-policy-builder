//! PolicySpec v1 — the canonical, deterministic middle layer (architecture §4.2).
//!
//! The spec is the audit boundary: synthesizer output and codegen input are both
//! `PolicySpec`, and the *only* way to reach code generation is through
//! [`PolicySpec::validate`], which returns the [`ValidatedSpec`] typestate. A spec
//! contains **no build outputs** — the artifact chain is acyclic.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::{domains, Hash32, LedgerSeq, NetworkId, Provenance};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stellar_xdr::{ScBytes, ScString, ScSymbol, ScVal, StringM};

pub const SPEC_SCHEMA: &str = "policy-spec/v1";

/// On-chain limits of the pinned `stellar-accounts` release (enforced at validation).
pub const MAX_POLICIES_PER_RULE: usize = 5;
pub const MAX_SIGNERS_PER_RULE: usize = 15;
pub const MAX_NAME_BYTES: usize = 20;
/// Defensive off-chain bounds. These are intentionally below Soroban collection limits so
/// validation, canonical hashing, code generation, and review remain predictably bounded.
pub const MAX_RULES: usize = 32;
pub const MAX_CALLS_PER_RULE: usize = 32;
pub const MAX_ARGS_PER_CALL: usize = 32;
pub const MAX_EVIDENCE_RECORDINGS: usize = 256;

// ---------------------------------------------------------------------------------------
// Schema types. Every struct is a closed schema (`deny_unknown_fields`); every map is a
// BTreeMap (canonical hashing).
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    /// Schema identifier. Named `schema` rather than `$schema`: the value is a plain
    /// identifier, not a JSON-Schema URI, and `$` is not a legal `Symbol` character, so the
    /// old name could not be encoded in a canonical preimage at all.
    pub schema: String,
    /// Rule name; ≤20 bytes, lowercase kebab (matches the contract's MAX_NAME_SIZE).
    pub name: String,
    pub network_id: NetworkId,
    /// Root hash of the registry snapshot whose entries this spec's decisions relied on.
    pub registry_snapshot: Hash32,
    pub smart_account: SmartAccountRecord,
    pub rules: Vec<RuleSpec>,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartAccountRecord {
    /// C-address (strkey) of the selected smart-account authorizer.
    pub address: String,
    pub observed_code_hash: Hash32,
    /// Human-readable registry resolution, e.g. "stellar-accounts@0.7.x (entry sha256:…)".
    pub registry_resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub context: ContextSpec,
    pub valid_until: Option<ValidUntil>,
    pub authorization: AuthorizationSpec,
    /// Disjunction of COMPLETE argument tuples — never per-index allowlists.
    pub allowed_calls: Vec<AllowedCall>,
    pub policies: Vec<PolicyRef>,
    pub state: Vec<StateSpec>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSpec {
    /// Phase 1 supports `CallContract` only; `Default` rules are never synthesized —
    /// minimum permission is structural.
    #[serde(rename = "type")]
    pub context_type: ContextType,
    /// C-address of the target contract.
    pub contract: String,
    pub target_code_hash: Option<TargetCodeHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextType {
    CallContract,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCodeHash {
    pub hash: Hash32,
    pub role: TargetHashRole,
    pub observed_ledger: LedgerSeq,
    pub on_drift: DriftResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHashRole {
    EvidenceOnly,
    AdapterRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftResponse {
    Warn,
    Refuse,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidUntil {
    pub ledger: LedgerSeq,
    /// Informational wall-clock approximation; never used for enforcement.
    pub approx_time: Option<String>,
}

/// The grant's signer predicate — REQUIRED on every rule (architecture §4.2/§4.3).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationSpec {
    pub kind: PredicateKind,
    /// Strict signer-set semantics: mandatory whenever the predicate names identities.
    pub strict_signer_set: bool,
    pub signers: Vec<SignerSpec>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PredicateKind {
    AnyOf,
    AllOf,
    Threshold {
        n: u32,
    },
    /// Explicitly dynamic: "one of the signers *currently managed by this rule*". Makes
    /// no claim that the original identities remain authoritative (Decision D1).
    AnyOfCurrentRuleSigners,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerSpec {
    Delegated {
        address: String,
    },
    External {
        verifier: String,
        verifier_code_hash: Hash32,
        key_hex: String,
    },
}

impl SignerSpec {
    /// The signer as the account stores it, expressed as an `ScVal`.
    ///
    /// This is the representation `__check_auth` matches against: `stellar-accounts` declares
    /// `Signer::Delegated(Address)` and `Signer::External(Address, Bytes)`, and a Soroban enum
    /// encodes as a vector led by its variant name. Building that, rather than a string derived
    /// from it, is the point — the previous encoding was `"external:" + strkey + ":" + hex`,
    /// whose injectivity depended on character-set validators living far from this function. Hash
    /// what the account compares, and the argument disappears.
    ///
    /// `verifier_code_hash` is deliberately absent: the account matches on `Signer`, which does
    /// not carry it. Including it here would hash something the on-chain comparison never sees.
    ///
    /// # Why the address is its strkey and not a parsed `ScVal::Address`
    ///
    /// `ScVal::Address` would be the exact on-chain type, and the first version of this used it.
    /// It made the function fallible, because parsing a strkey verifies its checksum — and this
    /// schema admits addresses that do not have one. `validate` checks an address's charset and
    /// length, never its checksum, so a spec carrying an unparseable address is a spec this crate
    /// accepts. A fallible hash over input the schema allows is how the caller ends up comparing
    /// two `Result`s, which is precisely the fail-open this replaced: two `Err`s compare equal, so
    /// an unencodable signer set silently matched every other unencodable one.
    ///
    /// A strkey is a checksummed, canonical encoding of exactly one address, so carrying it as a
    /// string is injective with respect to the address it denotes — nothing is conflated. What the
    /// earlier encoding got wrong was not the strkey but the concatenation around it:
    /// `"external:" + strkey + ":" + hex` depended on no field containing the separator. Here the
    /// variant tag and each field occupy their own position in a vector, so there is no separator
    /// to reason about.
    pub fn to_stored_scval(&self) -> Result<ScVal, SpecError> {
        match self {
            SignerSpec::Delegated { address } => {
                scval_vec(vec![scval_symbol("Delegated")?, scval_string(address)?])
            }
            SignerSpec::External {
                verifier, key_hex, ..
            } => {
                let key = hex::decode(key_hex).map_err(|_| {
                    SpecError::Schema(format!("{key_hex:?} is not hex-encoded key material"))
                })?;
                let bytes: ScBytes = key.try_into().map_err(|_| {
                    SpecError::Schema("key material exceeds the XDR length limit".to_string())
                })?;
                scval_vec(vec![
                    scval_symbol("External")?,
                    scval_string(verifier)?,
                    ScVal::Bytes(bytes),
                ])
            }
        }
    }
}

fn scval_symbol(name: &str) -> Result<ScVal, SpecError> {
    let sym: ScSymbol = name
        .try_into()
        .map_err(|_| SpecError::Schema(format!("{name:?} is not a valid Symbol")))?;
    Ok(ScVal::Symbol(sym))
}

fn scval_string(value: &str) -> Result<ScVal, SpecError> {
    let inner: StringM = value.try_into().map_err(|_| {
        SpecError::Schema("address exceeds the XDR string length limit".to_string())
    })?;
    Ok(ScVal::String(ScString(inner)))
}

fn scval_vec(items: Vec<ScVal>) -> Result<ScVal, SpecError> {
    Ok(ScVal::Vec(Some(items.try_into().map_err(|_| {
        SpecError::Schema("signer vector exceeds the XDR length limit".to_string())
    })?)))
}

/// Canonical signer-set hash: the stored `Signer` values, sorted, under the signer-set domain.
///
/// Sorting is over the encoded `ScVal`s using the XDR crate's own ordering, which is the same
/// comparison `ScMap` uses to canonicalise its keys — so the set has one encoding regardless of
/// the order the signers were listed in, and that ordering is a published rule rather than one
/// invented here.
pub fn signer_set_hash(signers: &[SignerSpec]) -> Result<Hash32, SpecError> {
    let mut encoded = signers
        .iter()
        .map(SignerSpec::to_stored_scval)
        .collect::<Result<Vec<_>, _>>()?;
    encoded.sort();
    ozpb_domain::canonical_hash_of(domains::SIGNER_SET, scval_vec(encoded)?)
        .map_err(|e| SpecError::Schema(format!("hashing the signer set: {e}")))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedCall {
    #[serde(rename = "fn")]
    pub fn_name: String,
    /// Complete tuple: one constraint per argument, indexes 0..n-1, exact arg count.
    pub args: Vec<ArgConstraint>,
    /// Evidence mapping: which recorded invocation(s) justify this tuple.
    pub justified_by: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgConstraint {
    #[serde(rename = "i")]
    pub index: u32,
    #[serde(rename = "c")]
    pub constraint: Constraint,
    #[serde(rename = "prov")]
    pub provenance: Provenance,
}

/// Address reference: `SELF` resolves at runtime to the smart account (so generated wasm
/// is account-independent — §4.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AddressRef {
    /// The literal string "SELF".
    SelfAccount(SelfMarker),
    Address(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfMarker {
    #[serde(rename = "SELF")]
    Marker,
}

impl AddressRef {
    pub fn self_account() -> Self {
        AddressRef::SelfAccount(SelfMarker::Marker)
    }
    pub fn address(a: impl Into<String>) -> Self {
        AddressRef::Address(a.into())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Constraint {
    /// Deep exact equality with an address argument.
    EqAddress { value: AddressRef },
    /// Deep exact equality with an arbitrary ScVal (canonical XDR, base64).
    EqScval { xdr_base64: String },
    /// Exact i128 amount (decimal string).
    EqI128 { value: String },
    /// Upper bound (inclusive) — only reachable through explicit widening.
    LeI128 { max: String },
    /// Lower bound (inclusive) — only reachable through explicit widening.
    GeI128 { min: String },
    /// Accept ANY value at this argument position — the maximal widening (e.g. W3's
    /// caller-chosen `deadline`). Only reachable through an explicit, high-blast-radius
    /// user decision; the report states the argument is unconstrained. Arity is still
    /// enforced (the argument must be present).
    AnyValue,
}

impl Constraint {
    /// Bounds and wildcards are widenings by definition; exact equality is the observed
    /// minimum.
    pub fn is_widening(&self) -> bool {
        matches!(
            self,
            Constraint::LeI128 { .. } | Constraint::GeI128 { .. } | Constraint::AnyValue
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyRef {
    /// A pre-existing reviewed policy, resolved via the capability registry by exact
    /// reviewed wasm hash (never by claimed kind).
    Reviewed {
        kind: String,
        capability: Hash32,
        params: ReviewedParams,
    },
    /// A toolkit-generated policy, identified pre-build by its audited template family;
    /// its exact wasm hash exists only in the BuildManifest (acyclic chain, §4.2).
    Generated {
        kind: String,
        template_family: String,
        capability_schema: Hash32,
    },
}

/// Parameters for a reviewed upstream policy: one variant per policy this toolkit composes.
///
/// Closed on purpose. It was previously an open `BTreeMap<String, serde_json::Value>`, which had
/// two problems. A `serde_json::Value` has no counterpart in Stellar's value system at all, so it
/// could not appear in a canonical preimage. And an opaque parameter bag inside a hashed
/// attestation contradicts what this project claims everywhere else — that the person the
/// attestation is for can read exactly what will execute.
///
/// Closing it costs little: the capability registry already recognises a reviewed policy by its
/// exact wasm hash, so composing a new one already requires a change here. Adding a variant is
/// that change.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewedParams {
    /// OpenZeppelin's spending limit: an amount cap over a rolling window of ledgers.
    ///
    /// `limit` is a canonical decimal `i128` for the same reason every other amount in this
    /// schema is a string — the value exceeds what a JSON number carries exactly.
    SpendingLimit { limit: String, period_ledgers: u32 },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StateSpec {
    /// Per-installation call cap: missing state denies, initialised only by `install`, and never
    /// reset by inactivity, TTL expiry or archival (§4.4).
    ///
    /// Named per-installation rather than lifetime because `uninstall` removes the counter entry
    /// and a later `install` legitimately starts from zero. Both are gated on the account
    /// owner's authorization, so only the owner reaches that path — but the guarantee stated to
    /// a user is per installation, and the name has to say so.
    CallCountPerInstallation { max_calls: u32 },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Canonically ordered, deduplicated recording references.
    pub recordings: Vec<RecordingRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingRef {
    pub hash: Hash32,
    pub trust: ozpb_domain::TrustLevel,
}

// ---------------------------------------------------------------------------------------
// Validation typestate
// ---------------------------------------------------------------------------------------

/// A validated PolicySpec. The only constructor is [`PolicySpec::validate`]; codegen and
/// the evaluator accept nothing else (parse, don't validate — §4.11).
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedSpec {
    spec: PolicySpec,
    hash: Hash32,
}

impl ValidatedSpec {
    pub fn spec(&self) -> &PolicySpec {
        &self.spec
    }

    /// Canonical spec hash (domain-separated; includes the canonicalization version).
    pub fn hash(&self) -> Hash32 {
        self.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("E_SPEC_SCHEMA: expected schema {SPEC_SCHEMA}, got {0}")]
    Schema(String),
    #[error("E_SPEC_NAME: name must be 1..=20 bytes of lowercase kebab ([a-z0-9-]): {0}")]
    Name(String),
    #[error("E_SPEC_EMPTY: a spec must contain at least one rule")]
    NoRules,
    #[error("E_SPEC_NO_CALLS: rule {0} has no allowed calls (default-deny needs a grant)")]
    NoCalls(usize),
    #[error(
        "E_SPEC_EXTERNAL_UNSUPPORTED: rule {rule}, signer {signer}: external verifiers are not \
         supported by the Phase 1 enforcement model"
    )]
    ExternalSignerUnsupported { rule: usize, signer: usize },
    #[error(
        "E_SPEC_SIGNER_POLICY: rule {rule} must contain exactly one generated \
         signer-enforcing policy; found {generated}"
    )]
    SignerPolicy { rule: usize, generated: usize },
    #[error("E_SPEC_NO_SIGNERS: rule {0} names a predicate over identities but lists none")]
    NoSigners(usize),
    #[error(
        "E_SPEC_STRICT_REQUIRED: rule {0} names concrete signer identities; verified mode \
         requires strict_signer_set (Decision D1)"
    )]
    StrictRequired(usize),
    #[error(
        "E_SPEC_DYNAMIC_STRICT: rule {0} uses the dynamic predicate; strict_signer_set is \
         contradictory there"
    )]
    DynamicStrict(usize),
    #[error("E_SPEC_THRESHOLD: rule {0}: threshold {1} not in 1..=signer count {2}")]
    Threshold(usize, u32, usize),
    #[error(
        "E_SPEC_DUPLICATE_SIGNER: rule {rule}: signer {duplicate} duplicates logical identity \
         at signer {first}"
    )]
    DuplicateSigner {
        rule: usize,
        first: usize,
        duplicate: usize,
    },
    #[error("E_SPEC_EXTERNAL_KEY: rule {rule}, signer {signer}: key_hex is not valid hex")]
    ExternalKey { rule: usize, signer: usize },
    #[error(
        "E_SPEC_I128: rule {rule}, call '{call}', arg {arg}: value '{value}' must be the \
         canonical decimal representation of an i128"
    )]
    I128 {
        rule: usize,
        call: String,
        arg: u32,
        value: String,
    },
    #[error("E_SPEC_STATE: rule {rule}: {reason}")]
    State { rule: usize, reason: String },
    #[error("E_SPEC_LIMITS: rule {0}: {1}")]
    Limits(usize, String),
    #[error("E_SPEC_LIMITS: {0}")]
    GlobalLimits(String),
    #[error(
        "E_SPEC_ARG_INDEXES: rule {0}, call '{1}': argument constraints must cover exactly \
         indexes 0..n-1 (complete tuples, exact arg count)"
    )]
    ArgIndexes(usize, String),
    #[error(
        "E_SPEC_WIDENING_PROVENANCE: rule {0}, call '{1}', arg {2}: bound constraints \
         require user_widened or adapter_derived provenance — never observed_exact"
    )]
    WideningProvenance(usize, String, u32),
    #[error("E_SPEC_NO_EVIDENCE: spec carries no recording references")]
    NoEvidence,
    #[error("E_SPEC_UNJUSTIFIED: rule {0}, call '{1}' maps to no justifying recording")]
    Unjustified(usize, String),
}

impl PolicySpec {
    /// Validate and seal the spec. Fail-closed: all violations are reported, none skipped.
    pub fn validate(self) -> Result<ValidatedSpec, Vec<SpecError>> {
        let mut errors = Vec::new();

        if self.schema != SPEC_SCHEMA {
            errors.push(SpecError::Schema(self.schema.clone()));
        }
        if !name_is_valid(&self.name) {
            errors.push(SpecError::Name(self.name.clone()));
        }
        if self.rules.is_empty() {
            errors.push(SpecError::NoRules);
        }
        if self.rules.len() > MAX_RULES {
            errors.push(SpecError::GlobalLimits(format!(
                "{} rules > max {MAX_RULES}",
                self.rules.len()
            )));
        }
        if self.evidence.recordings.is_empty() {
            errors.push(SpecError::NoEvidence);
        }
        if self.evidence.recordings.len() > MAX_EVIDENCE_RECORDINGS {
            errors.push(SpecError::GlobalLimits(format!(
                "{} evidence recordings > max {MAX_EVIDENCE_RECORDINGS}",
                self.evidence.recordings.len()
            )));
        }
        for (ri, rule) in self.rules.iter().enumerate() {
            if rule.allowed_calls.is_empty() {
                errors.push(SpecError::NoCalls(ri));
            }
            if rule.allowed_calls.len() > MAX_CALLS_PER_RULE {
                errors.push(SpecError::Limits(
                    ri,
                    format!(
                        "{} allowed calls > max {MAX_CALLS_PER_RULE}",
                        rule.allowed_calls.len()
                    ),
                ));
            }
            if rule.policies.len() > MAX_POLICIES_PER_RULE {
                errors.push(SpecError::Limits(
                    ri,
                    format!(
                        "{} policies > max {}",
                        rule.policies.len(),
                        MAX_POLICIES_PER_RULE
                    ),
                ));
            }
            let generated_policies = rule
                .policies
                .iter()
                .filter(|policy| matches!(policy, PolicyRef::Generated { .. }))
                .count();
            if generated_policies != 1 {
                errors.push(SpecError::SignerPolicy {
                    rule: ri,
                    generated: generated_policies,
                });
            }
            if rule.authorization.signers.len() > MAX_SIGNERS_PER_RULE {
                errors.push(SpecError::Limits(
                    ri,
                    format!(
                        "{} signers > max {}",
                        rule.authorization.signers.len(),
                        MAX_SIGNERS_PER_RULE
                    ),
                ));
            }

            let mut signer_identities: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
            for (si, signer) in rule.authorization.signers.iter().enumerate() {
                if matches!(signer, SignerSpec::External { .. }) {
                    // `stellar-accounts` stores only the verifier address and key. The Phase 1
                    // spec also names a verifier Wasm hash, but neither the generated policy nor
                    // the account binds that hash to the address at authorization time. Reject
                    // the shape until a later, verified installation/binding layer can prove it.
                    errors.push(SpecError::ExternalSignerUnsupported {
                        rule: ri,
                        signer: si,
                    });
                }
                let identity = match logical_signer_identity(signer) {
                    Ok(identity) => identity,
                    Err(()) => {
                        errors.push(SpecError::ExternalKey {
                            rule: ri,
                            signer: si,
                        });
                        continue;
                    }
                };
                if let Some(first) = signer_identities.insert(identity, si) {
                    errors.push(SpecError::DuplicateSigner {
                        rule: ri,
                        first,
                        duplicate: si,
                    });
                }
            }

            match &rule.authorization.kind {
                PredicateKind::AnyOfCurrentRuleSigners => {
                    if rule.authorization.strict_signer_set {
                        errors.push(SpecError::DynamicStrict(ri));
                    }
                }
                named => {
                    if rule.authorization.signers.is_empty() {
                        errors.push(SpecError::NoSigners(ri));
                    }
                    if !rule.authorization.strict_signer_set {
                        errors.push(SpecError::StrictRequired(ri));
                    }
                    if let PredicateKind::Threshold { n } = named {
                        let count = rule.authorization.signers.len();
                        if *n == 0 || (*n as usize) > count {
                            errors.push(SpecError::Threshold(ri, *n, count));
                        }
                    }
                }
            }

            if rule.state.len() > 1 {
                errors.push(SpecError::State {
                    rule: ri,
                    reason: "only one lifetime call-count declaration is supported".to_string(),
                });
            }
            for state in &rule.state {
                match state {
                    StateSpec::CallCountPerInstallation { max_calls: 0 } => {
                        errors.push(SpecError::State {
                            rule: ri,
                            reason: "max_calls must be greater than zero".to_string(),
                        });
                    }
                    StateSpec::CallCountPerInstallation { .. } => {}
                }
            }

            for call in &rule.allowed_calls {
                if call.args.len() > MAX_ARGS_PER_CALL {
                    errors.push(SpecError::Limits(
                        ri,
                        format!(
                            "call '{}' has {} args > max {MAX_ARGS_PER_CALL}",
                            call.fn_name,
                            call.args.len()
                        ),
                    ));
                }
                // Complete tuples: indexes must be exactly 0..n-1, no gaps, no dupes.
                let mut idx: Vec<u32> = call.args.iter().map(|a| a.index).collect();
                idx.sort_unstable();
                let complete = idx.iter().enumerate().all(|(i, v)| *v == i as u32);
                if !complete {
                    errors.push(SpecError::ArgIndexes(ri, call.fn_name.clone()));
                }
                for arg in &call.args {
                    let numeric = match &arg.constraint {
                        Constraint::EqI128 { value } => Some(value),
                        Constraint::LeI128 { max } => Some(max),
                        Constraint::GeI128 { min } => Some(min),
                        Constraint::EqAddress { .. }
                        | Constraint::EqScval { .. }
                        | Constraint::AnyValue => None,
                    };
                    if let Some(value) = numeric {
                        if !is_canonical_i128(value) {
                            errors.push(SpecError::I128 {
                                rule: ri,
                                call: call.fn_name.clone(),
                                arg: arg.index,
                                value: value.clone(),
                            });
                        }
                    }
                    if arg.constraint.is_widening()
                        && matches!(arg.provenance, Provenance::ObservedExact)
                    {
                        errors.push(SpecError::WideningProvenance(
                            ri,
                            call.fn_name.clone(),
                            arg.index,
                        ));
                    }
                }
                if call.justified_by.is_empty() {
                    errors.push(SpecError::Unjustified(ri, call.fn_name.clone()));
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }
        let hash = spec_hash(&self)?;
        Ok(ValidatedSpec { spec: self, hash })
    }
}

fn logical_signer_identity(signer: &SignerSpec) -> Result<Vec<u8>, ()> {
    match signer {
        SignerSpec::Delegated { address } => {
            let mut identity = b"delegated:".to_vec();
            identity.extend_from_slice(address.as_bytes());
            Ok(identity)
        }
        SignerSpec::External {
            verifier, key_hex, ..
        } => {
            let key = hex::decode(key_hex).map_err(|_| ())?;
            let mut identity = b"external:".to_vec();
            identity.extend_from_slice(verifier.as_bytes());
            identity.push(0);
            identity.extend_from_slice(&key);
            Ok(identity)
        }
    }
}

fn is_canonical_i128(value: &str) -> bool {
    value
        .parse::<i128>()
        .map(|parsed| parsed.to_string() == value)
        .unwrap_or(false)
}

fn name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn spec_hash(spec: &PolicySpec) -> Result<Hash32, Vec<SpecError>> {
    ozpb_domain::canonical_hash(domains::POLICY_SPEC, spec)
        .map_err(|e| vec![SpecError::Schema(format!("canonicalization failed: {e}"))])
}

// ---------------------------------------------------------------------------------------
// Shared fixture (used across crates' tests; deterministic)
// ---------------------------------------------------------------------------------------

// Deterministic test-support builders shared across crates. `unwrap`/`panic` on
// known-good literals is intentional; the core-logic lint stays in force elsewhere.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod fixtures {
    use super::*;
    use ozpb_domain::sha256;

    // Real strkeys, with valid checksums, rather than readable mnemonics.
    //
    // The mnemonic versions could not exist: codegen rejects them (`E_CODEGEN_ADDRESS`), so a
    // spec built from this fixture was one the toolkit would refuse to generate from. That went
    // unnoticed while the committed example was maintained by hand with real values — the
    // fixture and the artifact a reader runs had quietly diverged, and only generating the
    // example *from* the fixture surfaced it.
    pub const ACCOUNT: &str = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";
    pub const TOKEN: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
    pub const MERCHANT: &str = "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC";
    pub const DELEGATE: &str = "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI";

    /// A W2-style subscription grant: `transfer(from=SELF, to=merchant, amount==50)`
    /// on one exact token contract, any_of over one delegated signer, strict set,
    /// composed with a reviewed spending-limit policy and a per-installation call cap.
    pub fn subscription_spec() -> PolicySpec {
        let params = ReviewedParams::SpendingLimit {
            limit: "500000000".to_string(),
            period_ledgers: 120960,
        };
        PolicySpec {
            schema: SPEC_SCHEMA.to_string(),
            name: "sub-transfer".to_string(),
            network_id: NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
            registry_snapshot: sha256(b"fixture-registry-snapshot"),
            smart_account: SmartAccountRecord {
                address: ACCOUNT.to_string(),
                observed_code_hash: sha256(b"fixture-account-wasm"),
                registry_resolution: "stellar-accounts@0.7.x (fixture)".to_string(),
            },
            rules: vec![RuleSpec {
                context: ContextSpec {
                    context_type: ContextType::CallContract,
                    contract: TOKEN.to_string(),
                    target_code_hash: Some(TargetCodeHash {
                        hash: sha256(b"fixture-token-wasm"),
                        role: TargetHashRole::EvidenceOnly,
                        observed_ledger: LedgerSeq(4_100_000),
                        on_drift: DriftResponse::Warn,
                    }),
                },
                valid_until: Some(ValidUntil {
                    ledger: LedgerSeq(4_223_456),
                    approx_time: Some("2026-10-01T00:00:00Z".to_string()),
                }),
                authorization: AuthorizationSpec {
                    kind: PredicateKind::AnyOf,
                    strict_signer_set: true,
                    signers: vec![SignerSpec::Delegated {
                        address: DELEGATE.to_string(),
                    }],
                },
                allowed_calls: vec![AllowedCall {
                    fn_name: "transfer".to_string(),
                    args: vec![
                        ArgConstraint {
                            index: 0,
                            constraint: Constraint::EqAddress {
                                value: AddressRef::self_account(),
                            },
                            provenance: Provenance::ObservedExact,
                        },
                        ArgConstraint {
                            index: 1,
                            constraint: Constraint::EqAddress {
                                value: AddressRef::address(MERCHANT),
                            },
                            provenance: Provenance::ObservedExact,
                        },
                        ArgConstraint {
                            index: 2,
                            constraint: Constraint::EqI128 {
                                value: "500000000".to_string(),
                            },
                            provenance: Provenance::ObservedExact,
                        },
                    ],
                    justified_by: vec!["recordings[0]/auth[0]/root".to_string()],
                }],
                policies: vec![
                    PolicyRef::Reviewed {
                        kind: "oz:spending_limit".to_string(),
                        capability: sha256(b"fixture-spending-limit-wasm"),
                        params,
                    },
                    PolicyRef::Generated {
                        kind: "gen:scope+count".to_string(),
                        template_family: "policy-templates/scope@1".to_string(),
                        capability_schema: sha256(b"fixture-template-capability"),
                    },
                ],
                state: vec![StateSpec::CallCountPerInstallation { max_calls: 12 }],
            }],
            evidence: Evidence {
                recordings: vec![RecordingRef {
                    hash: sha256(b"fixture-recording"),
                    trust: ozpb_domain::TrustLevel::self_supplied(),
                }],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::subscription_spec;
    use super::*;

    #[test]
    fn fixture_spec_validates() {
        let v = subscription_spec().validate();
        assert!(v.is_ok(), "fixture must validate: {:?}", v.err());
    }

    #[test]
    fn spec_hash_is_deterministic() {
        let a = subscription_spec().validate().unwrap();
        let b = subscription_spec().validate().unwrap();
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn spec_round_trips_through_json_with_closed_schema() {
        let s = subscription_spec();
        let json = serde_json::to_string(&s).unwrap();
        let back: PolicySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
        // Unknown fields anywhere are rejected.
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["surprise"] = serde_json::Value::Bool(true);
        let r: Result<PolicySpec, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn wrong_schema_fails() {
        let mut s = subscription_spec();
        s.schema = "policy-spec/v0".to_string();
        let errs = s.validate().unwrap_err();
        assert!(matches!(errs[0], SpecError::Schema(_)));
    }

    #[test]
    fn bad_names_fail() {
        for bad in [
            "",
            "UPPER",
            "way-too-long-a-name-for-oz",
            "has space",
            "uné",
        ] {
            let mut s = subscription_spec();
            s.name = bad.to_string();
            let errs = s.validate().unwrap_err();
            assert!(
                errs.iter().any(|e| matches!(e, SpecError::Name(_))),
                "expected name error for {bad:?}"
            );
        }
    }

    #[test]
    fn zero_rules_fails() {
        let mut s = subscription_spec();
        s.rules.clear();
        let errs = s.validate().unwrap_err();
        assert!(errs.contains(&SpecError::NoRules));
    }

    #[test]
    fn named_predicate_without_signers_fails() {
        let mut s = subscription_spec();
        s.rules[0].authorization.signers.clear();
        let errs = s.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, SpecError::NoSigners(0))));
    }

    #[test]
    fn named_identities_require_strict_signer_set() {
        // Decision D1: fixed identities are strict by default and mandatory in verified mode.
        let mut s = subscription_spec();
        s.rules[0].authorization.strict_signer_set = false;
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::StrictRequired(0))));
    }

    #[test]
    fn dynamic_predicate_rejects_strict_flag() {
        let mut s = subscription_spec();
        s.rules[0].authorization.kind = PredicateKind::AnyOfCurrentRuleSigners;
        s.rules[0].authorization.strict_signer_set = true;
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::DynamicStrict(0))));
    }

    #[test]
    fn threshold_bounds_are_checked() {
        let mut s = subscription_spec();
        s.rules[0].authorization.kind = PredicateKind::Threshold { n: 2 }; // only 1 signer
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::Threshold(0, 2, 1))));

        let mut s = subscription_spec();
        s.rules[0].authorization.kind = PredicateKind::Threshold { n: 0 };
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::Threshold(0, 0, 1))));
    }

    #[test]
    fn external_signers_are_rejected_until_verifier_code_is_bound_at_runtime() {
        let mut spec = subscription_spec();
        spec.rules[0].authorization.signers = vec![SignerSpec::External {
            verifier: fixtures::TOKEN.to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"fixture-verifier-wasm"),
            key_hex: "aa".repeat(32),
        }];
        let errors = spec.validate().unwrap_err();
        assert!(errors.contains(&SpecError::ExternalSignerUnsupported { rule: 0, signer: 0 }));
    }

    #[test]
    fn duplicate_logical_signers_fail_validation() {
        let mut delegated = subscription_spec();
        delegated.rules[0].authorization.kind = PredicateKind::Threshold { n: 2 };
        let duplicate = delegated.rules[0].authorization.signers[0].clone();
        delegated.rules[0].authorization.signers.push(duplicate);
        let errs = delegated.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_SPEC_DUPLICATE_SIGNER:")),
            "duplicate delegated identity must not turn 2-of-2 into one effective signer: {errs:?}"
        );

        // External signer keys are bytes on-chain. Hex casing must not create two logical
        // identities that compile to the same Signer value and double-count one signature.
        let mut external = subscription_spec();
        external.rules[0].authorization.kind = PredicateKind::Threshold { n: 2 };
        let verifier_code_hash = ozpb_domain::sha256(b"fixture-verifier-wasm");
        external.rules[0].authorization.signers = vec![
            SignerSpec::External {
                verifier: fixtures::TOKEN.to_string(),
                verifier_code_hash,
                key_hex: "aabb".to_string(),
            },
            SignerSpec::External {
                verifier: fixtures::TOKEN.to_string(),
                verifier_code_hash,
                key_hex: "AABB".to_string(),
            },
        ];
        let errs = external.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_SPEC_DUPLICATE_SIGNER:")),
            "hex aliases of one external signer must be rejected: {errs:?}"
        );
    }

    #[test]
    fn i128_constraints_require_canonical_decimal_literals() {
        for bad in [
            "({ return true; 0 } as i128) + 0",
            "+1",
            "01",
            " 1",
            "170141183460469231731687303715884105728",
        ] {
            let mut s = subscription_spec();
            s.rules[0].allowed_calls[0].args[2].constraint = Constraint::EqI128 {
                value: bad.to_string(),
            };
            let errs = s.validate().unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| e.to_string().starts_with("E_SPEC_I128:")),
                "non-canonical or out-of-range i128 {bad:?} must fail before codegen: {errs:?}"
            );
        }

        for good in [
            i128::MIN.to_string(),
            "-1".to_string(),
            "0".to_string(),
            i128::MAX.to_string(),
        ] {
            let mut s = subscription_spec();
            s.rules[0].allowed_calls[0].args[2].constraint = Constraint::EqI128 { value: good };
            assert!(s.validate().is_ok());
        }
    }

    #[test]
    fn widened_i128_constraints_reject_source_tokens() {
        for constraint in [
            Constraint::LeI128 {
                max: "({ return true; 0 } as i128) + 0".to_string(),
            },
            Constraint::GeI128 {
                min: "1; panic!()".to_string(),
            },
        ] {
            let mut s = subscription_spec();
            s.rules[0].allowed_calls[0].args[2].constraint = constraint;
            s.rules[0].allowed_calls[0].args[2].provenance = Provenance::UserWidened {
                intent: "test hostile input".to_string(),
                blast_radius: ozpb_domain::BlastRadius::High,
            };
            let errs = s.validate().unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| e.to_string().starts_with("E_SPEC_I128:")),
                "widening values must never be emitted as source tokens: {errs:?}"
            );
        }
    }

    #[test]
    fn incomplete_tuples_fail() {
        // Gap: indexes {0, 2}.
        let mut s = subscription_spec();
        s.rules[0].allowed_calls[0].args.remove(1);
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::ArgIndexes(0, _))));

        // Duplicate index.
        let mut s = subscription_spec();
        s.rules[0].allowed_calls[0].args[1].index = 0;
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::ArgIndexes(0, _))));
    }

    #[test]
    fn widening_with_observed_exact_provenance_fails() {
        let mut s = subscription_spec();
        s.rules[0].allowed_calls[0].args[2].constraint = Constraint::LeI128 {
            max: "1000000000".to_string(),
        };
        // provenance still ObservedExact -> must fail
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::WideningProvenance(0, _, 2))));

        // With user_widened provenance it validates.
        let mut s = subscription_spec();
        s.rules[0].allowed_calls[0].args[2].constraint = Constraint::LeI128 {
            max: "1000000000".to_string(),
        };
        s.rules[0].allowed_calls[0].args[2].provenance = Provenance::UserWidened {
            intent: "allow headroom up to 100".to_string(),
            blast_radius: ozpb_domain::BlastRadius::Medium,
        };
        assert!(s.validate().is_ok());
    }

    #[test]
    fn policy_and_signer_limits_enforced() {
        let mut s = subscription_spec();
        let extra = s.rules[0].policies[0].clone();
        for _ in 0..5 {
            s.rules[0].policies.push(extra.clone());
        }
        let errs = s.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, SpecError::Limits(0, _))));

        let mut s = subscription_spec();
        for i in 0..16 {
            s.rules[0]
                .authorization
                .signers
                .push(SignerSpec::Delegated {
                    address: format!("GEXTRA{i}"),
                });
        }
        let errs = s.validate().unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, SpecError::Limits(0, _))));
    }

    #[test]
    fn unbacked_policy_fails_validation() {
        let mut no_policy = subscription_spec();
        no_policy.rules[0].policies.clear();
        let errs = no_policy.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_SPEC_SIGNER_POLICY:")),
            "a policy-bearing account delegates signer enforcement to a policy: {errs:?}"
        );

        let mut reviewed_only = subscription_spec();
        reviewed_only.rules[0]
            .policies
            .retain(|policy| matches!(policy, PolicyRef::Reviewed { .. }));
        let errs = reviewed_only.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_SPEC_SIGNER_POLICY:")),
            "this template set requires exactly one generated signer-enforcing policy: {errs:?}"
        );

        let mut duplicate_generated = subscription_spec();
        let generated = duplicate_generated.rules[0].policies[1].clone();
        duplicate_generated.rules[0].policies.push(generated);
        let errs = duplicate_generated.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_SPEC_SIGNER_POLICY:")),
            "one rule cannot be represented by multiple generated policy contracts: {errs:?}"
        );
    }

    #[test]
    fn state_invariants_reject_zero_or_duplicate_call_caps() {
        let mut zero = subscription_spec();
        zero.rules[0].state = vec![StateSpec::CallCountPerInstallation { max_calls: 0 }];
        let errs = zero.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_SPEC_STATE:")),
            "a zero-call grant can never replay its original invocation: {errs:?}"
        );

        let mut duplicate = subscription_spec();
        duplicate.rules[0]
            .state
            .push(StateSpec::CallCountPerInstallation { max_calls: 20 });
        let errs = duplicate.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().starts_with("E_SPEC_STATE:")),
            "duplicate state declarations currently emit duplicate constants and must fail: {errs:?}"
        );
    }

    #[test]
    fn spec_collections_have_explicit_resource_limits() {
        let base = subscription_spec();

        let mut too_many_rules = base.clone();
        let rule = too_many_rules.rules[0].clone();
        too_many_rules.rules = vec![rule; MAX_RULES + 1];
        let errs = too_many_rules.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|error| error.to_string().starts_with("E_SPEC_LIMITS:")),
            "rule count must be bounded before hashing/codegen: {errs:?}"
        );

        let mut too_many_calls = base.clone();
        let call = too_many_calls.rules[0].allowed_calls[0].clone();
        too_many_calls.rules[0].allowed_calls = vec![call; MAX_CALLS_PER_RULE + 1];
        let errs = too_many_calls.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|error| error.to_string().starts_with("E_SPEC_LIMITS:")),
            "per-rule call count must be bounded: {errs:?}"
        );

        let mut too_many_args = base;
        let arg = too_many_args.rules[0].allowed_calls[0].args[0].clone();
        too_many_args.rules[0].allowed_calls[0].args = vec![arg; MAX_ARGS_PER_CALL + 1];
        let errs = too_many_args.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|error| error.to_string().starts_with("E_SPEC_LIMITS:")),
            "per-call argument count must be bounded: {errs:?}"
        );
    }

    #[test]
    fn missing_evidence_and_justification_fail() {
        let mut s = subscription_spec();
        s.evidence.recordings.clear();
        let errs = s.validate().unwrap_err();
        assert!(errs.contains(&SpecError::NoEvidence));

        let mut s = subscription_spec();
        s.rules[0].allowed_calls[0].justified_by.clear();
        let errs = s.validate().unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, SpecError::Unjustified(0, _))));
    }

    #[test]
    fn signer_set_hash_is_order_independent_and_value_sensitive() {
        let a = SignerSpec::Delegated {
            address: "GA".to_string(),
        };
        let b = SignerSpec::External {
            verifier: "CV".to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"v"),
            key_hex: "aabb".to_string(),
        };
        let h1 = signer_set_hash(&[a.clone(), b.clone()]);
        let h2 = signer_set_hash(&[b.clone(), a.clone()]);
        assert_eq!(h1, h2, "sorted canonical encoding: order must not matter");
        let h3 = signer_set_hash(&[a]);
        assert_ne!(h1, h3, "different sets must hash differently");
    }

    #[test]
    fn self_marker_serializes_as_literal_self() {
        let r = AddressRef::self_account();
        assert_eq!(serde_json::to_string(&r).unwrap(), "\"SELF\"");
        let back: AddressRef = serde_json::from_str("\"SELF\"").unwrap();
        assert_eq!(back, AddressRef::self_account());
        let addr: AddressRef = serde_json::from_str("\"GABC\"").unwrap();
        assert_eq!(addr, AddressRef::address("GABC"));
    }
}
