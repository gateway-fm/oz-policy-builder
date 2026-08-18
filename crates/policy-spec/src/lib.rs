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
use stellar_xdr::{
    Limits, ReadXdr, ScBytes, ScString, ScSymbol, ScVal, StringM, Validate, WriteXdr,
};

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
/// One exact value should stay reviewable and comfortably below the 4 MiB canonical-preimage
/// ceiling. The limit is over decoded XDR, not base64 text.
pub const MAX_SCVAL_XDR_BYTES: usize = 64 * 1024;
/// Per generated rule. Decimal byte-array rendering expands XDR by roughly 4–5x; keeping the
/// aggregate below 256 KiB leaves room under the builder's 2 MiB source limit.
pub const MAX_RULE_SCVAL_XDR_BYTES: usize = 256 * 1024;
pub const MAX_JUSTIFICATIONS_PER_CALL: usize = 256;
pub const MAX_EXTERNAL_KEY_BYTES: usize = 256;
const MAX_SHORT_METADATA_BYTES: usize = 256;

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
        "E_SPEC_EXTERNAL_SIGNER_UNSUPPORTED: rule {rule}, signer {signer}: Phase 1 cannot bind \
         verifier_code_hash to the verifier address, so external signers are rejected"
    )]
    ExternalSignerUnsupported { rule: usize, signer: usize },
    #[error("E_SPEC_ADDRESS: {field} is not a valid {expected} strkey: {value}")]
    Address {
        field: String,
        expected: &'static str,
        value: String,
    },
    #[error("E_SPEC_SYMBOL: {field} must be 1..=32 bytes of [A-Za-z0-9_]: {value}")]
    Symbol { field: String, value: String },
    #[error("E_SPEC_TEMPLATE_FAMILY: rule {rule}: invalid template_family: {value}")]
    TemplateFamily { rule: usize, value: String },
    #[error("E_SPEC_SCVAL: rule {rule}, call '{call}', arg {arg}: {reason}")]
    Scval {
        rule: usize,
        call: String,
        arg: u32,
        reason: String,
    },
    #[error("E_SPEC_TEXT: {field}: {reason}")]
    Text { field: String, reason: String },
    #[error(
        "E_SPEC_DUPLICATE_CALL: rule {rule}: calls {first} and {duplicate} grant the same tuple"
    )]
    DuplicateCall {
        rule: usize,
        first: usize,
        duplicate: usize,
    },
    #[error("E_SPEC_DUPLICATE_EVIDENCE: recordings {first} and {duplicate} have the same hash")]
    DuplicateEvidence { first: usize, duplicate: usize },
    #[error(
        "E_SPEC_EVIDENCE_REF: rule {rule}, call '{call}': invalid evidence reference {value:?}"
    )]
    EvidenceReference {
        rule: usize,
        call: String,
        value: String,
    },
    #[error(
        "E_SPEC_EXPIRY: rule {rule}: valid_until {valid_until} must be greater than evidence \
         ledger {evidence_ledger}"
    )]
    ExpiryNotAfterEvidence {
        rule: usize,
        valid_until: u32,
        evidence_ledger: u32,
    },
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
    #[error("E_SPEC_REVIEWED_POLICY: rule {rule}: {reason}")]
    ReviewedPolicy { rule: usize, reason: String },
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
    #[error("E_SPEC_CANONICAL: canonical spec preimage cannot be encoded: {0}")]
    Canonicalization(String),
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
        let mut evidence_hashes: BTreeMap<Hash32, usize> = BTreeMap::new();
        for (index, recording) in self.evidence.recordings.iter().enumerate() {
            if let Some(first) = evidence_hashes.insert(recording.hash, index) {
                errors.push(SpecError::DuplicateEvidence {
                    first,
                    duplicate: index,
                });
            }
        }
        validate_text(
            &self.smart_account.registry_resolution,
            MAX_SHORT_METADATA_BYTES,
            "smart_account.registry_resolution",
            &mut errors,
        );
        validate_address(
            &self.smart_account.address,
            AddressExpectation::Contract,
            "smart_account.address",
            &mut errors,
        );
        for (ri, rule) in self.rules.iter().enumerate() {
            let mut rule_scval_xdr_bytes = 0usize;
            validate_address(
                &rule.context.contract,
                AddressExpectation::Contract,
                &format!("rules[{ri}].context.contract"),
                &mut errors,
            );
            if let (Some(valid_until), Some(target)) = (
                rule.valid_until.as_ref(),
                rule.context.target_code_hash.as_ref(),
            ) {
                if valid_until.ledger.0 <= target.observed_ledger.0 {
                    errors.push(SpecError::ExpiryNotAfterEvidence {
                        rule: ri,
                        valid_until: valid_until.ledger.0,
                        evidence_ledger: target.observed_ledger.0,
                    });
                }
            }
            if let Some(valid_until) = &rule.valid_until {
                if let Some(approx_time) = &valid_until.approx_time {
                    validate_text(
                        approx_time,
                        MAX_SHORT_METADATA_BYTES,
                        &format!("rules[{ri}].valid_until.approx_time"),
                        &mut errors,
                    );
                }
            }
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
            for policy in &rule.policies {
                let PolicyRef::Reviewed { kind, params, .. } = policy else {
                    continue;
                };
                match (kind.as_str(), params) {
                    (
                        "oz:spending_limit",
                        ReviewedParams::SpendingLimit {
                            limit,
                            period_ledgers,
                        },
                    ) => {
                        let parsed_limit = limit
                            .parse::<i128>()
                            .ok()
                            .filter(|value| *value > 0 && value.to_string() == limit.as_str());
                        if parsed_limit.is_none() || *period_ledgers == 0 {
                            errors.push(SpecError::ReviewedPolicy {
                                rule: ri,
                                reason: "oz:spending_limit requires a canonical positive i128 \
                                         limit and a nonzero period_ledgers"
                                    .to_string(),
                            });
                        }
                        for call in &rule.allowed_calls {
                            let amount = call.args.iter().find(|arg| arg.index == 2);
                            if call.fn_name != "transfer"
                                || !amount.is_some_and(|arg| {
                                    matches!(
                                        arg.constraint,
                                        Constraint::EqI128 { .. }
                                            | Constraint::LeI128 { .. }
                                            | Constraint::GeI128 { .. }
                                    )
                                })
                            {
                                errors.push(SpecError::ReviewedPolicy {
                                    rule: ri,
                                    reason: format!(
                                        "oz:spending_limit may cover only SEP-41 transfer \
                                         tuples whose argument 2 is constrained as i128; got \
                                         '{}'",
                                        call.fn_name
                                    ),
                                });
                                continue;
                            }
                            if let (Some(limit), Some(amount)) = (parsed_limit, amount) {
                                let can_permit_nonnegative_amount = match &amount.constraint {
                                    Constraint::EqI128 { value } => value
                                        .parse::<i128>()
                                        .is_ok_and(|value| (0..=limit).contains(&value)),
                                    Constraint::LeI128 { max } => {
                                        max.parse::<i128>().is_ok_and(|max| max >= 0)
                                    }
                                    Constraint::GeI128 { min } => {
                                        min.parse::<i128>().is_ok_and(|min| min <= limit)
                                    }
                                    Constraint::EqAddress { .. }
                                    | Constraint::EqScval { .. }
                                    | Constraint::AnyValue => false,
                                };
                                if !can_permit_nonnegative_amount {
                                    errors.push(SpecError::ReviewedPolicy {
                                        rule: ri,
                                        reason: format!(
                                            "oz:spending_limit and transfer argument 2 have no \
                                             common nonnegative amount within limit {limit}"
                                        ),
                                    });
                                }
                            }
                        }
                    }
                    _ => errors.push(SpecError::ReviewedPolicy {
                        rule: ri,
                        reason: format!(
                            "reviewed kind '{kind}' does not match its supported parameter shape"
                        ),
                    }),
                }
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
                match signer {
                    SignerSpec::Delegated { address } => validate_address(
                        address,
                        AddressExpectation::SorobanAddress,
                        &format!("rules[{ri}].authorization.signers[{si}].address"),
                        &mut errors,
                    ),
                    SignerSpec::External {
                        verifier, key_hex, ..
                    } => {
                        validate_address(
                            verifier,
                            AddressExpectation::Contract,
                            &format!("rules[{ri}].authorization.signers[{si}].verifier"),
                            &mut errors,
                        );
                        match hex::decode(key_hex) {
                            Ok(key) if !key.is_empty() && key.len() <= MAX_EXTERNAL_KEY_BYTES => {}
                            _ => errors.push(SpecError::ExternalKey {
                                rule: ri,
                                signer: si,
                            }),
                        }
                        errors.push(SpecError::ExternalSignerUnsupported {
                            rule: ri,
                            signer: si,
                        });
                    }
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
                if !symbol_is_valid(&call.fn_name) {
                    errors.push(SpecError::Symbol {
                        field: format!("rules[{ri}].allowed_calls.fn"),
                        value: call.fn_name.clone(),
                    });
                }
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
                    match &arg.constraint {
                        Constraint::EqAddress {
                            value: AddressRef::Address(address),
                        } => validate_address(
                            address,
                            AddressExpectation::SorobanAddress,
                            &format!(
                                "rules[{ri}].allowed_calls[{}].args[{}].address",
                                call.fn_name, arg.index
                            ),
                            &mut errors,
                        ),
                        Constraint::EqScval { xdr_base64 } => {
                            match validate_canonical_scval(xdr_base64) {
                                Ok(size) => {
                                    rule_scval_xdr_bytes =
                                        rule_scval_xdr_bytes.saturating_add(size);
                                }
                                Err(reason) => errors.push(SpecError::Scval {
                                    rule: ri,
                                    call: call.fn_name.clone(),
                                    arg: arg.index,
                                    reason,
                                }),
                            }
                        }
                        Constraint::EqAddress {
                            value: AddressRef::SelfAccount(_),
                        }
                        | Constraint::EqI128 { .. }
                        | Constraint::LeI128 { .. }
                        | Constraint::GeI128 { .. }
                        | Constraint::AnyValue => {}
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
                    match &arg.provenance {
                        Provenance::ObservedExact => {}
                        Provenance::UserWidened { intent, .. } => validate_text(
                            intent,
                            MAX_SHORT_METADATA_BYTES,
                            &format!(
                                "rules[{ri}].allowed_calls[{}].args[{}].prov.intent",
                                call.fn_name, arg.index
                            ),
                            &mut errors,
                        ),
                        Provenance::AdapterDerived { adapter, .. } => validate_text(
                            adapter,
                            MAX_SHORT_METADATA_BYTES,
                            &format!(
                                "rules[{ri}].allowed_calls[{}].args[{}].prov.adapter",
                                call.fn_name, arg.index
                            ),
                            &mut errors,
                        ),
                    }
                }
                if call.justified_by.is_empty() {
                    errors.push(SpecError::Unjustified(ri, call.fn_name.clone()));
                }
                if call.justified_by.len() > MAX_JUSTIFICATIONS_PER_CALL {
                    errors.push(SpecError::Limits(
                        ri,
                        format!(
                            "call '{}' has {} justifications > max {MAX_JUSTIFICATIONS_PER_CALL}",
                            call.fn_name,
                            call.justified_by.len()
                        ),
                    ));
                }
                for reference in &call.justified_by {
                    if reference.len() > MAX_SHORT_METADATA_BYTES
                        || !evidence_reference_is_valid(reference, self.evidence.recordings.len())
                    {
                        errors.push(SpecError::EvidenceReference {
                            rule: ri,
                            call: call.fn_name.clone(),
                            value: reference.clone(),
                        });
                    }
                }
            }
            if rule_scval_xdr_bytes > MAX_RULE_SCVAL_XDR_BYTES {
                errors.push(SpecError::Limits(
                    ri,
                    format!(
                        "exact ScVal XDR totals {rule_scval_xdr_bytes} bytes > max \
                         {MAX_RULE_SCVAL_XDR_BYTES} per generated rule"
                    ),
                ));
            }
            for duplicate in 1..rule.allowed_calls.len() {
                if let Some(first) = rule.allowed_calls[..duplicate]
                    .iter()
                    .position(|call| same_grant(call, &rule.allowed_calls[duplicate]))
                {
                    errors.push(SpecError::DuplicateCall {
                        rule: ri,
                        first,
                        duplicate,
                    });
                }
            }
            for policy in &rule.policies {
                match policy {
                    PolicyRef::Generated {
                        kind,
                        template_family,
                        ..
                    } => {
                        validate_text(
                            kind,
                            MAX_SHORT_METADATA_BYTES,
                            &format!("rules[{ri}].policies.generated.kind"),
                            &mut errors,
                        );
                        if !template_family_is_valid(template_family) {
                            errors.push(SpecError::TemplateFamily {
                                rule: ri,
                                value: template_family.clone(),
                            });
                        }
                    }
                    PolicyRef::Reviewed { kind, params, .. } => {
                        validate_text(
                            kind,
                            MAX_SHORT_METADATA_BYTES,
                            &format!("rules[{ri}].policies.reviewed.kind"),
                            &mut errors,
                        );
                        match params {
                            ReviewedParams::SpendingLimit {
                                limit,
                                period_ledgers,
                            } => {
                                if !is_canonical_i128(limit) {
                                    errors.push(SpecError::I128 {
                                        rule: ri,
                                        call: "reviewed:spending_limit".to_string(),
                                        arg: 0,
                                        value: limit.clone(),
                                    });
                                }
                                if *period_ledgers == 0 {
                                    errors.push(SpecError::Limits(
                                        ri,
                                        "spending-limit period_ledgers must be greater than zero"
                                            .to_string(),
                                    ));
                                }
                            }
                        }
                    }
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

#[derive(Clone, Copy)]
enum AddressExpectation {
    Contract,
    SorobanAddress,
}

fn validate_address(
    value: &str,
    expectation: AddressExpectation,
    field: &str,
    errors: &mut Vec<SpecError>,
) {
    let parsed = stellar_strkey::Strkey::from_string(value);
    let valid = matches!(
        (expectation, parsed),
        (
            AddressExpectation::Contract,
            Ok(stellar_strkey::Strkey::Contract(_))
        ) | (
            AddressExpectation::SorobanAddress,
            Ok(stellar_strkey::Strkey::Contract(_) | stellar_strkey::Strkey::PublicKeyEd25519(_)),
        )
    );
    if !valid {
        errors.push(SpecError::Address {
            field: field.to_string(),
            expected: match expectation {
                AddressExpectation::Contract => "contract (C...) address",
                AddressExpectation::SorobanAddress => "contract (C...) or account (G...) address",
            },
            value: value.to_string(),
        });
    }
}

fn symbol_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn template_family_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'@'))
}

fn validate_text(value: &str, max: usize, field: &str, errors: &mut Vec<SpecError>) {
    let reason = if value.is_empty() {
        Some("must not be empty".to_string())
    } else if value.len() > max {
        Some(format!("{} bytes > max {max}", value.len()))
    } else if value.chars().any(char::is_control) {
        Some("must not contain control characters".to_string())
    } else {
        None
    };
    if let Some(reason) = reason {
        errors.push(SpecError::Text {
            field: field.to_string(),
            reason,
        });
    }
}

fn validate_canonical_scval(value: &str) -> Result<usize, String> {
    if value.len() > MAX_SCVAL_XDR_BYTES.div_ceil(3) * 4 {
        return Err(format!(
            "base64 text is too large for the {MAX_SCVAL_XDR_BYTES}-byte XDR limit"
        ));
    }
    let limits = Limits {
        depth: 64,
        len: MAX_SCVAL_XDR_BYTES,
    };
    let scval = ScVal::from_xdr_base64(value, limits.clone())
        .map_err(|error| format!("not a bounded ScVal XDR value: {error}"))?;
    Validate::validate(&scval).map_err(|error| format!("invalid ScVal: {error}"))?;
    let canonical = scval
        .to_xdr_base64(limits.clone())
        .map_err(|error| format!("cannot re-encode ScVal: {error}"))?;
    if canonical != value {
        return Err("base64/XDR encoding is not canonical".to_string());
    }
    scval
        .to_xdr(limits)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("cannot size ScVal: {error}"))
}

fn same_grant(left: &AllowedCall, right: &AllowedCall) -> bool {
    if left.fn_name != right.fn_name || left.args.len() != right.args.len() {
        return false;
    }
    let mut left_args: Vec<_> = left
        .args
        .iter()
        .map(|arg| (arg.index, &arg.constraint))
        .collect();
    let mut right_args: Vec<_> = right
        .args
        .iter()
        .map(|arg| (arg.index, &arg.constraint))
        .collect();
    left_args.sort_by_key(|(index, _)| *index);
    right_args.sort_by_key(|(index, _)| *index);
    left_args == right_args
}

fn evidence_reference_is_valid(value: &str, recording_count: usize) -> bool {
    let Some(rest) = value.strip_prefix("recordings[") else {
        return false;
    };
    let Some((recording, rest)) = rest.split_once(']') else {
        return false;
    };
    let Ok(recording): Result<usize, _> = recording.parse() else {
        return false;
    };
    if recording >= recording_count || !rest.starts_with("/auth[") {
        return false;
    }
    let Some((auth, mut rest)) = rest[6..].split_once(']') else {
        return false;
    };
    if auth.parse::<usize>().is_err() {
        return false;
    }
    while let Some(after_prefix) = rest.strip_prefix("/sub[") {
        let Some((sub, after)) = after_prefix.split_once(']') else {
            return false;
        };
        if sub.parse::<usize>().is_err() {
            return false;
        }
        rest = after;
    }
    rest.is_empty() || rest == "/root"
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
        .map_err(|e| vec![SpecError::Canonicalization(e.to_string())])
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
                    // This is a deterministic fixture ledger, not a wall-clock prediction.
                    approx_time: None,
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
    use stellar_xdr::{Limits, ScVal, WriteXdr};

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
            s.rules[0].policies.remove(0);
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
            s.rules[0].policies.remove(0);
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
    fn spending_limit_requires_transfer_amount_at_argument_two() {
        let mut spec = subscription_spec();
        spec.rules[0].allowed_calls[0].args[2].constraint = Constraint::AnyValue;
        spec.rules[0].allowed_calls[0].args[2].provenance = Provenance::UserWidened {
            intent: "let caller choose the value".to_string(),
            blast_radius: ozpb_domain::BlastRadius::High,
        };
        let errors = spec.validate().unwrap_err();
        assert!(errors.iter().any(
            |error| matches!(error, SpecError::ReviewedPolicy { reason, .. }
                if reason.contains("argument 2 is constrained as i128"))
        ));

        let mut spec = subscription_spec();
        let PolicyRef::Reviewed { params, .. } = &mut spec.rules[0].policies[0] else {
            panic!("fixture must carry its reviewed spending limit")
        };
        *params = ReviewedParams::SpendingLimit {
            limit: "0500000000".to_string(),
            period_ledgers: 0,
        };
        let errors = spec.validate().unwrap_err();
        assert!(errors.iter().any(
            |error| matches!(error, SpecError::ReviewedPolicy { reason, .. }
                if reason.contains("canonical positive i128"))
        ));

        let mut spec = subscription_spec();
        spec.rules[0].allowed_calls[0].args[2].constraint = Constraint::EqI128 {
            value: "500000001".to_string(),
        };
        let errors = spec.validate().unwrap_err();
        assert!(errors.iter().any(
            |error| matches!(error, SpecError::ReviewedPolicy { reason, .. }
                if reason.contains("no common nonnegative amount"))
        ));
    }

    #[test]
    fn aggregate_exact_scval_size_is_bounded_per_rule() {
        let value = ScVal::Bytes(ScBytes(vec![7_u8; 60 * 1024].try_into().unwrap()));
        let xdr_base64 = value
            .to_xdr_base64(Limits {
                depth: 64,
                len: MAX_SCVAL_XDR_BYTES,
            })
            .unwrap();
        let mut spec = subscription_spec();
        for index in 3..8 {
            spec.rules[0].allowed_calls[0].args.push(ArgConstraint {
                index,
                constraint: Constraint::EqScval {
                    xdr_base64: xdr_base64.clone(),
                },
                provenance: Provenance::ObservedExact,
            });
        }

        let errors = spec.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SpecError::Limits(_, reason)
                if reason.contains("exact ScVal XDR totals"))));
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
    fn all_address_and_symbol_surfaces_validate_before_codegen() {
        let mut bad_account = subscription_spec();
        bad_account.smart_account.address = fixtures::DELEGATE.to_string();
        assert!(bad_account
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, SpecError::Address { .. })));

        let mut bad_target = subscription_spec();
        bad_target.rules[0].context.contract = "CNOT-A-STRKEY".to_string();
        assert!(bad_target
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, SpecError::Address { .. })));

        let mut bad_signer = subscription_spec();
        bad_signer.rules[0].authorization.signers[0] = SignerSpec::Delegated {
            address: "GNOT-A-STRKEY".to_string(),
        };
        assert!(bad_signer
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, SpecError::Address { .. })));

        let mut bad_arg = subscription_spec();
        bad_arg.rules[0].allowed_calls[0].args[1].constraint = Constraint::EqAddress {
            value: AddressRef::address("MALFORMED"),
        };
        assert!(bad_arg
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, SpecError::Address { .. })));

        for bad in ["", "has-hyphen", "line\nbreak", &"a".repeat(33)] {
            let mut spec = subscription_spec();
            spec.rules[0].allowed_calls[0].fn_name = bad.to_string();
            assert!(spec
                .validate()
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, SpecError::Symbol { .. })));
        }
    }

    #[test]
    fn template_family_and_metadata_are_bounded_source_safe_text() {
        for bad in [
            "scope@1\n#![cfg(any())]".to_string(),
            "scope with spaces".to_string(),
            "a".repeat(65),
        ] {
            let mut spec = subscription_spec();
            let PolicyRef::Generated {
                template_family, ..
            } = &mut spec.rules[0].policies[1]
            else {
                panic!("fixture generated policy");
            };
            *template_family = bad;
            assert!(spec
                .validate()
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, SpecError::TemplateFamily { .. })));
        }

        let mut spec = subscription_spec();
        spec.smart_account.registry_resolution = "x".repeat(MAX_SHORT_METADATA_BYTES + 1);
        assert!(spec
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, SpecError::Text { .. })));
    }

    #[test]
    fn eq_scval_requires_canonical_bounded_complete_xdr() {
        let canonical = ScVal::U64(42).to_xdr_base64(Limits::none()).unwrap();
        let mut valid = subscription_spec();
        valid.rules[0].policies.remove(0);
        valid.rules[0].allowed_calls[0].args[2].constraint = Constraint::EqScval {
            xdr_base64: canonical.clone(),
        };
        assert!(valid.validate().is_ok());

        for bad in [
            "not base64".to_string(),
            // Valid base64, but only a truncated XDR discriminant.
            "AAAA".to_string(),
            format!("{canonical}\n"),
            "A".repeat(MAX_SCVAL_XDR_BYTES.div_ceil(3) * 4 + 1),
        ] {
            let mut spec = subscription_spec();
            spec.rules[0].policies.remove(0);
            spec.rules[0].allowed_calls[0].args[2].constraint =
                Constraint::EqScval { xdr_base64: bad };
            assert!(spec
                .validate()
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, SpecError::Scval { .. })));
        }
    }

    #[test]
    fn duplicate_grants_and_evidence_are_rejected() {
        let mut duplicate_call = subscription_spec();
        let mut same_grant = duplicate_call.rules[0].allowed_calls[0].clone();
        same_grant.justified_by = vec!["recordings[0]/auth[1]".to_string()];
        duplicate_call.rules[0].allowed_calls.push(same_grant);
        assert!(duplicate_call
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, SpecError::DuplicateCall { .. })));

        let mut duplicate_evidence = subscription_spec();
        duplicate_evidence
            .evidence
            .recordings
            .push(duplicate_evidence.evidence.recordings[0].clone());
        assert!(duplicate_evidence
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, SpecError::DuplicateEvidence { .. })));
    }

    #[test]
    fn evidence_references_are_structural_and_in_range() {
        for bad in [
            "recordings[1]/auth[0]",
            "recordings[0]/auth[x]",
            "recordings[0]/movement[0]",
            "../recordings[0]/auth[0]",
            "recordings[0]/auth[0]/sub[x]",
        ] {
            let mut spec = subscription_spec();
            spec.rules[0].allowed_calls[0].justified_by = vec![bad.to_string()];
            assert!(spec
                .validate()
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, SpecError::EvidenceReference { .. })));
        }

        let mut nested = subscription_spec();
        nested.rules[0].allowed_calls[0].justified_by =
            vec!["recordings[0]/auth[0]/sub[2]/sub[0]".to_string()];
        assert!(nested.validate().is_ok());
    }

    #[test]
    fn expiry_must_follow_the_ledger_bound_evidence() {
        for ledger in [4_099_999, 4_100_000] {
            let mut spec = subscription_spec();
            spec.rules[0].valid_until.as_mut().unwrap().ledger = LedgerSeq(ledger);
            assert!(spec
                .validate()
                .unwrap_err()
                .iter()
                .any(|error| matches!(error, SpecError::ExpiryNotAfterEvidence { .. })));
        }
        let mut spec = subscription_spec();
        spec.rules[0].valid_until.as_mut().unwrap().ledger = LedgerSeq(4_100_001);
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn phase1_rejects_external_signers_until_code_hash_binding_exists() {
        let mut spec = subscription_spec();
        spec.rules[0].authorization.signers = vec![SignerSpec::External {
            verifier: fixtures::TOKEN.to_string(),
            verifier_code_hash: ozpb_domain::sha256(b"claimed verifier code"),
            key_hex: hex::encode([7u8; 32]),
        }];
        let errors = spec.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| matches!(error, SpecError::ExternalSignerUnsupported { .. })));
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
