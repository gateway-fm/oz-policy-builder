//! Render-safe literals (architecture §4.4, "Rendering safety").
//!
//! Emission builds Rust source by concatenation, so any recorded value that reaches a
//! `format!` is a potential source-injection vector. The rule the architecture states is that
//! untrusted values are embedded as validated literals and never interpolated into
//! identifiers or source fragments. Before this module that rule held only by convention:
//! every emission site remembered to call a validator first, and nothing forced it.
//!
//! Here it is a property of the types. Each literal below has a **private** inner value and a
//! single fallible constructor that runs the validator; there is no `From<String>`, no public
//! field, and no `Deref` to `str`. [`RenderRule`] converts a whole `RuleSpec` up front, so the
//! emitter never holds a `RuleSpec` at all and cannot interpolate a raw spec string even by
//! accident. [`RenderConstraint`] is matched exhaustively, so a new `Constraint` variant is a
//! compile error here rather than a silently unvalidated value downstream.

use crate::CodegenError;
use base64::Engine;
use ozpb_policy_spec::{
    AddressRef, Constraint, PredicateKind, RuleSpec, SignerSpec, StateSpec, ValidUntil,
};
use std::fmt;

/// A Stellar strkey, proven decodable (checksum included) by `stellar_strkey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Strkey(String);

impl Strkey {
    pub fn new(raw: &str) -> Result<Self, CodegenError> {
        // Decodable is not enough: only a contract (`C…`) or an ed25519 account (`G…`) is a
        // Soroban `Address`. A muxed (`M…`) or pre-auth (`T…`) strkey decodes fine and would
        // be emitted into `Address::from_str`, where the SDK panics at *runtime* — a policy
        // that deploys and then denies everything, which no offline gate would catch.
        match stellar_strkey::Strkey::from_string(raw) {
            Ok(stellar_strkey::Strkey::Contract(_))
            | Ok(stellar_strkey::Strkey::PublicKeyEd25519(_)) => Ok(Strkey(raw.to_string())),
            _ => Err(CodegenError::Address(raw.to_string())),
        }
    }
}

impl fmt::Display for Strkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Soroban symbol: 1..=32 bytes of `[A-Za-z0-9_]`. The charset is what makes it safe to
/// place inside a Rust string literal — it cannot contain a quote, backslash, or newline.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolName(String);

impl SymbolName {
    pub fn new(raw: &str) -> Result<Self, CodegenError> {
        let ok = !raw.is_empty()
            && raw.len() <= 32
            && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if ok {
            Ok(SymbolName(raw.to_string()))
        } else {
            Err(CodegenError::Symbol(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SymbolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An audited template-family identifier, e.g. `policy-templates/scope@1`.
///
/// This one is easy to overlook because it feels like our own metadata, but it arrives on the
/// **spec**, and `generate_code`/`verify` accept a caller-supplied spec: the registry check
/// that resolves a family exists only on the *synthesize* path. It is emitted into the
/// generated file's header comment, so an unvalidated value containing a newline can open new
/// `//!` lines — enough to forge the limits a human reviewer reads, or to inject a crate-root
/// inner attribute (`#![doc = include_str!(…)]`, `#![cfg(any())]`). The charset below excludes
/// newline, backtick, quote, `#` and `[`, so none of that is expressible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateFamily(String);

impl TemplateFamily {
    pub fn new(raw: &str) -> Result<Self, CodegenError> {
        let ok = !raw.is_empty()
            && raw.len() <= 64
            && raw.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'@')
            });
        if ok {
            Ok(TemplateFamily(raw.to_string()))
        } else {
            Err(CodegenError::TemplateFamily(raw.to_string()))
        }
    }
}

impl fmt::Display for TemplateFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An `i128` literal. Validated by round-tripping through `i128`, so only a canonical
/// decimal form is accepted and the rendered text is derived from the parsed value's own
/// string form, never from caller text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I128Literal(i128);

impl I128Literal {
    pub fn new(raw: &str) -> Result<Self, CodegenError> {
        match raw.parse::<i128>() {
            Ok(value) if value.to_string() == raw => Ok(I128Literal(value)),
            _ => Err(CodegenError::I128(raw.to_string())),
        }
    }
}

impl fmt::Display for I128Literal {
    /// `<v>i128`, except `i128::MIN`: its magnitude is `i128::MAX + 1`, so the positive
    /// literal overflows *before* the unary `-` applies and the generated crate would fail
    /// to compile. The named constant keeps "a ValidatedSpec always generates compilable
    /// Rust" true across the full range.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == i128::MIN {
            f.write_str("i128::MIN")
        } else {
            write!(f, "{}i128", self.0)
        }
    }
}

/// Raw bytes rendered as a Rust byte-array literal. Numeric by construction, so no caller
/// text ever reaches the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteArray(Vec<u8>);

impl ByteArray {
    pub fn from_base64(raw: &str) -> Result<Self, CodegenError> {
        base64::engine::general_purpose::STANDARD
            .decode(raw)
            .map(ByteArray)
            .map_err(|_| CodegenError::Scval)
    }

    pub fn from_hex(raw: &str) -> Result<Self, CodegenError> {
        hex::decode(raw)
            .map(ByteArray)
            .map_err(|_| CodegenError::KeyHex)
    }
}

impl fmt::Display for ByteArray {
    /// `[0xab, 0xcd]` — hex bytes, matching the emitted form exactly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "0x{byte:02x}")?;
        }
        f.write_str("]")
    }
}

/// The emitter's view of one argument constraint. Exhaustive over `Constraint` by
/// construction — see [`RenderRule::from_rule`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderConstraint {
    /// `SELF`: compared against the `smart_account` parameter at runtime, never compiled to
    /// a literal address.
    EqSelf,
    EqAddress(Strkey),
    EqI128(I128Literal),
    LeI128(I128Literal),
    GeI128(I128Literal),
    EqScval(ByteArray),
    AnyValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderSigner {
    Delegated(Strkey),
    External { verifier: Strkey, key: ByteArray },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderArg {
    pub index: u32,
    pub constraint: RenderConstraint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderCall {
    pub fn_name: SymbolName,
    /// Sorted by `index`; emission relies on that order for determinism.
    pub args: Vec<RenderArg>,
}

/// Everything emission is allowed to see. Built once by [`RenderRule::from_rule`], which is
/// the single place spec values are validated.
#[derive(Clone, Debug, PartialEq)]
pub struct RenderRule {
    pub template_family: TemplateFamily,
    pub target: Strkey,
    pub valid_until_ledger: Option<u32>,
    pub predicate: PredicateKind,
    pub strict_signer_set: bool,
    /// Sorted by `SignerSpec`'s own ordering, so the emitted source is deterministic.
    ///
    /// Deliberately **not** the order `signer_set_hash` uses: that one sorts the encoded
    /// `ScVal`s, because the hash must be stable against the stored representation. Here any
    /// stable order will do, and adopting the hashing order would add a fallible encode step
    /// to satisfy a property nothing here needs.
    pub signers: Vec<RenderSigner>,
    pub calls: Vec<RenderCall>,
    pub max_calls_per_installation: Option<u32>,
}

impl RenderRule {
    pub fn from_rule(rule: &RuleSpec, template_family: &str) -> Result<Self, CodegenError> {
        let mut signers_sorted = rule.authorization.signers.clone();
        signers_sorted.sort();
        let signers = signers_sorted
            .iter()
            .map(|signer| match signer {
                SignerSpec::Delegated { address } => {
                    Ok(RenderSigner::Delegated(Strkey::new(address)?))
                }
                SignerSpec::External {
                    verifier, key_hex, ..
                } => Ok(RenderSigner::External {
                    verifier: Strkey::new(verifier)?,
                    key: ByteArray::from_hex(key_hex)?,
                }),
            })
            .collect::<Result<Vec<_>, CodegenError>>()?;

        let calls = rule
            .allowed_calls
            .iter()
            .map(|call| {
                let mut args = call
                    .args
                    .iter()
                    .map(|arg| {
                        // Exhaustive on purpose: a new `Constraint` variant must be given an
                        // explicit, validated rendering here rather than silently skipped.
                        let constraint = match &arg.constraint {
                            Constraint::EqAddress {
                                value: AddressRef::SelfAccount(_),
                            } => RenderConstraint::EqSelf,
                            Constraint::EqAddress {
                                value: AddressRef::Address(address),
                            } => RenderConstraint::EqAddress(Strkey::new(address)?),
                            Constraint::EqI128 { value } => {
                                RenderConstraint::EqI128(I128Literal::new(value)?)
                            }
                            Constraint::LeI128 { max } => {
                                RenderConstraint::LeI128(I128Literal::new(max)?)
                            }
                            Constraint::GeI128 { min } => {
                                RenderConstraint::GeI128(I128Literal::new(min)?)
                            }
                            Constraint::EqScval { xdr_base64 } => {
                                RenderConstraint::EqScval(ByteArray::from_base64(xdr_base64)?)
                            }
                            Constraint::AnyValue => RenderConstraint::AnyValue,
                        };
                        Ok(RenderArg {
                            index: arg.index,
                            constraint,
                        })
                    })
                    .collect::<Result<Vec<_>, CodegenError>>()?;
                // Emission walks args in index order regardless of spec ordering.
                args.sort_by_key(|arg| arg.index);
                Ok(RenderCall {
                    fn_name: SymbolName::new(&call.fn_name)?,
                    args,
                })
            })
            .collect::<Result<Vec<_>, CodegenError>>()?;

        // Spec validation already rejects more than one state entry. Rejecting it here too is
        // defense in depth: the previous code emitted one `const MAX_CALLS` per entry, so a
        // duplicate was a loud compile error. Silently taking the first would, if that
        // validation ever regressed, keep the *looser* cap.
        if rule.state.len() > 1 {
            return Err(CodegenError::Internal(format!(
                "rule carries {} state entries; exactly one is supported",
                rule.state.len()
            )));
        }
        // Exhaustive match, so a new `StateSpec` variant is a compile error here.
        let max_calls_per_installation = rule
            .state
            .iter()
            .map(|state| match state {
                StateSpec::CallCountPerInstallation { max_calls } => *max_calls,
            })
            .next();

        Ok(RenderRule {
            template_family: TemplateFamily::new(template_family)?,
            target: Strkey::new(&rule.context.contract)?,
            valid_until_ledger: rule.valid_until.as_ref().map(|v: &ValidUntil| v.ledger.0),
            predicate: rule.authorization.kind.clone(),
            strict_signer_set: rule.authorization.strict_signer_set,
            signers,
            calls,
            max_calls_per_installation,
        })
    }

    pub fn has_state(&self) -> bool {
        self.max_calls_per_installation.is_some()
    }

    pub fn has_scval(&self) -> bool {
        self.calls
            .iter()
            .flat_map(|call| &call.args)
            .any(|arg| matches!(arg.constraint, RenderConstraint::EqScval(_)))
    }

    pub fn has_external_signer(&self) -> bool {
        self.signers
            .iter()
            .any(|signer| matches!(signer, RenderSigner::External { .. }))
    }

    /// True when the predicate is evaluated against the rule's *current* signers, in which
    /// case no expected-signer set is compiled in.
    pub fn is_dynamic_predicate(&self) -> bool {
        matches!(self.predicate, PredicateKind::AnyOfCurrentRuleSigners)
    }
}
