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

/// The two widths the emitted layout has to agree with, under the `rustfmt.toml` the generated
/// crate now ships — OpenZeppelin's own, so that `cargo fmt --check` here and there is one gate.
///
/// The generated crate is a shipped artifact and a fmt gate covers it, so emission has to produce
/// text rustfmt would leave alone. Deriving the layout instead of shelling out to rustfmt keeps
/// codegen a pure function of the spec: running the formatter over the output would make the
/// rustfmt version an input to every shipped wasm hash.
///
/// `MAX_WIDTH` is `max_width`, unchanged by the config. What the config *does* change is
/// `use_small_heuristics = "Max"`, which raises every sub-width — `fn_call_width` 60 → 100,
/// `array_width` 60 → 100, `chain_width` 60 → 100 — to `max_width`. So there is no second
/// number for calls and arrays any more: a call or an array literal stays on one line whenever
/// the whole line fits, and `ARRAY_WIDTH` went with the setting that gave it a separate value.
///
/// `COMMENT_WIDTH` is `comment_width`, which `wrap_comments = true` makes load-bearing.
/// **Measured, and not what the name suggests**: rustfmt applies it to the comment *from its
/// `//` onward*, ignoring the indentation in front — so an 88-column line at indent 8 is left
/// alone while an 81-column line at indent 0 is rewritten. Probed against the pinned
/// toolchain's rustfmt across indents 0, 4, 8 and 12 rather than read off the option's
/// description. A comment whose prefix-to-end width is within this budget is a fixed point;
/// exceed it anywhere in a paragraph and rustfmt re-flows the whole paragraph.
pub const MAX_WIDTH: usize = 100;
pub const COMMENT_WIDTH: usize = 80;

/// Greedily wrap one comment paragraph the way `wrap_comments = true` wraps one.
///
/// `prefix` is the comment marker *with* its trailing space and any indentation (`"//! "`,
/// `"/// "`, `"        // "`); `text` is a single paragraph with no newlines. Lines are filled
/// so that each one, measured from the marker, fits `COMMENT_WIDTH` — a word longer than the
/// budget still gets its own line, since rustfmt does not break inside a word either. A 64-hex
/// digest is exactly that case, which is why the header's hash lands on a line of its own.
pub fn wrap_comment(prefix: &str, text: &str) -> String {
    let marker_offset = prefix.len() - prefix.trim_start().len();
    let budget = COMMENT_WIDTH + marker_offset;
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let candidate = if line.is_empty() {
            format!("{prefix}{word}")
        } else {
            format!("{line} {word}")
        };
        if !line.is_empty() && candidate.chars().count() > budget {
            out.push_str(&line);
            out.push('\n');
            line = format!("{prefix}{word}");
        } else {
            line = candidate;
        }
    }
    if !line.is_empty() {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// One grouped `use` per crate, laid out the way rustfmt lays one out.
///
/// `imports_granularity = "Crate"` is what OpenZeppelin's `rustfmt.toml` sets and what both
/// sibling policy examples show, so this is the shape the generated crate has to reach. The
/// layout is derived rather than hand-written because *which* items a rule needs varies —
/// `Bytes` appears only for an `ScVal` comparison or an external signer's key, `xdr::ToXdr`
/// only for the former — so a fixed spelling would be wrong for most of the combinations.
///
/// Two rules, both measured against the pinned toolchain's rustfmt rather than assumed:
///
///   * ordering is by first path segment, snake_case before CamelCase — `auth::Context`,
///     `contract`, …, `xdr::ToXdr`, then `Address`, `Bytes`, … — which is `reorder_imports`'
///     own key, not ASCII order (ASCII would put every type ahead of every macro);
///   * one line while `use <crate>::{…};` fits `MAX_WIDTH` **and** no item is itself a brace
///     group, since a nested group forces the vertical layout at any width; otherwise a greedy
///     fill into `MAX_WIDTH` columns, counting the trailing comma of the last item on the line.
pub fn use_statement(crate_name: &str, items: &[&str]) -> String {
    let mut items: Vec<&str> = items.to_vec();
    items.sort_by_key(|item| {
        let head = item.split("::").next().unwrap_or(item);
        (
            head.starts_with(|c: char| c.is_ascii_uppercase()),
            item.to_string(),
        )
    });
    let nested = items.iter().any(|item| item.contains('{'));
    let one_line = format!("use {crate_name}::{{{}}};\n", items.join(", "));
    if !nested && one_line.trim_end().chars().count() <= MAX_WIDTH {
        return one_line;
    }
    let indent = "    ";
    let mut out = format!("use {crate_name}::{{\n");
    if nested {
        // Vertical: rustfmt gives every item its own line once one of them is a brace group.
        for item in &items {
            out.push_str(&format!("{indent}{item},\n"));
        }
    } else {
        let mut line = String::new();
        for item in &items {
            let candidate = if line.is_empty() {
                format!("{indent}{item},")
            } else {
                format!("{line} {item},")
            };
            if !line.is_empty() && candidate.chars().count() > MAX_WIDTH {
                out.push_str(&format!("{line}\n"));
                line = format!("{indent}{item},");
            } else {
                line = candidate;
            }
        }
        out.push_str(&format!("{line}\n"));
    }
    out.push_str("};\n");
    out
}

/// The constant holding signer `index`'s external key.
///
/// Names for emitted constants are built here, from positions, so that the identifier in the
/// generated source cannot carry recorded text — the same rule the literal types above enforce
/// for values. Emission calls this for the reference and `render_signer_key_const` for the
/// definition, so the two spellings cannot drift apart.
pub fn signer_key_name(index: usize) -> String {
    format!("SIGNER_{index}_KEY")
}

/// The constant holding the XDR that argument `arg` of call `call` must equal.
pub fn arg_xdr_name(call: usize, arg: u32) -> String {
    format!("CALL_{call}_ARG_{arg}_XDR")
}

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

    /// `const SIGNER_<index>_KEY: [u8; N] = …;` — signer `index`'s external key.
    pub fn render_signer_key_const(&self, index: usize) -> String {
        self.render_const(&signer_key_name(index))
    }

    /// `const CALL_<call>_ARG_<arg>_XDR: [u8; N] = …;` — the XDR an argument must equal.
    pub fn render_arg_xdr_const(&self, call: usize, arg: u32) -> String {
        self.render_const(&arg_xdr_name(call, arg))
    }

    /// A module-level `const` item holding these bytes: `const NAME: [u8; N] = [0xab, 0xcd];`.
    ///
    /// Hoisted to a constant rather than written at the point of use because the use sites sit
    /// several levels deep, where rustfmt breaks a long array across five nested lines. At
    /// module level the indentation is fixed, so the layout is derivable — and under
    /// `use_small_heuristics = "Max"` it has three forms, not two, which is the part a reader
    /// would not guess and which the previous `array_width = 60` never reached:
    ///
    ///   1. the whole item on one line, while it fits `MAX_WIDTH`;
    ///   2. otherwise the literal alone on the next line at one indent, while *that* fits — the
    ///      form a 13-to-15-byte array takes, and the one nothing emitted before this;
    ///   3. otherwise a greedy fill, sixteen elements to a line.
    ///
    /// All three were read off the pinned toolchain's rustfmt on a probe covering 8 to 48
    /// elements, which is where the boundaries (12 → 13 and 15 → 16 elements) come from.
    ///
    /// Private, and reached only through the two wrappers above: `name` lands unescaped in an
    /// identifier position, so the only way to reach it is with a name this module built from
    /// integers. A `&str` parameter on a callable surface would be the one place in here where a
    /// value's safety rested on the caller remembering, which is what the rest of the module
    /// exists to avoid.
    fn render_const(&self, name: &str) -> String {
        let items: Vec<String> = self.0.iter().map(|byte| format!("0x{byte:02x}")).collect();
        let head = format!("const {name}: [u8; {}] = ", self.0.len());
        let flat = format!("[{}]", items.join(", "));
        let indent = "    ";
        let one_line = format!("{head}{flat};");
        if one_line.len() <= MAX_WIDTH {
            return format!("{one_line}\n");
        }
        // rustfmt drops the trailing space from the `=` line when the value moves down.
        let wrapped = format!("{indent}{flat};");
        if wrapped.len() <= MAX_WIDTH {
            return format!("{}\n{wrapped}\n", head.trim_end());
        }
        // `0xNN, ` occupies six columns; the last element on a line drops the trailing space,
        // and the last line of all carries a trailing comma.
        let per_line = (MAX_WIDTH + 2 - indent.len()) / 6;
        let mut out = format!("{head}[\n");
        for row in items.chunks(per_line) {
            out.push_str(indent);
            out.push_str(&row.join(", "));
            out.push_str(",\n");
        }
        out.push_str("];\n");
        out
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

    /// The signers compiled into the artifact: none under a dynamic predicate, which is
    /// evaluated against `context_rule.signers` at run time instead. Spec validation permits a
    /// dynamic rule to carry signers regardless, so emission has to ask this rather than ask
    /// whether the rule *has* signers — and asking it in one place is what keeps the compiled-in
    /// key constants, the `Bytes` import and the `expected_signers` body from disagreeing.
    pub fn compiled_signers(&self) -> &[RenderSigner] {
        if self.is_dynamic_predicate() {
            &[]
        } else {
            &self.signers
        }
    }

    /// True when a signer *compiled into the artifact* carries an external key. That, and not the
    /// presence of one on the rule, is what puts a key constant and the `Bytes` import in the
    /// emitted source — a rule whose signers are read at run time emits neither.
    pub fn has_external_signer(&self) -> bool {
        self.compiled_signers()
            .iter()
            .any(|signer| matches!(signer, RenderSigner::External { .. }))
    }

    /// True when the predicate is evaluated against the rule's *current* signers, in which
    /// case no expected-signer set is compiled in.
    pub fn is_dynamic_predicate(&self) -> bool {
        matches!(self.predicate, PredicateKind::AnyOfCurrentRuleSigners)
    }
}
