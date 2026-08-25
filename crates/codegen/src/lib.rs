//! Deterministic code generation (architecture §4.4): `ValidatedSpec` → an immutable,
//! per-grant specialized Soroban policy crate.
//!
//! Templates, not free-form generation: every emitted statement comes from the fixed
//! snippet set in this file; recorded values are embedded as validated literals, never
//! interpolated into identifiers. The wasm-relevant identity is the **normalized codegen
//! input** — constraint tuples, predicate, signers, lifetime, state — so the same grant
//! shape yields byte-identical source for any account (`SELF` resolves at runtime) and
//! any evidence trail. No setters, no upgrade entry point: reconfiguration is
//! remove-and-reinstall.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::{domains, Hash32};
use ozpb_policy_spec::{
    Constraint, PolicyRef, PredicateKind, RuleSpec, SignerSpec, StateSpec, ValidatedSpec,
};
use serde::Serialize;
use std::collections::BTreeMap;

mod render;
use render::{RenderConstraint, RenderRule, RenderSigner};

/// Version pins embedded in the generated crate. These must match the audited
/// `stellar-accounts` release (recorded in the BuildManifest by the caller).
#[derive(Clone, Debug)]
pub struct Pins {
    pub soroban_sdk: String,
    pub stellar_accounts: String,
    /// rustc channel the generated crate pins for itself.
    ///
    /// A wasm hash is compiler-dependent — the same source under a different rustc produces a
    /// different artifact, which is why `verify-pinned-upstream.sh` has to force a channel to
    /// reproduce upstream's hashes at all. A generated crate that pins nothing therefore has a
    /// `BuildManifest.wasm_hash` nobody else can reproduce: the manifest records which compiler
    /// was used, but a second party building the crate silently gets whatever rustc is default.
    pub rust_channel: String,
}

impl Default for Pins {
    fn default() -> Self {
        Pins {
            soroban_sdk: "26.1.0".to_string(),
            stellar_accounts: "0.7.2".to_string(),
            // Kept equal to this repository's own rust-toolchain.toml by
            // `the_pinned_channel_matches_the_repository_toolchain`.
            rust_channel: "1.91.1".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GeneratedCrate {
    pub crate_name: String,
    /// Relative path → file contents ("Cargo.toml", "src/lib.rs").
    pub files: BTreeMap<String, String>,
    /// Pre-build identity: hash of the normalized codegen input (§4.10). The exact wasm
    /// hash exists only post-build, in the BuildManifest — never here.
    pub normalized_input_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodegenError {
    #[error("E_CODEGEN_RULE_INDEX: spec has no rule {0}")]
    RuleIndex(usize),
    #[error("E_CODEGEN_NO_GENERATED_REF: rule {0} composes no generated policy")]
    NoGeneratedRef(usize),
    #[error("E_CODEGEN_ADDRESS: '{0}' is not a valid strkey")]
    Address(String),
    #[error("E_CODEGEN_SYMBOL: '{0}' is not a valid Soroban symbol (<=32 [a-zA-Z0-9_])")]
    Symbol(String),
    #[error("E_CODEGEN_SCVAL: constraint carries invalid base64 XDR")]
    Scval,
    #[error("E_CODEGEN_I128: '{0}' is not a canonical decimal i128")]
    I128(String),
    #[error("E_CODEGEN_TEMPLATE_FAMILY: '{0}' is not a valid template-family identifier")]
    TemplateFamily(String),
    #[error("E_CODEGEN_KEY: external signer key is not valid hex")]
    KeyHex,
    #[error("E_CODEGEN_RESOURCE_LIMIT: generated crate is {actual} bytes; maximum is {maximum}")]
    ResourceLimit { actual: usize, maximum: usize },
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------------------
// Normalized codegen input — the only spec content that may influence emitted bytes.
// ---------------------------------------------------------------------------------------

#[derive(Serialize)]
struct NormalizedInput<'a> {
    codegen_version: u32,
    template_family: &'a str,
    target: &'a str,
    valid_until: Option<u32>,
    predicate: &'a PredicateKind,
    strict_signer_set: bool,
    /// The rule's signers, sorted. Carried as the specification's own values rather than a
    /// stringified encoding: the canonical encoder handles them, and a string would be a second
    /// representation of the same thing to keep in step.
    signers: Vec<&'a SignerSpec>,
    calls: Vec<NormCall<'a>>,
    state: &'a [StateSpec],
}

#[derive(Serialize)]
struct NormCall<'a> {
    fn_name: &'a str,
    args: Vec<(u32, &'a Constraint)>,
}

const CODEGEN_VERSION: u32 = 1;
/// Must remain equal to build-runner's input ceiling. Enforcing it at generation keeps a caller
/// from receiving an artifact that the very next Phase 1 stage necessarily refuses.
const MAX_GENERATED_CRATE_BYTES: usize = 2 * 1024 * 1024;

pub fn normalized_input_hash(
    rule: &RuleSpec,
    template_family: &str,
) -> Result<Hash32, CodegenError> {
    let mut signers: Vec<&SignerSpec> = rule.authorization.signers.iter().collect();
    signers.sort();
    let calls: Vec<NormCall> = rule
        .allowed_calls
        .iter()
        .map(|c| NormCall {
            fn_name: &c.fn_name,
            args: c.args.iter().map(|a| (a.index, &a.constraint)).collect(),
        })
        .collect();
    let norm = NormalizedInput {
        codegen_version: CODEGEN_VERSION,
        template_family,
        target: &rule.context.contract,
        valid_until: rule.valid_until.as_ref().map(|v| v.ledger.0),
        predicate: &rule.authorization.kind,
        strict_signer_set: rule.authorization.strict_signer_set,
        signers,
        calls,
        state: &rule.state,
    };
    ozpb_domain::canonical_hash(domains::CODEGEN_INPUT, &norm)
        .map_err(|e| CodegenError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------------------
// generate()
// ---------------------------------------------------------------------------------------

pub fn generate(
    spec: &ValidatedSpec,
    rule_index: usize,
    pins: &Pins,
) -> Result<GeneratedCrate, CodegenError> {
    let rule = spec
        .spec()
        .rules
        .get(rule_index)
        .ok_or(CodegenError::RuleIndex(rule_index))?;
    let template_family = rule
        .policies
        .iter()
        .find_map(|p| match p {
            PolicyRef::Generated {
                template_family, ..
            } => Some(template_family.as_str()),
            _ => None,
        })
        .ok_or(CodegenError::NoGeneratedRef(rule_index))?;

    // Convert every recorded value into a render-safe literal BEFORE emission. This is the
    // one validation boundary: `RenderRule` cannot exist unless every strkey, symbol, i128
    // and byte string passed its own constructor, and `emit_lib` sees nothing else — so an
    // untrusted value cannot reach a source fragment even by accident (§4.4).
    let render_rule = render::RenderRule::from_rule(rule, template_family)?;

    let hash = normalized_input_hash(rule, template_family)?;
    let crate_name = format!("generated-{}-r{}", spec.spec().name, rule_index);

    let mut files = BTreeMap::new();
    files.insert("Cargo.lock".to_string(), emit_lockfile(&crate_name, pins)?);
    files.insert("Cargo.toml".to_string(), emit_cargo_toml(&crate_name, pins));
    files.insert("rust-toolchain.toml".to_string(), emit_rust_toolchain(pins));
    files.insert("rustfmt.toml".to_string(), emit_rustfmt_toml());
    let (crate_root, contract) = emit_lib(&render_rule, &hash);
    files.insert("src/lib.rs".to_string(), crate_root);
    files.insert("src/contract.rs".to_string(), contract);

    let generated_bytes = files.values().try_fold(0usize, |total, body| {
        total
            .checked_add(body.len())
            .ok_or(CodegenError::ResourceLimit {
                actual: usize::MAX,
                maximum: MAX_GENERATED_CRATE_BYTES,
            })
    })?;
    if generated_bytes > MAX_GENERATED_CRATE_BYTES {
        return Err(CodegenError::ResourceLimit {
            actual: generated_bytes,
            maximum: MAX_GENERATED_CRATE_BYTES,
        });
    }

    Ok(GeneratedCrate {
        crate_name,
        files,
        normalized_input_hash: hash,
    })
}

fn emit_lockfile(crate_name: &str, pins: &Pins) -> Result<String, CodegenError> {
    const LOCKFILE: &str = include_str!("../../../contracts/golden-transfer-policy/Cargo.lock");
    if !LOCKFILE.contains(&format!(
        "name = \"soroban-sdk\"\nversion = \"{}\"",
        pins.soroban_sdk
    )) || !LOCKFILE.contains(&format!(
        "name = \"stellar-accounts\"\nversion = \"{}\"",
        pins.stellar_accounts
    )) {
        return Err(CodegenError::Internal(
            "committed generated-contract lockfile does not match dependency pins".to_string(),
        ));
    }
    Ok(LOCKFILE.replacen(
        "name = \"generated-sub-transfer-r0\"",
        &format!("name = \"{crate_name}\""),
        1,
    ))
}

// ---------------------------------------------------------------------------------------
// Emission (fixed snippet set; deterministic ordering everywhere)
// ---------------------------------------------------------------------------------------

/// Pin the compiler and the wasm target in the crate itself, so the artifact is reproducible
/// by whoever builds it rather than only by whoever generated it.
///
/// Declaring `targets` also means the build works in a directory that inherits no toolchain
/// configuration — a generated crate is normally unpacked outside any workspace — because rustup
/// installs what the file asks for instead of failing on a missing `wasm32v1-none`.
fn emit_rust_toolchain(pins: &Pins) -> String {
    format!(
        r#"# GENERATED POLICY CRATE — DO NOT EDIT BY HAND (see src/lib.rs header).
#
# The wasm hash recorded in build-manifest.json is specific to this channel: identical source
# under a different rustc compiles to a different artifact. Changing the channel here without
# rebuilding invalidates that hash.
[toolchain]
channel = "{channel}"
targets = ["wasm32v1-none"]
"#,
        channel = pins.rust_channel
    )
}

/// A `<Event> { … }.publish(e);` statement inside a trait method.
///
/// Their form exactly: the struct is constructed at the emission site and published, with no
/// `emit_*` free function in between. `code-quality.md` asks for that wrapper in a library module
/// whose events are published from a *different* file than they are declared in; here declaration
/// and use are one file and one crate, and a wrapper would add a name without adding a seam.
///
/// The layout is rustfmt's for this shape and was measured against it: a struct literal that fits
/// `struct_lit_width` — `max_width` under the shipped config — stays on the `.publish` chain's own
/// line, and one that does not takes a field per line with `.publish(e)` on the closing brace's
/// line. Both occur here, which is why the width is computed rather than assumed.
fn emit_publish(event: &str, fields: &[&str]) -> String {
    let indent = "        ";
    let one_line = format!("{indent}{event} {{ {} }}.publish(e);", fields.join(", "));
    if one_line.chars().count() <= render::MAX_WIDTH {
        return format!("\n{one_line}\n");
    }
    let mut out = format!("\n{indent}{event} {{\n");
    for field in fields {
        out.push_str(&format!("{indent}    {field},\n"));
    }
    out.push_str(&format!("{indent}}}\n{indent}.publish(e);\n"));
    out
}

/// A doc comment in OpenZeppelin's prescribed shape.
///
/// `paragraphs` becomes the summary and any prose after it, then each non-empty section is
/// emitted as a `# Heading` and a `*`-bullet list. Callers pass the sections in the order their
/// conventions fix — `# Arguments` → `# Errors` → `# Events` → `# Notes` → `# Security Warning`,
/// skipping what does not apply but never reordering — and an empty list drops its heading, which
/// is what makes "skip what does not apply" a property of the data rather than of every call site.
///
/// Built rather than written out because an `# Errors` list is a function of the rule. A policy
/// with no validity window can never raise `RuleExpired` and one with no call cap can never raise
/// `CallCountExceeded`; a doc listing them regardless would be prose overclaiming its code, in the
/// one artifact whose whole value is that its prose can be trusted against its behaviour.
fn emit_doc(indent: &str, paragraphs: &[String], sections: &[(&str, Vec<String>)]) -> String {
    let blank = format!("{indent}///\n");
    let mut out = String::new();
    for paragraph in paragraphs {
        if !out.is_empty() {
            out.push_str(&blank);
        }
        out.push_str(&render::wrap_comment(&format!("{indent}/// "), paragraph));
    }
    for (heading, bullets) in sections {
        if bullets.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push_str(&blank);
        }
        out.push_str(&format!("{indent}/// {heading}\n"));
        out.push_str(&blank);
        for bullet in bullets {
            out.push_str(&render::wrap_comment_bullet(indent, bullet));
        }
    }
    out
}

/// A `// ################## NAME ##################` section delimiter.
///
/// Their canonical form is eighteen hashes on each side (`code-quality.md`, "Module file
/// layout"), and it is canonical in the strong sense: the rule says variations like `// === NAME
/// ===` are to be rewritten to it. Built here from a repeat count so the two sides cannot drift,
/// and so the count is stated once rather than in every emitted heading.
///
/// The section *names* are theirs where their files have one — ERRORS, CONSTANTS, EVENTS, QUERY
/// STATE, CHANGE STATE, LOW-LEVEL HELPERS. STORAGE KEYS is ours: their storage-key type sits at
/// the top of a `storage.rs` of its own and so needs no heading, which a single-file contract has
/// no analogue for.
fn section(name: &str) -> String {
    let rule = "#".repeat(18);
    format!("// {rule} {name} {rule}\n\n")
}

/// OpenZeppelin's own rustfmt configuration, shipped inside the generated crate.
///
/// The option set is copied verbatim from `OpenZeppelin/stellar-contracts` at v0.7.2
/// (`rustfmt.toml`), in their order. The point is not tidiness: the generated crate is meant to
/// be read and re-checked by the library's own maintainers, and without their config a reviewer
/// running the command their `CONTRIBUTING.md` prescribes — `cargo +nightly fmt --all -- --check`
/// — gets a diff on an artifact our gate calls clean. Shipping it makes the two gates one gate.
///
/// Emission derives its layout from these settings instead of piping output through rustfmt,
/// which would put the rustfmt version among the inputs to every shipped wasm hash.
///
/// Upstream's file ends with a commented-out block proposing `wrap_comments` and
/// `format_code_in_doc_comments`, both of which are already enabled above it. That contradiction
/// is not copied; the options are.
fn emit_rustfmt_toml() -> String {
    r#"# GENERATED POLICY CRATE — DO NOT EDIT BY HAND (see src/lib.rs header).
#
# OpenZeppelin's own rustfmt configuration, so that `cargo fmt --check` on this crate is the same
# gate the stellar-contracts library holds itself to. Copied from OpenZeppelin/stellar-contracts
# v0.7.2 `rustfmt.toml`; most of these options are unstable, hence `unstable_features`, and a
# stable rustfmt warns about those and applies the rest.
format_macro_bodies = true
format_macro_matchers = true
format_strings = true
imports_granularity = "Crate"
reorder_impl_items = true
group_imports = "StdExternalCrate"
use_small_heuristics = "Max"
use_field_init_shorthand = true
wrap_comments = true
format_code_in_doc_comments = true
unstable_features = true
"#
    .to_string()
}

/// The TTL-extension statements shared by every entry point that extends.
///
/// All four use it — `enforce`, `install`, `is_installed` and `remaining_calls` — so "a read
/// inherits the same bound as a write" is true by construction rather than by four copies
/// agreeing. A threshold or an entry set that drifted between them would be a cost bug rather
/// than a compile error, so the text is written once. Every site sits at the same indent, one
/// `impl` block deep, which is what lets the block be shared verbatim.
///
/// The host extends when `current_ttl <= threshold` (`soroban-env-host`, `Storage::extend_ttl`).
/// The SDK's own doc comment says "below", which is off by one; the wording here follows the host.
/// Half the target is used so a busy policy pays for one extension per half-window instead of one
/// per authorization — a threshold equal to the target would write on every call.
///
/// When the rule caps its call count, `remaining` gates the whole block: an installation that has
/// just spent its last permitted call can never permit again, and buying the largest possible
/// extension at exactly that moment is the opposite of what the artifact claims to do. The shared
/// instance entry stays alive through whichever *other* installation is still active, and when
/// none is, the contract is useless to everyone and is meant to expire. The **code** entry is not
/// extended here at all — it is shared with every other deployment of the same wasm, so its rent
/// is not this policy's to pay (§3 of the conformance record states that as a decision).
///
/// The chained `extend_ttl` calls are one line each: `chain_width` is `max_width` under
/// `use_small_heuristics = "Max"`, so the three-segment chain no longer breaks across lines the
/// way rustfmt's default 60 forced it to.
fn ttl_extension_block(has_state: bool) -> String {
    if has_state {
        format!(
            "\n{}        if remaining > 0u32 {{\n            let ttl = ttl_target(e);\n            if ttl > 0 {{\n                e.storage().instance().extend_ttl(ttl / 2, ttl);\n                e.storage().persistent().extend_ttl(&installed_key, ttl / 2, ttl);\n                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);\n            }}\n        }}\n",
            render::wrap_comment(
                "        // ",
                "The `remaining` gate is not a permission check — nothing here decides \
                 anything. It is the rent rule: an installation that can never permit again \
                 stops paying. Otherwise this keeps the entries the policy depends on, and the \
                 contract instance, out of archival."
            )
        )
    } else {
        format!(
            "\n{}        let ttl = ttl_target(e);\n        if ttl > 0 {{\n            e.storage().instance().extend_ttl(ttl / 2, ttl);\n            e.storage().persistent().extend_ttl(&installed_key, ttl / 2, ttl);\n        }}\n",
            render::wrap_comment(
                "        // ",
                "Not a permission check — nothing here decides anything. This keeps this \
                 installation and the contract instance out of archival. The wasm code entry is \
                 deliberately not extended: it is shared with every other deployment of the same \
                 code. With no call cap there is no condition under which the extension is \
                 withheld."
            )
        )
    }
}

/// The `ttl_target` helper, emitted at the end of the artifact.
///
/// Placed last on purpose. A reader opening a generated policy is there to learn what it permits,
/// and rent arithmetic between the constants and the signer set puts prose about archival ahead of
/// the first permission. Top-to-bottom now reads constants → signers → checks, with the storage
/// bookkeeping after `uninstall`.
fn emit_ttl_target(has_valid_until: bool) -> String {
    let summary = render::wrap_comment(
        "/// ",
        "Ledgers this policy's own entries should be kept alive for.",
    );
    if has_valid_until {
        format!(
            "\n{summary}///\n{}///\n{}fn ttl_target(e: &Env) -> u32 {{\n    let remaining = VALID_UNTIL_LEDGER.saturating_sub(e.ledger().sequence());\n    let max = e.storage().max_ttl();\n    if remaining < max {{\n        remaining\n    }} else {{\n        max\n    }}\n}}\n",
            render::wrap_comment(
                "/// ",
                "Bounded twice. By the network's rolling `max_ttl()`, because a single extension \
                 can never reach further — a distant window is approached across successive calls \
                 rather than in one step. And by the rule's own window, because past \
                 VALID_UNTIL_LEDGER every entry point denies, so extending beyond it would pay \
                 rent for an artifact that can no longer permit anything."
            ),
            render::wrap_comment(
                "/// ",
                "`saturating_sub` is defense in depth after the explicit expiry checks: later \
                 changes cannot turn an already-expired rule into the largest possible extension."
            ),
        )
    } else {
        format!(
            "\n{summary}///\n{}fn ttl_target(e: &Env) -> u32 {{\n    e.storage().max_ttl()\n}}\n",
            render::wrap_comment(
                "/// ",
                "This rule carries no validity window, so the only bound is the network's rolling \
                 `max_ttl()`; a single extension can never reach further than that."
            ),
        )
    }
}

fn emit_cargo_toml(crate_name: &str, pins: &Pins) -> String {
    format!(
        r#"# GENERATED POLICY CRATE — DO NOT EDIT BY HAND (see src/lib.rs header).
[package]
name = "{crate_name}"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0 OR MIT"
publish = false

# Every package in OpenZeppelin's workspace declares this, so a generated crate dropped into it
# is shaped like the rest. Cargo ignores `package.metadata`, and the key is inert in a standalone
# crate, which is what makes carrying it free.
[package.metadata.stellar]
cargo_inherit = true

# `crate-type` keeps `lib` alongside `cdylib`, which their example policies do not: the
# in-process differential suite links this crate directly, so `lib` is load-bearing here in a way
# it is not for them. `doctest = false` is theirs, and applies for the same reason — a contract
# crate has no doctests to run.
[lib]
crate-type = ["lib", "cdylib"]
doctest = false

[dependencies]
soroban-sdk = "={sdk}"
stellar-accounts = "={accounts}"

[dev-dependencies]
soroban-sdk = {{ version = "={sdk}", features = ["testutils"] }}

# `stellar contract build` requires overflow-checks on the release profile; emitting it
# here lets the crate build standalone (not only inside a workspace that supplies it).
[profile.release]
opt-level = "z"
overflow-checks = true
strip = "symbols"
panic = "abort"
codegen-units = 1
lto = true
"#,
        crate_name = crate_name,
        sdk = pins.soroban_sdk,
        accounts = pins.stellar_accounts,
    )
}

/// Emit `src/lib.rs`.
///
/// Takes a [`RenderRule`], never a `RuleSpec`: every value here has already been through its
/// validating constructor, so no raw spec string is in scope to interpolate (§4.4 rendering
/// safety). Emission is infallible for a well-formed `RenderRule`.
fn emit_lib(rule: &RenderRule, hash: &Hash32) -> (String, String) {
    let template_family = &rule.template_family;
    let has_state = rule.has_state();
    let has_scval = rule.has_scval();
    let dynamic = rule.is_dynamic_predicate();
    // The signers compiled into the artifact — empty under a dynamic predicate. Everything that
    // depends on them reads this one slice: the `Bytes` import, the external-key constants and
    // the `expected_signers` body. A constant emitted without its use site is a dead-code warning
    // in a shipped crate, an import without one is an unused-import warning, and a use site
    // without its constant does not compile — so the three cannot be allowed to disagree.
    let compiled_signers = rule.compiled_signers();
    let has_external = rule.has_external_signer();

    let mut out = String::from("// SPDX-License-Identifier: Apache-2.0 OR MIT\n");
    // The header, wrapped rather than written pre-broken.
    //
    // `wrap_comments = true` re-flows any comment paragraph containing a line wider than
    // `comment_width`, so a hand-broken header is a fixed point only by luck — and two of these
    // lines carry values whose width is not ours to choose. The recorded hash is 64 characters,
    // which no label leaves room for, and a template-family identifier may be 64 (see
    // `render::TemplateFamily`), so the first line's width is a property of the spec. Emitting
    // through the same greedy fill rustfmt uses makes every paragraph here stable for any input,
    // and leaves prose edits in this function free of layout arithmetic.
    //
    // The two rent paragraphs are built from the rule's shape rather than written once for every
    // shape, because both of their load-bearing claims are shape-dependent: which entry points
    // extend (`remaining_calls` exists only where a cap does) and whether anything bounds an
    // unauthenticated read (only a validity window does). A single fixed wording would be false
    // for one shape or the other, in the one artifact whose prose has to be readable as an
    // assertion about its own behaviour.
    let readers = if has_state {
        "a successful read through `is_installed` or `remaining_calls`"
    } else {
        "a successful read through `is_installed`"
    };
    let cap_clause = if has_state {
        " Once a call cap is spent the policy stops extending entirely: it can never permit \
         again, so it stops paying rent."
    } else {
        ""
    };
    let storage_lifetime = format!(
        "Storage lifetime is maintained **only while this policy is used**: a permitted call, \
         `install`, and {readers} each extend the entries the policy depends on toward the \
         rule's validity window where one is set and the network maximum otherwise — never past \
         either. Every one of them goes through the same `ttl_target` computation, so no entry \
         point can buy rent that another could not. A policy nothing calls at all still drifts \
         into archival, and so does one that only ever denies, since a denial reverts the \
         extension along with everything else. First use after a long gap may therefore cost a \
         restore.{cap_clause}"
    );
    let rent_bound = if rule.valid_until_ledger.is_some() {
        "The reads are unauthenticated, and bounded by the same thing the writes are: \
         `ttl_target` clamps every extension to VALID_UNTIL_LEDGER, past which every entry point \
         denies. A third party can pay to keep this policy out of archival, and only for as long \
         as it can still permit something."
            .to_string()
    } else {
        "The reads are unauthenticated, and this rule sets no validity window, so the network's \
         rolling `max_ttl()` is the only bound on them: a third party can hold these entries out \
         of archival for as long as they keep paying for the extension. They gain nothing else by \
         it — a read decides no authorization — but this is the one case where what this \
         contract's entries cost to keep alive is not bounded by the rule itself."
            .to_string()
    };
    // Paragraph by paragraph, so the blank `//!` separators stay where they are; rustfmt joins
    // lines only inside a paragraph it has to re-flow, and it never has to re-flow these.
    for paragraph in [
        format!("GENERATED POLICY — template family `{template_family}`."),
        format!("Normalized codegen input hash: {hash}"),
        String::new(),
        "DO NOT EDIT BY HAND: any manual change switches this artifact to CUSTOM SOURCE MODE \
         (architecture §4.4) — spec conformance, differential testing, and generated-mode \
         guarantees no longer apply to an edited copy."
            .to_string(),
        String::new(),
        "Check order is the generated-code contract (§4.4): account authorization and \
         installation state first, then the signer predicate (the OZ account defers signer \
         validation to policies), then strict signer-set, then target/function/tuple scoping, \
         then stateful invariants (missing state denies; the call cap never resets within an \
         installation — only `uninstall`, which the smart account alone can call, clears it). No \
         setters, no upgrade entry point."
            .to_string(),
        String::new(),
        storage_lifetime,
        String::new(),
        rent_bound,
    ] {
        if paragraph.is_empty() {
            out.push_str("//!\n");
        } else {
            out.push_str(&render::wrap_comment("//! ", &paragraph));
        }
    }
    // The crate root ends here, and the contract goes in a module of its own. That is the shape
    // OpenZeppelin's example policies have — `#![no_std]` and a `mod contract;`, with the contract
    // in `src/contract.rs` — and the layout rule their checklist states for an example crate.
    //
    // `pub mod`, not `mod`. Theirs are `cdylib`-only, so nothing needs to name the types from
    // outside; ours also builds as a `lib` for the in-process differential suite, which imports
    // `PolicyStorageKey` and the contract type. `pub mod` keeps them reachable and keeps the crate
    // root to declarations alone, which is the other half of their rule.
    //
    // Their example roots also carry `#![allow(dead_code)]`. Ours must not: a suppression is a
    // violation of their own lint rule, and this emitter goes to some length to emit no dead code
    // — `unbalanced_constants` exists to prove a constant is never emitted without its use site —
    // so the attribute would hide the very thing that test checks for.
    out.push_str("#![no_std]\n\npub mod contract;\n");
    let crate_root = out;

    let mut out = String::new();
    out.push_str(&render::wrap_comment(
        "//! ",
        "The compiled rule. Its guarantees, its check order and the hash of the codegen input it \
         came from are stated in the crate root.",
    ));
    out.push('\n');

    // Imports (conditional to keep the generated crate warning-free).
    //
    // One grouped `use` per crate. That is what `imports_granularity = "Crate"` produces — the
    // setting in OpenZeppelin's own `rustfmt.toml` — and what both sibling policy examples show
    // (`examples/multisig-smart-account/threshold-policy/src/contract.rs:8-12` and
    // `spending-limit-policy/src/contract.rs:18-22` at v0.7.2).
    //
    // This was previously five separate statements, deliberately: under *default* rustfmt one
    // brace group naming every item ran to 148 characters, so rustfmt reflowed it, and the fill
    // it chose depended on which items the rule needed — a formatting choice that would then
    // vary from policy to policy. `render::use_statement` removes the reason for the split by
    // deriving that same fill, so the grouped form is stable for every combination instead of
    // being avoided.
    let mut sdk: Vec<&str> = vec![
        "auth::Context",
        "contract",
        "contracterror",
        "contractevent",
        "contractimpl",
        "contracttype",
        "panic_with_error",
        "Address",
        "Env",
        "Symbol",
        "TryFromVal",
        "Val",
        "Vec",
    ];
    if has_scval {
        sdk.push("xdr::ToXdr");
    }
    if has_scval || has_external {
        sdk.push("Bytes");
    }
    out.push_str(&render::use_statement("soroban_sdk", &sdk));
    out.push_str(&render::use_statement(
        "stellar_accounts",
        &["policies::Policy", "smart_account::{ContextRule, Signer}"],
    ));
    out.push('\n');

    out.push_str(&section("ERRORS"));
    // Error enum (stable numbering; mirrors the reference evaluator's deny reasons).
    //
    // Every variant is declared whatever the rule's shape, so a code means the same thing across
    // artifacts — which is also why the per-entry-point `# Errors` lists below are built from the
    // shape instead of copying this list: the enum is the vocabulary, not the set of reachable
    // refusals for a given policy.
    out.push_str(&emit_doc(
        "",
        &[
            "Every reason this policy can refuse an authorization, an install or an uninstall."
                .to_string(),
            "The numbering is the published deny-reason contract rather than a position in a \
             range: a code identifies one refusal, an independently written reference evaluator \
             asserts the same mapping, and every variant is declared in every generated policy \
             whatever its rule's shape — so a reader can read a code the same way across \
             artifacts."
                .to_string(),
        ],
        &[],
    ));
    out.push_str(
        "#[contracterror]\n#[derive(Copy, Clone, Debug, PartialEq)]\n#[repr(u32)]\npub enum PolicyError {\n",
    );
    for (variant, code, doc) in [
        (
            "ZeroSigners",
            1,
            "No signer authenticated this authorization. The account defers signer validation \
             to its policies, so an empty set has to be refused here.",
        ),
        (
            "PredicateUnsatisfied",
            2,
            "The authenticated signers do not satisfy the rule's signer predicate.",
        ),
        (
            "SignerSetDiverged",
            3,
            "The context rule's live signer set is no longer the one compiled in, so the grant \
             a reader approved is not the grant being exercised.",
        ),
        (
            "TargetMismatch",
            4,
            "The invoked contract is not the one this policy is scoped to.",
        ),
        (
            "FunctionNotAllowed",
            5,
            "The invoked function is not one of the allowed calls, or the authorization is not \
             a contract invocation at all.",
        ),
        (
            "NoTupleMatched",
            6,
            "The arguments satisfy no allowed call tuple: arity, a constraint, or both.",
        ),
        (
            "CallCountExceeded",
            7,
            "This installation has used every call its cap allows. The count never resets \
             within an installation.",
        ),
        (
            "MissingState",
            8,
            "State this policy owns for the (smart account, context rule) is absent. Missing \
             state denies rather than reading as zero.",
        ),
        (
            "RuleExpired",
            9,
            "The ledger is past the rule's validity window.",
        ),
        (
            "AlreadyInstalled",
            10,
            "The policy is already installed for this (smart account, context rule).",
        ),
        (
            "NotInstalled",
            11,
            "The policy is not installed for this (smart account, context rule).",
        ),
    ] {
        out.push_str(&render::wrap_comment("    /// ", doc));
        out.push_str(&format!("    {variant} = {code},\n"));
    }
    out.push_str("}\n\n");

    out.push_str(&section("STORAGE KEYS"));
    // `PolicyStorageKey`, not `DataKey`: their convention is `<Module>StorageKey`
    // (`code-quality.md`, "Naming"), and every storage-key enum in the library follows it —
    // `SimpleThresholdStorageKey` at `policies/simple_threshold.rs:121`, and the same shape in
    // the weighted-threshold and spending-limit modules. `Policy` is the module name our error
    // enum already uses, so the pair reads together.
    out.push_str(&emit_doc(
        "",
        &[
            "Keys for the state this policy owns.".to_string(),
            "Every variant is segregated by (smart account, context rule id), which is what lets \
             one deployment serve any number of accounts without their installations observing \
             each other."
                .to_string(),
        ],
        &[],
    ));
    out.push_str(
        "#[contracttype]\n#[derive(Clone, Debug)]\npub enum PolicyStorageKey {\n    /// Installation marker, segregated by (smart account, context rule id).\n    Installed(Address, u32),\n",
    );
    if has_state {
        out.push_str(
            "    /// Call count for one installation. Never resets until `uninstall`.\n    CallCount(Address, u32),\n",
        );
    }
    out.push_str("}\n\n");

    out.push_str(&section("CONSTANTS"));
    // Compiled-in constants.
    out.push_str(&format!("const TARGET: &str = \"{}\";\n", rule.target));
    if let Some(ledger) = rule.valid_until_ledger {
        out.push_str(&format!(
            "/// Defense in depth: the account also enforces the rule's valid_until.\nconst VALID_UNTIL_LEDGER: u32 = {ledger};\n"
        ));
    }
    if let Some(max_calls) = rule.max_calls_per_installation {
        out.push_str(&format!("const MAX_CALLS: u32 = {max_calls};\n"));
    }
    // Recorded byte strings — an external signer's key, an `ScVal` an argument must equal — are
    // the only emitted literals whose length is not fixed, so they live here rather than at the
    // point of use: at module level their layout depends on nothing but their own length. Their
    // names are built from signer and argument positions inside `render`, so no recorded value
    // reaches an identifier.
    for (index, signer) in compiled_signers.iter().enumerate() {
        if let RenderSigner::External { key, .. } = signer {
            out.push_str(&key.render_signer_key_const(index));
        }
    }
    for (ci, call) in rule.calls.iter().enumerate() {
        for arg in &call.args {
            if let RenderConstraint::EqScval(bytes) = &arg.constraint {
                out.push_str(&bytes.render_arg_xdr_const(ci, arg.index));
            }
        }
    }
    out.push('\n');

    // The private helpers go last, under their own heading, which is where OpenZeppelin's
    // `storage.rs` puts LOW-LEVEL HELPERS. They are emitted into a buffer here and appended after
    // the entry points, so a reader opening a generated policy meets the three things it exposes
    // before the arithmetic they are built from — which is the ordering the `ttl_target` note
    // already argued for, now applied to every helper rather than to that one.
    let mut helpers = String::new();

    // The contract struct, then the read-only surface, then the trait impl. Both sibling policy
    // examples expose their getters from an inherent `#[contractimpl]` block beside the trait one
    // (`threshold-policy/src/contract.rs:62-78`, `spending-limit-policy/src/contract.rs:67-87`),
    // and `code-quality.md` reserves plain `#[contractimpl]` for exactly that block.
    //
    // Until now the artifact exported only the three trait methods, so there was no on-chain way
    // to ask whether a policy was installed or how many calls an installation had left — a gap
    // with a second consequence: the library's "extend TTL on read, not on write" rule had no
    // read site to attach to, which is why this artifact diverged from it. It now has one.
    // Events. The trait's own documentation asks for them —
    // `stellar-accounts-0.7.2/src/policies/mod.rs:106-111` for `install` and `:144-149` for
    // `uninstall` — and all three library policies emit on all three entry points, so `enforce`
    // is included by their practice rather than by the docstring alone. Their shape, followed
    // rather than re-invented: one `#[contractevent]` struct per verb named `<Policy><Verb>`,
    // `smart_account` as the single topic, `context_rule_id` in the data, and the enforcement
    // event additionally carrying the context and the policy's own running number.
    //
    // Ours is the remaining call count, which is the closest analogue to `spending_limit`'s
    // `total_spent_in_period` (`policies/spending_limit.rs:46-53`) — and it exists only where a
    // cap does, for the same reason `remaining_calls` does.
    //
    // A denial cannot be observed this way and that is not a gap to be worked around:
    // `panic_with_error!` reverts the invocation, so an event published before it is reverted
    // with it. Events are possible on a permit only.
    out.push_str(&section("EVENTS"));
    out.push_str(&emit_doc(
        "",
        &[
            "Emitted when this policy permits an authorization.".to_string(),
            "Derives `Clone` alone where the other two events also derive `Debug`, `Eq` and \
             `PartialEq`, because `Context` implements none of those — which is the same reason \
             `SimpleEnforced` and `SpendingLimitEnforced` derive `Clone` alone upstream."
                .to_string(),
        ],
        &[],
    ));
    out.push_str("#[contractevent]\n#[derive(Clone)]\npub struct GeneratedPolicyEnforced {\n");
    out.push_str("    /// The smart account whose authorization was permitted.\n");
    out.push_str("    #[topic]\n    pub smart_account: Address,\n");
    out.push_str("    /// The authorization that was permitted.\n");
    out.push_str("    pub context: Context,\n");
    out.push_str("    /// The context rule this policy is attached to.\n");
    out.push_str("    pub context_rule_id: u32,\n");
    if has_state {
        out.push_str(&render::wrap_comment(
            "    /// ",
            "Calls this installation may still permit after the one just spent. Zero means the \
             installation can never permit again.",
        ));
        out.push_str("    pub remaining_calls: u32,\n");
    }
    out.push_str("}\n\n");

    for (verb, summary) in [
        (
            "Installed",
            "Emitted when this policy is installed for a context rule of a smart account.",
        ),
        (
            "Uninstalled",
            "Emitted when this policy is removed from a context rule of a smart account.",
        ),
    ] {
        out.push_str(&emit_doc("", &[summary.to_string()], &[]));
        out.push_str(&format!(
            "#[contractevent]\n#[derive(Clone, Debug, Eq, PartialEq)]\npub struct GeneratedPolicy{verb} {{\n    /// The smart account this policy is installed for.\n    #[topic]\n    pub smart_account: Address,\n    /// The context rule this policy is attached to.\n    pub context_rule_id: u32,\n}}\n\n"
        ));
    }

    out.push_str(&section("QUERY STATE"));
    out.push_str(&emit_doc(
        "",
        &[
            "This rule, compiled to a policy contract.".to_string(),
            "One deployment serves any number of smart accounts: everything the rule fixes is a \
             constant in this file, and everything that varies per installation is keyed by \
             (smart account, context rule id). There are no setters and no upgrade entry point, \
             so reconfiguration is remove-and-reinstall — which is what makes the wasm hash a \
             statement about behaviour rather than about a starting state."
                .to_string(),
        ],
        &[],
    ));
    out.push_str("#[contract]\npub struct GeneratedPolicy;\n\n");
    out.push_str("#[contractimpl]\nimpl GeneratedPolicy {\n");

    let mut is_installed_notes = vec![
        "A successful read extends the lifetime of the entries this policy depends on — the same \
         entries, through the same `ttl_target` computation, as a permitted call. Extending on \
         read is the library's rule for entries a contract owns, so this is a state-changing \
         call, cheap but not free, and any caller may make it. The only write it can perform is \
         an extension, so paying for one on another account's behalf is the whole of what an \
         unauthorized caller can do here."
            .to_string(),
    ];
    if has_state {
        is_installed_notes.push(
            "The extension is withheld once the call cap is spent, and the counter is read for \
             no other reason: an installation that can never permit again must stop paying rent, \
             which is what the crate header promises and what a read that extended \
             unconditionally would quietly break."
                .to_string(),
        );
    }
    // The bound a read inherits, stated where a reader of the read will look for it. With a
    // window there is a real ceiling and it is the same one the write paths have; without one
    // there is nothing to inherit, and saying so is the honest half of this design.
    is_installed_notes.push(if rule.valid_until_ledger.is_some() {
        "The target is `ttl_target(e)`, so an unauthenticated read can no more carry these \
         entries past VALID_UNTIL_LEDGER than a permitted call can: past that ledger every entry \
         point denies, and the extension stops there."
            .to_string()
    } else {
        "This rule carries no validity window, so `ttl_target(e)` is the network's rolling \
         `max_ttl()` and there is no further ceiling for a read to inherit. Any caller may \
         therefore hold these entries out of archival for as long as they keep paying for the \
         extension. That buys them nothing else — a read grants no authorization — but it is the \
         one case where this contract's rent is not bounded by the rule itself."
            .to_string()
    });
    out.push_str(&emit_doc(
        "    ",
        &[
            "Whether this policy is installed for one context rule of one smart account."
                .to_string(),
            "`false` for an absent installation rather than a panic: this is a query, and a \
             missing entry is an answer to it."
                .to_string(),
        ],
        &[
            (
                "# Arguments",
                vec![
                    "`e` - Access to the Soroban environment.".to_string(),
                    "`context_rule_id` - The context rule to ask about.".to_string(),
                    "`smart_account` - The smart account to ask about.".to_string(),
                ],
            ),
            ("# Notes", is_installed_notes),
        ],
    ));
    if has_state {
        out.push_str(
            "    pub fn is_installed(e: &Env, context_rule_id: u32, smart_account: Address) -> bool {\n        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule_id);\n        if !e.storage().persistent().has(&installed_key) {\n            return false;\n        }\n        let key = PolicyStorageKey::CallCount(smart_account, context_rule_id);\n        let remaining = match e.storage().persistent().get::<_, u32>(&key) {\n            Some(used) => MAX_CALLS.saturating_sub(used),\n            None => 0u32,\n        };\n",
        );
        out.push_str(&ttl_extension_block(true));
        out.push_str("\n        true\n    }\n");
    } else {
        out.push_str(
            "    pub fn is_installed(e: &Env, context_rule_id: u32, smart_account: Address) -> bool {\n        let installed_key = PolicyStorageKey::Installed(smart_account, context_rule_id);\n        if !e.storage().persistent().has(&installed_key) {\n            return false;\n        }\n",
        );
        out.push_str(&ttl_extension_block(false));
        out.push_str("\n        true\n    }\n");
    }
    // `remaining_calls` exists only where a cap does. A rule with no cap has no counter to
    // report, and the alternatives are both worse than an absent function: a sentinel like
    // `u32::MAX` would be a magic value a caller has to know about, and returning zero would
    // read as "exhausted" for a policy that is in fact unlimited. The exported function list is
    // itself the answer to "does this policy cap calls".
    if has_state {
        out.push('\n');
        out.push_str(&emit_doc(
            "    ",
            &[
                "Calls this installation may still permit.".to_string(),
                "Counts down from the compiled-in cap and never resets: only `uninstall`, which \
                 the smart account alone can call, clears the count."
                    .to_string(),
            ],
            &[
                (
                    "# Arguments",
                    vec![
                        "`e` - Access to the Soroban environment.".to_string(),
                        "`context_rule_id` - The context rule to ask about.".to_string(),
                        "`smart_account` - The smart account to ask about.".to_string(),
                    ],
                ),
                (
                    "# Errors",
                    vec![
                        "[`PolicyError::MissingState`] - When no installation marker exists for \
                         this smart account and context rule, or when the marker exists and the \
                         call counter does not. A count is required setup data, so its absence \
                         is an error rather than a zero."
                            .to_string(),
                    ],
                ),
                (
                    "# Notes",
                    vec![
                        "Extends the same entries `is_installed` does, through the same \
                         computation, and withholds the extension once the count is spent."
                            .to_string(),
                    ],
                ),
            ],
        ));
        out.push_str(
            "    pub fn remaining_calls(e: &Env, context_rule_id: u32, smart_account: Address) -> u32 {\n        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule_id);\n        if !e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::MissingState);\n        }\n        let key = PolicyStorageKey::CallCount(smart_account, context_rule_id);\n        let used: u32 = match e.storage().persistent().get(&key) {\n            Some(used) => used,\n            None => panic_with_error!(e, PolicyError::MissingState),\n        };\n        let remaining = MAX_CALLS.saturating_sub(used);\n",
        );
        out.push_str(&ttl_extension_block(true));
        out.push_str("\n        remaining\n    }\n");
    }
    out.push_str("}\n\n");

    out.push_str(&section("CHANGE STATE"));
    out.push_str("#[contractimpl]\nimpl Policy for GeneratedPolicy {\n");
    out.push_str(&render::wrap_comment(
        "    /// ",
        "Installation parameters. A generated policy has none — every limit is compiled in — so \
         this is a placeholder the smart account's `install` call has to pass something for.",
    ));
    out.push_str("    type AccountParams = u32;\n\n");

    // enforce()
    //
    // The `# Errors` list is assembled from the same conditions that decide which checks are
    // emitted, so a check and its documentation cannot get out of step: adding a refusal to the
    // body without listing it here, or listing one the body cannot raise, would take a second
    // edit in the same expression rather than in a distant string.
    let mut enforce_errors = vec![if has_state {
        // Two raise sites, so two conditions. The second is an invariant violation rather than an
        // ordinary refusal — `install` writes the marker and the counter together — and it denies
        // for the same reason the first does.
        "[`PolicyError::MissingState`] - When no installation marker exists for this smart \
         account and context rule, or when the marker exists and the call counter this policy \
         owns does not. Missing state denies rather than reading as zero."
            .to_string()
    } else {
        "[`PolicyError::MissingState`] - When no installation marker exists for this smart \
         account and context rule. Missing state denies rather than reading as zero."
            .to_string()
    }];
    if rule.valid_until_ledger.is_some() {
        enforce_errors.push(
            "[`PolicyError::RuleExpired`] - When the ledger sequence is past the rule's \
             validity window."
                .to_string(),
        );
    }
    enforce_errors.push(
        "[`PolicyError::ZeroSigners`] - When no signer authenticated this authorization."
            .to_string(),
    );
    enforce_errors.push(
        "[`PolicyError::PredicateUnsatisfied`] - When the authenticated signers do not satisfy \
         the rule's signer predicate."
            .to_string(),
    );
    if rule.strict_signer_set && !dynamic {
        enforce_errors.push(
            "[`PolicyError::SignerSetDiverged`] - When the context rule's live signer set is a \
             different size from the one compiled in, or when a compiled-in signer is absent \
             from it. Either way the grant a reader approved is not the grant being exercised."
                .to_string(),
        );
    }
    enforce_errors.push(
        "[`PolicyError::FunctionNotAllowed`] - When the authorization is not a contract \
         invocation at all, or when it invokes a function outside the allowed calls."
            .to_string(),
    );
    enforce_errors.push(
        "[`PolicyError::TargetMismatch`] - When the invoked contract is not the one this policy \
         is scoped to."
            .to_string(),
    );
    enforce_errors.push(
        "[`PolicyError::NoTupleMatched`] - When the arguments satisfy no allowed call tuple."
            .to_string(),
    );
    if has_state {
        enforce_errors.push(
            "[`PolicyError::CallCountExceeded`] - When this installation has already used every \
             call its cap allows."
                .to_string(),
        );
    }
    let mut enforce_notes = vec![
        "Refusals are ordered: the code a caller sees is the first condition that failed, in the \
         order the crate header documents, not an arbitrary one of several."
            .to_string(),
    ];
    if has_state {
        enforce_notes.push(
            "The call counter is advanced only on the permitting path, and a panic anywhere later \
             in the invocation reverts that increment along with everything else."
                .to_string(),
        );
    }
    out.push_str(&emit_doc(
        "    ",
        &[
            "Enforces this policy for one authorization attempt.".to_string(),
            "Returning is the permit; every refusal is a panic carrying the code that names it."
                .to_string(),
        ],
        &[
            (
                "# Arguments",
                vec![
                    "`e` - Access to the Soroban environment.".to_string(),
                    "`context` - The authorization context being enforced.".to_string(),
                    "`authenticated_signers` - The signers the smart account has already \
                     verified. The account defers signer validation to its policies, so this \
                     list is checked here rather than trusted."
                        .to_string(),
                    "`context_rule` - The context rule this policy is attached to.".to_string(),
                    "`smart_account` - The smart account being authorized.".to_string(),
                ],
            ),
            ("# Errors", enforce_errors),
            (
                "# Events",
                vec![
                    "topics - `[\"generated_policy_enforced\", smart_account: Address]`"
                        .to_string(),
                    format!(
                        "data - `[context: Context, context_rule_id: u32{}]`",
                        if has_state {
                            ", remaining_calls: u32"
                        } else {
                            ""
                        }
                    ),
                ],
            ),
            ("# Notes", enforce_notes),
        ],
    ));
    out.push_str(
        "    fn enforce(\n        e: &Env,\n        context: Context,\n        authenticated_signers: Vec<Signer>,\n        context_rule: ContextRule,\n        smart_account: Address,\n    ) {\n        smart_account.require_auth();\n\n",
    );
    out.push_str(
        "        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);\n        if !e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::MissingState);\n        }\n\n",
    );
    if rule.valid_until_ledger.is_some() {
        out.push_str(
            "        if e.ledger().sequence() > VALID_UNTIL_LEDGER {\n            panic_with_error!(e, PolicyError::RuleExpired);\n        }\n\n",
        );
    }
    // `is_empty()`, not `len() == 0`: `clippy::len_zero` is warn-by-default, the generated
    // crate is linted with `-D warnings` by the contracts job, and OpenZeppelin's conventions
    // forbid silencing a lint with `#[allow]` — so the zero-length spelling is a build failure
    // in a shipped artifact rather than a matter of taste. `soroban_sdk::Vec::is_empty` exists
    // (`soroban-sdk-26.1.0/src/vec.rs:835`), so no host call is added by preferring it.
    out.push_str(
        "        if authenticated_signers.is_empty() {\n            panic_with_error!(e, PolicyError::ZeroSigners);\n        }\n",
    );
    if dynamic {
        out.push_str(
            "        let matched = matched_count(&authenticated_signers, &context_rule.signers);\n        if matched < 1u32 {\n            panic_with_error!(e, PolicyError::PredicateUnsatisfied);\n        }\n\n",
        );
    } else {
        out.push_str("        let expected = expected_signers(e);\n");
        out.push_str("        let matched = matched_count(&authenticated_signers, &expected);\n");
        match &rule.predicate {
            PredicateKind::AnyOf => out.push_str(
                "        if matched < 1u32 {\n            panic_with_error!(e, PolicyError::PredicateUnsatisfied);\n        }\n",
            ),
            PredicateKind::AllOf => out.push_str(
                "        if matched != expected.len() {\n            panic_with_error!(e, PolicyError::PredicateUnsatisfied);\n        }\n",
            ),
            PredicateKind::Threshold { n } => out.push_str(&format!(
                "        if matched < {n}u32 {{\n            panic_with_error!(e, PolicyError::PredicateUnsatisfied);\n        }}\n"
            )),
            PredicateKind::AnyOfCurrentRuleSigners => unreachable!("handled by `dynamic`"),
        }
        if rule.strict_signer_set {
            out.push_str(
                "\n        if context_rule.signers.len() != expected.len() {\n            panic_with_error!(e, PolicyError::SignerSetDiverged);\n        }\n        for exp in expected.iter() {\n            let mut found = false;\n            for live in context_rule.signers.iter() {\n                if live == exp {\n                    found = true;\n                    break;\n                }\n            }\n            if !found {\n                panic_with_error!(e, PolicyError::SignerSetDiverged);\n            }\n        }\n",
            );
        }
        out.push('\n');
    }

    // Context scoping.
    out.push_str(
        "        let c = match &context {\n            Context::Contract(c) => c.clone(),\n            _ => panic_with_error!(e, PolicyError::FunctionNotAllowed),\n        };\n        if c.contract != Address::from_str(e, TARGET) {\n            panic_with_error!(e, PolicyError::TargetMismatch);\n        }\n",
    );
    let fn_names: Vec<&str> = {
        let mut names: Vec<&str> = rule.calls.iter().map(|c| c.fn_name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names
    };
    // One binding per allowed function name, so the comparison against the invoked name is
    // written once and both checks below read it. Previously each check inlined
    // `c.fn_name == Symbol::new(e, "…")`, which put the length of the `tuple_ok` line at the
    // mercy of the recorded function name: `transfer` overshot rustfmt's width by four columns
    // and `swap_exact_tokens_for_tokens` by twenty-seven, and rustfmt broke each differently.
    // A binding is at most 87 columns: the longest symbol Soroban accepts under a two-digit
    // binding index, both of which the spec's own bounds admit (MAX_CALLS_PER_RULE is 32).
    for (fi, name) in fn_names.iter().enumerate() {
        out.push_str(&format!(
            "        let fn_{fi}_ok = c.fn_name == Symbol::new(e, \"{name}\");\n"
        ));
    }
    let known_names: Vec<String> = (0..fn_names.len())
        .map(|fi| format!("fn_{fi}_ok"))
        .collect();
    // The disjunction of every binding grows with the number of unique names — up to 386
    // columns at the spec's 32-call bound — so, like the byte arrays in `render`, its layout
    // is derived from rustfmt's own rules rather than assumed. One line while the whole `if`
    // fits `MAX_WIDTH`, because rustfmt collapses a shorter chain back onto the `if` line;
    // once it does not fit, rustfmt's canonical break for an over-wide `||` chain: every
    // operand on its own line, block-indented one level, and — after a multiline condition —
    // the opening brace on its own line. The switch is measured on the rendered line, not
    // derived from the name count, because operand width varies with the index's digit count
    // (`fn_10_ok` is a column wider than `fn_9_ok`).
    //
    // A single allowed name needs no parens around the negation (clippy: unnecessary_parens).
    let known_expr = known_names.join(" || ");
    let if_line = if fn_names.len() > 1 {
        format!("        if !({known_expr}) {{")
    } else {
        format!("        if !{known_expr} {{")
    };
    // The same measure `overlong_lines` applies to every emitted line; scalar count,
    // byte length and display width all coincide here, since the operands are `fn_<n>_ok`.
    if if_line.chars().count() <= render::MAX_WIDTH {
        out.push_str(&if_line);
        out.push('\n');
    } else {
        out.push_str(&format!("        if !({}", known_names[0]));
        for name in &known_names[1..] {
            out.push_str(&format!("\n            || {name}"));
        }
        out.push_str(")\n        {\n");
    }
    out.push_str("            panic_with_error!(e, PolicyError::FunctionNotAllowed);\n        }\n");
    // `&&` binds tighter than `||`, so per-disjunct parens are unnecessary; a single
    // allowed call must emit no wrapping parens at all (clippy: unnecessary_parens).
    let multi = rule.calls.len() > 1;
    let tuple_expr = rule
        .calls
        .iter()
        .enumerate()
        .map(|(ci, call)| {
            // `fn_names` is sorted and deduplicated just above, so the lookup is a binary
            // search rather than a scan per call — and it uses the ordering that is already
            // established instead of building a second index beside it. (A hash map is not an
            // option here in any case: `clippy.toml` bans `HashMap` across both workspaces,
            // because per-process iteration order is how emitted bytes stop being reproducible.)
            let fi = fn_names
                .binary_search(&call.fn_name.as_str())
                .unwrap_or_else(|_| unreachable!("fn_names is built from rule.calls"));
            let inner = format!("fn_{fi}_ok && check_call_{ci}(e, &c.args, &smart_account)");
            if multi {
                format!("({inner})")
            } else {
                inner
            }
        })
        .collect::<Vec<_>>()
        .join("\n            || ");
    out.push_str(&format!(
        "        let tuple_ok = {tuple_expr};\n        if !tuple_ok {{\n            panic_with_error!(e, PolicyError::NoTupleMatched);\n        }}\n"
    ));

    // State.
    if has_state {
        out.push_str(
            "\n        let key = PolicyStorageKey::CallCount(smart_account.clone(), context_rule.id);\n        let count: u32 = match e.storage().persistent().get(&key) {\n            Some(c) => c,\n            None => panic_with_error!(e, PolicyError::MissingState),\n        };\n        if count >= MAX_CALLS {\n            panic_with_error!(e, PolicyError::CallCountExceeded);\n        }\n        e.storage().persistent().set(&key, &(count + 1u32));\n        let remaining = MAX_CALLS - (count + 1u32);\n",
        );
    }
    // Storage lifetime goes last. In `install` that ordering is required — the counter key does
    // not exist until its `set`, and extending first fails with `Error(Storage, MissingValue)`. In
    // `enforce` the key is guaranteed to exist by the `MissingState` check, so here it is a choice:
    // the two blocks stay textually identical, and a panic reverts the whole invocation anyway, so
    // there is nothing to gain by extending before the checks have passed.
    out.push_str(&ttl_extension_block(has_state));
    // The event goes after the storage bookkeeping, so the function reads checks → state → rent
    // → announcement. Anywhere in the permitting path would be equivalent: a panic later in the
    // invocation reverts the publish along with the counter increment.
    out.push_str(&emit_publish(
        "GeneratedPolicyEnforced",
        &if has_state {
            vec![
                "smart_account: smart_account.clone()",
                "context",
                "context_rule_id: context_rule.id",
                "remaining_calls: remaining",
            ]
        } else {
            vec![
                "smart_account: smart_account.clone()",
                "context",
                "context_rule_id: context_rule.id",
            ]
        },
    ));
    out.push_str("    }\n\n");

    // install() / uninstall()
    //
    // `install` extends; `uninstall` deliberately does not. Extending on the way out would buy
    // rent for an entry being removed and for a contract the account is detaching from — and if
    // the code were archived, the call could not be executing in the first place.
    let mut install_errors = Vec::new();
    if rule.valid_until_ledger.is_some() {
        install_errors.push(
            "[`PolicyError::RuleExpired`] - When the ledger sequence is already past the rule's \
             validity window, so the installation could never permit anything."
                .to_string(),
        );
    }
    install_errors.push(
        "[`PolicyError::AlreadyInstalled`] - When this (smart account, context rule) already \
         carries an installation. Re-installing would be the one way to reset the state a rule \
         relies on, so it is refused rather than made idempotent."
            .to_string(),
    );
    let install_doc = emit_doc(
        "    ",
        &[
            "Installs this policy for one context rule of one smart account.".to_string(),
            format!(
                "Writes the installation marker{} and extends the lifetime of the entries this \
                 policy depends on. `_install_params` is accepted and ignored: every limit is \
                 compiled in, so there is nothing an installation could configure.",
                if has_state {
                    " and the call counter"
                } else {
                    ""
                }
            ),
        ],
        &[
            (
                "# Arguments",
                vec![
                    "`e` - Access to the Soroban environment.".to_string(),
                    "`_install_params` - Unused; see above.".to_string(),
                    "`context_rule` - The context rule this policy is being attached to."
                        .to_string(),
                    "`smart_account` - The smart account installing this policy.".to_string(),
                ],
            ),
            ("# Errors", install_errors),
            (
                "# Events",
                vec![
                    "topics - `[\"generated_policy_installed\", smart_account: Address]`"
                        .to_string(),
                    "data - `[context_rule_id: u32]`".to_string(),
                ],
            ),
        ],
    );
    let uninstall_doc = emit_doc(
        "    ",
        &[
            format!(
                "Removes this policy's own state for one context rule of one smart account{}.",
                if has_state {
                    " — the installation marker and the call count"
                } else {
                    ""
                }
            ),
            "Extends nothing on the way out: buying rent for entries being removed, on behalf of \
             an account detaching from this contract, is the one place where the extension would \
             be spent for nobody."
                .to_string(),
        ],
        &[
            (
                "# Arguments",
                vec![
                    "`e` - Access to the Soroban environment.".to_string(),
                    "`context_rule` - The context rule this policy is being removed from."
                        .to_string(),
                    "`smart_account` - The smart account uninstalling this policy.".to_string(),
                ],
            ),
            (
                "# Errors",
                vec![
                    "[`PolicyError::NotInstalled`] - When this (smart account, context rule) \
                     carries no installation."
                        .to_string(),
                ],
            ),
            (
                "# Events",
                vec![
                    "topics - `[\"generated_policy_uninstalled\", smart_account: Address]`"
                        .to_string(),
                    "data - `[context_rule_id: u32]`".to_string(),
                ],
            ),
        ],
    );
    if has_state {
        out.push_str(&install_doc);
        out.push_str(
            "    fn install(e: &Env, _install_params: u32, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n",
        );
        if rule.valid_until_ledger.is_some() {
            out.push_str(
                "        if e.ledger().sequence() > VALID_UNTIL_LEDGER {\n            panic_with_error!(e, PolicyError::RuleExpired);\n        }\n",
            );
        }
        out.push_str(
            "        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);\n        if e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::AlreadyInstalled);\n        }\n        let key = PolicyStorageKey::CallCount(smart_account.clone(), context_rule.id);\n        e.storage().persistent().set(&installed_key, &true);\n        e.storage().persistent().set(&key, &0u32);\n        let remaining = MAX_CALLS;\n",
        );
        out.push_str(&ttl_extension_block(true));
        out.push_str(&emit_publish(
            "GeneratedPolicyInstalled",
            &[
                "smart_account: smart_account.clone()",
                "context_rule_id: context_rule.id",
            ],
        ));
        out.push_str("    }\n\n");
        out.push_str(&uninstall_doc);
        out.push_str(
            "    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);\n        if !e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::NotInstalled);\n        }\n        let key = PolicyStorageKey::CallCount(smart_account.clone(), context_rule.id);\n        e.storage().persistent().remove(&key);\n        e.storage().persistent().remove(&installed_key);\n",
        );
        out.push_str(&emit_publish(
            "GeneratedPolicyUninstalled",
            &[
                "smart_account: smart_account.clone()",
                "context_rule_id: context_rule.id",
            ],
        ));
        out.push_str("    }\n");
    } else {
        out.push_str(&install_doc);
        out.push_str(
            "    fn install(e: &Env, _install_params: u32, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n",
        );
        if rule.valid_until_ledger.is_some() {
            out.push_str(
                "        if e.ledger().sequence() > VALID_UNTIL_LEDGER {\n            panic_with_error!(e, PolicyError::RuleExpired);\n        }\n",
            );
        }
        out.push_str(
            "        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);\n        if e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::AlreadyInstalled);\n        }\n        e.storage().persistent().set(&installed_key, &true);\n",
        );
        out.push_str(&ttl_extension_block(false));
        out.push_str(&emit_publish(
            "GeneratedPolicyInstalled",
            &[
                "smart_account: smart_account.clone()",
                "context_rule_id: context_rule.id",
            ],
        ));
        out.push_str("    }\n\n");
        out.push_str(&uninstall_doc);
        out.push_str(
            "    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n        let installed_key = PolicyStorageKey::Installed(smart_account.clone(), context_rule.id);\n        if !e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::NotInstalled);\n        }\n        e.storage().persistent().remove(&installed_key);\n",
        );
        out.push_str(&emit_publish(
            "GeneratedPolicyUninstalled",
            &[
                "smart_account: smart_account.clone()",
                "context_rule_id: context_rule.id",
            ],
        ));
        out.push_str("    }\n");
    }
    out.push_str("}\n\n");
    // Expected signer set (sorted canonical order — deterministic).
    if !dynamic {
        helpers.push_str(
            "fn expected_signers(e: &Env) -> Vec<Signer> {\n    soroban_sdk::vec![\n        e,\n",
        );
        // Already in canonical signer order — see `RenderRule::from_rule`.
        //
        // Both forms are rustfmt's, under the shipped config and measured against it — and they
        // differ, which is the point of writing them out rather than picking one shape. A strkey
        // is always 56 characters, so `Signer::Delegated(Address::from_str(e, "…")),` is 108
        // columns and cannot fit `max_width` at this indentation however wide `fn_call_width`
        // gets: rustfmt breaks the outer call and puts each argument on its own line. Inside
        // `Signer::External(` the same call sits one level deeper but on a line of its own, where
        // it comes to 93 columns and now fits — under the previous `fn_call_width = 60` it did
        // not, which is why the argument list used to be split there too.
        for (index, signer) in compiled_signers.iter().enumerate() {
            match signer {
                RenderSigner::Delegated(address) => helpers.push_str(&format!(
                    "        Signer::Delegated(Address::from_str(\n            e,\n            \"{address}\"\n        )),\n"
                )),
                RenderSigner::External { verifier, .. } => helpers.push_str(&format!(
                    "        Signer::External(\n            Address::from_str(e, \"{verifier}\"),\n            Bytes::from_slice(e, &{})\n        ),\n",
                    render::signer_key_name(index)
                )),
            }
        }
        helpers.push_str("    ]\n}\n\n");
    }

    // Matched-count helper (iterates expected → duplicates never double-count).
    helpers.push_str(
        "fn matched_count(authenticated: &Vec<Signer>, expected: &Vec<Signer>) -> u32 {\n    let mut matched: u32 = 0;\n    for exp in expected.iter() {\n        for got in authenticated.iter() {\n            if got == exp {\n                matched += 1;\n                break;\n            }\n        }\n    }\n    matched\n}\n\n",
    );

    // One check function per allowed tuple.
    for (ci, call) in rule.calls.iter().enumerate() {
        helpers.push_str(&format!(
            "fn check_call_{ci}(e: &Env, args: &Vec<Val>, smart_account: &Address) -> bool {{\n"
        ));
        helpers.push_str(&format!(
            "    if args.len() != {}u32 {{\n        return false;\n    }}\n",
            call.args.len()
        ));
        // `call.args` is already in index order (see `RenderRule::from_rule`).
        for arg in &call.args {
            let i = arg.index;
            // AnyValue (maximal widening): enforce arity only, never bind the value.
            if matches!(arg.constraint, RenderConstraint::AnyValue) {
                helpers.push_str(&format!(
                    "    if args.get({i}u32).is_none() {{\n        return false;\n    }}\n"
                ));
                continue;
            }
            helpers.push_str(&format!(
                "    let Some(v{i}) = args.get({i}u32) else {{\n        return false;\n    }};\n"
            ));
            match &arg.constraint {
                RenderConstraint::EqSelf | RenderConstraint::EqAddress(_) => {
                    // Two shapes, because the condition's width decides where the brace goes and
                    // the address form lands exactly on the boundary. `Address::from_str` now
                    // fits one line — `fn_call_width` is `max_width` under the shipped config —
                    // and at this indentation, with a strkey's fixed 56 characters, that line is
                    // 100 columns: precisely `max_width`, so there is no room for the ` {` and
                    // rustfmt puts the brace on its own line. The `SELF` form is short and keeps
                    // the brace where a reader expects it. Both were taken from rustfmt's output.
                    let guard = match &arg.constraint {
                        RenderConstraint::EqSelf => {
                            "            if *smart_account != a {\n".to_string()
                        }
                        RenderConstraint::EqAddress(address) => format!(
                            "            if a != Address::from_str(e, \"{address}\")\n            {{\n"
                        ),
                        _ => unreachable!("guarded by the outer arm"),
                    };
                    helpers.push_str(&format!(
                        "    match Address::try_from_val(e, &v{i}) {{\n        Ok(a) => {{\n{guard}                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                RenderConstraint::EqI128(lit) => {
                    helpers.push_str(&format!(
                        "    match i128::try_from_val(e, &v{i}) {{\n        Ok(x) => {{\n            if x != {lit} {{\n                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                RenderConstraint::LeI128(lit) => {
                    helpers.push_str(&format!(
                        "    match i128::try_from_val(e, &v{i}) {{\n        Ok(x) => {{\n            if x > {lit} {{\n                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                RenderConstraint::GeI128(lit) => {
                    helpers.push_str(&format!(
                        "    match i128::try_from_val(e, &v{i}) {{\n        Ok(x) => {{\n            if x < {lit} {{\n                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                // The bytes are a module constant (emitted above), so this line is short
                // whatever the recorded `ScVal` encodes to.
                RenderConstraint::EqScval(_) => {
                    helpers.push_str(&format!(
                        "    if v{i}.to_xdr(e) != Bytes::from_slice(e, &{}) {{\n        return false;\n    }}\n",
                        render::arg_xdr_name(ci, i)
                    ));
                }
                // Handled before the match (arity-only); listed for exhaustiveness.
                RenderConstraint::AnyValue => unreachable!("AnyValue handled before the match"),
            }
        }
        helpers.push_str("    true\n}\n\n");
    }

    helpers.push_str(emit_ttl_target(rule.valid_until_ledger.is_some()).trim_start_matches('\n'));

    out.push_str(&section("LOW-LEVEL HELPERS"));
    out.push_str(&helpers);

    (crate_root, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every emitted Rust file, joined for searching.
    ///
    /// Emission produces two source files — a crate root carrying the header and the module
    /// declaration, and `src/contract.rs` carrying the contract — so a test that read
    /// `files["src/lib.rs"]` would be asking about the header alone. Joined rather than picked
    /// apart because almost every assertion here is about *what was emitted* and not about which
    /// file it landed in; the few that care name the file directly, and anything that parses the
    /// source has to do so per file, since two sets of inner attributes cannot share one file.
    fn emitted_rust(generated: &GeneratedCrate) -> String {
        rust_files(generated)
            .into_iter()
            .map(|(_, body)| body)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The emitted Rust files in path order, as `(path, contents)`.
    fn rust_files(generated: &GeneratedCrate) -> Vec<(String, String)> {
        let files: Vec<(String, String)> = generated
            .files
            .iter()
            .filter(|(path, _)| path.ends_with(".rs"))
            .map(|(path, body)| (path.clone(), body.clone()))
            .collect();
        assert_eq!(
            files
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/contract.rs", "src/lib.rs"],
            "the emitted source file set changed; these helpers decide what every test reads"
        );
        files
    }

    /// Emission for `spec`, joined for searching. The shape most tests want.
    fn emitted_for(spec: &ValidatedSpec) -> String {
        emitted_rust(&generate(spec, 0, &Pins::default()).expect("the spec must generate"))
    }

    /// Every emitted file must parse as Rust — checked per file, because each carries its own
    /// inner attributes and two sets of them cannot share one parse.
    fn each_file_parses(generated: &GeneratedCrate) {
        for (path, body) in rust_files(generated) {
            syn::parse_file(&body)
                .unwrap_or_else(|error| panic!("generated {path} must parse: {error}\n{body}"));
        }
    }
    use ozpb_synthesizer::fixtures::{golden_delegate_strkey, golden_spec};

    // --- rendering safety (§4.4: untrusted values never reach source fragments) -----------

    #[test]
    fn a_render_literal_cannot_be_built_from_an_unvalidated_address() {
        for hostile in [
            "not a strkey",
            // The shape an injection would take if a raw string reached emission.
            "CABC\"; pub fn back_door() {} const X: &str = \"",
            "CABC\nconst Y: u32 = 0;",
            "",
        ] {
            assert!(
                render::Strkey::new(hostile).is_err(),
                "Strkey accepted {hostile:?}"
            );
        }
        assert!(render::Strkey::new(&golden_delegate_strkey()).is_ok());
    }

    #[test]
    fn a_render_literal_cannot_be_built_from_an_unvalidated_symbol() {
        for hostile in [
            "transfer\"); evil(e, \"",
            "transfer\n",
            "with space",
            "",
            // 33 characters: one past the Soroban symbol limit.
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                render::SymbolName::new(hostile).is_err(),
                "SymbolName accepted {hostile:?}"
            );
        }
        assert!(render::SymbolName::new("transfer").is_ok());
    }

    #[test]
    fn a_render_literal_cannot_be_built_from_a_noncanonical_i128() {
        for hostile in ["0x10", "007", "1 ", "+1", "1i128", "", "1_000"] {
            assert!(
                render::I128Literal::new(hostile).is_err(),
                "I128Literal accepted {hostile:?}"
            );
        }
        assert_eq!(
            render::I128Literal::new("-1").unwrap().to_string(),
            "-1i128"
        );
        // i128::MIN must stay the named constant: the positive literal overflows before the
        // unary minus applies, so the generated crate would not compile.
        assert_eq!(
            render::I128Literal::new(&i128::MIN.to_string())
                .unwrap()
                .to_string(),
            "i128::MIN"
        );
    }

    #[test]
    fn a_hostile_template_family_cannot_inject_header_lines_or_crate_attributes() {
        // `template_family` arrives on the *spec*, and generate_code/verify accept a
        // caller-supplied spec — the registry check that resolves a family runs only on the
        // synthesize path. It is emitted into the header comment, so a newline would open new
        // `//!` lines: enough to forge the limits a reviewer reads, or to inject a crate-root
        // attribute like `#![doc = include_str!(…)]` (an arbitrary-file read inside the
        // operator's build) or `#![cfg(any())]` (which strips the whole policy).
        for hostile in [
            "policy-templates/scope@1`.\n#![doc = include_str!(\"/etc/passwd\")]\n//! `",
            "scope@1\n//! LIMITS: caps transfers at 1 stroop",
            "scope@1\n#![cfg(any())]",
            "scope@1 with spaces",
            "",
            &"a".repeat(65),
        ] {
            assert!(
                render::TemplateFamily::new(hostile).is_err(),
                "TemplateFamily accepted {hostile:?}"
            );
        }
        assert!(render::TemplateFamily::new("policy-templates/scope@1").is_ok());

        // End to end: a spec carrying the hostile family must be refused, not rendered.
        let mut spec = golden_spec().spec().clone();
        for policy in &mut spec.rules[0].policies {
            if let PolicyRef::Generated {
                template_family, ..
            } = policy
            {
                *template_family = "scope@1\n#![cfg(any())]".to_string();
            }
        }
        let errors = spec.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.to_string().starts_with("E_SPEC_TEMPLATE_FAMILY:")),
            "hostile template metadata must be rejected at the typestate boundary: {errors:?}"
        );
    }

    #[test]
    fn only_contract_and_account_strkeys_are_accepted_as_addresses() {
        // A muxed or pre-auth strkey decodes cleanly but is not a Soroban `Address`; emitting
        // one produces a policy that deploys and then traps on every call.
        let muxed =
            stellar_strkey::Strkey::MuxedAccountEd25519(stellar_strkey::ed25519::MuxedAccount {
                ed25519: [7u8; 32],
                id: 1,
            })
            .to_string();
        let pre_auth =
            stellar_strkey::Strkey::PreAuthTx(stellar_strkey::PreAuthTx([7u8; 32])).to_string();
        for rejected in [&muxed, &pre_auth] {
            assert!(
                render::Strkey::new(rejected).is_err(),
                "accepted a non-Address strkey: {rejected}"
            );
        }
        assert!(render::Strkey::new(&golden_delegate_strkey()).is_ok());
        assert!(render::Strkey::new(&ozpb_synthesizer::fixtures::golden_token_strkey()).is_ok());
    }

    #[test]
    fn every_string_literal_in_generated_source_is_a_bare_identifier_or_strkey() {
        // Tripwire: the only quoted values in an emitted policy are strkeys and symbols.
        // Anything containing a quote, newline, space, or punctuation means an untrusted
        // value escaped its literal — the injection this design exists to prevent.
        for (label, spec) in [
            ("W2 subscription", golden_spec()),
            (
                "W3 soroswap",
                ozpb_synthesizer::walkthroughs::soroswap_swap_spec(),
            ),
            (
                "W1 blend",
                ozpb_synthesizer::walkthroughs::blend_claim_spec(),
            ),
        ] {
            let source = emitted_for(&spec);
            let mut rest = source.as_str();
            let mut literals = 0usize;
            while let Some(open) = rest.find('"') {
                rest = &rest[open + 1..];
                let close = rest
                    .find('"')
                    .unwrap_or_else(|| panic!("{label}: unterminated string literal"));
                let content = &rest[..close];
                assert!(
                    content
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "{label}: emitted string literal {content:?} is not a bare \
                     identifier/strkey; an untrusted value escaped its literal"
                );
                literals += 1;
                rest = &rest[close + 1..];
            }
            // Non-vacuity: every policy embeds at least TARGET and one function symbol.
            assert!(
                literals >= 2,
                "{label}: found only {literals} string literals, so the scan proved nothing"
            );
        }
    }

    // --- "always compilable" as a property (§4.4; the RFP's compilable-contracts claim) ----
    //
    // The invariant these assert: *any* ValidatedSpec generates Rust that parses. The golden
    // files pin two known shapes; this covers the constraint/predicate/state space around
    // them. The strategies below are the repo's first — they are deliberately scoped to the
    // fields that influence emitted bytes (§4.4 normalized codegen input), because nothing
    // else can affect compilability.
    mod compilability {
        use super::*;
        use ozpb_domain::{BlastRadius, LedgerSeq, Provenance};
        use ozpb_policy_spec::{
            AddressRef, AllowedCall, ArgConstraint, Constraint, PredicateKind, SignerSpec,
            StateSpec, ValidUntil, MAX_ARGS_PER_CALL, MAX_CALLS_PER_RULE, MAX_SIGNERS_PER_RULE,
        };
        use proptest::prelude::Strategy;
        use proptest::strategy::Just;
        use stellar_xdr::{Limits, ScBytes, ScVal, WriteXdr};

        fn scval_b64(value: ScVal) -> String {
            value.to_xdr_base64(Limits::none()).unwrap()
        }

        /// A widening constraint with `ObservedExact` provenance is rejected by spec
        /// validation, so provenance is derived from the constraint rather than generated.
        fn provenance_for(constraint: &Constraint) -> Provenance {
            if constraint.is_widening() {
                Provenance::UserWidened {
                    intent: "property-test widening".to_string(),
                    // AnyValue is the maximal widening: validation holds it to the
                    // high-blast-radius acknowledgement its schema contract states.
                    blast_radius: if matches!(constraint, Constraint::AnyValue) {
                        BlastRadius::High
                    } else {
                        BlastRadius::Medium
                    },
                }
            } else {
                Provenance::ObservedExact
            }
        }

        fn constraint_strategy() -> impl Strategy<Value = Constraint> {
            // Real strkeys: codegen decodes them (checksum included), unlike the evaluator.
            let addresses = vec![
                ozpb_synthesizer::fixtures::golden_merchant_strkey(),
                ozpb_synthesizer::fixtures::golden_token_strkey(),
                golden_delegate_strkey(),
            ];
            // Boundary i128 values are included on purpose: i128::MIN must render as the
            // named constant or the generated crate will not compile.
            let numbers = vec![
                "0".to_string(),
                "-1".to_string(),
                "500000000".to_string(),
                i128::MAX.to_string(),
                i128::MIN.to_string(),
            ];
            proptest::prop_oneof![
                Just(Constraint::EqAddress {
                    value: AddressRef::self_account()
                }),
                proptest::sample::select(addresses).prop_map(|a| Constraint::EqAddress {
                    value: AddressRef::address(a)
                }),
                proptest::sample::select(numbers.clone())
                    .prop_map(|value| Constraint::EqI128 { value }),
                proptest::sample::select(numbers.clone())
                    .prop_map(|max| Constraint::LeI128 { max }),
                proptest::sample::select(numbers).prop_map(|min| Constraint::GeI128 { min }),
                proptest::sample::select(vec![
                    scval_b64(ScVal::U32(0)),
                    scval_b64(ScVal::U64(u64::MAX)),
                    scval_b64(ScVal::Bytes(ScBytes(vec![0xabu8; 24].try_into().unwrap()))),
                ])
                .prop_map(|xdr_base64| Constraint::EqScval { xdr_base64 }),
                Just(Constraint::AnyValue),
            ]
        }

        fn call_strategy() -> impl Strategy<Value = AllowedCall> {
            // Enough distinct names that a rule can reach MAX_CALLS_PER_RULE *unique* ones:
            // the emitted known-function check grows with the number of distinct names, so a
            // pool smaller than the call bound would cap the very dimension the corpus is
            // widened to explore. Collisions still happen constantly (up to 32 draws from 36
            // names), so the emitter's name dedup keeps being exercised too.
            let mut names = vec![
                "transfer".to_string(),
                "swap".to_string(),
                "claim_rewards".to_string(),
                // Boundary: the longest symbol Soroban accepts.
                "a".repeat(32),
            ];
            names.extend((0..MAX_CALLS_PER_RULE).map(|i| format!("f{i}")));
            (
                proptest::sample::select(names),
                // The full declared range here too (MAX_ARGS_PER_CALL is 32): argument
                // indices reach two digits at 10, which widens every index-bearing line.
                // Both bounds together cost the property test about 14 seconds instead of
                // 7 — measured, and paid, because a corpus that stops short of the domain
                // it quantifies over is how the 32-call corner went unvisited before.
                proptest::collection::vec(constraint_strategy(), 0..=MAX_ARGS_PER_CALL),
            )
                .prop_map(|(fn_name, constraints)| AllowedCall {
                    fn_name,
                    args: constraints
                        .into_iter()
                        .enumerate()
                        .map(|(index, constraint)| ArgConstraint {
                            index: index as u32,
                            provenance: provenance_for(&constraint),
                            constraint,
                        })
                        .collect(),
                    justified_by: vec!["recordings[0]/auth[0]/root".to_string()],
                })
        }

        fn predicate_strategy() -> impl Strategy<Value = (PredicateKind, bool)> {
            proptest::prop_oneof![
                Just((PredicateKind::AnyOf, true)),
                Just((PredicateKind::AnyOf, false)),
                Just((PredicateKind::AllOf, true)),
                Just((PredicateKind::Threshold { n: 1 }, true)),
                Just((PredicateKind::Threshold { n: 2 }, true)),
                // Dynamic predicate: no expected-signer set is compiled in.
                Just((PredicateKind::AnyOfCurrentRuleSigners, false)),
            ]
        }

        /// Build a spec by replacing only the wasm-relevant fields of the fixture rule.
        pub(super) fn spec_with(
            calls: Vec<AllowedCall>,
            predicate: (PredicateKind, bool),
            valid_until: Option<u32>,
            max_calls: Option<u32>,
            extra_signer: bool,
        ) -> Option<ozpb_policy_spec::ValidatedSpec> {
            // Based on the synthesizer's golden spec because its addresses are real
            // strkeys; `policy_spec::fixtures` carries evaluator placeholders that codegen
            // (correctly) refuses to embed.
            let mut spec = golden_spec().spec().clone();
            let rule = spec.rules.get_mut(0)?;
            rule.allowed_calls = calls;
            rule.authorization.kind = predicate.0;
            rule.authorization.strict_signer_set = predicate.1;
            if extra_signer {
                rule.authorization.signers.push(SignerSpec::Delegated {
                    address: ozpb_synthesizer::fixtures::golden_merchant_strkey(),
                });
            }
            rule.valid_until = valid_until.map(|ledger| ValidUntil {
                ledger: LedgerSeq(ledger),
                approx_time: None,
            });
            rule.state = match max_calls {
                Some(max_calls) => vec![StateSpec::CallCountPerInstallation { max_calls }],
                None => vec![],
            };
            spec.validate().ok()
        }

        /// The storage-lifetime emission across all four shapes of rule.
        ///
        /// Only the golden (state + validity window) reaches the soroban-environment tests, and
        /// the proptest above only checks that output parses — so without this the other three
        /// variants are emitted but never inspected.
        #[test]
        fn ttl_emission_matches_the_shape_of_the_rule() {
            let calls = golden_spec().spec().rules[0].allowed_calls.clone();
            for (valid_until, max_calls) in [
                (Some(4_223_456u32), Some(12u32)),
                (None, Some(12u32)),
                (Some(4_223_456u32), None),
                (None, None),
            ] {
                let label = format!("valid_until={valid_until:?} max_calls={max_calls:?}");
                let spec = spec_with(
                    calls.clone(),
                    (PredicateKind::AnyOf, true),
                    valid_until,
                    max_calls,
                    false,
                )
                .unwrap_or_else(|| panic!("spec must validate for {label}"));
                let source = emitted_rust(
                    &generate(&spec, 0, &Pins::default())
                        .unwrap_or_else(|e| panic!("codegen refused {label}: {e}")),
                );

                // The window clamp is emitted only when there is a window to clamp to.
                assert_eq!(
                    source.contains("VALID_UNTIL_LEDGER.saturating_sub"),
                    valid_until.is_some(),
                    "validity clamp does not match the rule shape for {label}"
                );
                // The cap gate is emitted only when there is a cap to spend.
                assert_eq!(
                    source.contains("if remaining > 0u32"),
                    max_calls.is_some(),
                    "cap gate does not match the rule shape for {label}"
                );
                // The lifecycle marker is persistent in every shape; the counter is additional
                // state only when a call cap exists.
                assert_eq!(
                    source.contains("extend_ttl(&key"),
                    max_calls.is_some(),
                    "counter extension does not match the rule shape for {label}"
                );
                assert!(
                    source.contains("extend_ttl(&installed_key"),
                    "installation marker extension missing for {label}"
                );
                // Instance and code are extended in every shape: archival of those makes the
                // contract unreachable whether or not it keeps state.
                assert!(
                    source.contains("instance().extend_ttl("),
                    "instance/code extension missing for {label}"
                );
                // `uninstall` never extends.
                let uninstall = source
                    .split_once("fn uninstall(")
                    .expect("an uninstall entry point")
                    .1;
                let uninstall_body = uninstall.split_once("\n    }").expect("a body").0;
                assert!(
                    !uninstall_body.contains("extend_ttl"),
                    "uninstall extends a TTL for {label}"
                );
                // Rent bookkeeping sits after the permission logic, so a reader meets the
                // permissions first.
                let ttl_target_at = source.find("fn ttl_target").expect("a ttl_target helper");
                let uninstall_at = source
                    .find("fn uninstall(")
                    .expect("an uninstall entry point");
                assert!(
                    ttl_target_at > uninstall_at,
                    "ttl_target is emitted before uninstall for {label}, putting rent \
                     arithmetic ahead of the permission checks"
                );
            }
        }

        #[test]
        fn stateless_no_expiry_rule_still_has_strict_install_lifecycle() {
            let calls = golden_spec().spec().rules[0].allowed_calls.clone();
            let spec = spec_with(calls, (PredicateKind::AnyOf, true), None, None, false)
                .expect("stateless no-expiry rule validates");
            let source = emitted_for(&spec);

            assert!(source.contains("Installed(Address, u32)"));
            assert!(!source.contains("CallCount(Address, u32)"));
            assert!(!source.contains("VALID_UNTIL_LEDGER"));
            assert!(source.contains("PolicyError::AlreadyInstalled"));
            assert!(source.contains("PolicyError::NotInstalled"));
            assert!(source.contains("remove(&installed_key)"));
            assert!(source.contains("extend_ttl(&installed_key"));
        }

        proptest::proptest! {
            /// Every ValidatedSpec must emit Rust that parses. Parsing (rather than
            /// compiling) keeps this fast enough for CI; `sampled_specs_compile_to_wasm`
            /// covers the real toolchain.
            #[test]
            fn any_validated_spec_generates_parseable_rust(
                // The full declared range: the spec admits MAX_CALLS_PER_RULE allowed calls,
                // and the corpus used to stop at three — below the point (nine unique names)
                // where the emitted known-function check outgrows rustfmt's width, so the
                // property read as proven over a domain it never reached.
                calls in proptest::collection::vec(call_strategy(), 1..=MAX_CALLS_PER_RULE),
                predicate in predicate_strategy(),
                valid_until in proptest::option::of(0u32..u32::MAX),
                max_calls in proptest::option::of(0u32..u32::MAX),
                extra_signer in proptest::prelude::any::<bool>(),
            ) {
                let Some(spec) = spec_with(calls, predicate, valid_until, max_calls, extra_signer)
                else {
                    // Some combinations are legitimately rejected by spec validation (e.g. a
                    // threshold above the signer count); those never reach codegen.
                    return Ok(());
                };
                let generated = generate(&spec, 0, &Pins::default())
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(
                        format!("codegen refused a ValidatedSpec: {e}")
                    ))?;
                // Per file: two sets of inner attributes cannot share one parse, so the crate
                // root and the contract module are checked separately rather than joined.
                for (path, source) in rust_files(&generated) {
                    syn::parse_file(&source).map_err(|e| {
                        proptest::test_runner::TestCaseError::fail(format!(
                            "generated {path} does not parse as Rust: {e}\n--- source ---\n{source}"
                        ))
                    })?;
                    let wide = overlong_lines(&source);
                    if !wide.is_empty() {
                        return Err(proptest::test_runner::TestCaseError::fail(format!(
                            "generated {path} has lines rustfmt would reflow: {wide:?}\
                             \n--- source ---\n{source}"
                        )));
                    }
                }
                let source = &emitted_rust(&generated);
                let unbalanced = unbalanced_constants(source);
                if !unbalanced.is_empty() {
                    return Err(proptest::test_runner::TestCaseError::fail(format!(
                        "compiled-in constants do not balance: {unbalanced:?}\
                         \n--- source ---\n{source}"
                    )));
                }
            }
        }

        /// Constants the emitted source declares but never reads, and constants it reads but
        /// never declares. Both are empty in a correct emission, and each failure mode is real:
        /// the first is a dead-code warning in a shipped crate, the second does not compile.
        ///
        /// This exists because the two sides are produced by different code — `render_*_const`
        /// writes the declaration, `render::*_name` the reference — and a compiled-in constant's
        /// name and its emission condition were each, at one point, decided in two places. The
        /// shapes the committed crates contain are caught by a real compile; the shapes they do
        /// not contain (a dynamic predicate, which must hoist no constant at all) are caught
        /// here, alongside the proptest corpus.
        fn unbalanced_constants(source: &str) -> Vec<String> {
            use std::collections::BTreeSet;
            // A set because the reference direction below asks membership once per distinct
            // token, and a maximal spec declares up to a constant per (call, argument) pair
            // — about a thousand names for a linear scan to walk per lookup. Ordered, so
            // the reported problems keep their deterministic order.
            let declared: BTreeSet<&str> = source
                .lines()
                .filter_map(|line| line.strip_prefix("const "))
                .filter_map(|rest| rest.split(':').next())
                .collect();
            // What counts as a read is an identifier *token* in code: substring counting
            // would credit a declared name with occurrences inside any longer identifier,
            // and text in a comment or a string literal was never a read at all. Comments
            // are dropped by line prefix (every comment the emitter produces is a whole
            // line); literals are dropped by keeping only the even-numbered segments
            // between quotes, which is exact for this grammar because
            // `every_string_literal_in_generated_source_is_a_bare_identifier_or_strkey`
            // pins emitted literals to one quote-free, backslash-free line. The literal
            // case is reachable, not theoretical: `TARGET` is a valid Soroban symbol, so a
            // rule may allow a function of that name and emit `Symbol::new(e, "TARGET")`.
            // Today's names happen to make substring and token counts agree — the
            // `_XDR`/`_KEY` suffix follows the index, so no emitted name nests in another —
            // but the checker must not lean on the naming scheme it exists to check.
            // Counted once into a map, so each direction below is a lookup rather than a
            // scan over every token per name — the boundary-sized sources this now runs on
            // hold a few thousand tokens. A BTreeMap, not a HashMap: `clippy.toml` bans
            // HashMap across both workspaces, and a test helper is not the place to start
            // depending on per-process iteration order.
            let mut token_counts: BTreeMap<&str, usize> = BTreeMap::new();
            let tokens = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .flat_map(|line| line.split('"').step_by(2))
                .flat_map(|code| code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')))
                .filter(|token| !token.is_empty());
            for token in tokens {
                *token_counts.entry(token).or_insert(0) += 1;
            }
            let mut problems = Vec::new();
            for name in &declared {
                // Once for the declaration; a read is any further occurrence.
                if token_counts.get(name).copied().unwrap_or(0) < 2 {
                    problems.push(format!("`{name}` is declared and never read"));
                }
            }
            // The generated names, wherever they appear. Anything matching that is not declared
            // is a reference emission failed to back with a constant.
            for token in token_counts.keys() {
                let generated = token.starts_with("SIGNER_") || token.starts_with("CALL_");
                if generated && !declared.contains(token) {
                    problems.push(format!("`{token}` is read and never declared"));
                }
            }
            problems.sort();
            problems.dedup();
            problems
        }

        /// The balance check counts identifier tokens, not substrings or prose.
        ///
        /// Counting with `source.matches(name)` credits a declared name with every occurrence
        /// of its text, including inside a *longer* identifier and inside comments. No two
        /// names the emitter produces today can nest — the `_XDR`/`_KEY` suffix follows the
        /// index, so ten-and-up argument indices do not contain their one-digit neighbours —
        /// but that is an accident of the suffix position, and this checker exists to catch
        /// precisely the renames that would not preserve such accidents. Both directions the
        /// accident could break are constructed here; substring counting is silent on each.
        #[test]
        fn unbalanced_constants_counts_identifier_tokens_not_substrings() {
            // Keep the "cannot nest today" claim checked where it is relied on.
            assert!(!"CALL_0_ARG_10_XDR".contains("CALL_0_ARG_1_XDR"));
            assert!(!"SIGNER_10_KEY".contains("SIGNER_1_KEY"));

            // Eleven arguments under index-*last* names — the shape `arg_xdr_name` would
            // produce if the suffix moved ahead of the index. The first argument's constant
            // is declared and its read has been lost; every declaration and read of the
            // eleventh contains the dead name as a prefix, so `source.matches` counts them
            // as its reads and reports nothing.
            let mut source = String::new();
            for i in 0..11 {
                source.push_str(&format!("const CALL_0_XDR_ARG_{i}: [u8; 1] = [0x00];\n"));
            }
            source.push_str("fn check_call_0(e: &Env, args: &Vec<Val>) -> bool {\n");
            for i in (0..11).filter(|i| *i != 1) {
                source.push_str(&format!(
                    "    if v.to_xdr(e) != Bytes::from_slice(e, &CALL_0_XDR_ARG_{i}) {{\n        \
                     return false;\n    }}\n"
                ));
            }
            source.push_str("    true\n}\n");
            assert_eq!(
                unbalanced_constants(&source),
                vec!["`CALL_0_XDR_ARG_1` is declared and never read".to_string()],
                "a dead constant whose name prefixes a live one's must still be reported"
            );

            // Prose is not a read: a doc comment naming a constant — as the emitted
            // `ttl_target` comment names VALID_UNTIL_LEDGER — must not keep it alive.
            let commented = "const SIGNER_0_KEY: [u8; 1] = [0x00];\n\
                             // SIGNER_0_KEY is compared against the caller's key.\n";
            assert_eq!(
                unbalanced_constants(commented),
                vec!["`SIGNER_0_KEY` is declared and never read".to_string()],
                "a constant read only by its own documentation is dead code"
            );

            // A string literal is not a read either, and the collision is reachable:
            // `TARGET` is a valid Soroban symbol, so a spec may name a function after the
            // constant, and the emitted `Symbol::new(e, "TARGET")` must not keep a constant
            // alive whose real read has been lost…
            let quoted = "const TARGET: &str = \"CAAAA\";\n\
                          let fn_0_ok = c.fn_name == Symbol::new(e, \"TARGET\");\n";
            assert_eq!(
                unbalanced_constants(quoted),
                vec!["`TARGET` is declared and never read".to_string()],
                "a constant whose name appears only inside a string literal is dead code"
            );
            // …nor may a symbol that merely *looks* like a generated constant name conjure
            // up a read of something never declared.
            let shaped = "let fn_0_ok = c.fn_name == Symbol::new(e, \"CALL_0_ARG_0_XDR\");\n";
            assert_eq!(
                unbalanced_constants(shaped),
                Vec::<String>::new(),
                "a quoted symbol shaped like a constant name is not a read of one"
            );
        }

        /// Lines rustfmt would have to reflow, as `(line, columns)`.
        ///
        /// Both widths are read from `render`, the module emission derives its layout from. A
        /// second copy of either number here would let the two drift, and the drift would show up
        /// as a passing test over source `cargo fmt --check` rejects.
        ///
        /// Comments are **included** now, because the shipped `rustfmt.toml` sets
        /// `wrap_comments = true`. Their budget is not `max_width`, and it is not one number
        /// either: [`render::comment_is_overlong`] holds both rules, and this reads it rather than
        /// restating them, so the emitter and the test cannot disagree about where a comment ends.
        /// The reported column count is always the whole line, whichever budget rejected it.
        ///
        /// This closes the hole that made the previous exclusion necessary: the header carries a
        /// template-family identifier and a 64-character digest, neither of whose width is ours
        /// to choose, and the answer is now that the emitter wraps them rather than that the test
        /// looks away. Every over-wide comment in a paragraph pulls the whole paragraph into a
        /// re-flow, so the condition is exact rather than approximate: nothing over the budget
        /// means nothing to re-flow, and rustfmt never joins lines it does not have to.
        pub(super) fn overlong_lines(source: &str) -> Vec<(usize, usize)> {
            source
                .lines()
                .enumerate()
                .filter(|(_, line)| {
                    if line.trim_start().starts_with("//") {
                        render::comment_is_overlong(line)
                    } else {
                        line.chars().count() > render::MAX_WIDTH
                    }
                })
                .map(|(index, line)| (index + 1, line.chars().count()))
                .collect()
        }

        /// Emission keeps every line inside the widths the shipped `rustfmt.toml` enforces.
        ///
        /// That is what makes the generated crates `cargo fmt --check`-clean without running
        /// rustfmt over codegen's output, which would put the rustfmt version among the inputs
        /// to every shipped wasm hash. The fmt gate adjudicates whichever crates a milestone
        /// commits; this
        /// covers the shapes they do not contain, choosing the awkward ones deliberately: the
        /// longest symbol Soroban accepts, an `ScVal` long enough to wrap, and more than one
        /// allowed call.
        #[test]
        fn emitted_code_stays_inside_rustfmt_width() {
            let long_scval = Constraint::EqScval {
                xdr_base64: scval_b64(ScVal::Bytes(ScBytes(vec![0xabu8; 40].try_into().unwrap()))),
            };
            let merchant = Constraint::EqAddress {
                value: AddressRef::address(ozpb_synthesizer::fixtures::golden_merchant_strkey()),
            };
            let justified = vec!["recordings[0]/auth[0]/root".to_string()];
            let mut spec = golden_spec().spec().clone();
            let rule = &mut spec.rules[0];
            rule.policies
                .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
            rule.allowed_calls = vec![
                AllowedCall {
                    // The longest symbol Soroban accepts: the shape that used to decide how
                    // rustfmt broke the `tuple_ok` line.
                    fn_name: "a".repeat(32),
                    args: vec![
                        ArgConstraint {
                            index: 0,
                            provenance: provenance_for(&long_scval),
                            constraint: long_scval,
                        },
                        ArgConstraint {
                            index: 1,
                            provenance: provenance_for(&merchant),
                            constraint: merchant,
                        },
                    ],
                    justified_by: justified.clone(),
                },
                AllowedCall {
                    fn_name: "transfer".to_string(),
                    args: vec![],
                    justified_by: justified,
                },
            ];
            let spec = spec.validate().expect("the awkward spec must validate");
            let source = emitted_rust(
                &generate(&spec, 0, &Pins::default())
                    .expect("codegen must accept the awkward spec"),
            );

            // Non-vacuity: a pass means nothing unless the awkward shapes are really emitted.
            for expected in ["const CALL_0_ARG_0_XDR: [u8; 48] = [", "let fn_1_ok = "] {
                assert!(
                    source.contains(expected),
                    "this test does not exercise what it claims: no {expected:?} in\n{source}"
                );
            }

            let wide = overlong_lines(&source);
            assert!(
                wide.is_empty(),
                "emitted lines rustfmt would reflow (line, columns): {wide:?}\n{source}"
            );
            // This spec carries both kinds of hoisted constant, so it is where a declaration and
            // a reference built by different code would show up as disagreeing.
            let unbalanced = unbalanced_constants(&source);
            assert!(
                unbalanced.is_empty(),
                "compiled-in constants do not balance: {unbalanced:?}\n{source}"
            );
        }

        #[test]
        fn maximum_rule_shape_stays_within_the_builder_input_limit() {
            let large_scval = scval_b64(ScVal::Bytes(ScBytes(
                vec![0xabu8; 60 * 1024].try_into().unwrap(),
            )));
            let mut spec = golden_spec().spec().clone();
            let rule = &mut spec.rules[0];
            rule.policies
                .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
            rule.allowed_calls = (0..ozpb_policy_spec::MAX_CALLS_PER_RULE)
                .map(|call_index| AllowedCall {
                    fn_name: format!("f_{call_index:02}"),
                    args: (0..ozpb_policy_spec::MAX_ARGS_PER_CALL)
                        .map(|arg_index| {
                            let constraint = if call_index == 0 && arg_index < 4 {
                                Constraint::EqScval {
                                    xdr_base64: large_scval.clone(),
                                }
                            } else {
                                Constraint::EqI128 {
                                    value: "0".to_string(),
                                }
                            };
                            ArgConstraint {
                                index: arg_index as u32,
                                provenance: Provenance::ObservedExact,
                                constraint,
                            }
                        })
                        .collect(),
                    justified_by: vec!["recordings[0]/auth[0]/root".to_string()],
                })
                .collect();

            let validated = spec
                .validate()
                .expect("the published maximum per-rule collection shape must validate");
            let generated = generate(&validated, 0, &Pins::default())
                .expect("the maximum accepted rule must fit the builder input boundary");
            let bytes: usize = generated.files.values().map(String::len).sum();
            assert!(
                bytes <= MAX_GENERATED_CRATE_BYTES,
                "generated {bytes} bytes"
            );
        }

        /// Emission stays rustfmt-clean at the largest spec validation admits.
        ///
        /// The property test samples the interior of the space; this pins its far corner
        /// deterministically: MAX_CALLS_PER_RULE allowed calls carrying that many *unique*
        /// function names, one call at MAX_ARGS_PER_CALL constraints, and the rule at
        /// MAX_SIGNERS_PER_RULE signers. The known-function check is the one statement that
        /// grows with every unique name — 32 of them joined on a single line reach 386
        /// columns — so this corner is where "generated source is rustfmt-clean" was
        /// contradicted while the corpus stopped at three calls.
        #[test]
        fn emitted_code_stays_inside_rustfmt_width_at_the_spec_size_boundary() {
            let justified = vec!["recordings[0]/auth[0]/root".to_string()];
            let mut calls: Vec<AllowedCall> = (0..MAX_CALLS_PER_RULE)
                .map(|i| AllowedCall {
                    fn_name: format!("f{i}"),
                    args: vec![],
                    justified_by: justified.clone(),
                })
                .collect();
            // The longest symbol Soroban accepts, on the call that also carries the full
            // argument load.
            calls[0].fn_name = "a".repeat(32);
            calls[0].args = (0..MAX_ARGS_PER_CALL as u32)
                .map(|i| {
                    let constraint = match i {
                        // One- and two-digit XDR constants side by side: CALL_0_ARG_1_XDR
                        // and CALL_0_ARG_10_XDR are the adjacent names the constant-balance
                        // check must tell apart. A canonical 40-byte ScVal::Bytes encodes to
                        // 48 XDR bytes — wide enough to force the wrapped array layout.
                        1 | 10 => Constraint::EqScval {
                            xdr_base64: scval_b64(ScVal::Bytes(ScBytes(
                                vec![0xabu8; 40].try_into().unwrap(),
                            ))),
                        },
                        2 => Constraint::EqAddress {
                            value: AddressRef::self_account(),
                        },
                        3 => Constraint::EqAddress {
                            value: AddressRef::address(
                                ozpb_synthesizer::fixtures::golden_merchant_strkey(),
                            ),
                        },
                        // The i128 boundaries, and a bound on the last argument index so a
                        // two-digit `v31` binding is emitted (AnyValue binds nothing).
                        4 => Constraint::EqI128 {
                            value: i128::MIN.to_string(),
                        },
                        5 => Constraint::LeI128 {
                            max: i128::MAX.to_string(),
                        },
                        6 | 31 => Constraint::GeI128 {
                            min: "-1".to_string(),
                        },
                        _ => Constraint::AnyValue,
                    };
                    ArgConstraint {
                        index: i,
                        provenance: provenance_for(&constraint),
                        constraint,
                    }
                })
                .collect();

            let mut spec = golden_spec().spec().clone();
            let rule = &mut spec.rules[0];
            // The fixture composes oz:spending_limit, which F-06 validation ties to a SEP-41
            // transfer shape; this rule's calls are f0..f31, so the reviewed policy goes.
            rule.policies
                .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
            rule.allowed_calls = calls;
            // Fill the signer set to its bound. Delegated, not External: since the F-01
            // hardening a validated spec cannot carry external signers, so the bound is
            // exercised with minted, pairwise-distinct delegated addresses instead.
            while rule.authorization.signers.len() < MAX_SIGNERS_PER_RULE {
                let n = rule.authorization.signers.len() as u8;
                rule.authorization.signers.push(SignerSpec::Delegated {
                    // format!: the crate's inherent `to_string` returns its heapless string.
                    address: format!("{}", stellar_strkey::ed25519::PublicKey([n | 0x80; 32])),
                });
            }
            let spec = spec
                .validate()
                .expect("the spec-size boundary is a valid spec");
            let generated = generate(&spec, 0, &Pins::default())
                .expect("codegen must accept the boundary spec");
            let source = emitted_rust(&generated);

            // Non-vacuity: every bound must actually be reached in the emitted source.
            for expected in [
                // 32 allowed calls under 32 unique names.
                "let fn_31_ok = ",
                "fn check_call_31(",
                // One call at the argument bound, with two-digit indices in play.
                "if args.len() != 32u32 {",
                "let Some(v31) = args.get(31u32)",
                "if args.get(30u32).is_none()",
                "const CALL_0_ARG_1_XDR: [u8; 48]",
                "const CALL_0_ARG_10_XDR: [u8; 48]",
            ] {
                assert!(
                    source.contains(expected),
                    "this test does not exercise what it claims: no {expected:?} in\n{source}"
                );
            }

            // The signer set at its bound: the last minted delegated address must be
            // compiled in. (The SIGNER_<i>_KEY constant family is external-only and external
            // signers are rejected at validation, so it cannot appear via a validated spec;
            // the two-digit-adjacency concern is carried by CALL_0_ARG_1/10_XDR above.)
            let last_signer = format!(
                "{}",
                stellar_strkey::ed25519::PublicKey([(MAX_SIGNERS_PER_RULE - 1) as u8 | 0x80; 32])
            );
            assert!(
                source.contains(&last_signer),
                "this test does not exercise the signer bound: no {last_signer} in\n{source}"
            );

            let wide = overlong_lines(&source);
            assert!(
                wide.is_empty(),
                "emitted lines rustfmt would reflow (line, columns): {wide:?}\n{source}"
            );
            // Width alone under-approximates "rustfmt-clean": rustfmt does not *tolerate*
            // within-width layouts of an over-wide `||` chain, it rewrites to exactly one —
            // each operand on its own line, block-indented, brace on its own line (verified
            // against the pinned toolchain's rustfmt). Pin that form so a within-width
            // variant rustfmt would still reflow cannot pass.
            let canonical_break = "        if !(fn_0_ok\n            || fn_1_ok\n";
            let canonical_close = "\n            || fn_31_ok)\n        {\n            \
                                   panic_with_error!(e, PolicyError::FunctionNotAllowed);\n        }\n";
            for expected in [canonical_break, canonical_close] {
                assert!(
                    source.contains(expected),
                    "the known-function check is not rustfmt's canonical multiline form \
                     (expected {expected:?}):\n{source}"
                );
            }

            each_file_parses(&generated);
            let unbalanced = unbalanced_constants(&source);
            assert!(
                unbalanced.is_empty(),
                "compiled-in constants do not balance: {unbalanced:?}\n{source}"
            );
        }

        /// A dynamic predicate carrying named signers compiles none of them into the artifact.
        ///
        /// The rule's list is irrelevant for this predicate: runtime `context_rule.signers` are
        /// authoritative. Get it wrong and the generated crate carries constants/imports with no
        /// use or, worse, silently narrows the dynamic rule to a stale compiled list.
        #[test]
        fn a_dynamic_predicate_compiles_in_no_signer_even_when_the_rule_carries_one() {
            let mut spec = golden_spec().spec().clone();
            let rule = &mut spec.rules[0];
            rule.authorization.kind = PredicateKind::AnyOfCurrentRuleSigners;
            // Dynamic rules may not be strict; spec validation rejects the pair.
            rule.authorization.strict_signer_set = false;
            rule.authorization.signers.push(SignerSpec::Delegated {
                address: ozpb_synthesizer::fixtures::golden_merchant_strkey(),
            });
            let signer_count = rule.authorization.signers.len();
            let spec = spec
                .validate()
                .expect("a dynamic rule carrying signers is a valid spec");
            // Non-vacuity: the point is that the rule *does* carry named signers.
            assert_eq!(
                signer_count, 2,
                "the rule must carry the signers under test"
            );

            let generated = generate(&spec, 0, &Pins::default())
                .expect("codegen must accept a dynamic rule carrying named signers");
            each_file_parses(&generated);
            let source = emitted_rust(&generated);
            for absent in [
                "SIGNER_",
                "expected_signers",
                // The only use of `Bytes` in this shape would have been the key.
                "Bytes",
            ] {
                assert!(
                    !source.contains(absent),
                    "a dynamic predicate compiles in no signer, so {absent:?} has no use here:\
                     \n{source}"
                );
            }
            assert!(
                unbalanced_constants(&source).is_empty(),
                "no constant is declared or read in this shape:\n{source}"
            );
            // What it reads instead.
            assert!(
                source.contains("matched_count(&authenticated_signers, &context_rule.signers)"),
                "a dynamic predicate must be evaluated against the rule's live signers:\n{source}"
            );
        }

        /// The real-compile counterpart lives in `ozpb-build-runner`
        /// (`boundary_specs_compile_to_wasm`): codegen cannot dev-depend on build-runner
        /// without duplicating its own types, since build-runner depends on codegen.
        const _REAL_COMPILE_LIVES_IN_BUILD_RUNNER: () = ();
    }

    #[test]
    fn generation_is_byte_deterministic() {
        let spec = golden_spec();
        let a = generate(&spec, 0, &Pins::default()).unwrap();
        let b = generate(&spec, 0, &Pins::default()).unwrap();
        assert_eq!(a, b);
        assert_eq!(emitted_rust(&a), emitted_rust(&b));
    }

    #[test]
    fn normalized_hash_ignores_non_code_fields() {
        // Two specs differing only in evidence/name/account metadata must produce the
        // same wasm-relevant bytes (§4.4 normalized codegen input).
        let base = golden_spec();
        let mut renamed = base.spec().clone();
        renamed.name = "other-name".to_string();
        renamed.registry_snapshot = ozpb_domain::sha256(b"different-snapshot");
        renamed.smart_account.address = format!("{}", stellar_strkey::Contract([9u8; 32]));
        let renamed = renamed.validate().unwrap();

        let a = generate(&base, 0, &Pins::default()).unwrap();
        let b = generate(&renamed, 0, &Pins::default()).unwrap();
        assert_eq!(a.normalized_input_hash, b.normalized_input_hash);
        assert_eq!(
            emitted_rust(&a),
            emitted_rust(&b),
            "lib.rs must be identical for identical constraint content"
        );
        assert_ne!(
            a.crate_name, b.crate_name,
            "crate name follows the grant name"
        );
    }

    #[test]
    fn normalized_hash_changes_with_constraints() {
        let base = golden_spec();
        let mut widened = base.spec().clone();
        widened.rules[0].allowed_calls[0].args[2].constraint =
            ozpb_policy_spec::Constraint::LeI128 {
                max: "1000000000".to_string(),
            };
        widened.rules[0].allowed_calls[0].args[2].provenance =
            ozpb_domain::Provenance::UserWidened {
                intent: "headroom".to_string(),
                blast_radius: ozpb_domain::BlastRadius::Medium,
            };
        let widened = widened.validate().unwrap();
        let a = generate(&base, 0, &Pins::default()).unwrap();
        let b = generate(&widened, 0, &Pins::default()).unwrap();
        assert_ne!(a.normalized_input_hash, b.normalized_input_hash);
        assert!(emitted_rust(&b).contains("if x > 1000000000i128"));
    }

    #[test]
    fn i128_min_emits_a_compilable_named_constant_not_an_overflowing_literal() {
        // i128::MIN passes spec validation (it is canonical decimal), but its positive
        // magnitude is i128::MAX + 1, so `-170...728i128` is NOT a legal Rust literal — the
        // positive part overflows before the unary minus applies. Codegen must emit the
        // named constant so the "a ValidatedSpec always generates compilable Rust" invariant
        // holds across the full i128 range (§4.4).
        let mut spec = golden_spec().spec().clone();
        spec.rules[0]
            .policies
            .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
        spec.rules[0].allowed_calls[0].args[2].constraint = ozpb_policy_spec::Constraint::EqI128 {
            value: i128::MIN.to_string(),
        };
        let spec = spec
            .validate()
            .expect("i128::MIN is a canonical, valid i128 constraint");
        let lib = emitted_for(&spec);
        assert!(
            lib.contains("if x != i128::MIN"),
            "i128::MIN must be emitted as the named constant, got:\n{lib}"
        );
        assert!(
            !lib.contains(&format!("{}i128", i128::MIN)),
            "the overflowing positive literal must never be emitted as a source token"
        );
    }

    /// The three lifecycle events are declared, published, and documented where they are emitted.
    ///
    /// Behaviour is the differential suite's job (`contracts/differential/tests/events.rs`);
    /// this is the shape, over every rule form, including the two the goldens do not cover.
    ///
    /// The `# Events` doc sections quote a topic symbol the `#[contractevent]` macro derives from
    /// the struct name, so nothing here can hold them to the artifact — the differential suite
    /// reads the published topics back and compares. What *is* checkable offline is that a
    /// function which publishes documents doing so, which is the direction that goes stale first.
    #[test]
    fn every_entry_point_declares_publishes_and_documents_its_event() {
        let calls = golden_spec().spec().rules[0].allowed_calls.clone();
        for (valid_until, max_calls) in [
            (Some(4_223_456u32), Some(12u32)),
            (None, Some(12u32)),
            (Some(4_223_456u32), None),
            (None, None),
        ] {
            let spec = compilability::spec_with(
                calls.clone(),
                (PredicateKind::AnyOf, true),
                valid_until,
                max_calls,
                false,
            )
            .expect("every shape of the golden rule validates");
            let source = emitted_for(&spec);
            let shape = format!("valid_until={valid_until:?} max_calls={max_calls:?}");

            for (verb, entry) in [
                ("Enforced", "enforce"),
                ("Installed", "install"),
                ("Uninstalled", "uninstall"),
            ] {
                let event = format!("GeneratedPolicy{verb}");
                assert!(
                    source.contains(&format!(
                        "#[contractevent]\n#[derive(Clone{}\npub struct {event} {{\n",
                        if verb == "Enforced" {
                            ")]"
                        } else {
                            ", Debug, Eq, PartialEq)]"
                        }
                    )),
                    "{shape}: {event} must be a `#[contractevent]` struct with the derives its \
                     fields allow:\n{source}"
                );
                // The single topic is the smart account, as it is in all three library policies.
                let declaration = &source[source
                    .find(&format!("pub struct {event} {{"))
                    .expect("just asserted")..];
                let declaration = &declaration[..declaration.find("\n}\n").expect("a struct ends")];
                assert!(
                    declaration.contains("    #[topic]\n    pub smart_account: Address,"),
                    "{shape}: {event}'s only topic must be the smart account:\n{declaration}"
                );
                assert_eq!(
                    declaration.matches("#[topic]").count(),
                    1,
                    "{shape}: {event} must carry exactly one topic:\n{declaration}"
                );
                assert!(
                    declaration.contains("pub context_rule_id: u32,"),
                    "{shape}: {event} must carry the context rule id:\n{declaration}"
                );

                // Published from the body of the entry point it belongs to, not merely declared.
                let body = body_of(&source, entry);
                assert!(
                    body.contains(&format!("{event} {{")) && body.contains(".publish(e);"),
                    "{shape}: `{entry}` must publish {event}:\n{body}"
                );
                // …and documented there, in the form their conventions fix.
                let doc = docs_of(&source, entry);
                assert!(
                    doc.contains("# Events")
                        && doc.contains("* topics - ")
                        && doc.contains("* data - "),
                    "{shape}: `{entry}` must document the event it publishes:\n{doc}"
                );
            }

            // The running number rides on the enforcement event only where a cap exists — the
            // same condition that decides whether `remaining_calls` is exported at all.
            let enforced = &source[source
                .find("pub struct GeneratedPolicyEnforced {")
                .expect("the enforcement event is declared")..];
            let enforced = &enforced[..enforced.find("\n}\n").expect("a struct ends")];
            assert_eq!(
                enforced.contains("pub remaining_calls: u32,"),
                max_calls.is_some(),
                "{shape}: the enforcement event carries a count iff the rule caps calls"
            );
            // Searched against the doc with its wrapping undone: `wrap_comments` may split any
            // phrase across two lines, and a substring search over the raw text would then be
            // asking about the line breaks rather than about the content.
            let enforce_doc = docs_of(&source, "enforce")
                .replace("///", " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(
                enforce_doc.contains("remaining_calls: u32"),
                max_calls.is_some(),
                "{shape}: and the doc says so iff the field is there:\n{enforce_doc}"
            );
            // The context always rides on it: an event naming only the account and the rule
            // would not say what was permitted, which is the one thing a reader wants from it.
            assert!(
                enforced.contains("pub context: Context,"),
                "{shape}: the enforcement event must carry what it permitted:\n{enforced}"
            );
        }
    }

    /// The artifact exposes its state for reading, and extends TTL where it reads.
    ///
    /// Both sibling policy examples expose getters from an inherent `#[contractimpl]` block beside
    /// the trait one; ours exported the three trait methods and nothing else, so there was no
    /// on-chain way to ask whether a policy was installed or how many calls an installation had
    /// left. That gap had a second consequence: the library's "extend TTL on read, not on write"
    /// rule had no read site to attach to, which is the whole reason this artifact diverged from
    /// it.
    ///
    /// `remaining_calls` is emitted only where a cap exists. A rule with no cap has no counter to
    /// report, and both alternatives are worse than an absent function — a `u32::MAX` sentinel is
    /// a magic value a caller has to know about, and zero reads as "exhausted" for a policy that
    /// is in fact unlimited. So the assertion is two-sided: present with a cap, absent without.
    #[test]
    fn the_artifact_exposes_its_state_for_reading() {
        let calls = golden_spec().spec().rules[0].allowed_calls.clone();
        for (valid_until, max_calls) in [
            (Some(4_223_456u32), Some(12u32)),
            (None, Some(12u32)),
            (Some(4_223_456u32), None),
            (None, None),
        ] {
            let spec = compilability::spec_with(
                calls.clone(),
                (PredicateKind::AnyOf, true),
                valid_until,
                max_calls,
                false,
            )
            .expect("every shape of the golden rule validates");
            let source = emitted_for(&spec);
            let shape = format!("valid_until={valid_until:?} max_calls={max_calls:?}");

            // The inherent block is the one their conventions reserve plain `#[contractimpl]`
            // for, and it must be distinct from the trait impl rather than folded into it.
            assert!(
                source.contains("#[contractimpl]\nimpl GeneratedPolicy {\n"),
                "{shape}: the getters must live in an inherent `#[contractimpl]` block:\n{source}"
            );
            assert!(
                source.contains("#[contractimpl]\nimpl Policy for GeneratedPolicy {\n"),
                "{shape}: the trait impl must stay its own block:\n{source}"
            );
            assert!(
                source.contains("pub fn is_installed(e: &Env, context_rule_id: u32, "),
                "{shape}: `is_installed` must be exported:\n{source}"
            );
            assert_eq!(
                source.contains("pub fn remaining_calls("),
                max_calls.is_some(),
                "{shape}: `remaining_calls` is emitted iff the rule caps calls"
            );

            // Extend on read: the body of each getter extends what it successfully read. Checked
            // per function body, because an `extend_ttl` anywhere in the file would satisfy a
            // whole-source search — `enforce` and `install` both carry one.
            let is_installed = body_of(&source, "is_installed");
            assert!(
                is_installed.contains("extend_ttl(&installed_key"),
                "{shape}: `is_installed` must extend the entry it read:\n{is_installed}"
            );
            if max_calls.is_some() {
                let remaining = body_of(&source, "remaining_calls");
                assert!(
                    remaining.contains("extend_ttl(&key"),
                    "{shape}: `remaining_calls` must extend the counter it read:\n{remaining}"
                );
                // …and withhold the extension once the cap is spent, which is what keeps the
                // header's "stops paying rent" claim true through a read as well as a write.
                for (name, body) in [
                    ("is_installed", &is_installed),
                    ("remaining_calls", &remaining),
                ] {
                    let guard = body.find("if remaining > 0u32 {").unwrap_or_else(|| {
                        panic!("{shape}: `{name}` extends unconditionally:\n{body}")
                    });
                    let extend = body
                        .find("extend_ttl(")
                        .expect("the body was just asserted to extend");
                    assert!(
                        guard < extend,
                        "{shape}: `{name}` extends before checking it can still permit:\n{body}"
                    );
                }
            }
            // A missing count is an error rather than a zero, matching `enforce`.
            if max_calls.is_some() {
                assert!(
                    body_of(&source, "remaining_calls")
                        .contains("None => panic_with_error!(e, PolicyError::MissingState)"),
                    "{shape}: an absent counter must deny rather than read as zero"
                );
            }
        }
    }

    /// The emitted file is divided by OpenZeppelin's canonical section delimiter, in their order.
    ///
    /// Their rule is unusually specific: eighteen hashes each side, and variations such as
    /// `// === NAME ===` are to be rewritten to that form. So the form is asserted exactly — a
    /// heading with seventeen hashes reads the same to a human and is a violation.
    ///
    /// The order matters more than the presence. `storage.rs` in the library runs keys → QUERY
    /// STATE → CHANGE STATE → LOW-LEVEL HELPERS, and a generated policy is a single file playing
    /// the part of both `mod.rs` and `storage.rs`, so the sequence below is the two of them
    /// concatenated. That is also why the private helpers now sit after the entry points rather
    /// than before them: a reader opening a policy meets what it exposes before the arithmetic it
    /// is built from.
    /// Every entry point that extends TTL extends the same entries, to the same bound.
    ///
    /// This is the property the dynamic `ttl_target` exists to provide, and the one an
    /// extend-on-read convention can quietly take away. The argument the artifact makes to a
    /// reviewer is that it provably never buys rent past the rule's validity window or after the
    /// call cap is spent — and `is_installed` is callable by anyone, so a read that computed its
    /// own target, or extended a different set of entries, would break that claim through the one
    /// path with no authorization on it.
    ///
    /// Asserted as an identity between the four bodies rather than against a written-down list,
    /// because a list is a second copy of the intent and would be updated in the same edit that
    /// broke the code. The emitter has one extension block and every site uses it; this is what
    /// says so.
    ///
    /// The asymmetry this replaces was real and was shipped: `is_installed` extended the marker
    /// and the counter, `remaining_calls` extended the counter alone, and neither extended the
    /// instance entry that `enforce` and `install` did. An installation read only through
    /// `remaining_calls` therefore kept its counter alive while its marker decayed — and a marker
    /// that archives while its counter does not is an installation `enforce` refuses as
    /// `MissingState` with the count intact.
    #[test]
    fn every_extending_entry_point_extends_the_same_entries_through_the_same_bound() {
        let calls = golden_spec().spec().rules[0].allowed_calls.clone();
        for (valid_until, max_calls) in [
            (Some(4_223_456u32), Some(12u32)),
            (None, Some(12u32)),
            (Some(4_223_456u32), None),
            (None, None),
        ] {
            let spec = compilability::spec_with(
                calls.clone(),
                (PredicateKind::AnyOf, true),
                valid_until,
                max_calls,
                false,
            )
            .expect("every shape of the golden rule validates");
            let source = emitted_for(&spec);
            let shape = format!("valid_until={valid_until:?} max_calls={max_calls:?}");

            let mut extenders = vec!["enforce", "install", "is_installed"];
            if max_calls.is_some() {
                extenders.push("remaining_calls");
            }

            let expected = extended_entries(&body_of(&source, "enforce"));
            assert!(
                expected.contains(&"instance".to_string())
                    && expected.contains(&"installed_key".to_string()),
                "{shape}: `enforce` must extend the instance and the marker, or this test has \
                 nothing to compare against: {expected:?}"
            );
            for entry in extenders {
                let body = body_of(&source, entry);
                assert_eq!(
                    extended_entries(&body),
                    expected,
                    "{shape}: `{entry}` extends a different entry set from `enforce`; a read that \
                     extends less than a write leaves one of this policy's entries to archive \
                     while the others are kept alive"
                );
                assert!(
                    body.contains("let ttl = ttl_target(e);"),
                    "{shape}: `{entry}` must take its target from `ttl_target`, which is the only \
                     thing that bounds an extension by the rule's own window:\n{body}"
                );
            }

            // The one entry point that must not extend, kept in the same test so the identity
            // above cannot be satisfied by extending everywhere.
            assert!(
                !body_of(&source, "uninstall").contains("extend_ttl"),
                "{shape}: `uninstall` must buy no rent for entries it is removing"
            );
        }
    }

    /// The entries one function body extends, named by what they are rather than by the call text.
    fn extended_entries(body: &str) -> Vec<String> {
        body.lines()
            .filter(|line| line.contains(".extend_ttl("))
            .map(|line| {
                let line = line.trim();
                if line.contains("instance()") {
                    "instance".to_string()
                } else if let Some(rest) = line.split(".extend_ttl(&").nth(1) {
                    rest.split(',')
                        .next()
                        .expect("an extend_ttl argument")
                        .to_string()
                } else {
                    panic!("an extension of nothing recognizable: {line}")
                }
            })
            .collect()
    }

    #[test]
    fn the_emitted_file_carries_the_canonical_section_delimiters_in_order() {
        let rule = "#".repeat(18);
        // Every section a generated policy has. Both EVENTS and QUERY STATE are unconditional:
        // every policy announces its three lifecycle steps and answers `is_installed`, whether or
        // not it also counts calls.
        let expected = [
            "ERRORS",
            "STORAGE KEYS",
            "CONSTANTS",
            "EVENTS",
            "QUERY STATE",
            "CHANGE STATE",
            "LOW-LEVEL HELPERS",
        ];
        for (label, spec) in [
            ("golden transfer", golden_spec()),
            (
                "W3 swap",
                ozpb_synthesizer::walkthroughs::soroswap_swap_spec(),
            ),
        ] {
            let source = emitted_rust(
                &generate(&spec, 0, &Pins::default())
                    .unwrap_or_else(|error| panic!("{label} must generate: {error}")),
            );

            // Every delimiter in the file, in the order it appears, read back from the text.
            let found: Vec<String> = source
                .lines()
                .filter_map(|line| line.strip_prefix(&format!("// {rule} ")))
                .filter_map(|rest| rest.strip_suffix(&format!(" {rule}")))
                .map(str::to_string)
                .collect();
            assert_eq!(
                found, expected,
                "{label}: section delimiters are missing, mis-formed or out of order"
            );

            // No near-miss forms: anything that looks like a heading must be the canonical one.
            let malformed: Vec<&str> = source
                .lines()
                .filter(|line| line.starts_with("// #") || line.starts_with("// ==="))
                .filter(|line| {
                    !line.starts_with(&format!("// {rule} "))
                        || !line.ends_with(&format!(" {rule}"))
                })
                .collect();
            assert!(
                malformed.is_empty(),
                "{label}: non-canonical section delimiters: {malformed:?}"
            );

            // The private helpers really are after the entry points, which is the ordering claim
            // the section list above only implies.
            let helpers = source
                .find(&format!("// {rule} LOW-LEVEL HELPERS"))
                .expect("the helper section must exist");
            for helper in ["fn matched_count(", "fn ttl_target(", "fn check_call_0("] {
                let at = source
                    .find(helper)
                    .unwrap_or_else(|| panic!("{label}: no {helper} in the emitted source"));
                assert!(
                    at > helpers,
                    "{label}: {helper} is emitted before the LOW-LEVEL HELPERS heading"
                );
            }
            assert!(
                source.find("fn enforce(").expect("enforce is emitted") < helpers,
                "{label}: the entry points must come before the helpers"
            );
        }
    }

    /// Every public item carries a doc comment, and every entry point an `# Errors` section.
    ///
    /// OpenZeppelin's conventions ask for a one-line summary on every public item and an
    /// `# Errors` section on every public function that can panic; ours panic several ways each.
    /// The asymmetry this removes is worth naming: the private `ttl_target` helper carried three
    /// paragraphs while `enforce`, `install` and `uninstall` — the whole callable surface of the
    /// artifact — carried none.
    ///
    /// Checked through `syn` rather than by searching for `///`, because the property is about
    /// items and not about text: a substring search cannot tell a doc comment attached to the
    /// enum from one attached to its first variant, and the variants are half of what was
    /// missing. `syn` is already a dev-dependency here for the parse check.
    #[test]
    fn every_public_item_of_the_generated_crate_is_documented() {
        fn documented(attrs: &[syn::Attribute]) -> bool {
            attrs.iter().any(|attr| attr.path().is_ident("doc"))
        }
        fn public(vis: &syn::Visibility) -> bool {
            matches!(vis, syn::Visibility::Public(_))
        }

        let mut stateless = golden_spec().spec().clone();
        stateless.rules[0].state.clear();
        stateless.rules[0].valid_until = None;
        let stateless = stateless
            .validate()
            .expect("a stateless rule with no window is a valid spec");

        // The roster is shape-dependent: `remaining_calls` exists only where a cap does, so a
        // fixed list would either miss it or demand it from a policy that has no counter.
        for (label, spec, capped) in [
            ("golden transfer", golden_spec(), true),
            (
                "W3 swap",
                ozpb_synthesizer::walkthroughs::soroswap_swap_spec(),
                true,
            ),
            ("stateless, no window", stateless, false),
        ] {
            let generated = generate(&spec, 0, &Pins::default())
                .unwrap_or_else(|error| panic!("{label} must generate: {error}"));
            each_file_parses(&generated);

            // Items from every emitted file. `pub mod contract;` is deliberately not among the
            // items checked below: a module's documentation is the `//!` block inside its own
            // file, which is asserted separately, and rustdoc renders it in the same place a
            // `///` on the declaration would have gone.
            let mut items: Vec<syn::Item> = Vec::new();
            for (path, body) in rust_files(&generated) {
                let parsed = syn::parse_file(&body).expect("just asserted to parse");
                if path == "src/contract.rs" {
                    assert!(
                        body.starts_with("//! "),
                        "{label}: the contract module must open with its own `//!` doc:\n{body}"
                    );
                }
                items.extend(parsed.items);
            }
            let source = emitted_rust(&generated);

            let mut undocumented: Vec<String> = Vec::new();
            let mut entry_points: Vec<String> = Vec::new();
            for item in &items {
                match item {
                    syn::Item::Enum(item) if public(&item.vis) => {
                        if !documented(&item.attrs) {
                            undocumented.push(format!("enum {}", item.ident));
                        }
                        for variant in &item.variants {
                            if !documented(&variant.attrs) {
                                undocumented
                                    .push(format!("variant {}::{}", item.ident, variant.ident));
                            }
                        }
                    }
                    syn::Item::Struct(item) if public(&item.vis) => {
                        if !documented(&item.attrs) {
                            undocumented.push(format!("struct {}", item.ident));
                        }
                    }
                    // Trait-impl members carry no `pub` of their own — they are as public as the
                    // trait — so visibility cannot be the filter here. This is the artifact's
                    // callable surface, which is exactly why it is checked.
                    syn::Item::Impl(item) => {
                        for member in &item.items {
                            let (kind, ident, attrs) = match member {
                                syn::ImplItem::Fn(member) => {
                                    ("fn", member.sig.ident.to_string(), member.attrs.clone())
                                }
                                syn::ImplItem::Type(member) => {
                                    ("type", member.ident.to_string(), member.attrs.clone())
                                }
                                _ => continue,
                            };
                            if !documented(&attrs) {
                                undocumented.push(format!("{kind} {ident}"));
                            }
                            if kind == "fn" {
                                entry_points.push(ident);
                            }
                        }
                    }
                    _ => {}
                }
            }
            assert!(
                undocumented.is_empty(),
                "{label}: public items without a doc comment: {undocumented:?}"
            );
            // Non-vacuity: an empty walk would also report nothing undocumented.
            entry_points.sort();
            let mut expected = vec!["enforce", "install", "is_installed", "uninstall"];
            if capped {
                expected.push("remaining_calls");
            }
            expected.sort();
            assert_eq!(
                entry_points, expected,
                "{label}: the walk did not reach the callable surface"
            );

            for entry in ["enforce", "install", "uninstall"] {
                let doc = docs_of(&source, entry);
                assert!(
                    doc.contains("# Errors"),
                    "{label}: `{entry}` has no `# Errors` section:\n{doc}"
                );
                assert!(
                    doc.contains("# Arguments"),
                    "{label}: `{entry}` has no `# Arguments` section:\n{doc}"
                );
                // Their section order is fixed: Arguments before Errors, never reordered.
                assert!(
                    doc.find("# Arguments") < doc.find("# Errors"),
                    "{label}: `{entry}` lists its sections out of order:\n{doc}"
                );
            }
        }
    }

    /// The doc comment immediately above `fn <name>`, as one string.
    ///
    /// Read off the emitted text rather than through `syn`, because what is under test is what a
    /// reader sees — the rendered section headings and bullets, not a token stream.
    fn docs_of(source: &str, name: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        let at = lines
            .iter()
            .position(|line| {
                line.trim_start()
                    .trim_start_matches("pub ")
                    .starts_with(&format!("fn {name}("))
            })
            .unwrap_or_else(|| panic!("no `fn {name}` in the emitted source"));
        let mut start = at;
        while start > 0 && lines[start - 1].trim_start().starts_with("///") {
            start -= 1;
        }
        lines[start..at].join("\n")
    }

    /// The `# Errors` bullets of one entry point, as (variant, prose) pairs.
    ///
    /// The prose matters as much as the variant. A list that names the right eleven codes while
    /// describing one of two conditions that raise a code is the failure this parses for, and it
    /// is invisible to any check that reads only the identifiers.
    fn error_bullets(doc: &str) -> Vec<(String, String)> {
        let mut bullets: Vec<(String, String)> = Vec::new();
        let mut inside = false;
        for line in doc.lines() {
            let text = line.trim_start().trim_start_matches("///").trim();
            if text.starts_with("# ") {
                inside = text == "# Errors";
                continue;
            }
            if !inside || text.is_empty() {
                continue;
            }
            if let Some(rest) = text.strip_prefix("* ") {
                let variant = rest
                    .split("[`PolicyError::")
                    .nth(1)
                    .and_then(|r| r.split('`').next())
                    .unwrap_or_else(|| panic!("an `# Errors` bullet that names no variant: {rest}"))
                    .to_string();
                bullets.push((variant, rest.to_string()));
            } else if let Some(last) = bullets.last_mut() {
                // A wrapped continuation line. Joined with a space so a condition broken across
                // two lines is still one occurrence of the word that introduces it.
                last.1.push(' ');
                last.1.push_str(text);
            }
        }
        bullets
    }

    /// An `# Errors` list names every refusal the emitted body can raise, no others, **and as
    /// many conditions as the body has raise sites for it**.
    ///
    /// This is the property that makes the section worth having in a generated artifact. The enum
    /// declares all eleven codes whatever the rule's shape, so copying that list into every
    /// entry point's docs would be easy and would be wrong: a rule with no validity window can
    /// never raise `RuleExpired`, and one with no call cap can never raise `CallCountExceeded`.
    ///
    /// Checked in three directions against the body itself: every `panic_with_error!` reachable
    /// from the function is listed, every listed error appears in one, and a code raised from *n*
    /// distinct sites is described by *n* conditions rather than one. That last direction is
    /// the one a variant-name comparison cannot see, and it is not hypothetical — `enforce`
    /// raises `MissingState` for a missing marker *and* for a missing counter, `SignerSetDiverged`
    /// from a size check *and* a membership loop, and `FunctionNotAllowed` from a non-contract
    /// context *and* a disallowed function name. Each was documented as one condition, so a
    /// reader of the docs knew about half of the code.
    ///
    /// A condition is counted by the word that introduces it — every bullet reads
    /// "`When` …, or `when` …" — which makes the count a property of the prose a reader
    /// actually sees rather than of a table kept beside it.
    ///
    /// All five entry points, not the three on the `Policy` trait. `is_installed` is here for the
    /// opposite reason to the others: it must document no refusal, because it can raise none, and
    /// a getter that started panicking without a doc would otherwise pass unnoticed.
    #[test]
    fn each_entry_point_documents_exactly_the_refusals_its_body_can_raise() {
        let calls = golden_spec().spec().rules[0].allowed_calls.clone();
        for (valid_until, max_calls) in [
            (Some(4_223_456u32), Some(12u32)),
            (None, Some(12u32)),
            (Some(4_223_456u32), None),
            (None, None),
        ] {
            let spec = compilability::spec_with(
                calls.clone(),
                (PredicateKind::AnyOf, true),
                valid_until,
                max_calls,
                false,
            )
            .expect("every shape of the golden rule validates");
            let source = emitted_for(&spec);
            let shape = format!("valid_until={valid_until:?} max_calls={max_calls:?}");

            // `remaining_calls` is emitted only where a cap exists; the other four always are.
            let mut entries = vec!["enforce", "install", "uninstall", "is_installed"];
            if max_calls.is_some() {
                entries.push("remaining_calls");
            }

            for entry in entries {
                let doc = docs_of(&source, entry);
                let bullets = error_bullets(&doc);
                let listed: Vec<String> = bullets.iter().map(|(v, _)| v.clone()).collect();
                let raised: Vec<String> = body_of(&source, entry)
                    .split("panic_with_error!(e, PolicyError::")
                    .skip(1)
                    .filter_map(|rest| rest.split(')').next())
                    .map(str::to_string)
                    .collect();

                for error in &raised {
                    assert!(
                        listed.contains(error),
                        "{shape}: `{entry}` can raise {error} and does not document it: \
                         {listed:?}"
                    );
                }
                for error in &listed {
                    assert!(
                        raised.contains(error),
                        "{shape}: `{entry}` documents {error}, which its body cannot raise: \
                         {raised:?}"
                    );
                }

                // One condition per raise site. The bullets for a variant are taken together, so
                // the emitter may either split a twice-raised code into two bullets or name both
                // conditions in one — what it may not do is describe fewer conditions than the
                // body has ways of reaching the code.
                for variant in &listed {
                    let sites = raised.iter().filter(|r| *r == variant).count();
                    let described: usize = bullets
                        .iter()
                        .filter(|(v, _)| v == variant)
                        .map(|(_, prose)| prose.to_lowercase().matches("when ").count())
                        .sum();
                    assert_eq!(
                        described,
                        sites,
                        "{shape}: `{entry}` raises {variant} from {sites} site(s) and its \
                         `# Errors` prose describes {described} condition(s); a code reachable \
                         two ways documented once tells a reader about one of them:\n{:?}",
                        bullets
                            .iter()
                            .filter(|(v, _)| v == variant)
                            .map(|(_, prose)| prose)
                            .collect::<Vec<_>>()
                    );
                }

                if entry == "is_installed" {
                    assert!(
                        raised.is_empty() && listed.is_empty(),
                        "{shape}: `is_installed` answers a query and must refuse nothing: \
                         raises {raised:?}, documents {listed:?}"
                    );
                } else {
                    assert!(
                        !raised.is_empty(),
                        "{shape}: no refusal found in `{entry}`, so this proves nothing"
                    );
                }
            }

            // The shape-dependent pair, stated directly: these are the two errors a copied list
            // would carry into a policy that cannot raise them.
            let enforce_doc = docs_of(&source, "enforce");
            assert_eq!(
                enforce_doc.contains("PolicyError::RuleExpired"),
                valid_until.is_some(),
                "{shape}: `RuleExpired` is documented iff the rule has a window"
            );
            assert_eq!(
                enforce_doc.contains("PolicyError::CallCountExceeded"),
                max_calls.is_some(),
                "{shape}: `CallCountExceeded` is documented iff the rule caps calls"
            );
        }
    }

    /// The body of `fn <name>`, from its signature to the line that closes it.
    ///
    /// Brace counting rather than `syn`, because the doc list above is compared against the
    /// emitted `panic_with_error!` calls and both should be read from the same text.
    fn body_of(source: &str, name: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        let at = lines
            .iter()
            .position(|line| {
                line.trim_start()
                    .trim_start_matches("pub ")
                    .starts_with(&format!("fn {name}("))
            })
            .unwrap_or_else(|| panic!("no `fn {name}` in the emitted source"));
        let mut depth = 0i32;
        let mut end = at;
        let mut opened = false;
        for (offset, line) in lines[at..].iter().enumerate() {
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            if line.contains('{') {
                opened = true;
            }
            if opened && depth <= 0 {
                end = at + offset;
                break;
            }
        }
        lines[at..=end].join("\n")
    }

    /// `wrap_comments` bounds a doc comment and an ordinary comment from different columns.
    ///
    /// This is the one rule in the emitted layout that no amount of reading the option's
    /// description would produce, and getting it backwards is invisible in exactly the wrong
    /// direction: emission would look right, this file's own width test would pass, and
    /// `cargo fmt --check` on the shipped artifact would rewrite it.
    ///
    /// Measured against the pinned toolchain's rustfmt with single-character words, so each
    /// boundary below is the exact last accepted width rather than wherever some sentence
    /// happened to break:
    ///
    ///   * `///` and `//!` are bounded by `comment_width` from **column zero** — 80 columns at
    ///     indent 0, and still 80 at indent 4 or 8, so the indentation is spent out of the same
    ///     budget as the text;
    ///   * `//` is bounded by `comment_width` from **its own marker** — 84 columns at indent 4,
    ///     88 at indent 8 — so the indentation costs it nothing.
    ///
    /// The pair at indent 8 is the whole point: 88 columns is a fixed point for `//` and eight
    /// columns too wide for `///`.
    ///
    /// The boundary is asserted through [`render::comment_is_overlong`] at width B and B+1 rather
    /// than by reading the widest line the wrapper produces. That reading is parity-dependent —
    /// with one-character words a `///` line at indent 0 can only land on odd widths, so it stops
    /// at 79 under a budget of 80 — and a test that expected 79 would be pinning the test's own
    /// word list instead of rustfmt's rule.
    #[test]
    fn a_doc_comment_and_a_plain_comment_are_bounded_from_different_columns() {
        for (indent, marker, budget) in [
            ("", "///", 80usize),
            ("", "//!", 80),
            ("    ", "///", 80),
            ("        ", "///", 80),
            ("    ", "//", 84),
            ("        ", "//", 88),
        ] {
            let prefix = format!("{indent}{marker} ");
            let at = |width: usize| format!("{prefix}{}", "a".repeat(width - prefix.len()));
            assert!(
                !render::comment_is_overlong(&at(budget)),
                "{marker} at indent {}: {budget} columns must be a fixed point",
                indent.len()
            );
            assert!(
                render::comment_is_overlong(&at(budget + 1)),
                "{marker} at indent {}: {} columns must not be",
                indent.len(),
                budget + 1
            );

            // The wrapper's output is a fixed point *and* greedily filled: every line fits, and
            // no line could have taken the next line's first word. Together those are exactly
            // what rustfmt leaves alone, so this is the property rather than a proxy for it.
            let wrapped = render::wrap_comment(&prefix, &"a ".repeat(120));
            let lines: Vec<&str> = wrapped.lines().collect();
            assert!(
                lines.len() > 1,
                "{marker} at indent {} did not wrap at all",
                indent.len()
            );
            for (index, line) in lines.iter().enumerate() {
                assert!(
                    !render::comment_is_overlong(line),
                    "wrapped line {} is over budget: {line:?}",
                    index + 1
                );
                if let Some(next) = lines.get(index + 1) {
                    let first_word = next
                        .trim_start()
                        .trim_start_matches('/')
                        .split_whitespace()
                        .next()
                        .expect("a wrapped line carries at least one word");
                    assert!(
                        render::comment_is_overlong(&format!("{line} {first_word}")),
                        "line {} left room for {first_word:?}, so the fill is not greedy: \
                         {line:?}",
                        index + 1
                    );
                }
            }
        }
    }

    /// The import block is one grouped `use` per crate, filled the way rustfmt fills one.
    ///
    /// `imports_granularity = "Crate"` is what OpenZeppelin's `rustfmt.toml` sets and what both
    /// sibling policy examples show. The exact text is asserted, not just the statement count,
    /// because the fill is derived from item widths: the interesting property is that the
    /// derivation agrees with rustfmt for every item set a rule can produce, and only a
    /// byte-for-byte comparison against text taken from rustfmt's own output says that.
    ///
    /// Both reachable sets are covered — the transfer rule (no `ScVal`, so no `Bytes` and no
    /// `xdr::ToXdr`) and the W3 swap rule (both) — and `use_statement` is exercised directly for
    /// the two shapes a validated spec cannot reach: `Bytes` without `xdr::ToXdr`, which needs an
    /// external signer, and a group short enough to stay on one line.
    #[test]
    fn imports_are_one_grouped_use_per_crate() {
        let expected_accounts = "use stellar_accounts::{\n    policies::Policy,\n    \
                                smart_account::{ContextRule, Signer},\n};\n";
        for (label, spec, expected_sdk) in [
            (
                "golden transfer",
                golden_spec(),
                "use soroban_sdk::{\n    auth::Context, contract, contracterror, contractevent, contractimpl, \
                 contracttype,\n    panic_with_error, Address, Env, Symbol, TryFromVal, Val, Vec,\n};\n",
            ),
            (
                "W3 swap",
                ozpb_synthesizer::walkthroughs::soroswap_swap_spec(),
                "use soroban_sdk::{\n    auth::Context, contract, contracterror, contractevent, \
                 contractimpl, contracttype,\n    panic_with_error, xdr::ToXdr, Address, Bytes, \
                 Env, Symbol, TryFromVal, Val, Vec,\n};\n",
            ),
        ] {
            let source = emitted_rust(
                    &generate(&spec, 0, &Pins::default())
                        .unwrap_or_else(|error| panic!("{label} must generate: {error}")),
                );
            assert!(
                source.contains(expected_sdk),
                "{label}: soroban_sdk import block is not rustfmt's grouped form\n\
                 expected:\n{expected_sdk}\ngot:\n{source}"
            );
            assert!(
                source.contains(expected_accounts),
                "{label}: stellar_accounts import block is not rustfmt's grouped form\n\
                 expected:\n{expected_accounts}\ngot:\n{source}"
            );
            // Two crates, therefore two statements. A split block satisfies the substrings
            // above only if it happens to contain them, so the count is what forbids the
            // per-item spelling this replaced.
            let statements = source.matches("\nuse ").count();
            assert_eq!(
                statements, 2,
                "{label}: expected one `use` per crate, found {statements}:\n{source}"
            );
        }

        // `Bytes` without `xdr::ToXdr` — the external-signer shape. Reachable through
        // `use_statement` only: a validated spec cannot carry an external signer.
        assert_eq!(
            render::use_statement(
                "soroban_sdk",
                &[
                    "auth::Context",
                    "contract",
                    "contracterror",
                    "contractimpl",
                    "contracttype",
                    "panic_with_error",
                    "Address",
                    "Bytes",
                    "Env",
                    "Symbol",
                    "TryFromVal",
                    "Val",
                    "Vec",
                ],
            ),
            "use soroban_sdk::{\n    auth::Context, contract, contracterror, contractimpl, \
             contracttype, panic_with_error, Address,\n    Bytes, Env, Symbol, TryFromVal, Val, \
             Vec,\n};\n"
        );
        // Short enough for one line, and nothing nested — the case the fill must not wrap.
        assert_eq!(
            render::use_statement("soroban_sdk", &["Env", "auth::Context"]),
            "use soroban_sdk::{auth::Context, Env};\n"
        );
        // Nested, and short: a brace group forces the vertical layout at any width.
        assert_eq!(
            render::use_statement("stellar_accounts", &["smart_account::{Signer}", "a::B"]),
            "use stellar_accounts::{\n    a::B,\n    smart_account::{Signer},\n};\n"
        );
    }

    /// Emission never writes a length comparison against zero.
    ///
    /// `clippy::len_zero` is warn-by-default and the generated crate ships with `-D warnings`
    /// over it, so this is a build failure in the artifact this project hands to a reviewer —
    /// and OpenZeppelin's own conventions forbid silencing it with `#[allow]`
    /// (`.claude/commands/code-quality.md`, "Lint suppression"). Written as a scan for the
    /// shape rather than an assertion about one statement, because every emitted `.len()` is a
    /// candidate: the arity check, the strict-signer-set comparison and the predicate all
    /// measure a `soroban_sdk::Vec`, and only `is_empty()` is accepted for the zero case.
    ///
    /// The corpus is the three specs whose emission differs most: the golden transfer rule, the
    /// W3 swap rule (bounds, exact `ScVal`, `AnyValue`) and a dynamic predicate, which is the
    /// one shape that compares against `context_rule.signers` instead of a compiled-in set.
    #[test]
    fn emission_never_compares_a_length_against_zero() {
        let mut dynamic = golden_spec().spec().clone();
        dynamic.rules[0].authorization.kind = PredicateKind::AnyOfCurrentRuleSigners;
        dynamic.rules[0].authorization.strict_signer_set = false;
        let dynamic = dynamic.validate().expect("a dynamic rule is a valid spec");

        for (label, spec) in [
            ("golden transfer", golden_spec()),
            (
                "W3 swap",
                ozpb_synthesizer::walkthroughs::soroswap_swap_spec(),
            ),
            ("dynamic predicate", dynamic),
        ] {
            let source = emitted_rust(
                &generate(&spec, 0, &Pins::default())
                    .unwrap_or_else(|error| panic!("{label} must generate: {error}")),
            );
            // Non-vacuity: a pass means nothing unless the predicate check is really emitted.
            assert!(
                source.contains("PolicyError::ZeroSigners"),
                "{label} does not emit the check this test is about:\n{source}"
            );
            let offenders: Vec<&str> = source
                .lines()
                .filter(|line| {
                    line.contains(".len() == 0")
                        || line.contains(".len() != 0")
                        || line.contains(".len() > 0")
                        || line.contains("0 == ") && line.contains(".len()")
                })
                .collect();
            assert!(
                offenders.is_empty(),
                "{label} emits a zero-length comparison clippy::len_zero rejects: {offenders:?}"
            );
        }
    }

    #[test]
    fn emitted_code_contains_the_generated_code_contract() {
        let spec = golden_spec();
        let g = generate(&spec, 0, &Pins::default()).unwrap();
        let lib = &emitted_rust(&g);
        // Signer predicate first, with strict set.
        assert!(lib.contains("PolicyError::ZeroSigners"));
        assert!(lib.contains("SignerSetDiverged"));
        assert!(lib.contains(&golden_delegate_strkey()));
        // SELF resolves at runtime (no account literal in the tuple check).
        assert!(lib.contains("*smart_account != a"));
        // The storage-key enum takes their `<Module>StorageKey` form, and the old name is gone
        // rather than aliased: `#[contracttype]` puts this name in the contract spec, so two
        // spellings would be two types on the wire.
        assert!(
            lib.contains("pub enum PolicyStorageKey {"),
            "the storage-key enum must be named for its module:\n{lib}"
        );
        assert!(
            !lib.contains("DataKey"),
            "the previous storage-key name must not survive anywhere:\n{lib}"
        );
        // Missing state denies; install-only init; no setters, no upgrade hook.
        assert!(lib.contains("PolicyError::MissingState"));
        assert!(lib.contains("AlreadyInstalled"));
        assert!(!lib.contains("fn set_"));
        assert!(!lib.contains("fn upgrade"));
        // Exact amount.
        assert!(lib.contains("if x != 500000000i128"));
        // Pinned dependencies in the crate manifest.
        let manifest = &g.files["Cargo.toml"];
        assert!(manifest.contains("soroban-sdk = \"=26.1.0\""));
        assert!(manifest.contains("stellar-accounts = \"=0.7.2\""));
        // The two declarations OpenZeppelin's packages all carry. `doctest = false` sits under
        // `[lib]`, so the assertion pins the block it belongs to rather than the bare line —
        // `doctest` is a valid key in `[dev-dependencies]`-adjacent tables too, and a stray one
        // elsewhere in the file would satisfy a substring search while changing nothing.
        assert!(
            manifest.contains("[package.metadata.stellar]\ncargo_inherit = true\n"),
            "the manifest must declare `[package.metadata.stellar] cargo_inherit`:\n{manifest}"
        );
        assert!(
            manifest.contains("[lib]\ncrate-type = [\"lib\", \"cdylib\"]\ndoctest = false\n"),
            "`[lib]` must keep the load-bearing `lib` and declare `doctest = false`:\n{manifest}"
        );
    }

    /// The generated crate ships OpenZeppelin's rustfmt configuration, option for option.
    ///
    /// The emitted text is laid out to satisfy that file, so a crate that carried the layout
    /// without the config would be formatted to rules nobody could check it against, and a crate
    /// that carried the config without the layout would fail the reviewer's own fmt command. The
    /// option set is therefore asserted in full rather than sampled: dropping one line from it
    /// silently changes which of the two the artifact is.
    #[test]
    fn the_generated_crate_ships_the_upstream_rustfmt_config() {
        let generated = generate(&golden_spec(), 0, &Pins::default()).unwrap();
        let config = generated
            .files
            .get("rustfmt.toml")
            .expect("the generated crate must carry a rustfmt.toml");
        for option in [
            "format_macro_bodies = true",
            "format_macro_matchers = true",
            "format_strings = true",
            "imports_granularity = \"Crate\"",
            "reorder_impl_items = true",
            "group_imports = \"StdExternalCrate\"",
            "use_small_heuristics = \"Max\"",
            "use_field_init_shorthand = true",
            "wrap_comments = true",
            "format_code_in_doc_comments = true",
            "unstable_features = true",
        ] {
            assert!(
                config.lines().any(|line| line == option),
                "rustfmt.toml is missing OpenZeppelin's `{option}`:\n{config}"
            );
        }
        // Nothing but their options and comments: a setting of our own here would be a rule the
        // library is not held to, which is the opposite of the reason for shipping the file.
        let ours: Vec<&str> = config
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .filter(|line| !line.contains(" = "))
            .collect();
        assert!(
            ours.is_empty(),
            "unexpected lines in rustfmt.toml: {ours:?}"
        );
    }

    /// A byte-array constant takes whichever of three layouts rustfmt would give it.
    ///
    /// `use_small_heuristics = "Max"` raises `array_width` to `max_width`, and that turns two
    /// forms into three: the middle one — the literal alone on the next line at one indent —
    /// exists only in a window between "fits on the `=` line" and "has to be chunked", and
    /// nothing emitted before the config change ever reached it.
    ///
    /// The boundaries are a function of the constant's *name* as well as its length, since both
    /// share the first line, so they are stated for the name this test renders and were read off
    /// the pinned toolchain's rustfmt for exactly that name.
    #[test]
    fn a_byte_array_constant_takes_rustfmts_layout_for_its_length() {
        let render_of = |len: usize| {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD.encode(vec![0xabu8; len]);
            render::ByteArray::from_base64(&bytes)
                .expect("valid base64")
                .render_arg_xdr_const(0, 0)
        };
        // 10 elements: the whole item still fits `max_width` (96 columns).
        assert_eq!(
            render_of(10),
            "const CALL_0_ARG_0_XDR: [u8; 10] = [0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, \
             0xab, 0xab];\n"
        );
        // 11: two over, so the literal moves to its own line — and the `=` loses its trailing
        // space, which is the detail a hand-written template would get wrong.
        assert_eq!(
            render_of(11),
            "const CALL_0_ARG_0_XDR: [u8; 11] =\n    [0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, \
             0xab, 0xab, 0xab, 0xab];\n"
        );
        // 15: the last length that still fits on that line (95 columns).
        assert!(render_of(15).starts_with("const CALL_0_ARG_0_XDR: [u8; 15] =\n    [0xab,"));
        // 16: one over again, so the greedy fill takes over — sixteen to a line.
        assert_eq!(
            render_of(16),
            "const CALL_0_ARG_0_XDR: [u8; 16] = [\n    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, \
             0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,\n];\n"
        );
        // Every one of them a line rustfmt would leave alone.
        for len in [10, 11, 15, 16, 32, 48] {
            let rendered = render_of(len);
            let wide = compilability::overlong_lines(&rendered);
            assert!(wide.is_empty(), "{len} elements: {wide:?}\n{rendered}");
        }
    }

    #[test]
    fn rules_without_generated_ref_fail_before_codegen() {
        let base = golden_spec();
        let mut stripped = base.spec().clone();
        stripped.rules[0]
            .policies
            .retain(|p| matches!(p, ozpb_policy_spec::PolicyRef::Reviewed { .. }));
        let errors = stripped.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.to_string().starts_with("E_SPEC_SIGNER_POLICY:")),
            "validated typestate must guarantee a signer-enforcing generated policy: {errors:?}"
        );
        assert_eq!(
            generate(&base, 5, &Pins::default()).unwrap_err(),
            CodegenError::RuleIndex(5)
        );
    }

    #[test]
    fn invalid_literals_fail_before_emission() {
        let base = golden_spec();
        let mut bad = base.spec().clone();
        bad.rules[0].allowed_calls[0].args[1].constraint =
            ozpb_policy_spec::Constraint::EqAddress {
                value: ozpb_policy_spec::AddressRef::address("NOT-A-STRKEY"),
            };
        let errors = bad.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.to_string().starts_with("E_SPEC_ADDRESS:")));

        let mut bad_fn = base.spec().clone();
        bad_fn.rules[0]
            .policies
            .retain(|policy| matches!(policy, PolicyRef::Generated { .. }));
        bad_fn.rules[0].allowed_calls[0].fn_name = "not a symbol!".to_string();
        let errors = bad_fn.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.to_string().starts_with("E_SPEC_SYMBOL:")));
    }

    #[test]
    fn numeric_source_tokens_cannot_cross_the_validated_typestate() {
        let base = golden_spec();
        let mut hostile = base.spec().clone();
        hostile.rules[0].allowed_calls[0].args[2].constraint =
            ozpb_policy_spec::Constraint::LeI128 {
                max: "({ return true; 0 } as i128) + 0".to_string(),
            };
        hostile.rules[0].allowed_calls[0].args[2].provenance =
            ozpb_domain::Provenance::UserWidened {
                intent: "attempt source injection".to_string(),
                blast_radius: ozpb_domain::BlastRadius::High,
            };

        let errors = hostile.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.to_string().starts_with("E_SPEC_I128:")),
            "codegen must be unreachable for non-numeric source tokens: {errors:?}"
        );
    }

    /// The committed golden crate under contracts/ must exactly match regeneration.
    /// Run with UPDATE_GOLDEN=1 to (re)write it after intentional template changes.
    #[test]
    fn golden_crate_matches_committed_output() {
        let spec = golden_spec();
        let g = generate(&spec, 0, &Pins::default()).unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/golden-transfer-policy");
        if std::env::var("UPDATE_GOLDEN").is_ok() {
            std::fs::create_dir_all(root.join("src")).unwrap();
            for (rel, content) in &g.files {
                std::fs::write(root.join(rel), content).unwrap();
            }
            return;
        }
        // One entry in this loop cannot fail, and saying so is better than implying coverage that
        // does not exist. `emit_lockfile` is `include_str!` of *this crate's* `Cargo.lock` with the
        // package name substituted, and for this crate the substitution is a no-op — so the
        // `Cargo.lock` assertion compares the file with itself. It is kept in the loop because
        // removing it would be a special case that later hides a real change, but the drift it
        // looks for is structurally impossible here.
        //
        // Lockfile drift is caught in two other places instead. A lockfile that is not a complete
        // resolution of the emitted manifest fails the `--locked` build in `BUILD_ARGS`, which is
        // what `ozpb generate` and the nightly wasm job run. And the W3 golden below compares the
        // *other* generated crate's committed lockfile against this one, which is what detects the
        // two drifting apart.
        for (rel, content) in &g.files {
            let committed = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|_| {
                panic!("missing committed golden file {rel}; run with UPDATE_GOLDEN=1")
            });
            assert_eq!(
                &committed, content,
                "golden {rel} drifted from codegen output; regenerate deliberately with \
                 UPDATE_GOLDEN=1 (custom-source edits are not allowed on the golden).\n\
                 If the emitter changed rather than the spec, that is a change to the template \
                 family: decide whether it needs a new one. A behavioural change — a different \
                 check, a different order, a different deny path — is a new family \
                 (`scope@N+1`), because installed policies and their BuildManifests name the \
                 family they were built from and nothing else distinguishes two emitters that \
                 share a name. A change that cannot alter what a policy permits (a comment, a \
                 doc header) keeps the family. Say which one it is in the commit message either \
                 way."
            );
        }
    }

    #[test]
    fn generated_crate_contains_the_pinned_dependency_lockfile() {
        let generated = generate(&golden_spec(), 0, &Pins::default()).unwrap();
        let lockfile = generated
            .files
            .get("Cargo.lock")
            .expect("verified generated mode must be buildable with --locked");
        assert!(lockfile.contains("name = \"soroban-sdk\""));
        assert!(lockfile.contains("version = \"26.1.0\""));
        assert!(lockfile.contains("name = \"stellar-accounts\""));
        assert!(lockfile.contains("version = \"0.7.2\""));
    }

    /// W3 (Soroswap) exercises the hardest emission shapes — LeI128 / GeI128 bounds,
    /// EqScval (path), AnyValue (deadline). The committed crate must match regeneration
    /// and (via the contracts workspace) compile to wasm.
    ///
    /// The assertions below are bound to the argument each constraint belongs to, not just to
    /// the comparison text. Every arm shadows its value as `x`, so `if x > 1000000000i128`
    /// alone says nothing about *which* argument is capped — the identical string is asserted
    /// elsewhere in this file for arg 2 of the transfer spec. An emitter that mapped the cap to
    /// `amount_out_min` and the floor to `amount_in` would emit both strings and satisfy
    /// unbound assertions, which is a misattribution the byte-for-byte comparison below does
    /// catch and a substring does not. Keeping both is deliberate: the comparison names the
    /// file that drifted, these name what the drift means.
    #[test]
    fn w3_golden_crate_matches_committed_output() {
        let spec = ozpb_synthesizer::walkthroughs::soroswap_swap_spec();
        let g = generate(&spec, 0, &Pins::default()).unwrap();
        // W3 must emit a bound check, a scval-equality check, and an arity-only AnyValue.
        let lib = &emitted_rust(&g);
        // arg 0 — amount_in, capped: an upper bound denies above it.
        assert!(
            lib.contains(
                "let Some(v0) = args.get(0u32) else {\n        return false;\n    };\n    \
                 match i128::try_from_val(e, &v0) {\n        Ok(x) => {\n            \
                 if x > 1000000000i128 {"
            ),
            "amount_in cap must be the bound on arg 0"
        );
        // arg 1 — amount_out_min, floored: a lower bound denies below it.
        assert!(
            lib.contains(
                "let Some(v1) = args.get(1u32) else {\n        return false;\n    };\n    \
                 match i128::try_from_val(e, &v1) {\n        Ok(x) => {\n            \
                 if x < 950000000i128 {"
            ),
            "amount_out_min floor must be the bound on arg 1"
        );
        // arg 2 — the exact route, compared against the bytes hoisted for this (call, arg).
        assert!(
            lib.contains("if v2.to_xdr(e) != Bytes::from_slice(e, &CALL_0_ARG_2_XDR)"),
            "exact path must compare arg 2 against its own hoisted constant"
        );
        // arg 4 — the caller-chosen deadline: arity only...
        assert!(
            lib.contains("if args.get(4u32).is_none()"),
            "any-deadline arity-only check"
        );
        // ...and never bound, which is the whole point of the widening. Bindings are named
        // `v{index}`, so the absence of this one is what says the AnyValue arm ran.
        assert!(
            !lib.contains("let Some(v4)"),
            "AnyValue must not bind the argument it leaves unconstrained"
        );

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/soroswap-swap-policy");
        if std::env::var("UPDATE_GOLDEN").is_ok() {
            std::fs::create_dir_all(root.join("src")).unwrap();
            for (rel, content) in &g.files {
                std::fs::write(root.join(rel), content).unwrap();
            }
            return;
        }
        // Every file, `Cargo.lock` included. It used to be exempted in favour of a substring check
        // on the *generated* content, which never read the committed file at all — so the committed
        // lockfile drifted from what codegen emits and nothing reported it. There is no reason for
        // the exemption: `emit_lockfile` includes one tracked lockfile and substitutes the package
        // name, so the output is a pure function of a committed file, and both generated crates
        // declare byte-identical manifests apart from that name.
        //
        // Unlike the W1 golden, this comparison can genuinely fail, and it is the only in-repo
        // check that detects the two committed lockfiles diverging.
        for (rel, content) in &g.files {
            let committed = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|_| {
                panic!("missing committed W3 golden {rel}; run with UPDATE_GOLDEN=1")
            });
            // Naming the file that drifted matters for the lockfile in particular: the generated
            // content comes from `contracts/golden-transfer-policy/Cargo.lock`, so editing *that*
            // file surfaces here, and a message blaming "W3" would point at the one file that did
            // not change.
            assert_eq!(
                &committed, content,
                "committed contracts/soroswap-swap-policy/{rel} differs from what codegen emits \
                 for it. For Cargo.lock the emitted content is \
                 contracts/golden-transfer-policy/Cargo.lock with the package name substituted, \
                 so a change to that file lands here too. Regenerate deliberately with \
                 UPDATE_GOLDEN=1. If the emitter changed rather than the spec, decide whether \
                 the template family needs a new version — see the note on the transfer golden."
            );
        }
    }
}
