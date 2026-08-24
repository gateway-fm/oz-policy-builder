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
    files.insert("src/lib.rs".to_string(), emit_lib(&render_rule, &hash));

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

/// The TTL-extension statements shared by `enforce` and `install`.
///
/// Both entry points need identical wording, and a threshold that drifted between them would be
/// a cost bug rather than a compile error, so the text is written once.
///
/// The host extends when `current_ttl <= threshold` (`soroban-env-host`, `Storage::extend_ttl`).
/// The SDK's own doc comment says "below", which is off by one; the wording here follows the host.
/// Half the target is used so a busy policy pays for one extension per half-window instead of one
/// per authorization — a threshold equal to the target would write on every call.
///
/// When the rule caps its call count, `remaining` gates the whole block: an installation that has
/// just spent its last permitted call can never permit again, and buying the largest possible
/// extension at exactly that moment is the opposite of what the artifact claims to do. The shared
/// instance and code entries stay alive through whichever *other* installation is still active,
/// and when none is, the contract is useless to everyone and is meant to expire.
fn ttl_extension_block(has_state: bool) -> &'static str {
    if has_state {
        "\n        // Not a permission check — every decision above is already made. This keeps the\n        // entries the policy depends on out of archival while it can still permit something.\n        if remaining > 0u32 {\n            let ttl = ttl_target(e);\n            if ttl > 0 {\n                e.storage().instance().extend_ttl(ttl / 2, ttl);\n                e.storage()\n                    .persistent()\n                    .extend_ttl(&installed_key, ttl / 2, ttl);\n                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);\n            }\n        }\n"
    } else {
        "\n        // Not a permission check — every decision above is already made. This keeps this\n        // installation, contract instance and code out of archival while it can permit.\n        let ttl = ttl_target(e);\n        if ttl > 0 {\n            e.storage().instance().extend_ttl(ttl / 2, ttl);\n            e.storage()\n                .persistent()\n                .extend_ttl(&installed_key, ttl / 2, ttl);\n        }\n"
    }
}

/// The `ttl_target` helper, emitted at the end of the artifact.
///
/// Placed last on purpose. A reader opening a generated policy is there to learn what it permits,
/// and rent arithmetic between the constants and the signer set puts prose about archival ahead of
/// the first permission. Top-to-bottom now reads constants → signers → checks, with the storage
/// bookkeeping after `uninstall`.
fn emit_ttl_target(has_valid_until: bool) -> &'static str {
    if has_valid_until {
        "\n/// Ledgers this policy's own entries should be kept alive for.\n///\n/// Bounded twice. By the network's rolling `max_ttl()`, because a single extension can\n/// never reach further — a distant window is approached across successive calls rather\n/// than in one step. And by the rule's own window, because past VALID_UNTIL_LEDGER every\n/// entry point denies, so extending beyond it would pay rent for an artifact that can no\n/// longer permit anything.\n///\n/// `saturating_sub` is defense in depth after the explicit expiry checks: later changes\n/// cannot turn an already-expired rule into the largest possible extension.\nfn ttl_target(e: &Env) -> u32 {\n    let remaining = VALID_UNTIL_LEDGER.saturating_sub(e.ledger().sequence());\n    let max = e.storage().max_ttl();\n    if remaining < max {\n        remaining\n    } else {\n        max\n    }\n}\n"
    } else {
        "\n/// Ledgers this policy's own entries should be kept alive for.\n///\n/// This rule carries no validity window, so the only bound is the network's rolling\n/// `max_ttl()`; a single extension can never reach further than that.\nfn ttl_target(e: &Env) -> u32 {\n    e.storage().max_ttl()\n}\n"
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

[lib]
crate-type = ["lib", "cdylib"]

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
fn emit_lib(rule: &RenderRule, hash: &Hash32) -> String {
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

    let mut out = String::new();
    out.push_str(&format!(
        "// SPDX-License-Identifier: Apache-2.0 OR MIT\n\
         //! GENERATED POLICY — template family `{template_family}`.\n\
         //! Normalized codegen input hash: {hash}\n\
         //!\n\
         //! DO NOT EDIT BY HAND: any manual change switches this artifact to CUSTOM\n\
         //! SOURCE MODE (architecture §4.4) — spec conformance, differential testing,\n\
         //! and generated-mode guarantees no longer apply to an edited copy.\n\
         //!\n\
         //! Check order is the generated-code contract (§4.4): account authorization and\n\
         //! installation state first, then the signer predicate (the OZ account defers\n\
         //! signer validation to policies), then strict\n\
         //! signer-set, then target/function/tuple scoping, then stateful invariants\n\
         //! (missing state denies; the call cap never resets within an installation —\n\
         //! only `uninstall`, which the smart account alone can call, clears it).\n\
         //! No setters, no upgrade entry point.\n\
         //!\n\
         //! Storage lifetime is maintained **only while this policy is used**: a permitted\n\
         //! call, or `install`, extends the entries it depends on toward the rule's validity\n\
         //! window where one is set and the network maximum otherwise — never past either.\n\
         //! An installed but idle policy still drifts into archival, and so does one that\n\
         //! only ever denies, since a denial reverts the extension along with everything\n\
         //! else. First use after a long gap may therefore cost a restore. Once a call cap\n\
         //! is spent the policy stops extending entirely: it can never permit again, so it\n\
         //! stops paying rent.\n"
    ));
    out.push_str("#![no_std]\n\n");

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

    // Error enum (stable numbering; mirrors the reference evaluator's deny reasons).
    out.push_str(
        "#[contracterror]\n#[derive(Copy, Clone, Debug, PartialEq)]\n#[repr(u32)]\npub enum PolicyError {\n    ZeroSigners = 1,\n    PredicateUnsatisfied = 2,\n    SignerSetDiverged = 3,\n    TargetMismatch = 4,\n    FunctionNotAllowed = 5,\n    NoTupleMatched = 6,\n    CallCountExceeded = 7,\n    MissingState = 8,\n    RuleExpired = 9,\n    AlreadyInstalled = 10,\n    NotInstalled = 11,\n}\n\n",
    );

    out.push_str(
        "#[contracttype]\n#[derive(Clone, Debug)]\npub enum DataKey {\n    /// Installation marker, segregated by (smart account, context rule id).\n    Installed(Address, u32),\n",
    );
    if has_state {
        out.push_str(
            "    /// Call count for one installation. Never resets until `uninstall`.\n    CallCount(Address, u32),\n",
        );
    }
    out.push_str("}\n\n");

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

    // Expected signer set (sorted canonical order — deterministic).
    if !dynamic {
        out.push_str(
            "fn expected_signers(e: &Env) -> Vec<Signer> {\n    soroban_sdk::vec![\n        e,\n",
        );
        // Already in canonical signer order — see `RenderRule::from_rule`.
        //
        // `Address::from_str` is written across four lines because rustfmt writes it that way:
        // a strkey is always 56 characters, so the argument list is 61 and exceeds rustfmt's
        // `fn_call_width` of 60 whatever the surrounding indentation. Emitting it on one line
        // meant every generated policy failed `cargo fmt --check`.
        for (index, signer) in compiled_signers.iter().enumerate() {
            match signer {
                RenderSigner::Delegated(address) => out.push_str(&format!(
                    "        Signer::Delegated(Address::from_str(\n            e,\n            \"{address}\"\n        )),\n"
                )),
                RenderSigner::External { verifier, .. } => out.push_str(&format!(
                    "        Signer::External(\n            Address::from_str(\n                e,\n                \"{verifier}\"\n            ),\n            Bytes::from_slice(e, &{})\n        ),\n",
                    render::signer_key_name(index)
                )),
            }
        }
        out.push_str("    ]\n}\n\n");
    }

    // Matched-count helper (iterates expected → duplicates never double-count).
    out.push_str(
        "fn matched_count(authenticated: &Vec<Signer>, expected: &Vec<Signer>) -> u32 {\n    let mut matched: u32 = 0;\n    for exp in expected.iter() {\n        for got in authenticated.iter() {\n            if got == exp {\n                matched += 1;\n                break;\n            }\n        }\n    }\n    matched\n}\n\n",
    );

    // One check function per allowed tuple.
    for (ci, call) in rule.calls.iter().enumerate() {
        out.push_str(&format!(
            "fn check_call_{ci}(e: &Env, args: &Vec<Val>, smart_account: &Address) -> bool {{\n"
        ));
        out.push_str(&format!(
            "    if args.len() != {}u32 {{\n        return false;\n    }}\n",
            call.args.len()
        ));
        // `call.args` is already in index order (see `RenderRule::from_rule`).
        for arg in &call.args {
            let i = arg.index;
            // AnyValue (maximal widening): enforce arity only, never bind the value.
            if matches!(arg.constraint, RenderConstraint::AnyValue) {
                out.push_str(&format!(
                    "    if args.get({i}u32).is_none() {{\n        return false;\n    }}\n"
                ));
                continue;
            }
            out.push_str(&format!(
                "    let Some(v{i}) = args.get({i}u32) else {{\n        return false;\n    }};\n"
            ));
            match &arg.constraint {
                RenderConstraint::EqSelf | RenderConstraint::EqAddress(_) => {
                    // The literal form is broken across lines for the reason given at
                    // `expected_signers`: a 56-character strkey puts `Address::from_str`'s
                    // argument list past rustfmt's `fn_call_width`, so rustfmt splits it here
                    // too — with a trailing comma, unlike inside the `vec!` above.
                    let cmp = match &arg.constraint {
                        RenderConstraint::EqSelf => "*smart_account != a".to_string(),
                        RenderConstraint::EqAddress(address) => format!(
                            "a != Address::from_str(\n                e,\n                \"{address}\",\n            )"
                        ),
                        _ => unreachable!("guarded by the outer arm"),
                    };
                    out.push_str(&format!(
                        "    match Address::try_from_val(e, &v{i}) {{\n        Ok(a) => {{\n            if {cmp} {{\n                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                RenderConstraint::EqI128(lit) => {
                    out.push_str(&format!(
                        "    match i128::try_from_val(e, &v{i}) {{\n        Ok(x) => {{\n            if x != {lit} {{\n                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                RenderConstraint::LeI128(lit) => {
                    out.push_str(&format!(
                        "    match i128::try_from_val(e, &v{i}) {{\n        Ok(x) => {{\n            if x > {lit} {{\n                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                RenderConstraint::GeI128(lit) => {
                    out.push_str(&format!(
                        "    match i128::try_from_val(e, &v{i}) {{\n        Ok(x) => {{\n            if x < {lit} {{\n                return false;\n            }}\n        }}\n        Err(_) => return false,\n    }}\n"
                    ));
                }
                // The bytes are a module constant (emitted above), so this line is short
                // whatever the recorded `ScVal` encodes to.
                RenderConstraint::EqScval(_) => {
                    out.push_str(&format!(
                        "    if v{i}.to_xdr(e) != Bytes::from_slice(e, &{}) {{\n        return false;\n    }}\n",
                        render::arg_xdr_name(ci, i)
                    ));
                }
                // Handled before the match (arity-only); listed for exhaustiveness.
                RenderConstraint::AnyValue => unreachable!("AnyValue handled before the match"),
            }
        }
        out.push_str("    true\n}\n\n");
    }

    // The contract.
    out.push_str("#[contract]\npub struct GeneratedPolicy;\n\n");
    out.push_str("#[contractimpl]\nimpl Policy for GeneratedPolicy {\n");
    out.push_str("    type AccountParams = u32;\n\n");

    // enforce()
    out.push_str(
        "    fn enforce(\n        e: &Env,\n        context: Context,\n        authenticated_signers: Vec<Signer>,\n        context_rule: ContextRule,\n        smart_account: Address,\n    ) {\n        smart_account.require_auth();\n\n",
    );
    out.push_str(
        "        let installed_key = DataKey::Installed(smart_account.clone(), context_rule.id);\n        if !e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::MissingState);\n        }\n\n",
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
        "        let c = match context {\n            Context::Contract(c) => c,\n            _ => panic_with_error!(e, PolicyError::FunctionNotAllowed),\n        };\n        if c.contract != Address::from_str(e, TARGET) {\n            panic_with_error!(e, PolicyError::TargetMismatch);\n        }\n",
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
    // The same measure `overlong_code_lines` applies to every emitted line; scalar count,
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
            "\n        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);\n        let count: u32 = match e.storage().persistent().get(&key) {\n            Some(c) => c,\n            None => panic_with_error!(e, PolicyError::MissingState),\n        };\n        if count >= MAX_CALLS {\n            panic_with_error!(e, PolicyError::CallCountExceeded);\n        }\n        e.storage().persistent().set(&key, &(count + 1u32));\n        let remaining = MAX_CALLS - (count + 1u32);\n",
        );
    }
    // Storage lifetime goes last. In `install` that ordering is required — the counter key does
    // not exist until its `set`, and extending first fails with `Error(Storage, MissingValue)`. In
    // `enforce` the key is guaranteed to exist by the `MissingState` check, so here it is a choice:
    // the two blocks stay textually identical, and a panic reverts the whole invocation anyway, so
    // there is nothing to gain by extending before the checks have passed.
    out.push_str(ttl_extension_block(has_state));
    out.push_str("    }\n\n");

    // install() / uninstall()
    //
    // `install` extends; `uninstall` deliberately does not. Extending on the way out would buy
    // rent for an entry being removed and for a contract the account is detaching from — and if
    // the code were archived, the call could not be executing in the first place.
    if has_state {
        out.push_str(
            "    fn install(e: &Env, _install_params: u32, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n",
        );
        if rule.valid_until_ledger.is_some() {
            out.push_str(
                "        if e.ledger().sequence() > VALID_UNTIL_LEDGER {\n            panic_with_error!(e, PolicyError::RuleExpired);\n        }\n",
            );
        }
        out.push_str(
            "        let installed_key = DataKey::Installed(smart_account.clone(), context_rule.id);\n        if e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::AlreadyInstalled);\n        }\n        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);\n        e.storage().persistent().set(&installed_key, &true);\n        e.storage().persistent().set(&key, &0u32);\n        let remaining = MAX_CALLS;\n",
        );
        out.push_str(ttl_extension_block(true));
        out.push_str(
            "    }\n\n    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n        let installed_key = DataKey::Installed(smart_account.clone(), context_rule.id);\n        if !e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::NotInstalled);\n        }\n        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);\n        e.storage().persistent().remove(&key);\n        e.storage().persistent().remove(&installed_key);\n    }\n",
        );
    } else {
        out.push_str(
            "    fn install(e: &Env, _install_params: u32, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n",
        );
        if rule.valid_until_ledger.is_some() {
            out.push_str(
                "        if e.ledger().sequence() > VALID_UNTIL_LEDGER {\n            panic_with_error!(e, PolicyError::RuleExpired);\n        }\n",
            );
        }
        out.push_str(
            "        let installed_key = DataKey::Installed(smart_account.clone(), context_rule.id);\n        if e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::AlreadyInstalled);\n        }\n        e.storage().persistent().set(&installed_key, &true);\n",
        );
        out.push_str(ttl_extension_block(false));
        out.push_str(
            "    }\n\n    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n        let installed_key = DataKey::Installed(smart_account.clone(), context_rule.id);\n        if !e.storage().persistent().has(&installed_key) {\n            panic_with_error!(e, PolicyError::NotInstalled);\n        }\n        e.storage().persistent().remove(&installed_key);\n    }\n",
        );
    }
    out.push_str("}\n");
    out.push_str(emit_ttl_target(rule.valid_until_ledger.is_some()));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
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
            let source = generate(&spec, 0, &Pins::default()).unwrap().files["src/lib.rs"].clone();
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
        fn spec_with(
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
                let source = generate(&spec, 0, &Pins::default())
                    .unwrap_or_else(|e| panic!("codegen refused {label}: {e}"))
                    .files["src/lib.rs"]
                    .clone();

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
            let source = generate(&spec, 0, &Pins::default()).unwrap().files["src/lib.rs"].clone();

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
                let source = &generated.files["src/lib.rs"];
                syn::parse_file(source).map_err(|e| {
                    proptest::test_runner::TestCaseError::fail(format!(
                        "generated source does not parse as Rust: {e}\n--- source ---\n{source}"
                    ))
                })?;
                let wide = overlong_code_lines(source);
                if !wide.is_empty() {
                    return Err(proptest::test_runner::TestCaseError::fail(format!(
                        "generated source has lines rustfmt would reflow: {wide:?}\
                         \n--- source ---\n{source}"
                    )));
                }
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

        /// Lines of emitted code that rustfmt would have to reflow, as `(line, columns)`.
        ///
        /// The width is read from `render::MAX_WIDTH`, the one emission derives its layout from.
        /// A second copy of the number here would let the two drift, and the drift would show up
        /// as a passing test over source `cargo fmt --check` rejects.
        ///
        /// Comments are excluded: rustfmt does not rewrap them (`wrap_comments` is off by
        /// default), and the generated header quotes a template-family identifier that can
        /// legitimately carry a `//!` line past the width.
        fn overlong_code_lines(source: &str) -> Vec<(usize, usize)> {
            use render::MAX_WIDTH;
            source
                .lines()
                .enumerate()
                .filter(|(_, line)| !line.trim_start().starts_with("//"))
                .map(|(index, line)| (index + 1, line.chars().count()))
                .filter(|(_, columns)| *columns > MAX_WIDTH)
                .collect()
        }

        /// Emission keeps every line of code inside rustfmt's default width.
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
            let source = generate(&spec, 0, &Pins::default())
                .expect("codegen must accept the awkward spec")
                .files["src/lib.rs"]
                .clone();

            // Non-vacuity: a pass means nothing unless the awkward shapes are really emitted.
            for expected in ["const CALL_0_ARG_0_XDR: [u8; 48] = [", "let fn_1_ok = "] {
                assert!(
                    source.contains(expected),
                    "this test does not exercise what it claims: no {expected:?} in\n{source}"
                );
            }

            let wide = overlong_code_lines(&source);
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
            let source = generate(&spec, 0, &Pins::default())
                .expect("codegen must accept the boundary spec")
                .files["src/lib.rs"]
                .clone();

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

            let wide = overlong_code_lines(&source);
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

            syn::parse_file(&source).expect("the boundary emission must parse");
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

            let source = generate(&spec, 0, &Pins::default())
                .expect("codegen must accept a dynamic rule carrying named signers")
                .files["src/lib.rs"]
                .clone();

            syn::parse_file(&source).expect("generated source must parse");
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
        assert_eq!(a.files["src/lib.rs"], b.files["src/lib.rs"]);
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
            a.files["src/lib.rs"], b.files["src/lib.rs"],
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
        assert!(b.files["src/lib.rs"].contains("if x > 1000000000i128"));
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
        let lib = generate(&spec, 0, &Pins::default()).unwrap().files["src/lib.rs"].clone();
        assert!(
            lib.contains("if x != i128::MIN"),
            "i128::MIN must be emitted as the named constant, got:\n{lib}"
        );
        assert!(
            !lib.contains(&format!("{}i128", i128::MIN)),
            "the overflowing positive literal must never be emitted as a source token"
        );
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
                "use soroban_sdk::{\n    auth::Context, contract, contracterror, contractimpl, \
                 contracttype, panic_with_error, Address,\n    Env, Symbol, TryFromVal, Val, \
                 Vec,\n};\n",
            ),
            (
                "W3 swap",
                ozpb_synthesizer::walkthroughs::soroswap_swap_spec(),
                "use soroban_sdk::{\n    auth::Context, contract, contracterror, contractimpl, \
                 contracttype, panic_with_error,\n    xdr::ToXdr, Address, Bytes, Env, Symbol, \
                 TryFromVal, Val, Vec,\n};\n",
            ),
        ] {
            let source = generate(&spec, 0, &Pins::default())
                .unwrap_or_else(|error| panic!("{label} must generate: {error}"))
                .files["src/lib.rs"]
                .clone();
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
            let source = generate(&spec, 0, &Pins::default())
                .unwrap_or_else(|error| panic!("{label} must generate: {error}"))
                .files["src/lib.rs"]
                .clone();
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
        let lib = &g.files["src/lib.rs"];
        // Signer predicate first, with strict set.
        assert!(lib.contains("PolicyError::ZeroSigners"));
        assert!(lib.contains("SignerSetDiverged"));
        assert!(lib.contains(&golden_delegate_strkey()));
        // SELF resolves at runtime (no account literal in the tuple check).
        assert!(lib.contains("*smart_account != a"));
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
        // Lockfile drift is caught elsewhere instead: a lockfile that is not a complete
        // resolution of the emitted manifest fails the `--locked` build in `BUILD_ARGS`, which is
        // what `ozpb generate` and the nightly wasm job run. With one committed generated crate in
        // the tree there is no second committed lockfile for this one to drift from.
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

    /// The comparators no committed crate exercises, held to the text they emit.
    ///
    /// This milestone commits one generated crate, the transfer golden, and its only argument
    /// comparator is an exact `EqI128` (`if x != 500000000i128`), so
    /// `LeI128`, `GeI128`, `EqScval` and `AnyValue` reach no committed artifact here. The
    /// property test (`any_validated_spec_generates_parseable_rust`) reaches them but checks
    /// shape alone: parses as Rust, stays inside rustfmt's width, balances its constants. An
    /// inverted comparison, a cap and floor swapped between arguments, or an `AnyValue` arm that
    /// bound the value it was widened away from satisfies all of that and still permits the
    /// wrong call.
    ///
    /// `soroswap_swap_spec` is the fixture that reaches all four at once, and it needs only the
    /// spec and the emitter. Which is why each assertion is bound to the argument its
    /// constraint belongs to: every arm shadows its value as `x`, so `if x > 1000000000i128`
    /// alone would not say *which* argument is capped.
    #[test]
    fn w3_emission_shapes_are_held_to_the_checks_they_claim() {
        let spec = ozpb_synthesizer::walkthroughs::soroswap_swap_spec();
        let lib = generate(&spec, 0, &Pins::default()).unwrap().files["src/lib.rs"].clone();
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
    }
}
