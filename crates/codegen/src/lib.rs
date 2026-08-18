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
        "\n        // Not a permission check — every decision above is already made. This keeps the\n        // entries the policy depends on out of archival while it can still permit something.\n        if remaining > 0u32 {\n            let ttl = ttl_target(e);\n            if ttl > 0 {\n                e.storage().instance().extend_ttl(ttl / 2, ttl);\n                e.storage().persistent().extend_ttl(&key, ttl / 2, ttl);\n            }\n        }\n"
    } else {
        "\n        // Not a permission check — every decision above is already made. This keeps this\n        // contract's instance and code entries out of archival.\n        let ttl = ttl_target(e);\n        if ttl > 0 {\n            e.storage().instance().extend_ttl(ttl / 2, ttl);\n        }\n"
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
        "\n/// Ledgers this policy's own entries should be kept alive for.\n///\n/// Bounded twice. By the network's rolling `max_ttl()`, because a single extension can\n/// never reach further — a distant window is approached across successive calls rather\n/// than in one step. And by the rule's own window, because past VALID_UNTIL_LEDGER every\n/// enforce denies, so extending beyond it would pay rent for an artifact that can no\n/// longer permit anything.\n///\n/// `saturating_sub` is load-bearing: `enforce` rejects an expired rule before reaching\n/// here, but `install` has no such check, and a wrapped subtraction would turn an\n/// already-expired rule into the largest possible extension.\nfn ttl_target(e: &Env) -> u32 {\n    let remaining = VALID_UNTIL_LEDGER.saturating_sub(e.ledger().sequence());\n    let max = e.storage().max_ttl();\n    if remaining < max {\n        remaining\n    } else {\n        max\n    }\n}\n"
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
        "//! GENERATED POLICY — template family `{template_family}`.\n\
         //! Normalized codegen input hash: {hash}\n\
         //!\n\
         //! DO NOT EDIT BY HAND: any manual change switches this artifact to CUSTOM\n\
         //! SOURCE MODE (architecture §4.4) — spec conformance, differential testing,\n\
         //! and generated-mode guarantees no longer apply to an edited copy.\n\
         //!\n\
         //! Check order is the generated-code contract (§4.4): signer predicate first\n\
         //! (the OZ account defers signer validation to policies), then strict\n\
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
    // Several statements rather than one brace group naming every item: that group ran to 148
    // characters, so rustfmt reflowed it, and the fill it picks depends on which items the rule
    // needs — a formatting choice that would then vary from policy to policy. Split this way no
    // statement exceeds 89 characters for any combination below, so nothing reflows. The order
    // is `reorder_imports`': module paths (`Ident`) before brace groups (`List`), and inside a
    // group snake_case before CamelCase — which is why types and macros are two groups rather
    // than one sorted list.
    out.push_str("use soroban_sdk::auth::Context;\n");
    if has_scval {
        out.push_str("use soroban_sdk::xdr::ToXdr;\n");
    }
    let mut sdk_macros: Vec<&str> = vec![
        "contract",
        "contracterror",
        "contractimpl",
        "panic_with_error",
    ];
    if has_state {
        sdk_macros.push("contracttype");
    }
    sdk_macros.sort();
    out.push_str(&format!(
        "use soroban_sdk::{{{}}};\n",
        sdk_macros.join(", ")
    ));
    let mut sdk_types: Vec<&str> = vec!["Address", "Env", "Symbol", "TryFromVal", "Val", "Vec"];
    if has_scval || has_external {
        sdk_types.push("Bytes");
    }
    sdk_types.sort();
    out.push_str(&format!("use soroban_sdk::{{{}}};\n", sdk_types.join(", ")));
    out.push_str("use stellar_accounts::policies::Policy;\n");
    out.push_str("use stellar_accounts::smart_account::{ContextRule, Signer};\n\n");

    // Error enum (stable numbering; mirrors the reference evaluator's deny reasons).
    out.push_str(
        "#[contracterror]\n#[derive(Copy, Clone, Debug, PartialEq)]\n#[repr(u32)]\npub enum PolicyError {\n    ZeroSigners = 1,\n    PredicateUnsatisfied = 2,\n    SignerSetDiverged = 3,\n    TargetMismatch = 4,\n    FunctionNotAllowed = 5,\n    NoTupleMatched = 6,\n    CallCountExceeded = 7,\n    MissingState = 8,\n    RuleExpired = 9,\n    AlreadyInstalled = 10,\n}\n\n",
    );

    if has_state {
        out.push_str(
            "#[contracttype]\n#[derive(Clone, Debug)]\npub enum DataKey {\n    /// Call count for one installation, segregated by (smart account, context rule id).\n    /// Never resets while installed; `uninstall` removes it.\n    CallCount(Address, u32),\n}\n\n",
        );
    }

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
    if rule.valid_until_ledger.is_some() {
        out.push_str(
            "        if e.ledger().sequence() > VALID_UNTIL_LEDGER {\n            panic_with_error!(e, PolicyError::RuleExpired);\n        }\n\n",
        );
    }
    out.push_str(
        "        if authenticated_signers.len() == 0 {\n            panic_with_error!(e, PolicyError::ZeroSigners);\n        }\n",
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
    // A binding is at most 86 columns for the longest symbol Soroban accepts.
    for (fi, name) in fn_names.iter().enumerate() {
        out.push_str(&format!(
            "        let fn_{fi}_ok = c.fn_name == Symbol::new(e, \"{name}\");\n"
        ));
    }
    let known_expr = (0..fn_names.len())
        .map(|fi| format!("fn_{fi}_ok"))
        .collect::<Vec<_>>()
        .join(" || ");
    // A single allowed name needs no parens around the negation (clippy: unnecessary_parens).
    let known_test = if fn_names.len() > 1 {
        format!("!({known_expr})")
    } else {
        format!("!{known_expr}")
    };
    out.push_str(&format!(
        "        if {known_test} {{\n            panic_with_error!(e, PolicyError::FunctionNotAllowed);\n        }}\n"
    ));
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
            "    fn install(e: &Env, _install_params: u32, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);\n        if e.storage().persistent().has(&key) {\n            panic_with_error!(e, PolicyError::AlreadyInstalled);\n        }\n        e.storage().persistent().set(&key, &0u32);\n        let remaining = MAX_CALLS;\n",
        );
        out.push_str(ttl_extension_block(true));
        out.push_str(
            "    }\n\n    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n        let key = DataKey::CallCount(smart_account.clone(), context_rule.id);\n        e.storage().persistent().remove(&key);\n    }\n",
        );
    } else {
        out.push_str(
            "    fn install(e: &Env, _install_params: u32, _context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n",
        );
        out.push_str(ttl_extension_block(false));
        out.push_str(
            "    }\n\n    fn uninstall(e: &Env, _context_rule: ContextRule, smart_account: Address) {\n        smart_account.require_auth();\n    }\n",
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
        let spec = spec
            .validate()
            .expect("spec validation does not police this field");
        assert!(
            matches!(
                generate(&spec, 0, &Pins::default()),
                Err(CodegenError::TemplateFamily(_))
            ),
            "codegen must refuse a hostile template family rather than emit it"
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
        use base64::Engine as _;
        use ozpb_domain::{BlastRadius, LedgerSeq, Provenance};
        use ozpb_policy_spec::{
            AddressRef, AllowedCall, ArgConstraint, Constraint, PredicateKind, SignerSpec,
            StateSpec, ValidUntil,
        };
        use proptest::prelude::Strategy;
        use proptest::strategy::Just;

        /// A widening constraint with `ObservedExact` provenance is rejected by spec
        /// validation, so provenance is derived from the constraint rather than generated.
        fn provenance_for(constraint: &Constraint) -> Provenance {
            if constraint.is_widening() {
                Provenance::UserWidened {
                    intent: "property-test widening".to_string(),
                    blast_radius: BlastRadius::Medium,
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
                proptest::collection::vec(proptest::prelude::any::<u8>(), 0..24).prop_map(
                    |bytes| Constraint::EqScval {
                        xdr_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                    }
                ),
                Just(Constraint::AnyValue),
            ]
        }

        fn call_strategy() -> impl Strategy<Value = AllowedCall> {
            let names = vec![
                "transfer".to_string(),
                "swap".to_string(),
                "claim_rewards".to_string(),
                // Boundary: the longest symbol Soroban accepts.
                "a".repeat(32),
            ];
            (
                proptest::sample::select(names),
                proptest::collection::vec(constraint_strategy(), 0..5),
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
                // The counter entry is extended only when there is a counter.
                assert_eq!(
                    source.contains("persistent().extend_ttl(&key"),
                    max_calls.is_some(),
                    "counter extension does not match the rule shape for {label}"
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

        proptest::proptest! {
            /// Every ValidatedSpec must emit Rust that parses. Parsing (rather than
            /// compiling) keeps this fast enough for CI; `sampled_specs_compile_to_wasm`
            /// covers the real toolchain.
            #[test]
            fn any_validated_spec_generates_parseable_rust(
                calls in proptest::collection::vec(call_strategy(), 1..4),
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
        /// not contain (an external signer, a dynamic predicate carrying one) are caught here.
        fn unbalanced_constants(source: &str) -> Vec<String> {
            let declared: Vec<&str> = source
                .lines()
                .filter_map(|line| line.strip_prefix("const "))
                .filter_map(|rest| rest.split(':').next())
                .collect();
            let mut problems = Vec::new();
            for name in &declared {
                // Once for the declaration; a read is any further occurrence.
                if source.matches(*name).count() < 2 {
                    problems.push(format!("`{name}` is declared and never read"));
                }
            }
            // The generated names, wherever they appear. Anything matching that is not declared
            // is a reference emission failed to back with a constant.
            for token in source.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                let generated = token.starts_with("SIGNER_") || token.starts_with("CALL_");
                if generated && !declared.contains(&token) {
                    problems.push(format!("`{token}` is read and never declared"));
                }
            }
            problems.sort();
            problems.dedup();
            problems
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
        /// to every shipped wasm hash. The fmt gate adjudicates the two committed crates; this
        /// covers the shapes they do not contain, choosing the awkward ones deliberately: the
        /// longest symbol Soroban accepts, an `ScVal` long enough to wrap, an external signer's
        /// key, and more than one allowed call.
        #[test]
        fn emitted_code_stays_inside_rustfmt_width() {
            let long_scval = Constraint::EqScval {
                xdr_base64: base64::engine::general_purpose::STANDARD.encode([0xabu8; 40]),
            };
            let merchant = Constraint::EqAddress {
                value: AddressRef::address(ozpb_synthesizer::fixtures::golden_merchant_strkey()),
            };
            let justified = vec!["recordings[0]/auth[0]/root".to_string()];
            let mut spec = golden_spec().spec().clone();
            let rule = &mut spec.rules[0];
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
            for expected in ["const CALL_0_ARG_0_XDR: [u8; 40] = [", "let fn_1_ok = "] {
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

        /// A dynamic predicate carrying an external signer emits neither the key constant nor
        /// anything that would reference it.
        ///
        /// Spec validation permits the combination — it only forbids `strict_signer_set` on a
        /// dynamic rule — so it is reachable, and it is the shape where the compiled-in signer
        /// set and the rule's signer list disagree. Get it wrong in either direction and the
        /// generated crate carries a constant nothing uses, an import nothing uses, or a
        /// reference to a constant that was never emitted; the last does not compile at all.
        #[test]
        fn a_dynamic_predicate_compiles_in_no_signer_even_when_the_rule_carries_one() {
            let mut spec = golden_spec().spec().clone();
            let rule = &mut spec.rules[0];
            rule.authorization.kind = PredicateKind::AnyOfCurrentRuleSigners;
            // Dynamic rules may not be strict; spec validation rejects the pair.
            rule.authorization.strict_signer_set = false;
            rule.authorization.signers.push(SignerSpec::External {
                verifier: ozpb_synthesizer::fixtures::golden_token_strkey(),
                verifier_code_hash: ozpb_domain::sha256(b"external-verifier-code"),
                key_hex: hex::encode([0x5au8; 32]),
            });
            let signer_count = rule.authorization.signers.len();
            let spec = spec
                .validate()
                .expect("a dynamic rule carrying signers is a valid spec");
            // Non-vacuity: the point is that the rule *does* carry an external signer.
            assert_eq!(
                signer_count, 2,
                "the rule must carry the signers under test"
            );

            let source = generate(&spec, 0, &Pins::default())
                .expect("codegen must accept a dynamic rule carrying an external signer")
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
        let bad = bad.validate().unwrap();
        assert!(matches!(
            generate(&bad, 0, &Pins::default()).unwrap_err(),
            CodegenError::Address(_)
        ));

        let mut bad_fn = base.spec().clone();
        bad_fn.rules[0].allowed_calls[0].fn_name = "not a symbol!".to_string();
        let bad_fn = bad_fn.validate().unwrap();
        assert!(matches!(
            generate(&bad_fn, 0, &Pins::default()).unwrap_err(),
            CodegenError::Symbol(_)
        ));
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
                 UPDATE_GOLDEN=1 (custom-source edits are not allowed on the golden)"
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
}
