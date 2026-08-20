//! Toolkit facade: turns the pure cores into the operations the MCP server and CLI
//! expose, translating domain results into the `api-types` wire contract (stable error
//! codes, JSON-carried artifacts). This is a thin orchestration layer — no policy logic
//! lives here; it delegates to the cores and never reaches a network (acquisition is the
//! caller's job, keeping this crate pure and testable).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use base64::Engine;
use ozpb_api_types::ErrorCode as EC;
use ozpb_api_types::{
    EvaluateSpecInput, EvaluateSpecOutput, GenerateCodeInput, GenerateCodeOutput, RecordOutput,
    SynthesizeInput, SynthesizeOutput, ToolError,
};
use ozpb_codegen::{generate, Pins};
use ozpb_domain::Hash32;
use ozpb_evaluator::{evaluate, EvalContext, Invocation, Verdict};
use ozpb_policy_spec::{PolicyRef, PolicySpec};
use ozpb_recorder_core::{record, EvidenceSnapshot, RecordOptions, RecordingBundle};
use ozpb_registry::{Registry, RegistryCheckpoint, RegistryError, RootPolicy, SignedSnapshot};
use ozpb_synthesizer::{synthesize, SynthesisInput, UserDecisions};

/// Build configuration, re-exported so the shells configure the builder through this facade
/// rather than depending on `ozpb-build-runner` directly. Operator-side only — the wire
/// contract carries no build settings (see [`ENV_BUILD_TIMEOUT_SECS`] and friends).
///
/// `Builder` is deliberately NOT re-exported: a facade consumer cannot name the hermetic stub,
/// which emits unattestable wasm. For the same reason the building tools have no
/// default-config convenience wrapper — every one of them takes an explicit `&BuildConfig`, so
/// a caller cannot silently bypass operator configuration by picking the shorter name.
pub use ozpb_build_runner::{
    BuildConfig, ENV_BUILD_CACHE_DIR, ENV_BUILD_JOBS, ENV_BUILD_TIMEOUT_SECS, ENV_STELLAR_BINARY,
};

#[derive(Clone, Debug)]
pub struct RegistryTrust {
    pub root_policy: RootPolicy,
    /// Persisted anti-rollback floor. Hosted deployments keep this in durable config/state;
    /// local callers pin it alongside the root key and signed snapshot.
    pub minimum_version: u64,
    pub checkpoint: Option<RegistryCheckpoint>,
}

/// Turn an acquired evidence snapshot into a RecordingBundle output. Acquisition (RPC or
/// import) happens in the shell; this stays pure.
pub fn record_snapshot(
    snapshot: &EvidenceSnapshot,
    options: RecordOptions,
) -> Result<RecordOutput, ToolError> {
    let bundle = record(snapshot, options).map_err(|e| map_record_err(&e))?;
    let recording_hash = bundle
        .recording_hash()
        .map_err(|e| ToolError::new(EC::EInternal, e.to_string()))?;
    Ok(RecordOutput {
        trust: bundle.trust.as_str().to_string(),
        notes: bundle.evidence_notes.clone(),
        recording_hash: recording_hash.to_hex(),
        bundle: to_value(&bundle)?,
    })
}

pub fn synthesize_policy(
    input: &SynthesizeInput,
    registry_trust: &RegistryTrust,
) -> Result<SynthesizeOutput, ToolError> {
    let mut bundles: Vec<RecordingBundle> = input
        .bundles
        .iter()
        .map(from_value)
        .collect::<Result<_, _>>()?;
    if bundles.is_empty() {
        return Err(ToolError::new(
            EC::ENoEvidence,
            "no recording bundles supplied",
        ));
    }
    // JSON supplied to this boundary is caller-controlled, even when it was originally emitted
    // by `record_snapshot`. A serialized `rpc_reported` / `trusted_indexer` label is descriptive
    // provenance, not an authenticated receipt. Downgrade it before it can drive synthesis; a
    // future hosted acquisition service may add a separately verified receipt instead.
    for bundle in &mut bundles {
        bundle.trust = ozpb_domain::TrustLevel::self_supplied();
    }
    let mut account: ozpb_policy_spec::SmartAccountRecord = from_value(&input.account)?;
    let decisions: UserDecisions = from_value(&input.decisions)?;
    let signed_registry: SignedSnapshot = from_value(&input.signed_registry_snapshot)?;
    let network = bundles[0].network_id;
    let mut registry = match registry_trust.checkpoint.clone() {
        Some(checkpoint) => Registry::with_pinned_roots_for_network_at_checkpoint(
            registry_trust.root_policy.clone(),
            network,
            checkpoint,
        ),
        None => Registry::with_pinned_roots_for_network_at_version(
            registry_trust.root_policy.clone(),
            network,
            registry_trust.minimum_version,
        ),
    }
    .map_err(map_registry_err)?;
    let registry_snapshot = registry.load(&signed_registry).map_err(map_registry_err)?;

    let account_capability = registry
        .resolve_account(&account.observed_code_hash)
        .map_err(map_registry_err)?;
    account.registry_resolution = format!(
        "{} (registry entry {})",
        account_capability.release,
        account.observed_code_hash.to_hex()
    );

    let template = registry
        .resolve_template(&input.template_family)
        .map_err(map_registry_err)?;
    let template_capability_schema = template.capability_schema;
    let declared_constraint_kinds = template.constraint_kinds.clone();
    let declared_signer_predicates = template.signer_predicates.clone();
    let spending_limit_capability = match &input.spending_limit_capability {
        Some(h) => {
            let hash = parse_hash(h)?;
            let capability = registry.resolve_policy(&hash).map_err(map_registry_err)?;
            if capability.kind != "oz:spending_limit" {
                return Err(ToolError::new(
                    EC::EUnregisteredPolicy,
                    format!(
                        "policy {} is registered as '{}', not oz:spending_limit",
                        hash.to_hex(),
                        capability.kind
                    ),
                ));
            }
            Some(hash)
        }
        None => None,
    };

    let syn_input = SynthesisInput {
        bundles,
        selected_authorizer: input.selected_authorizer.clone(),
        account,
        registry_snapshot,
        spending_limit_capability,
        template_family: input.template_family.clone(),
        template_capability_schema,
        // Reviewed, code-hash-bound adapters would be resolved from the registry here (by the
        // target's observed code hash). No adapter capability is pinned in the current snapshot
        // schema, so synthesis stays exact-by-default + explicit user widenings.
        adapters: Vec::new(),
    };

    let out = synthesize(&syn_input, &decisions).map_err(map_synth_errs)?;
    within_declared_capabilities(
        &out.spec,
        &declared_constraint_kinds,
        &declared_signer_predicates,
    )?;
    // Validate immediately: the wire always carries a spec that passed validation.
    let validated = out
        .spec
        .clone()
        .validate()
        .map_err(|errs| spec_error(&errs))?;
    Ok(SynthesizeOutput {
        spec: to_value(&out.spec)?,
        spec_hash: validated.hash().to_hex(),
        rationale: out.rationale,
    })
}

/// Parse a pinned ed25519 registry root from configuration. This is deliberately separate
/// from `SynthesizeInput`: a request must never be able to choose the key that authenticates
/// its own registry snapshot.
pub fn parse_registry_root_hex(value: &str) -> Result<[u8; 32], ToolError> {
    hex::decode(value)
        .map_err(|_| ToolError::new(EC::ERegistrySignature, "registry root is not valid hex"))?
        .try_into()
        .map_err(|_| {
            ToolError::new(
                EC::ERegistrySignature,
                "registry root must be exactly 32 bytes",
            )
        })
}

pub fn registry_trust_from_config(
    root_hex: &str,
    minimum_version: u64,
) -> Result<RegistryTrust, ToolError> {
    Ok(RegistryTrust {
        root_policy: RootPolicy {
            threshold: 1,
            keys: std::collections::BTreeMap::from([(
                "legacy".to_string(),
                parse_registry_root_hex(root_hex)?,
            )]),
        },
        minimum_version,
        checkpoint: None,
    })
}

/// Parse a production threshold-root policy from JSON:
/// `{ "threshold": 2, "keys": { "ops-a": "<32-byte hex>", ... } }`.
pub fn registry_trust_from_roots_json(
    roots_json: &str,
    minimum_version: u64,
) -> Result<RegistryTrust, ToolError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RootConfig {
        threshold: u32,
        keys: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        checkpoint: Option<RegistryCheckpoint>,
    }
    let config: RootConfig = serde_json::from_str(roots_json).map_err(|error| {
        ToolError::new(
            EC::ERegistrySignature,
            format!("invalid registry roots JSON: {error}"),
        )
    })?;
    let keys = config
        .keys
        .into_iter()
        .map(|(id, encoded)| parse_registry_root_hex(&encoded).map(|key| (id, key)))
        .collect::<Result<_, _>>()?;
    let root_policy = RootPolicy {
        threshold: config.threshold,
        keys,
    };
    Registry::with_pinned_roots(root_policy.clone()).map_err(map_registry_err)?;
    if config
        .checkpoint
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.version < minimum_version)
    {
        return Err(ToolError::new(
            EC::ERegistryRollback,
            "registry checkpoint is older than the configured minimum version",
        ));
    }
    Ok(RegistryTrust {
        root_policy,
        minimum_version,
        checkpoint: config.checkpoint,
    })
}

pub fn evaluate_spec(input: &EvaluateSpecInput) -> Result<EvaluateSpecOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errs| spec_error(&errs))?;
    let context: EvalContext = from_value(&input.context)?;
    let invocation: Invocation = from_value(&input.invocation)?;
    Ok(match evaluate(&validated, &context, &invocation) {
        Verdict::Permit => EvaluateSpecOutput {
            verdict: "permit".to_string(),
            deny_reason: None,
        },
        Verdict::Deny(reason) => EvaluateSpecOutput {
            verdict: "deny".to_string(),
            deny_reason: Some(format!("{reason:?}")),
        },
        Verdict::Indeterminate(reason) => EvaluateSpecOutput {
            verdict: "indeterminate".to_string(),
            deny_reason: Some(format!("{reason:?}")),
        },
    })
}

pub fn generate_code_with_build_config(
    input: &GenerateCodeInput,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<GenerateCodeOutput, ToolError> {
    let spec: PolicySpec = from_value(&input.spec)?;
    let validated = spec.validate().map_err(|errs| spec_error(&errs))?;
    let pins = Pins::default();
    let g = generate(&validated, input.rule_index, &pins)
        .map_err(|e| ToolError::new(EC::ECodegen, e.to_string()))?;
    let rule = validated
        .spec()
        .rules
        .get(input.rule_index)
        .ok_or_else(|| ToolError::new(EC::ECodegen, "rule index out of range"))?;
    let template_family = rule
        .policies
        .iter()
        .find_map(|policy| match policy {
            PolicyRef::Generated {
                template_family, ..
            } => Some(template_family.as_str()),
            PolicyRef::Reviewed { .. } => None,
        })
        .ok_or_else(|| ToolError::new(EC::ECodegen, "rule has no generated policy"))?;
    let artifact = ozpb_build_runner::build(
        &ozpb_build_runner::BuildRequest {
            generated: &g,
            spec_hash: validated.hash(),
            registry_snapshot: validated.spec().registry_snapshot,
            rule_index: input.rule_index,
            template_family,
            pins: &pins,
        },
        build_config,
    )
    .map_err(map_build_err)?;
    Ok(GenerateCodeOutput {
        crate_name: g.crate_name,
        files: g.files,
        normalized_input_hash: g.normalized_input_hash.to_hex(),
        soroban_sdk_version: pins.soroban_sdk,
        stellar_accounts_version: pins.stellar_accounts,
        wasm_base64: base64::engine::general_purpose::STANDARD.encode(&artifact.wasm),
        wasm_hash: artifact.manifest.wasm_hash.to_hex(),
        build_manifest: to_value(&artifact.manifest)?,
        build_manifest_hash: artifact.manifest_hash.to_hex(),
    })
}

#[cfg(test)]
pub(crate) mod test_support;

// --- helpers ---------------------------------------------------------------------------

fn to_value<T: serde::Serialize>(v: &T) -> Result<serde_json::Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::new(EC::EInternal, e.to_string()))
}

fn from_value<T: serde::de::DeserializeOwned>(v: &serde_json::Value) -> Result<T, ToolError> {
    serde_json::from_value(v.clone())
        .map_err(|e| ToolError::new(EC::ESpecInvalid, format!("malformed input JSON: {e}")))
}

fn parse_hash(hex: &str) -> Result<Hash32, ToolError> {
    Hash32::from_hex(hex).map_err(|e| ToolError::new(EC::ESpecInvalid, e.to_string()))
}

fn spec_error(errs: &[ozpb_policy_spec::SpecError]) -> ToolError {
    ToolError::new(EC::ESpecInvalid, "PolicySpec failed validation")
        .with_details(errs.iter().map(|e| e.to_string()).collect())
}

/// The serialized name of a constraint, as the registry's `constraint_kinds` spells it.
///
/// Matched exhaustively rather than through `serde_json`, for the same reason
/// `RenderRule::from_rule` is exhaustive: a new `Constraint` variant must be a compile error
/// here. Deriving the name from serialization would silently admit the new variant, and this
/// check would then vouch for a capability the reviewed template never declared.
fn constraint_kind_name(constraint: &ozpb_policy_spec::Constraint) -> &'static str {
    use ozpb_policy_spec::Constraint as C;
    match constraint {
        C::EqAddress { .. } => "eq_address",
        C::EqScval { .. } => "eq_scval",
        C::EqI128 { .. } => "eq_i128",
        C::LeI128 { .. } => "le_i128",
        C::GeI128 { .. } => "ge_i128",
        C::AnyValue => "any_value",
    }
}

/// Likewise for the signer predicate.
fn predicate_kind_name(kind: &ozpb_policy_spec::PredicateKind) -> &'static str {
    use ozpb_policy_spec::PredicateKind as P;
    match kind {
        P::AnyOf => "any_of",
        P::AllOf => "all_of",
        P::Threshold { .. } => "threshold",
        P::AnyOfCurrentRuleSigners => "any_of_current_rule_signers",
    }
}

/// Refuse a spec that uses a constraint or predicate the resolved template does not declare.
///
/// The registry entry for a template family records which predicate and constraint kinds a
/// reviewed instantiation implements. Until now nothing read those lists: they were an
/// assertion inside a signed document that no code checked, so the snapshot could describe a
/// vocabulary narrower or wider than the template's without any gate noticing — which is how
/// two entries came to name things that are not constraints or predicates at all.
///
/// Today this can only fire if the two drift apart, because synthesis emits exactly what
/// `exact_for` and the user's widenings produce and the corrected lists cover all of it. That
/// is the point: it is a tripwire for the next `Constraint` variant, or for the first
/// adapter-derived constraint, reaching a spec before the reviewed template claims to
/// implement it. `constraint_kind_name` is exhaustive so the variant cannot arrive unnoticed,
/// and this refuses if the registry has not caught up.
///
/// Scoped to the synthesize path deliberately: `generate_code` and `verify` take a
/// caller-supplied spec and are given no registry, so neither can perform this check. Closing
/// that path means making the signed snapshot a required input to those operations, which
/// changes the wire contract — later-milestone work, and stated here rather than left as an
/// implied guarantee.
fn within_declared_capabilities(
    spec: &PolicySpec,
    declared_constraint_kinds: &[String],
    declared_signer_predicates: &[String],
) -> Result<(), ToolError> {
    let mut undeclared: Vec<String> = Vec::new();
    for (rule_index, rule) in spec.rules.iter().enumerate() {
        let predicate = predicate_kind_name(&rule.authorization.kind);
        if !declared_signer_predicates.iter().any(|d| d == predicate) {
            undeclared.push(format!(
                "rules[{rule_index}] uses signer predicate '{predicate}', which \
                 {} does not declare",
                spec.rules[rule_index]
                    .policies
                    .iter()
                    .find_map(|policy| match policy {
                        PolicyRef::Generated {
                            template_family, ..
                        } => Some(template_family.as_str()),
                        PolicyRef::Reviewed { .. } => None,
                    })
                    .unwrap_or("the resolved template family")
            ));
        }
        for call in &rule.allowed_calls {
            for arg in &call.args {
                let kind = constraint_kind_name(&arg.constraint);
                if !declared_constraint_kinds.iter().any(|d| d == kind) {
                    undeclared.push(format!(
                        "rules[{rule_index}]/{}/arg {} uses constraint kind '{kind}', which the \
                         resolved template family does not declare",
                        call.fn_name, arg.index
                    ));
                }
            }
        }
    }
    if undeclared.is_empty() {
        return Ok(());
    }
    undeclared.sort();
    undeclared.dedup();
    Err(ToolError::new(
        EC::EUnregisteredTemplate,
        "the synthesized spec uses capabilities the resolved template family does not declare",
    )
    .with_details(undeclared))
}

fn map_record_err(e: &ozpb_recorder_core::RecordError) -> ToolError {
    use ozpb_recorder_core::RecordError as R;
    let code = match e {
        R::EnvelopeParse(_) => EC::EEnvelopeParse,
        R::UnsupportedEnvelope(_) => EC::EUnsupportedEnvelope,
        R::NoSorobanOp => EC::ENoSorobanOp,
        R::OperationSelection(_) => EC::EOperationSelection,
        R::TxFailed => EC::ETxFailed,
        R::UnsupportedMetaVersion(_) => EC::EUnsupportedMetaVersion,
        R::MetaParse(_) => EC::EMetaParse,
        R::UnsupportedAddress(_) => EC::EUnsupportedAddress,
        R::AuthParse(_) => EC::EAuthParse,
        R::ResourceLimit(_) => EC::EResourceLimit,
        R::Internal(_) => EC::EInternal,
    };
    ToolError::new(code, e.to_string())
}

fn map_synth_errs(errs: Vec<ozpb_synthesizer::SynthError>) -> ToolError {
    use ozpb_synthesizer::SynthError as S;
    let code = match errs.first() {
        Some(S::NoEvidence) => EC::ENoEvidence,
        Some(S::EvidenceTrust(_, _)) => EC::EEvidenceTrust,
        Some(S::NetworkMismatch) => EC::ENetworkMismatch,
        Some(S::AuthorizerNotFound(_)) => EC::EAuthorizerNotFound,
        Some(S::IncompatibleAccount(_)) => EC::EIncompatibleAccount,
        Some(S::UnsupportedPattern(_)) => EC::EUnsupportedPattern,
        Some(S::AmbiguousArgSemantics { .. }) => EC::EAmbiguousArgSemantics,
        Some(S::UnregisteredPolicy(_)) => EC::EUnregisteredPolicy,
        Some(S::NeedsDecision(_)) => EC::ENeedsDecision,
        Some(S::InvalidDecision(_)) => EC::ESpecInvalid,
        Some(S::Internal(_)) | None => EC::EInternal,
    };
    ToolError::new(code, "synthesis failed")
        .with_details(errs.iter().map(|e| e.to_string()).collect())
}

fn map_registry_err(error: RegistryError) -> ToolError {
    let code = match &error {
        RegistryError::Signature
        | RegistryError::RootPolicy(_)
        | RegistryError::Schema(_)
        | RegistryError::Parse(_) => EC::ERegistrySignature,
        RegistryError::Rollback { .. } => EC::ERegistryRollback,
        RegistryError::Transparency(_) => EC::ERegistryTransparency,
        RegistryError::Revoked { .. } => EC::ERegistryRevoked,
        RegistryError::Network { .. } => EC::ERegistryNetwork,
        RegistryError::NotYetValid { .. } | RegistryError::Expired { .. } => EC::ERegistryExpired,
        RegistryError::Validity { .. } => EC::ERegistryValidity,
        RegistryError::UnknownPolicy(_) => EC::EUnregisteredPolicy,
        RegistryError::UnknownAccount(_) => EC::EIncompatibleAccount,
        RegistryError::UnknownVerifier(_) => EC::EUnregisteredVerifier,
        RegistryError::UnknownTemplate(_) => EC::EUnregisteredTemplate,
        RegistryError::NotLoaded => EC::ERegistryEmpty,
        RegistryError::Internal(_) => EC::EInternal,
    };
    ToolError::new(code, error.to_string())
}

fn map_build_err(error: ozpb_build_runner::BuildError) -> ToolError {
    let code = match error {
        ozpb_build_runner::BuildError::Timeout => EC::EBuildTimeout,
        ozpb_build_runner::BuildError::ResourceLimit(_) => EC::EBuildResourceLimit,
        // Operator faults (unusable builder path, unusable cache) are not the caller's spec.
        ozpb_build_runner::BuildError::Unavailable(_) => EC::EBuildUnavailable,
        ozpb_build_runner::BuildError::Input(_)
        | ozpb_build_runner::BuildError::Failed(_)
        | ozpb_build_runner::BuildError::Internal(_) => EC::EBuildFailed,
    };
    ToolError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use ozpb_policy_spec::SignerSpec;
    use ozpb_recorder_core::fixtures::executed_snapshot;
    use ozpb_registry::dev as registry_dev;
    use ozpb_synthesizer::fixtures as fx;

    #[test]
    fn build_errors_map_to_distinct_wire_codes_per_cause() {
        use ozpb_build_runner::BuildError;
        for (error, expected) in [
            (BuildError::Timeout, EC::EBuildTimeout),
            (
                BuildError::ResourceLimit("too big".to_string()),
                EC::EBuildResourceLimit,
            ),
            (
                BuildError::Unavailable("no such builder".to_string()),
                EC::EBuildUnavailable,
            ),
            (
                BuildError::Failed("compile error".to_string()),
                EC::EBuildFailed,
            ),
        ] {
            assert_eq!(map_build_err(error.clone()).code, expected, "{error}");
        }
    }

    #[test]
    fn a_misconfigured_builder_is_not_reported_as_a_spec_that_will_not_compile() {
        let spec = fx::golden_spec();
        let input = GenerateCodeInput {
            spec: to_value(spec.spec()).unwrap(),
            rule_index: 0,
        };
        let misconfigured = ozpb_build_runner::BuildConfig {
            stellar_binary: std::path::PathBuf::from("/nonexistent/ozpb-not-a-builder"),
            ..ozpb_build_runner::BuildConfig::default()
        };
        let error = generate_code_with_build_config(&input, &misconfigured).unwrap_err();
        assert_eq!(
            error.code,
            EC::EBuildUnavailable,
            "an operator's broken builder path must not read as ESpecInvalid/EBuildFailed \
             to an agent: {}",
            error.message
        );
    }

    #[test]
    fn recorder_resource_limits_have_a_stable_wire_code() {
        let error = map_record_err(&ozpb_recorder_core::RecordError::ResourceLimit(
            "oversized evidence".to_string(),
        ));
        assert_eq!(error.code, EC::EResourceLimit);
    }

    #[test]
    fn record_then_synthesize_then_generate_end_to_end() {
        // The full Phase 1 pipeline through the wire types.
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(rec.trust, "rpc_reported");

        let syn_input = SynthesizeInput {
            bundles: vec![rec.bundle.clone()],
            selected_authorizer: fx::golden_account_strkey(),
            account: serde_json::to_value(&fx::golden_input().account).unwrap(),
            signed_registry_snapshot: signed_registry_json(),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let syn = synthesize_policy(&syn_input, &registry_trust()).unwrap();
        assert!(!syn.spec_hash.is_empty());

        let gen = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: syn.spec.clone(),
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap();
        assert!(gen.files.contains_key("src/lib.rs"));
        assert_eq!(gen.stellar_accounts_version, "0.7.2");

        // The generated scope permits, but the full spec also composes a reviewed
        // spending-limit policy that the Phase 1 evaluator deliberately does not simulate.
        let ctx = serde_json::json!({
            "smart_account": fx::golden_account_strkey(),
            "current_ledger": 100,
            "authenticated_signers": [{"delegated":{"address": fx::golden_delegate_strkey()}}],
            "rule_live_signers": [{"delegated":{"address": fx::golden_delegate_strkey()}}],
            "call_count_so_far": 0
        });
        let inv = serde_json::json!({
            "contract": fx::golden_token_strkey(),
            "fn_name": "transfer",
            "args": [
                {"address": fx::golden_account_strkey()},
                {"address": fx::golden_merchant_strkey()},
                {"i128": 500000000i64}
            ]
        });
        let out = evaluate_spec(&EvaluateSpecInput {
            spec: syn.spec.clone(),
            context: ctx,
            invocation: inv,
        })
        .unwrap();
        assert_eq!(out.verdict, "indeterminate");
        assert_eq!(
            out.deny_reason.as_deref(),
            Some("ReviewedPoliciesUnmodeled")
        );
    }

    #[test]
    fn generated_artifact_includes_wasm_and_a_binding_manifest() {
        let input = GenerateCodeInput {
            spec: serde_json::to_value(fx::golden_spec().spec()).unwrap(),
            rule_index: 0,
        };
        let config = build_config();
        let generated = generate_code_with_build_config(&input, &config).unwrap();

        assert!(!generated.wasm_base64.is_empty());
        assert_eq!(
            generated.build_manifest["wasm_hash"],
            serde_json::json!(generated.wasm_hash)
        );
        assert!(!generated.build_manifest_hash.is_empty());
    }

    #[test]
    fn synthesis_errors_map_to_stable_codes() {
        let mut d = fx::golden_decisions();
        d.delegate_signers.clear();
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let input = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: fx::golden_account_strkey(),
            account: serde_json::to_value(&fx::golden_input().account).unwrap(),
            signed_registry_snapshot: signed_registry_json(),
            decisions: serde_json::to_value(d).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::ENeedsDecision);
    }

    #[test]
    fn synthesis_rejects_untrusted_registry_evidence() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let mut input = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: fx::golden_account_strkey(),
            account: serde_json::to_value(&fx::golden_input().account).unwrap(),
            signed_registry_snapshot: signed_registry_json(),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };

        input.signed_registry_snapshot["snapshot"]["version"] = serde_json::json!(999);
        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::ERegistrySignature);

        input.signed_registry_snapshot = signed_registry_json();
        let attacker_trust = RegistryTrust {
            root_policy: RootPolicy {
                threshold: 1,
                keys: std::collections::BTreeMap::from([(
                    "legacy".to_string(),
                    ozpb_domain::sha256(b"attacker registry root").0,
                )]),
            },
            minimum_version: 1,
            checkpoint: None,
        };
        let err = synthesize_policy(&input, &attacker_trust).unwrap_err();
        assert_eq!(err.code, EC::ERegistrySignature);

        input.signed_registry_snapshot = signed_registry_json();
        let rollback_floor = RegistryTrust {
            root_policy: RootPolicy {
                threshold: 1,
                keys: std::collections::BTreeMap::from([(
                    "legacy".to_string(),
                    registry_dev::dev_root_verifying_bytes(),
                )]),
            },
            minimum_version: 2,
            checkpoint: None,
        };
        let err = synthesize_policy(&input, &rollback_floor).unwrap_err();
        assert_eq!(err.code, EC::ERegistryRollback);
    }

    #[test]
    fn synthesis_resolves_every_security_capability_from_the_registry() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let base = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: fx::golden_account_strkey(),
            account: serde_json::to_value(&fx::golden_input().account).unwrap(),
            signed_registry_snapshot: signed_registry_json(),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };

        let mut unknown_account = base.clone();
        unknown_account.account["observed_code_hash"] =
            serde_json::json!(ozpb_domain::sha256(b"unknown-account").to_hex());
        let err = synthesize_policy(&unknown_account, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EIncompatibleAccount);

        let mut unknown_policy = base.clone();
        unknown_policy.spending_limit_capability =
            Some(ozpb_domain::sha256(b"unknown-policy").to_hex());
        let err = synthesize_policy(&unknown_policy, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnregisteredPolicy);

        let mut unknown_template = base.clone();
        unknown_template.template_family = "policy-templates/unknown@1".to_string();
        let err = synthesize_policy(&unknown_template, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnregisteredTemplate);

        let mut decisions = fx::golden_decisions();
        decisions.delegate_signers = vec![SignerSpec::External {
            verifier: fx::golden_token_strkey(),
            verifier_code_hash: ozpb_domain::sha256(b"unknown-verifier"),
            key_hex: "00".repeat(32),
        }];
        let mut unsupported_external = base;
        unsupported_external.decisions = serde_json::to_value(decisions).unwrap();
        let err = synthesize_policy(&unsupported_external, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnsupportedPattern);
        assert!(err
            .details
            .iter()
            .any(|detail| detail.contains("external verifiers are unavailable in Phase 1")));
    }

    /// A spec may only use capabilities the resolved template family declares.
    ///
    /// The registry's `constraint_kinds` and `signer_predicates` were, until now, an assertion
    /// inside a signed document that no code read. This asserts they are read, and it does so
    /// the only way that can fail today: by narrowing the snapshot rather than widening the
    /// spec, because synthesis emits exactly what the corrected lists already cover. Take the
    /// dev snapshot, drop `eq_address` from the template's declared constraints, re-sign it
    /// with the dev key, and synthesize the golden spec — whose first argument is `SELF`, an
    /// `eq_address`. It must refuse.
    ///
    /// Narrowing the snapshot is also what the check is *for*: the failure it guards against is
    /// the reviewed template and the signed description of it drifting apart, in either
    /// direction.
    #[test]
    fn a_spec_may_not_use_capabilities_the_template_does_not_declare() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        let mut narrowed_snapshot = ozpb_registry::dev::dev_snapshot(
            ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
            1,
        );
        let template = narrowed_snapshot
            .templates
            .get_mut("policy-templates/scope@1")
            .expect("the dev snapshot declares the scope template");
        template
            .constraint_kinds
            .retain(|kind| kind != "eq_address");
        let re_signed =
            ozpb_registry::sign_snapshot(&registry_dev::dev_signing_key(), narrowed_snapshot)
                .expect("re-signing the dev snapshot");

        let input = SynthesizeInput {
            bundles: vec![rec.bundle],
            selected_authorizer: fx::golden_account_strkey(),
            account: serde_json::to_value(&fx::golden_input().account).unwrap(),
            signed_registry_snapshot: serde_json::to_value(&re_signed).unwrap(),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };

        let err = synthesize_policy(&input, &registry_trust()).unwrap_err();
        assert_eq!(err.code, EC::EUnregisteredTemplate);
        assert!(
            err.details
                .iter()
                .any(|detail| detail.contains("'eq_address'")),
            "the refusal must name the undeclared kind: {:?}",
            err.details
        );
    }
    #[test]
    fn caller_supplied_provenance_labels_are_downgraded_before_synthesis() {
        let rec = record_snapshot(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(rec.bundle["trust"], serde_json::json!("rpc_reported"));

        let mut forged = rec.bundle;
        forged["trust"] = serde_json::json!("trusted_indexer");
        let input = SynthesizeInput {
            bundles: vec![forged],
            selected_authorizer: fx::golden_account_strkey(),
            account: serde_json::to_value(&fx::golden_input().account).unwrap(),
            signed_registry_snapshot: signed_registry_json(),
            decisions: serde_json::to_value(fx::golden_decisions()).unwrap(),
            spending_limit_capability: Some(
                fx::golden_input()
                    .spending_limit_capability
                    .unwrap()
                    .to_hex(),
            ),
            template_family: "policy-templates/scope@1".to_string(),
        };
        let output = synthesize_policy(&input, &registry_trust()).unwrap();

        assert_eq!(
            output.spec["evidence"]["recordings"][0]["trust"],
            serde_json::json!("self_supplied"),
            "an unauthenticated wire label must not survive as trusted provenance"
        );
    }
}
