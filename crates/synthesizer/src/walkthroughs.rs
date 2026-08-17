//! Recording fixtures over unlike protocol shapes, so that the synthesizer and the code
//! generator are exercised on more than one. The shared fixtures carry a SEP-41 subscription
//! transfer; this module adds a Blend yield claim (inbound, no spending limit, an exact
//! reserve list) and a bounded Soroswap delegation (a user-widened input cap, a user-supplied
//! output floor, an exact route, a caller-chosen deadline). Each is built by running the
//! synthesizer over a constructed recording plus explicit user decisions and then validating
//! the result, so a shape that stops being synthesizable fails here instead of surviving as a
//! hand-written literal that no longer corresponds to anything the pipeline produces.
//!
//! `ozpb-codegen` uses them as the corpus for its emitted-literal tripwire, where the value is
//! exactly that the three specs disagree about argument kinds, widening provenance and
//! constraint mix — one fixture would not tell it much.
//!
//! Architecture §7 describes three end-to-end walkthroughs over these same protocols; those
//! are second-milestone deliverables. What is here borrows the protocols, not the deliverable:
//! these are inputs to this milestone's tests.

use crate::{synthesize, PredicateChoice, SynthesisInput, UserDecisions, Widening, WideningBound};
use ozpb_domain::pinned_upstream;
use ozpb_domain::{sha256, BlastRadius, NetworkId, TESTNET_PASSPHRASE};
use ozpb_policy_spec::{SignerSpec, SmartAccountRecord, ValidatedSpec};
use ozpb_recorder_core::{
    ArgSummary, AuthorizationRecord, AuthorizedCall, CredentialRecord, ExecutableObservation,
    Execution, InvocationNode, ObservedExecutable, RawEvidence, RecordingBundle, RECORDING_SCHEMA,
};
use std::collections::BTreeMap;

fn account() -> String {
    format!("{}", stellar_strkey::Contract([1u8; 32]))
}
fn delegate() -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey([7u8; 32]))
}
fn contract(byte: u8) -> String {
    format!("{}", stellar_strkey::Contract([byte; 32]))
}

fn account_record() -> SmartAccountRecord {
    SmartAccountRecord {
        address: account(),
        observed_code_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
        registry_resolution: "stellar-accounts@0.7.x (walkthrough)".to_string(),
        install_safe: true,
    }
}

/// Build a single-authorization RecordingBundle for a contract call (`fn(args)`) by the
/// account authorizer. Constructed directly (not from XDR) — the recorder's XDR path is
/// covered by its own fixtures; here we exercise the synthesizer over the shapes.
fn bundle_for(target: &str, fn_name: &str, args: Vec<ArgSummary>, tag: &[u8]) -> RecordingBundle {
    let mut contract_executables = BTreeMap::new();
    contract_executables.insert(
        account(),
        ExecutableObservation {
            executable: ObservedExecutable::Wasm {
                code_hash: account_record().observed_code_hash,
            },
            observed_ledger: ozpb_domain::LedgerSeq(4_200_000),
        },
    );
    contract_executables.insert(
        target.to_string(),
        ExecutableObservation {
            executable: ObservedExecutable::Wasm {
                code_hash: sha256(tag),
            },
            observed_ledger: ozpb_domain::LedgerSeq(4_200_000),
        },
    );
    RecordingBundle {
        schema: RECORDING_SCHEMA.to_string(),
        canonicalization_version: ozpb_domain::CANONICALIZATION_VERSION,
        network_id: NetworkId::from_passphrase(TESTNET_PASSPHRASE),
        trust: ozpb_domain::TrustLevel::rpc_reported(),
        execution: Execution::ExecutedSuccess,
        ledger: Some(ozpb_domain::LedgerSeq(4_200_000)),
        created_at_unix: Some(1_780_000_000),
        operation_index: 0,
        authorizations: vec![AuthorizationRecord {
            authorizer: account(),
            credential: CredentialRecord::Address {
                nonce: 1,
                signature_expiration_ledger: 4_210_000,
            },
            fingerprint: sha256(tag),
            root: InvocationNode {
                call: AuthorizedCall::Contract {
                    contract: target.to_string(),
                    fn_name: fn_name.to_string(),
                    args,
                },
                sub_invocations: vec![],
            },
        }],
        token_movements: vec![],
        state_changes: vec![],
        contract_executables,
        evidence_notes: vec![],
        raw: RawEvidence {
            envelope_xdr_base64: format!("fixture-envelope-{}", hex::encode(tag)),
            result_meta_xdr_base64: None,
            simulated_auth_xdr_base64: vec![],
        },
    }
}

fn base_input(bundle: RecordingBundle) -> SynthesisInput {
    SynthesisInput {
        bundles: vec![bundle],
        selected_authorizer: account(),
        account: account_record(),
        registry_snapshot: sha256(b"dev-registry-snapshot"),
        spending_limit_capability: Some(pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM),
        template_family: "policy-templates/scope@1".to_string(),
        template_capability_schema: sha256(b"policy-templates/scope@1:capability-algebra"),
        adapters: vec![],
    }
}

fn delegate_signers() -> Vec<SignerSpec> {
    vec![SignerSpec::Delegated {
        address: delegate(),
    }]
}

// ---------------------------------------------------------------------------------------
// W1 — Blend yield claim
// ---------------------------------------------------------------------------------------

pub const BLEND_POOL: fn() -> String = || contract(20);

/// `claim(from = SELF, reserve_token_ids, to = SELF)` on one specific Blend pool.
/// Exact-by-default: only that pool, only `claim`, `from`/`to` == SELF, the exact reserve
/// list, bounded by a call cap and `valid_until`. No spending limit (a claim is inbound).
pub fn blend_claim_spec() -> ValidatedSpec {
    let pool = BLEND_POOL();
    // reserve_token_ids modeled as an opaque ScVal (a Vec<u32>); recorded as Other.
    let reserve_ids = ArgSummary::Other {
        xdr_base64: "AAAAEAAAAAEAAAABAAAAAwAAAAA=".to_string(),
    };
    let bundle = bundle_for(
        &pool,
        "claim",
        vec![
            ArgSummary::Address(account()),
            reserve_ids,
            ArgSummary::Address(account()),
        ],
        b"w1-blend-claim",
    );
    let mut input = base_input(bundle);
    input.spending_limit_capability = None; // inbound claim: no spend cap needed
    let decisions = UserDecisions {
        grant_name: "blend-claim".to_string(),
        delegate_signers: delegate_signers(),
        predicate: PredicateChoice::AnyOf,
        valid_until_ledger: Some(4_300_000),
        no_expiry_acknowledged: false,
        max_calls: Some(30),
        widenings: vec![],
        spending_limit: None,
    };
    let out = synthesize(&input, &decisions).expect("W1 synthesis");
    out.spec.validate().expect("W1 validates")
}

// ---------------------------------------------------------------------------------------
// W3 — bounded Soroswap delegation
// ---------------------------------------------------------------------------------------

pub const SOROSWAP_ROUTER: fn() -> String = || contract(30);

/// `swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)`.
/// - amount_in: user_widened cap (LeI128)
/// - amount_out_min: user-provided absolute floor (GeI128) — never auto-derived
/// - path: exact (whitelisted route)
/// - to: SELF
/// - deadline: user-widened AnyValue (high blast radius; caller-chosen)
pub fn soroswap_swap_spec() -> ValidatedSpec {
    let router = SOROSWAP_ROUTER();
    let observed_amount_in: i128 = 1_000_000_000;
    let observed_out_min: i128 = 950_000_000;
    let path = ArgSummary::Other {
        xdr_base64: "AAAAEAAAAAEAAAACAAAAEgAAAAA=".to_string(),
    };
    let bundle = bundle_for(
        &router,
        "swap_exact_tokens_for_tokens",
        vec![
            ArgSummary::I128(observed_amount_in),
            ArgSummary::I128(observed_out_min),
            path,
            ArgSummary::Address(account()),
            ArgSummary::U64(1_780_500_000),
        ],
        b"w3-soroswap-swap",
    );
    let input = {
        let mut i = base_input(bundle);
        i.spending_limit_capability = None; // swap value is bounded by amount_in cap
        i
    };
    let decisions = UserDecisions {
        grant_name: "soroswap-swap".to_string(),
        delegate_signers: delegate_signers(),
        predicate: PredicateChoice::AnyOf,
        valid_until_ledger: Some(4_260_000),
        no_expiry_acknowledged: false,
        max_calls: Some(10),
        widenings: vec![
            Widening {
                contract: router.clone(),
                fn_name: "swap_exact_tokens_for_tokens".to_string(),
                arg_index: 0,
                bound: WideningBound::LeI128 {
                    max: observed_amount_in.to_string(),
                },
                intent: "cap amount_in at the observed maximum input".to_string(),
                blast_radius: BlastRadius::Medium,
            },
            Widening {
                contract: router.clone(),
                fn_name: "swap_exact_tokens_for_tokens".to_string(),
                arg_index: 1,
                bound: WideningBound::GeI128 {
                    min: observed_out_min.to_string(),
                },
                intent: "floor amount_out_min (user-provided absolute slippage floor)".to_string(),
                blast_radius: BlastRadius::Medium,
            },
            Widening {
                contract: router,
                fn_name: "swap_exact_tokens_for_tokens".to_string(),
                arg_index: 4,
                bound: WideningBound::AnyValue,
                intent: "deadline is caller-chosen; leave unconstrained (rule valid_until \
                         still bounds WHEN authorization can occur)"
                    .to_string(),
                blast_radius: BlastRadius::High,
            },
        ],
        spending_limit: None,
    };
    let out = synthesize(&input, &decisions).expect("W3 synthesis");
    out.spec.validate().expect("W3 validates")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_policy_spec::Constraint;

    #[test]
    fn w1_blend_claim_is_exact_and_scoped() {
        let spec = blend_claim_spec();
        let rule = &spec.spec().rules[0];
        assert_eq!(rule.context.contract, BLEND_POOL());
        assert_eq!(rule.allowed_calls[0].fn_name, "claim");
        // from and to are SELF; reserve ids exact.
        let args = &rule.allowed_calls[0].args;
        assert!(matches!(
            &args[0].constraint,
            Constraint::EqAddress {
                value: ozpb_policy_spec::AddressRef::SelfAccount(_)
            }
        ));
        assert!(matches!(&args[1].constraint, Constraint::EqScval { .. }));
        assert!(matches!(
            &args[2].constraint,
            Constraint::EqAddress {
                value: ozpb_policy_spec::AddressRef::SelfAccount(_)
            }
        ));
        // A claim is inbound → only the generated scope policy, no spending limit.
        assert_eq!(rule.policies.len(), 1);
    }

    #[test]
    fn w3_soroswap_has_cap_floor_exact_path_and_any_deadline() {
        let spec = soroswap_swap_spec();
        let rule = &spec.spec().rules[0];
        let args = &rule.allowed_calls[0].args;
        assert!(
            matches!(&args[0].constraint, Constraint::LeI128 { .. }),
            "amount_in cap"
        );
        assert!(
            matches!(&args[1].constraint, Constraint::GeI128 { .. }),
            "amount_out_min floor"
        );
        assert!(
            matches!(&args[2].constraint, Constraint::EqScval { .. }),
            "exact path"
        );
        assert!(matches!(
            &args[3].constraint,
            Constraint::EqAddress {
                value: ozpb_policy_spec::AddressRef::SelfAccount(_)
            }
        ));
        assert!(
            matches!(&args[4].constraint, Constraint::AnyValue),
            "any deadline"
        );
        // The deadline widening must be flagged high blast radius.
        assert!(matches!(
            &args[4].provenance,
            ozpb_domain::Provenance::UserWidened {
                blast_radius: BlastRadius::High,
                ..
            }
        ));
    }
}
