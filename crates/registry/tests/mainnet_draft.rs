//! `registry/mainnet/v0001.draft.json` is the unsigned genesis custodians would sign for mainnet.
//!
//! It is derived, not hand-written: the reviewed entries of development version 7 whose code is
//! identical on every network — the 0.7.3 account with its scan protocol and method inventory,
//! the ed25519 and WebAuthn verifiers, OpenZeppelin's spending limit and the template pack — as
//! version 1 of a new chain keyed by the mainnet network ID, keeping the revocation of the 0.7.2
//! account and dropping both its entry and the testnet-only Soroswap router binding. Its
//! validity interval is a placeholder, and the template pack's review reference is pending text:
//! the custodians set both before they sign (`registry/mainnet/README.md`).
//!
//! When the derivation changes, regenerate and read the diff before committing:
//!
//!     UPDATE_REGISTRY_DRAFT=1 cargo test -p ozpb-registry --test mainnet_draft

use ed25519_dalek::SigningKey;
use ozpb_domain::{pinned_upstream, sha256, target_adapters, NetworkId, MAINNET_PASSPHRASE};
use ozpb_registry::{
    dev, sign_snapshot_with_roots, Registry, RegistryError, RegistrySnapshot, RootPolicy,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// 2027-01-01T00:00:00Z: a placeholder, decided by the custodians at signing.
const PLACEHOLDER_VALID_FROM: i64 = 1_798_761_600;
/// 2027-07-01T00:00:00Z: a placeholder, decided by the custodians at signing.
const PLACEHOLDER_EXPIRES_AT: i64 = 1_814_400_000;

/// How a review reference the custodians must still supply begins.
const PENDING: &str = ozpb_registry::governance::PENDING_REVIEW_PREFIX;

fn mainnet() -> NetworkId {
    NetworkId::from_passphrase(MAINNET_PASSPHRASE)
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../registry/mainnet/v0001.draft.json")
}

fn derived() -> RegistrySnapshot {
    let mut snapshot = dev::range_constraint_successor(mainnet()).unwrap();
    snapshot.version = 1;
    snapshot.log_index = 1;
    snapshot.previous_root = None;
    snapshot.valid_from_unix = PLACEHOLDER_VALID_FROM;
    snapshot.expires_at_unix = PLACEHOLDER_EXPIRES_AT;
    // A development-registry assertion about the testnet router's code, not a reviewed binding.
    snapshot.target_adapters.clear();
    // Revoked: the revocation stays, so a refusal names the advisory; the entry does not.
    snapshot
        .accounts
        .remove(&pinned_upstream::OZ_SMART_ACCOUNT_0_7_2_WASM.to_hex());
    for revocation in snapshot.revocations.values_mut() {
        revocation.effective_version = 1;
    }
    // The development text claims an audit that has not happened; custodians sign every word.
    for template in snapshot.templates.values_mut() {
        template.review_reference = format!(
            "{PENDING} the reference of the completed security review that covers this template \
             family's code generation. No review is referenced yet."
        );
    }
    snapshot
}

fn committed() -> RegistrySnapshot {
    serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap()
}

#[test]
fn the_committed_mainnet_draft_is_the_derived_genesis() {
    let expected = serde_json::to_string_pretty(&derived()).unwrap() + "\n";
    if std::env::var_os("UPDATE_REGISTRY_DRAFT").is_some() {
        std::fs::write(path(), &expected).unwrap();
    }
    let actual = std::fs::read_to_string(path()).unwrap_or_default();
    assert_eq!(
        actual, expected,
        "registry/mainnet/v0001.draft.json has drifted from its derivation — regenerate with \
         `UPDATE_REGISTRY_DRAFT=1 cargo test -p ozpb-registry --test mainnet_draft` and read the diff"
    );
}

/// What the draft must hold, independently of how it is derived.
#[test]
fn the_draft_is_a_mainnet_genesis_with_only_cross_network_code() {
    let draft = committed();
    assert_eq!(draft.network_id, mainnet());
    assert_eq!((draft.version, draft.log_index), (1, 1));
    assert_eq!(draft.previous_root, None);
    assert!(
        draft.target_adapters.is_empty(),
        "no testnet-only adapter bindings"
    );
    assert_eq!(
        draft.accounts.keys().collect::<Vec<_>>(),
        vec![&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex()]
    );
    assert_eq!(
        draft.policies.keys().collect::<Vec<_>>(),
        vec![&pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM.to_hex()]
    );
    let mut verifiers = vec![
        pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex(),
        pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM.to_hex(),
    ];
    verifiers.sort();
    assert_eq!(
        draft.verifiers.keys().cloned().collect::<Vec<_>>(),
        verifiers
    );
    assert_eq!(
        draft.templates.keys().collect::<Vec<_>>(),
        vec!["policy-templates/scope@1"]
    );
    assert_eq!(
        (draft.valid_from_unix, draft.expires_at_unix),
        (PLACEHOLDER_VALID_FROM, PLACEHOLDER_EXPIRES_AT)
    );
}

/// Custodians sign every word of the draft, so it claims no review that has not happened. The
/// development entries' "audited with the template pack" is such a claim; the template pack's
/// reference is pending text the custodians replace with the real review's before signing.
#[test]
fn the_draft_claims_no_audit_and_marks_what_custodians_must_fill_in() {
    let draft = committed();
    let references: Vec<&str> = draft
        .policies
        .values()
        .map(|entry| entry.review_reference.as_str())
        .chain(
            draft
                .accounts
                .values()
                .map(|entry| entry.review_reference.as_str()),
        )
        .chain(
            draft
                .verifiers
                .values()
                .map(|entry| entry.review_reference.as_str()),
        )
        .chain(
            draft
                .templates
                .values()
                .map(|entry| entry.review_reference.as_str()),
        )
        .collect();
    for reference in &references {
        assert!(
            !reference.to_ascii_lowercase().contains("audited"),
            "a mainnet entry claims an audit: {reference}"
        );
    }
    let template = &draft.templates["policy-templates/scope@1"].review_reference;
    assert!(template.starts_with(PENDING), "{template}");
    // And so the draft as committed cannot be signed, combined or verified by accident.
    assert!(ozpb_registry::governance::require_no_pending_review(&draft).is_err());
}

/// Signed by any production-shaped root policy, the draft loads for mainnet inside its interval
/// and recognizes everything a mainnet install needs — and nothing for testnet.
#[test]
fn the_draft_loads_for_mainnet_once_signed_and_recognizes_the_reviewed_code() {
    let custodian = |id: &str| SigningKey::from_bytes(&sha256(id.as_bytes()).0);
    let roots = RootPolicy {
        threshold: 2,
        keys: ["a", "b", "c"]
            .into_iter()
            .map(|id| (id.to_string(), custodian(id).verifying_key().to_bytes()))
            .collect(),
    };
    let draft = committed();
    let signed = sign_snapshot_with_roots(
        &BTreeMap::from([
            ("a".to_string(), custodian("a")),
            ("c".to_string(), custodian("c")),
        ]),
        draft.clone(),
    )
    .unwrap();

    let mut registry =
        Registry::with_pinned_roots_for_network_at_version(roots.clone(), mainnet(), 1).unwrap();
    registry.load_at(&signed, PLACEHOLDER_VALID_FROM).unwrap();
    let authority = registry
        .resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM)
        .unwrap();
    assert_eq!(authority.methods.methods.len(), 17);
    for verifier in [
        pinned_upstream::OZ_ED25519_VERIFIER_WASM,
        pinned_upstream::OZ_WEBAUTHN_VERIFIER_WASM,
    ] {
        registry.resolve_signature_verifier(&verifier).unwrap();
    }
    assert_eq!(
        registry
            .resolve_policy(&pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM)
            .unwrap()
            .kind,
        "oz:spending_limit"
    );
    registry
        .resolve_template("policy-templates/scope@1")
        .unwrap();
    assert!(matches!(
        registry.resolve_account(&pinned_upstream::OZ_SMART_ACCOUNT_0_7_2_WASM),
        Err(RegistryError::Revoked { reason, .. }) if reason.starts_with("GHSA-jpg9-m7w4-c7wc")
    ));
    assert_eq!(
        registry
            .resolve_target_adapter(&target_adapters::SOROSWAP_ROUTER_TESTNET_WASM)
            .unwrap(),
        None
    );

    // Before its interval opens, and for testnet, it is refused.
    let mut early =
        Registry::with_pinned_roots_for_network_at_version(roots.clone(), mainnet(), 1).unwrap();
    assert!(matches!(
        early.load_at(&signed, PLACEHOLDER_VALID_FROM - 1),
        Err(RegistryError::NotYetValid { .. })
    ));
    let testnet = NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE);
    let mut elsewhere =
        Registry::with_pinned_roots_for_network_at_version(roots, testnet, 1).unwrap();
    assert!(matches!(
        elsewhere.load_at(&signed, PLACEHOLDER_VALID_FROM),
        Err(RegistryError::Network { .. })
    ));
}
