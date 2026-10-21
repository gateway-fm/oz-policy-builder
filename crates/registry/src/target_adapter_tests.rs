use super::*;
use ozpb_domain::{sha256, target_adapters};

fn fixture() -> (Hash32, RegistrySnapshot) {
    let hash = sha256(b"synthetic router implementation");
    let mut snapshot = dev::dev_snapshot(
        NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
        1,
    );
    snapshot.target_adapters.insert(
        hash.to_hex(),
        TargetAdapterCapability {
            implementation: "soroswap-router@1".into(),
            semantics_digest: target_adapters::soroswap_router().digest().unwrap(),
            review_reference: "https://example.invalid/synthetic-source-review".into(),
        },
    );
    (hash, snapshot)
}

fn load(snapshot: RegistrySnapshot) -> Result<Registry, RegistryError> {
    let mut registry = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })?;
    registry.load(&sign_snapshot(&dev::dev_signing_key(), snapshot)?)?;
    Ok(registry)
}

#[test]
fn existing_signed_snapshot_keeps_its_root_and_signature() {
    let text = include_str!("../../../docs/examples/registry.signed.json");
    let signed: SignedSnapshot = serde_json::from_str(text).unwrap();
    assert!(signed.snapshot.target_adapters.is_empty());
    assert_eq!(
        serde_json::to_value(&signed).unwrap(),
        serde_json::from_str::<serde_json::Value>(text).unwrap()
    );
    let mut registry = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })
    .unwrap();
    let root = registry.load(&signed).unwrap();
    assert_eq!(
        root.to_hex(),
        "a035495a8a898ba123c0d63c3eedc2f433666110a32f5f56fd089f8c0663803f"
    );
    let (_, injected) = fixture();
    let mut forged = signed;
    forged.snapshot.target_adapters = injected.target_adapters;
    let mut other = Registry::with_pinned_roots(RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
    })
    .unwrap();
    assert_eq!(other.load(&forged), Err(RegistryError::Signature));
}

#[test]
fn only_matching_active_reviewed_semantics_resolve() {
    let (hash, snapshot) = fixture();
    let registry = load(snapshot.clone()).unwrap();
    assert_eq!(
        registry.resolve_target_adapter(&hash).unwrap(),
        Some(target_adapters::soroswap_router())
    );
    assert_eq!(
        registry
            .resolve_target_adapter(&sha256(b"another code"))
            .unwrap(),
        None
    );
    for mutation in 0..3 {
        let mut changed = snapshot.clone();
        let entry = changed.target_adapters.get_mut(&hash.to_hex()).unwrap();
        match mutation {
            0 => entry.implementation = "unimplemented-adapter@1".into(),
            1 => entry.semantics_digest = sha256(b"altered roles"),
            _ => entry.review_reference = "  ".into(),
        }
        assert!(matches!(
            load(changed).unwrap().resolve_target_adapter(&hash),
            Err(RegistryError::TargetAdapterUnsupported(_))
        ));
    }
    for remove in [false, true] {
        let mut revoked = snapshot.clone();
        revoked.revocations.insert(
            format!("target_adapter/{hash}"),
            Revocation {
                reason: "synthetic revoked review".into(),
                effective_version: 1,
            },
        );
        if remove {
            revoked.target_adapters.clear();
        }
        assert!(matches!(
            load(revoked).unwrap().resolve_target_adapter(&hash),
            Err(RegistryError::Revoked { .. })
        ));
    }
}

#[test]
fn adapters_cannot_alias_other_code_roles_or_malformed_hashes() {
    let (_, snapshot) = fixture();
    let binding = snapshot.target_adapters.values().next().unwrap().clone();
    for hash in snapshot
        .policies
        .keys()
        .chain(snapshot.accounts.keys())
        .chain(snapshot.verifiers.keys())
    {
        let mut changed = snapshot.clone();
        changed
            .target_adapters
            .insert(hash.clone(), binding.clone());
        assert!(matches!(load(changed), Err(RegistryError::Parse(_))));
    }
    for bad in ["AB".repeat(32), "x".into(), "11".repeat(31)] {
        let mut changed = snapshot.clone();
        changed.target_adapters.insert(bad.clone(), binding.clone());
        assert!(matches!(load(changed), Err(RegistryError::Parse(_))));
        let mut changed = snapshot.clone();
        changed.revocations.insert(
            format!("target_adapter/{bad}"),
            Revocation {
                reason: "test".into(),
                effective_version: 1,
            },
        );
        assert!(matches!(load(changed), Err(RegistryError::Parse(_))));
    }
}
