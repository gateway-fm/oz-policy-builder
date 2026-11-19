use super::*;
use crate::dev;
use ozpb_domain::{sha256, MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

fn network() -> NetworkId {
    NetworkId::from_passphrase(TESTNET_PASSPHRASE)
}

/// A throwaway custodian key, never a real one.
fn custodian(id: &str) -> SigningKey {
    SigningKey::from_bytes(&sha256(format!("governance test custodian {id}").as_bytes()).0)
}

/// Two of three throwaway custodians.
fn roots() -> RootPolicy {
    RootPolicy {
        threshold: 2,
        keys: ["a", "b", "c"]
            .into_iter()
            .map(|id| (id.to_string(), custodian(id).verifying_key().to_bytes()))
            .collect(),
    }
}

/// A production-shaped genesis: the development v6 capabilities as version 1 of a new chain.
fn genesis() -> RegistrySnapshot {
    let mut snapshot = dev::account_advisory_successor(network()).unwrap();
    snapshot.version = 1;
    snapshot.log_index = 1;
    snapshot.previous_root = None;
    snapshot.valid_from_unix = 1_000;
    snapshot.expires_at_unix = 2_000;
    for revocation in snapshot.revocations.values_mut() {
        revocation.effective_version = 1;
    }
    snapshot
}

fn signed_by(snapshot: &RegistrySnapshot, ids: &[&str]) -> SignedSnapshot {
    let detached: Vec<_> = ids
        .iter()
        .map(|id| sign_detached(id, &custodian(id), snapshot).unwrap())
        .collect();
    combine(&roots(), snapshot.clone(), &detached).unwrap()
}

fn changes(valid_from: i64, expires_at: i64) -> ChangeSet {
    ChangeSet {
        schema: CHANGE_SCHEMA.to_string(),
        valid_from_unix: valid_from,
        expires_at_unix: expires_at,
        policies: BTreeMap::new(),
        accounts: BTreeMap::new(),
        verifiers: BTreeMap::new(),
        target_adapters: BTreeMap::new(),
        templates: BTreeMap::new(),
        revocations: BTreeMap::new(),
    }
}

fn revoked_hash() -> Hash32 {
    sha256(b"a reviewed policy later found faulty")
}

/// v1 → v2 (revokes [`revoked_hash`]) → v3, each signed by a different pair.
fn chain() -> Vec<SignedSnapshot> {
    let v1 = signed_by(&genesis(), &["a", "b"]);
    let mut revoke = changes(1_500, 3_000);
    revoke.revocations.insert(
        format!("policy/{}", revoked_hash().to_hex()),
        "found faulty in review".to_string(),
    );
    let v2 = successor(roots(), network(), &v1, &revoke, 1_600).unwrap();
    let v2 = signed_by(&v2, &["b", "c"]);
    let v3 = successor(roots(), network(), &v2, &changes(2_500, 5_000), 2_600).unwrap();
    let v3 = signed_by(&v3, &["a", "c"]);
    vec![v1, v2, v3]
}

#[test]
fn a_successor_is_the_next_link_and_loads_once_signed() {
    let v1 = signed_by(&genesis(), &["a", "b"]);
    let mut declared = changes(1_500, 3_000);
    let added = sha256(b"a newly reviewed policy");
    declared.policies.insert(
        added.to_hex(),
        PolicyCapability {
            kind: "oz:spending_limit".to_string(),
            signer_predicates: vec![],
            security_relevant_methods: vec!["enforce".to_string()],
            review_reference: "review of the new build".to_string(),
        },
    );
    declared.revocations.insert(
        format!("policy/{}", revoked_hash().to_hex()),
        "found faulty in review".to_string(),
    );
    let next = successor(roots(), network(), &v1, &declared, 1_600).unwrap();
    assert_eq!((next.version, next.log_index), (2, 2));
    assert_eq!(
        next.previous_root,
        Some(snapshot_root(&v1.snapshot).unwrap())
    );
    assert_eq!((next.valid_from_unix, next.expires_at_unix), (1_500, 3_000));
    assert!(next.policies.contains_key(&added.to_hex()));
    let revocation = &next.revocations[&format!("policy/{}", revoked_hash().to_hex())];
    assert_eq!(revocation.effective_version, 2);
    // Everything the parent carried is still there.
    for (key, value) in &v1.snapshot.accounts {
        assert_eq!(next.accounts.get(key), Some(value));
    }
    for (key, value) in &v1.snapshot.revocations {
        assert_eq!(next.revocations.get(key), Some(value));
    }

    // A consumer holding v1's checkpoint accepts it once two custodians sign it.
    let mut consumer =
        Registry::with_pinned_roots_for_network_at_version(roots(), network(), 1).unwrap();
    consumer.load_at(&v1, 1_100).unwrap();
    let checkpoint = consumer.checkpoint().unwrap();
    let mut restarted =
        Registry::with_pinned_roots_for_network_at_checkpoint(roots(), network(), checkpoint)
            .unwrap();
    restarted
        .load_at(&signed_by(&next, &["a", "c"]), 1_600)
        .unwrap();
}

/// Whatever a consumer's load would refuse is refused before anyone signs it.
#[test]
fn a_successor_a_consumer_would_refuse_is_never_built() {
    let v1 = signed_by(&genesis(), &["a", "b"]);
    let refused = |declared: &ChangeSet, now: i64| {
        successor(roots(), network(), &v1, declared, now).unwrap_err()
    };

    let mut wrong_schema = changes(1_500, 3_000);
    wrong_schema.schema = "registry-change/v0".to_string();
    assert!(matches!(
        refused(&wrong_schema, 1_600),
        GovernanceError::Change(_)
    ));

    // Already over at the time it would be published.
    assert!(matches!(
        refused(&changes(1_500, 3_000), 3_001),
        GovernanceError::Registry(RegistryError::Expired { .. })
    ));
    assert!(matches!(
        refused(&changes(3_000, 1_500), 1_600),
        GovernanceError::Registry(RegistryError::Validity { .. })
    ));

    let mut bad_key = changes(1_500, 3_000);
    bad_key.policies.insert(
        "NOT-A-HASH".to_string(),
        v1.snapshot.policies.values().next().unwrap().clone(),
    );
    assert!(matches!(
        refused(&bad_key, 1_600),
        GovernanceError::Registry(RegistryError::Parse(_))
    ));

    // A hash the parent knows as an account cannot also become a policy.
    let mut two_roles = changes(1_500, 3_000);
    two_roles.policies.insert(
        v1.snapshot.accounts.keys().next().unwrap().clone(),
        v1.snapshot.policies.values().next().unwrap().clone(),
    );
    assert!(matches!(
        refused(&two_roles, 1_600),
        GovernanceError::Registry(RegistryError::Parse(_))
    ));

    let mut blank_reason = changes(1_500, 3_000);
    blank_reason.revocations.insert(
        format!("policy/{}", revoked_hash().to_hex()),
        " ".to_string(),
    );
    assert!(matches!(
        refused(&blank_reason, 1_600),
        GovernanceError::Registry(RegistryError::Parse(_))
    ));

    // A recorded revocation is never rewritten.
    let recorded = v1.snapshot.revocations.keys().next().unwrap().clone();
    let mut rewrite = changes(1_500, 3_000);
    rewrite
        .revocations
        .insert(recorded, "a different reason".to_string());
    assert!(matches!(
        refused(&rewrite, 1_600),
        GovernanceError::Change(_)
    ));

    // The parent itself must be one a consumer accepts: signed under the pinned roots, for the
    // pinned network, by a root allowed there.
    let mut forged = v1.clone();
    forged.signatures.remove("b");
    assert!(matches!(
        successor(roots(), network(), &forged, &changes(1_500, 3_000), 1_600),
        Err(GovernanceError::Registry(RegistryError::Signature))
    ));
    let mainnet = NetworkId::from_passphrase(MAINNET_PASSPHRASE);
    assert!(matches!(
        successor(roots(), mainnet, &v1, &changes(1_500, 3_000), 1_600),
        Err(GovernanceError::Registry(RegistryError::Network { .. }))
    ));
    let development = RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("legacy".to_string(), dev::dev_root_verifying_bytes())]),
    };
    assert!(matches!(
        successor(development, mainnet, &v1, &changes(1_500, 3_000), 1_600),
        Err(GovernanceError::Registry(RegistryError::RootPolicy(_)))
    ));
}

#[test]
fn combine_takes_only_pinned_signers_over_this_root_up_to_the_threshold() {
    let snapshot = genesis();
    let a = sign_detached("a", &custodian("a"), &snapshot).unwrap();
    let b = sign_detached("b", &custodian("b"), &snapshot).unwrap();
    let combined = combine(&roots(), snapshot.clone(), &[a.clone(), b.clone()]).unwrap();
    // Exactly what the existing signer produces for the same keys.
    let direct = sign_snapshot_with_roots(
        &BTreeMap::from([
            ("a".to_string(), custodian("a")),
            ("b".to_string(), custodian("b")),
        ]),
        snapshot.clone(),
    )
    .unwrap();
    assert_eq!(combined, direct);

    assert_eq!(
        combine(&roots(), snapshot.clone(), std::slice::from_ref(&a)).unwrap_err(),
        GovernanceError::BelowThreshold { have: 1, need: 2 }
    );
    assert_eq!(
        combine(&roots(), snapshot.clone(), &[a.clone(), a.clone()]).unwrap_err(),
        GovernanceError::DuplicateSigner("a".to_string())
    );
    let mut other = snapshot.clone();
    other.expires_at_unix += 1;
    let stale = sign_detached("b", &custodian("b"), &other).unwrap();
    assert!(matches!(
        combine(&roots(), snapshot.clone(), &[a.clone(), stale]).unwrap_err(),
        GovernanceError::WrongRoot { .. }
    ));
    let outsider = sign_detached("d", &custodian("d"), &snapshot).unwrap();
    assert_eq!(
        combine(&roots(), snapshot.clone(), &[a.clone(), outsider]).unwrap_err(),
        GovernanceError::UnknownSigner("d".to_string())
    );
    // `b`'s id with `c`'s key: a valid signature, by the wrong custodian.
    let impostor = sign_detached("b", &custodian("c"), &snapshot).unwrap();
    assert_eq!(
        combine(&roots(), snapshot.clone(), &[a.clone(), impostor]).unwrap_err(),
        GovernanceError::SignerKeyMismatch("b".to_string())
    );
    let mut tampered = b;
    tampered.signature.replace_range(0..2, "00");
    assert_eq!(
        combine(&roots(), snapshot, &[a, tampered]).unwrap_err(),
        GovernanceError::BadSignature("b".to_string())
    );
}

/// A custodian whose key never leaves a device signs the printed root there; the result is the
/// same detached signature a local key produces.
#[test]
fn an_external_signature_over_the_root_is_accepted_only_if_it_verifies() {
    use ed25519_dalek::Signer;
    let snapshot = genesis();
    let root = snapshot_root(&snapshot).unwrap();
    let key = custodian("c");
    let produced = hex::encode(key.sign(&root.0).to_bytes());
    let public = key.verifying_key().to_bytes();
    let external = external_signature("c", &public, &produced.to_uppercase(), &snapshot).unwrap();
    assert_eq!(external, sign_detached("c", &key, &snapshot).unwrap());

    let over_something_else = hex::encode(key.sign(b"not the root").to_bytes());
    assert_eq!(
        external_signature("c", &public, &over_something_else, &snapshot).unwrap_err(),
        GovernanceError::BadSignature("c".to_string())
    );
    // The compressed identity point: a weak key that would verify a forged constant signature.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        external_signature("c", &identity, &produced, &snapshot).unwrap_err(),
        GovernanceError::BadSignature("c".to_string())
    );
    assert!(matches!(
        external_signature("", &public, &produced, &snapshot),
        Err(GovernanceError::Change(_))
    ));
}

#[test]
fn replay_accepts_exactly_an_unbroken_chain_from_genesis() {
    let chain = chain();
    let head = replay(roots(), network(), &chain, 2_600).unwrap();
    assert_eq!((head.version, head.log_index), (3, 3));
    assert_eq!(head.root, snapshot_root(&chain[2].snapshot).unwrap());

    assert!(matches!(
        replay(roots(), network(), &[], 2_600),
        Err(GovernanceError::Chain(_))
    ));
    // Starting mid-chain is not a replay from genesis, and neither is a version 1 that claims
    // a parent.
    assert!(matches!(
        replay(roots(), network(), &chain[1..], 2_600),
        Err(GovernanceError::Chain(_))
    ));
    let mut orphan = genesis();
    orphan.previous_root = Some(sha256(b"a history nobody published"));
    assert!(matches!(
        replay(
            roots(),
            network(),
            &[signed_by(&orphan, &["a", "b"])],
            1_500
        ),
        Err(GovernanceError::Chain(_))
    ));
    // A gap.
    assert!(matches!(
        replay(
            roots(),
            network(),
            &[chain[0].clone(), chain[2].clone()],
            2_600
        ),
        Err(GovernanceError::Chain(_))
    ));
    // A fork: a different version 2 that does not extend the published version 1.
    let mut fork = chain[1].snapshot.clone();
    fork.previous_root = Some(sha256(b"some other parent"));
    let fork = signed_by(&fork, &["a", "b"]);
    assert!(matches!(
        replay(roots(), network(), &[chain[0].clone(), fork], 1_600),
        Err(GovernanceError::Registry(RegistryError::Transparency(_)))
    ));
    // A version 2 that drops a recorded revocation.
    let mut forgetful = chain[2].snapshot.clone();
    forgetful.revocations.clear();
    forgetful.previous_root = Some(snapshot_root(&chain[1].snapshot).unwrap());
    let forgetful = signed_by(&forgetful, &["a", "b"]);
    assert!(matches!(
        replay(
            roots(),
            network(),
            &[chain[0].clone(), chain[1].clone(), forgetful],
            2_600
        ),
        Err(GovernanceError::Registry(RegistryError::Transparency(_)))
    ));
    // The head must be valid now; history need not be.
    assert!(matches!(
        replay(roots(), network(), &chain, 5_001),
        Err(GovernanceError::Registry(RegistryError::Expired { .. }))
    ));
    // Under other roots nothing verifies.
    let others = RootPolicy {
        threshold: 1,
        keys: BTreeMap::from([("x".to_string(), custodian("x").verifying_key().to_bytes())]),
    };
    assert!(matches!(
        replay(others, network(), &chain, 2_600),
        Err(GovernanceError::Registry(RegistryError::Signature))
    ));
}

fn checkpoint_of(chain: &[SignedSnapshot]) -> RegistryCheckpoint {
    let at = chain.last().unwrap().snapshot.valid_from_unix;
    replay(roots(), network(), chain, at).unwrap()
}

#[test]
fn monitoring_reports_newer_versions_expiry_and_watched_revocations() {
    let chain = chain();
    let at_v1 = checkpoint_of(&chain[..1]);
    let watch_nothing: [Hash32; 0] = [];

    let report = monitor(
        roots(),
        network(),
        at_v1.clone(),
        &chain,
        2_600,
        600,
        &watch_nothing,
    )
    .unwrap();
    assert_eq!(report.status, MonitorStatus::NewerVersion);
    assert!(report.newer_version_available);
    assert_eq!(report.checkpoint_version, 1);
    assert_eq!(report.head, checkpoint_of(&chain));
    assert_eq!(report.validity, ValidityStatus::Valid);

    // A hash the consumer relies on was revoked in a version it has not seen.
    let watched = [revoked_hash(), sha256(b"an unrelated hash")];
    let report = monitor(
        roots(),
        network(),
        at_v1.clone(),
        &chain,
        2_600,
        600,
        &watched,
    )
    .unwrap();
    assert_eq!(report.status, MonitorStatus::Revoked);
    assert_eq!(report.revoked.len(), 1);
    assert_eq!(report.revoked[0].wasm_hash, revoked_hash());
    assert_eq!(report.revoked[0].effective_version, 2);
    assert_eq!(report.revoked[0].reason, "found faulty in review");

    let at_v3 = checkpoint_of(&chain);
    let current = monitor(
        roots(),
        network(),
        at_v3.clone(),
        &chain,
        2_600,
        600,
        &watch_nothing,
    )
    .unwrap();
    assert_eq!(current.status, MonitorStatus::Current);
    assert!(!current.newer_version_available);
    let soon = monitor(
        roots(),
        network(),
        at_v3.clone(),
        &chain,
        4_500,
        600,
        &watch_nothing,
    )
    .unwrap();
    assert_eq!(
        (soon.status, soon.validity),
        (MonitorStatus::ExpiresSoon, ValidityStatus::ExpiresSoon)
    );
    let over = monitor(
        roots(),
        network(),
        at_v3.clone(),
        &chain,
        5_001,
        600,
        &watch_nothing,
    )
    .unwrap();
    assert_eq!(
        (over.status, over.validity),
        (MonitorStatus::Expired, ValidityStatus::Expired)
    );
    // The revocation outranks expiry: it is the one that needs the user's wallet.
    let both = monitor(roots(), network(), at_v1, &chain, 5_001, 600, &watched).unwrap();
    assert_eq!(both.status, MonitorStatus::Revoked);
    assert_eq!(both.validity, ValidityStatus::Expired);
}

/// A published log the consumer cannot reconcile with its checkpoint is an error, never a
/// status: a cron job must not read "current" from a log that has been rewritten.
#[test]
fn monitoring_fails_loudly_on_a_log_that_contradicts_the_checkpoint() {
    let chain = chain();
    let at_v2 = checkpoint_of(&chain[..2]);
    let none: [Hash32; 0] = [];

    // Same version, different contents: equivocation.
    let mut equivocation = chain[1].snapshot.clone();
    equivocation.expires_at_unix -= 1;
    let equivocation = signed_by(&equivocation, &["a", "c"]);
    assert!(matches!(
        monitor(
            roots(),
            network(),
            at_v2.clone(),
            &[chain[0].clone(), equivocation],
            1_600,
            0,
            &none
        ),
        Err(GovernanceError::Registry(RegistryError::Transparency(_)))
    ));
    // The published head is older than what the consumer already accepted.
    assert!(matches!(
        monitor(
            roots(),
            network(),
            at_v2.clone(),
            &chain[..1],
            1_600,
            0,
            &none
        ),
        Err(GovernanceError::Registry(RegistryError::Rollback { .. }))
    ));
    // A head that skips a version the consumer has not seen cannot be linked to its checkpoint.
    let at_v1 = checkpoint_of(&chain[..1]);
    assert!(matches!(
        monitor(roots(), network(), at_v1, &chain[2..], 2_600, 0, &none),
        Err(GovernanceError::Registry(RegistryError::Transparency(_)))
    ));
    // Signed by a key the consumer never pinned.
    let mut foreign = chain[2].clone();
    foreign.signatures.insert(
        "a".to_string(),
        sign_detached("a", &custodian("x"), &chain[2].snapshot)
            .unwrap()
            .signature,
    );
    assert!(matches!(
        monitor(roots(), network(), at_v2, &[foreign], 2_600, 0, &none),
        Err(GovernanceError::Registry(RegistryError::Signature))
    ));
}
