//! The committed `docs/examples/` trust files must still match what `registry::dev` produces.
//!
//! Those two files are not illustrations. `DEVELOPERS.md` and `scripts/demo-tranche1.sh` feed
//! them straight into `ozpb synthesize`, so a reader runs the committed bytes. If the dev
//! snapshot changes — a pinned hash, a capability entry, the signing key — and the files are
//! not regenerated, everything a reader can actually run fails with `E_REGISTRY_SIGNATURE` or
//! an unrecognized capability, while every test in the workspace still passes.
//!
//! The demo used to run `ozpb dev-registry` immediately before consuming these files, which
//! rewrote them in place: drift was repaired instead of reported, and the demo passed either
//! way. A check that can silently fix what it measures is not a check. This one is offline,
//! deterministic, and has no write path.
//!
//! When it fails, regenerate and read the diff before committing — a change here changes what
//! readers are asked to trust:
//!
//!     cargo run -p ozpb-cli -- dev-registry

use ozpb_domain::{NetworkId, TESTNET_PASSPHRASE};
use ozpb_registry::{Registry, SignedSnapshot};

/// The same arguments `ozpb dev-registry` passes. If the CLI's defaults change without this
/// following, the test measures a snapshot nobody ships.
fn current() -> (String, String) {
    ozpb_registry::dev::dev_trust_files(NetworkId::from_passphrase(TESTNET_PASSPHRASE), 1)
        .expect("the development trust files must build")
}

fn committed(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

#[test]
fn the_committed_signed_snapshot_is_current() {
    let (snapshot, _) = current();
    assert_eq!(
        committed("registry.signed.json"),
        snapshot,
        "docs/examples/registry.signed.json has drifted from registry::dev — regenerate with \
         `cargo run -p ozpb-cli -- dev-registry` and review the diff"
    );
}

#[test]
fn the_committed_roots_are_current() {
    let (_, roots) = current();
    assert_eq!(
        committed("registry-roots.json"),
        roots,
        "docs/examples/registry-roots.json has drifted from registry::dev — regenerate with \
         `cargo run -p ozpb-cli -- dev-registry` and review the diff"
    );
}

/// Byte equality alone would still pass if both files were regenerated from a snapshot that no
/// longer verifies, so assert the property they exist for — through the path the CLI uses, not
/// a reimplementation of it.
#[test]
fn the_committed_pair_verifies_through_the_cli_path() {
    let trust = ozpb_toolkit::registry_trust_from_roots_json(&committed("registry-roots.json"), 1)
        .expect("the committed roots must parse as a root policy");
    let mut registry = Registry::with_pinned_roots_for_network_at_version(
        trust.root_policy,
        NetworkId::from_passphrase(TESTNET_PASSPHRASE),
        trust.minimum_version,
    )
    .expect("the committed root policy must be usable");

    let signed: SignedSnapshot = serde_json::from_str(&committed("registry.signed.json"))
        .expect("the committed snapshot must parse");
    registry
        .load(&signed)
        .expect("the committed snapshot must verify under the committed roots");

    // And it must still recognize the upstream artifacts the demo depends on, so a snapshot
    // that verifies but no longer covers them fails here rather than mid-demo.
    registry
        .resolve_policy(&ozpb_domain::pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM)
        .expect("the pinned spending-limit policy must be a recognized capability");
    registry
        .resolve_account(&ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM)
        .expect("the pinned smart account must be a recognized capability");
}

/// The committed example spec must be exactly the shared fixture, serialized.
///
/// It was hand-maintained, which is how it came to describe a schema the crate no longer
/// accepts: `scripts/verify-phase1.sh` feeds it to `ozpb generate` and the MCP integration tests
/// parse it, so a stale copy fails a reader running the documented command while every unit test
/// still passes. Making it code-backed removes the drift rather than detecting it later.
///
/// Regenerate with `UPDATE_EXAMPLES=1 cargo test -p ozpb-toolkit --test examples_are_current`,
/// and read the diff — this file is what a reader runs.
#[test]
fn the_committed_example_spec_is_the_fixture() {
    let expected = serde_json::to_string_pretty(&ozpb_policy_spec::fixtures::subscription_spec())
        .expect("the fixture must serialize")
        + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/subscription-spec.json");

    if std::env::var_os("UPDATE_EXAMPLES").is_some() {
        std::fs::write(&path, &expected).expect("writing the example spec");
        return;
    }

    assert_eq!(
        committed("subscription-spec.json"),
        expected,
        "docs/examples/subscription-spec.json has drifted from the shared fixture — regenerate \
         with UPDATE_EXAMPLES=1 and review the diff"
    );
}
