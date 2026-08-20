//! The committed `docs/examples/` files must still match what the code produces.
//!
//! These files are not illustrations. `DEVELOPERS.md`, `scripts/demo-tranche1.sh` and
//! `docs/TESTNET-EVIDENCE.md` feed them straight into `ozpb synthesize` / `import_recording`, so
//! a reader runs the committed bytes. If what produces them changes — a pinned hash, a capability
//! entry, the signing key, a field the import format gains — and the files are not regenerated,
//! everything a reader can actually run fails with `E_REGISTRY_SIGNATURE`, an unrecognized
//! capability, or weaker trust than the document claims, while every test in the workspace still
//! passes.
//!
//! The demo used to run `ozpb dev-registry` immediately before consuming these files, which
//! rewrote them in place: drift was repaired instead of reported, and the demo passed either way.
//! A check that can silently fix what it measures is not a check. These are offline and
//! deterministic, and no run of the suite rewrites a committed file: regeneration is a separate,
//! explicit act — an operator command, or `UPDATE_EXAMPLES=1` named on the command line — so the
//! diff is something a person reads and commits, never something a green test produced.
//!
//! When one fails, regenerate and read the diff before committing — a change here changes what
//! readers are asked to trust:
//!
//!     cargo run -p ozpb-cli -- dev-registry
//!     UPDATE_EXAMPLES=1 cargo test -p ozpb-toolkit --test examples_are_current

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

/// The committed import example must be exactly what the recorder fixture yields, in the
/// import format's own type.
///
/// It was produced by an emitter nothing ran (`EMIT_BUNDLE_PATH` had no caller), which is the
/// same hazard the spec example had before it became code-backed: `docs/TESTNET-EVIDENCE.md`
/// hands these bytes to `import_recording`, so a field the format gains — `result_xdr_base64`
/// is the one that just happened — leaves the committed file describing an import that is
/// accepted with weaker trust than the document claims, while every test still passes. One
/// producer, checked here, replaces that emitter.
///
/// Regenerate with `UPDATE_EXAMPLES=1 cargo test -p ozpb-toolkit --test examples_are_current`,
/// and read the diff — this file is what a reader runs.
#[test]
fn the_committed_import_bundle_is_the_fixture() {
    use ozpb_recorder_core::fixtures as fx;

    let recorded = ozpb_recorder_core::record(
        &fx::imported_snapshot(true),
        ozpb_recorder_core::RecordOptions::default(),
    )
    .expect("the fixture import must record");
    let bundle = ozpb_source_bundle::ImportedBundle {
        network_passphrase: ozpb_domain::TESTNET_PASSPHRASE.to_string(),
        envelope_xdr_base64: recorded.raw.envelope_xdr_base64.clone(),
        result_meta_xdr_base64: recorded.raw.result_meta_xdr_base64.clone(),
        result_xdr_base64: Some(fx::transaction_result_base64(true)),
        ledger: recorded.ledger.map(|ledger| ledger.0),
        created_at_unix: recorded.created_at_unix,
        successful: true,
    };
    // Keys are emitted in sorted order because the committed bytes are sorted and their order
    // is not worth churning. Sorted explicitly rather than by relying on `serde_json::Map`
    // being a `BTreeMap`: that is the default, but any dependency enabling `preserve_order`
    // would flip it to insertion order through feature unification and turn this gate into a
    // spurious failure that says "drifted" about a build-feature change.
    let expected = serde_json::to_string_pretty(&with_sorted_keys(
        serde_json::to_value(&bundle).expect("the import bundle must serialize"),
    ))
    .expect("the import bundle must render");

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/import-bundle.json");
    if std::env::var_os("UPDATE_EXAMPLES").is_some() {
        std::fs::write(&path, &expected).expect("writing the import example");
        return;
    }
    assert_eq!(
        committed("import-bundle.json"),
        expected,
        "docs/examples/import-bundle.json has drifted from the recorder fixture — regenerate \
         with UPDATE_EXAMPLES=1 and review the diff"
    );
    // The ordering the comparison depends on, asserted rather than assumed: this holds under
    // either `serde_json` map implementation, so it fails if the sort above stops working.
    let keys: Vec<String> = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
        &committed("import-bundle.json"),
    )
    .expect("the committed example must be a JSON object")
    .keys()
    .cloned()
    .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "the committed example's keys must be sorted");

    // Byte equality would still pass if the bytes no longer imported, so assert the property
    // the file exists for, through the operation a reader's `import_recording` call runs —
    // parsing alone would not notice bytes that stopped recording.
    let imported = ozpb_toolkit::import_recording(
        &committed("import-bundle.json"),
        ozpb_recorder_core::RecordOptions::default(),
    )
    .expect("the committed example must import and record");
    assert_eq!(
        imported.trust, "self_supplied",
        "the committed example must carry the transaction result that earns self_supplied"
    );
}

/// Re-materialize every object with its keys in sorted order, so rendered bytes do not depend
/// on which map implementation `serde_json` was compiled with.
fn with_sorted_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, serde_json::Value> = map
                .into_iter()
                .map(|(key, child)| (key, with_sorted_keys(child)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(with_sorted_keys).collect())
        }
        other => other,
    }
}
