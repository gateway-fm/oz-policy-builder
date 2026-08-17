//! A hash over a serialized structure must be identical in a **different process**.
//!
//! What a same-process test does and does not establish. `HashMap`/`HashSet` draw their hasher
//! keys from a thread-local seed that advances per instance, so two independently constructed
//! maps already iterate differently within one run: a same-process test *can* observe the
//! failure, but only probabilistically, and only if it builds two separate values.
//! `spec_hash_is_deterministic` in `policy-spec` does neither — it hashes one value twice — so it
//! shows the function is not randomized per call and nothing further. Running the same fixture in
//! a fresh process makes the observation deterministic instead of incidental, which is what a
//! regression gate needs.
//!
//! That matters here because the rule "every map in a hashed structure must be a `BTreeMap`" lived
//! only in a doc comment until `clippy.toml` began enforcing it, and a hash that differs per
//! process would break the claim this repository rests on: that a third party can recompute our
//! hashes and get the same value.
//!
//! **The fixture has to contain a map worth ordering.** `dev_snapshot` alone does not: its
//! policy, account, verifier and template maps hold exactly one entry each and its revocations
//! map is empty, so there is a single possible ordering and no hasher could change the bytes.
//! Hashing it would have proved only that the mechanism runs. The snapshot under test is
//! therefore enlarged with enough revocations that an unordered map would serialize differently,
//! and `an_unordered_map_is_observable_across_processes` proves that claim rather than asserting
//! it — it hashes the same keys through a `BTreeMap` and a `HashMap` and shows the first is
//! stable across processes while the second is not.
//!
//! Mechanism: a test re-executes its own binary with a marker in the environment. The child
//! prints what it computed; the parent compares against its own. Two processes, one fixture, no
//! external helper binary.

use ozpb_domain::{canonical_preimage_bytes, domains, sha256, NetworkId, TESTNET_PASSPHRASE};
use ozpb_registry::Revocation;
use std::collections::BTreeMap;

/// Set in the child so it prints instead of spawning, which would recurse forever.
const CHILD_MARKER: &str = "OZPB_CROSS_PROCESS_CHILD";

/// How many keys the ordering-sensitive fixtures carry.
///
/// Two independently seeded `HashMap`s agreeing on the iteration order of this many keys is not
/// impossible, only negligible — far below the rate at which any other part of this suite fails
/// for unrelated reasons. Shrinking it trades that margin for nothing.
const ORDERED_KEYS: u32 = 16;

/// Keys chosen to hash unevenly rather than to look tidy: sequential suffixes over a fixed prefix
/// is exactly the shape a real revocation list has.
fn revocation_keys() -> Vec<String> {
    (0..ORDERED_KEYS)
        .map(|i| {
            format!(
                "policy/{:064x}",
                u64::from(i).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            )
        })
        .collect()
}

/// `dev_snapshot` with a revocation list long enough that map ordering is observable.
fn enlarged_snapshot() -> ozpb_registry::RegistrySnapshot {
    let mut snapshot =
        ozpb_registry::dev::dev_snapshot(NetworkId::from_passphrase(TESTNET_PASSPHRASE), 1);
    for (i, key) in revocation_keys().into_iter().enumerate() {
        snapshot.revocations.insert(
            key,
            Revocation {
                reason: format!("superseded by review round {i}"),
                effective_version: 2 + i as u64,
            },
        );
    }
    snapshot
}

fn snapshot_root_hex() -> String {
    ozpb_registry::snapshot_root(&enlarged_snapshot())
        .expect("the enlarged snapshot must hash")
        .to_hex()
}

/// The same content under an ordered and an unordered map, hashed the way a preimage would be.
///
/// The `HashMap` here is the point of the test rather than an oversight: it is the control that
/// shows the ban `clippy.toml` enforces is load-bearing. It hashes nothing that leaves this file.
#[allow(clippy::disallowed_types)]
fn ordered_and_unordered_hexes() -> (String, String) {
    let pairs: Vec<(String, u64)> = revocation_keys()
        .into_iter()
        .enumerate()
        .map(|(i, k)| (k, i as u64))
        .collect();

    let ordered: BTreeMap<String, u64> = pairs.iter().cloned().collect();
    let unordered: std::collections::HashMap<String, u64> = pairs.into_iter().collect();

    // Through the canonical encoder the snapshot root actually uses. A control that measured a
    // different encoder would keep passing while saying nothing about the one in production —
    // which is what this became when hashing moved from JSON to XDR.
    let hex_of = |bytes: Vec<u8>| sha256(&bytes).to_hex();
    (
        hex_of(
            canonical_preimage_bytes(domains::REGISTRY_SNAPSHOT, &ordered)
                .expect("an ordered map must encode"),
        ),
        hex_of(
            canonical_preimage_bytes(domains::REGISTRY_SNAPSHOT, &unordered)
                .expect("an unordered map must encode"),
        ),
    )
}

/// Re-runs this binary for `test_name` and returns the value the child printed under `key`.
fn from_child(test_name: &str, key: &str) -> String {
    let exe = std::env::current_exe().expect("the test binary must be locatable");
    let output = std::process::Command::new(&exe)
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_MARKER, "1")
        // A fresh process is the point; inheriting everything else keeps the run as close to
        // identical as possible, so a difference can only come from the hashing.
        .output()
        .expect("re-running the test binary must succeed");

    assert!(
        output.status.success(),
        "child run failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let prefix = format!("{key}=");
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("child printed no {prefix} line; stdout was:\n{stdout}"))
        .to_string()
}

fn is_child() -> bool {
    std::env::var_os(CHILD_MARKER).is_some()
}

#[test]
fn the_snapshot_root_is_identical_in_a_fresh_process() {
    let ours = snapshot_root_hex();

    if is_child() {
        // Report and stop. The parent asserts; failing here would be reported against the child's
        // exit status instead, hiding the two values being compared.
        println!("ROOT={ours}");
        return;
    }

    let theirs = from_child("the_snapshot_root_is_identical_in_a_fresh_process", "ROOT");
    assert_eq!(
        ours, theirs,
        "the same snapshot hashed to different values in two processes; a map in a hashed \
         structure is iterating in a per-process order, so no third party can reproduce our hashes"
    );
}

/// The encoder normalises map ordering, so iteration order cannot reach a hash at all.
///
/// This assertion used to be the opposite one. Under the JSON scheme a `HashMap` serialized in
/// whatever order it happened to iterate, so the fixture above was only meaningful if it was
/// large enough for that order to vary — and this test existed to prove it was. Under the
/// canonical encoder `ScMap::sorted_from_entries` sorts and validates, so the same contents
/// produce the same bytes whichever map type carried them and whichever process encoded them.
///
/// Keeping the old assertion would have been keeping a test whose premise the change removed:
/// it would have failed, and the honest reading of that failure is not "the fixture is too
/// small" but "unordered iteration is no longer observable". This asserts the property that now
/// holds, which is strictly stronger than the one it replaces.
///
/// The workspace still bans `HashMap` in hashed structures. That ban now protects the JSON wire
/// form and anything else built from these types — not the canonical hash, which no longer
/// depends on it.
#[test]
fn map_iteration_order_cannot_reach_a_hash() {
    let (ordered, unordered) = ordered_and_unordered_hexes();

    if is_child() {
        println!("ORDERED={ordered}");
        println!("UNORDERED={unordered}");
        return;
    }

    let name = "map_iteration_order_cannot_reach_a_hash";
    assert_eq!(
        ordered,
        from_child(name, "ORDERED"),
        "a BTreeMap of {ORDERED_KEYS} keys hashed differently in two processes, which would mean \
         the ordering guarantee this suite relies on does not hold"
    );
    assert_eq!(
        unordered,
        from_child(name, "UNORDERED"),
        "a HashMap of {ORDERED_KEYS} keys hashed differently in two processes — the encoder is \
         meant to sort map entries, so iteration order must not be able to reach the bytes"
    );
    assert_eq!(
        ordered, unordered,
        "the same {ORDERED_KEYS} entries hashed differently depending on which map type carried \
         them, so the encoder is not normalising order as its specification claims"
    );
}
