//! Fixtures shared by the test modules of this crate.
//!
//! A real module rather than helpers inside one `mod tests`, because the MVP surface and the
//! post-MVP surface are tested in separate files and both need the same signed registry, trust
//! configuration and build settings. Duplicating them would let the two copies drift, and a
//! fixture that drifts makes one of the two suites quietly test something else.

use crate::RegistryTrust;
use ozpb_registry::{dev as registry_dev, sign_snapshot, RootPolicy};

pub(crate) fn signed_registry_json() -> serde_json::Value {
    let snapshot = registry_dev::account_advisory_successor(
        ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
    )
    .unwrap();
    serde_json::to_value(sign_snapshot(&registry_dev::dev_signing_key(), snapshot).unwrap())
        .unwrap()
}

pub(crate) fn registry_trust() -> RegistryTrust {
    RegistryTrust {
        root_policy: RootPolicy {
            threshold: 1,
            keys: std::collections::BTreeMap::from([(
                "legacy".to_string(),
                registry_dev::dev_root_verifying_bytes(),
            )]),
        },
        minimum_version: 1,
        checkpoint: None,
        configured_snapshot: None,
    }
}

/// The golden spec as it can legitimately arrive over the JSON tool boundary.
///
/// `synthesize_policy` downgrades bundle trust to `self_supplied` before synthesis, so a
/// wire-carried spec never claims stronger acquisition context; the in-process golden fixture's
/// `rpc_reported` is the one thing about it that cannot survive serialization honestly.
pub(crate) fn wire_spec() -> ozpb_policy_spec::ValidatedSpec {
    let mut raw = ozpb_synthesizer::fixtures::golden_spec().spec().clone();
    for recording in &mut raw.evidence.recordings {
        recording.trust = ozpb_domain::TrustLevel::self_supplied();
    }
    raw.validate()
        .expect("downgrading trust preserves validity")
}

pub(crate) fn build_config() -> ozpb_build_runner::BuildConfig {
    // Hermetic + deterministic: the toolkit's verify/binding/manifest logic only needs a
    // reproducible builder, not the real toolchain. This keeps `cargo test` free of a
    // `stellar` dependency and of cargo package-cache lock contention. The real
    // `stellar contract build` path is covered by build-runner's #[ignore]d E2E test.
    ozpb_build_runner::BuildConfig {
        builder: ozpb_build_runner::Builder::Stub,
        ..ozpb_build_runner::BuildConfig::default()
    }
}

/// Move a live-check request to mainnet under a development-signed mainnet snapshot whose root the
/// spec names. Everything about the request is then consistent except its trust root, which is
/// the public development key: the one thing every entry point must refuse outside testnet.
pub(crate) fn moved_to_mainnet(input: &mut ozpb_api_types::CheckPolicyCallSurfaceInput) {
    let mainnet = ozpb_domain::NetworkId::from_passphrase(ozpb_domain::MAINNET_PASSPHRASE);
    let mut snapshot = registry_dev::account_advisory_successor(mainnet).unwrap();
    snapshot.network_id = mainnet;
    let signed = sign_snapshot(&registry_dev::dev_signing_key(), snapshot).unwrap();
    let mut spec: ozpb_policy_spec::PolicySpec =
        serde_json::from_value(input.spec.clone()).unwrap();
    spec.network_id = mainnet;
    spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
    input.spec = serde_json::to_value(&spec).unwrap();
    input.network_id = mainnet.0.to_hex();
    input.binding_set.network_id = mainnet.0.to_hex();
    input.signed_registry_snapshot = serde_json::to_value(signed).unwrap();
}
