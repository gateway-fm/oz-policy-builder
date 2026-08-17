//! Fixtures shared by the test modules of this crate.
//!
//! A real module rather than helpers inside one `mod tests`, because the MVP surface and the
//! post-MVP surface are tested in separate files and both need the same signed registry, trust
//! configuration and build settings. Duplicating them would let the two copies drift, and a
//! fixture that drifts makes one of the two suites quietly test something else.

use crate::RegistryTrust;
use ozpb_registry::{dev as registry_dev, sign_snapshot, RootPolicy};

pub(crate) fn signed_registry_json() -> serde_json::Value {
    let snapshot = registry_dev::dev_snapshot(
        ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
        1,
    );
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
    }
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
