//! Shared domain vocabulary for the OZ Accounts Policy Builder.
//!
//! Architecture §4.11: this crate is pure — no I/O, no async, no framework deps.
//! Everything hashed in the toolkit goes through the domain-separated helpers here,
//! and all canonical serialization rules are documented on [`canonical_json_bytes`].

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

mod canonical;
pub use canonical::{
    canonical_hash, canonical_hash_of, canonical_preimage_bytes, canonical_preimage_bytes_of,
    to_scval,
};

/// Canonicalization scheme version. Bumped whenever the canonical byte encoding of any
/// hashed structure changes; it participates in every full recording / spec hash.
///
/// **v2** encodes every hashed structure as an `ScVal` and hashes its XDR — see
/// [`canonical`] for the rules and `docs/CANONICAL-HASHING.md` for the specification an
/// external implementation follows. v1 hashed `serde_json` output, whose byte layout was
/// specified only by this crate's source, so nobody outside it could reproduce a hash.
pub const CANONICALIZATION_VERSION: u32 = 2;

/// Hash domains. Every hash in the toolkit is domain-separated so values from different
/// artifact kinds can never collide or be replayed across contexts.
///
/// One structure kind, one domain. A domain reused across two structures forfeits exactly the
/// separation this module exists to provide, and an unused constant is not evidence that some
/// other value belongs under it — it means the structure it names has not been hashed yet.
///
/// Adding a domain means adding it to [`ALL`] as well; `all_domains_are_declared_in_all` fails
/// otherwise, so the list cannot silently fall behind the constants.
pub mod domains {
    pub const AUTH_FINGERPRINT: &str = "ozpb:v1:auth-fingerprint";
    pub const RECORDING: &str = "ozpb:v1:recording";
    pub const POLICY_SPEC: &str = "ozpb:v1:policy-spec";
    pub const SIGNER_SET: &str = "ozpb:v1:signer-set";
    pub const REGISTRY_SNAPSHOT: &str = "ozpb:v1:registry-snapshot";
    pub const CODEGEN_INPUT: &str = "ozpb:v1:codegen-input";
    pub const BUILD_MANIFEST: &str = "ozpb:v1:build-manifest";
    pub const POLICY_BINDING_SET: &str = "ozpb:v1:policy-binding-set";
    /// The enumerated account rule-set a call-surface verdict was computed over.
    pub const ACCOUNT_STATE: &str = "ozpb:v1:account-state";
    /// A generated crate's source files, lockfile excluded — the value a BuildManifest records
    /// as `source_hash`.
    pub const GENERATED_SOURCE: &str = "ozpb:v1:generated-source";
    /// A generated crate's complete emitted file set, lockfile included. Used only to derive the
    /// stub builder's placeholder wasm deterministically; it attests nothing, and has its own
    /// domain because it hashes a different structure than [`GENERATED_SOURCE`] — reusing that
    /// one because the two look similar is how a domain comes to mean two things.
    pub const GENERATED_CRATE_FILES: &str = "ozpb:v1:generated-crate-files";
    /// Reserved for the verdict itself. Deliberately unused: the verdict is not hashed yet.
    /// Architecture §4.8 records it inside an `InstallationRecord`, and §6.3 chains those onto
    /// the artifact provenance — so that is where this domain will be spent. Reaching for it to
    /// hash anything else would put two structures under one domain, which is the collision the
    /// separation exists to prevent.
    pub const SURFACE_VERDICT: &str = "ozpb:v1:surface-verdict";

    /// Every domain declared above, so the invariants can be asserted over the whole set
    /// rather than over whichever pair a test happened to name.
    pub const ALL: &[&str] = &[
        AUTH_FINGERPRINT,
        RECORDING,
        POLICY_SPEC,
        SIGNER_SET,
        REGISTRY_SNAPSHOT,
        CODEGEN_INPUT,
        BUILD_MANIFEST,
        POLICY_BINDING_SET,
        ACCOUNT_STATE,
        GENERATED_SOURCE,
        GENERATED_CRATE_FILES,
        SURFACE_VERDICT,
    ];
}

/// A 32-byte hash, hex-encoded in serialized form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        let bytes = hex::decode(s).map_err(|_| DomainError::InvalidHash(s.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DomainError::InvalidHash(s.to_string()))?;
        Ok(Hash32(arr))
    }
}

/// Reviewed upstream artifacts, pinned by exact wasm hash.
///
/// Why these live here rather than in `registry`: the capability registry and the shared test
/// fixtures must agree on them exactly, and `domain` is the only crate both already depend on.
/// Duplicating a hash in two places is how the two drift apart.
///
/// **Provenance — reproduce with these exact inputs or you will get a different hash.**
///
/// | | |
/// |---|---|
/// | Source | `github.com/OpenZeppelin/stellar-contracts`, `examples/multisig-smart-account/` |
/// | Tag | `v0.7.2` |
/// | Commit | `a9c42169000638da937577f592ebf61a7a3c94ca` |
/// | `stellar-accounts` | 0.7.2 · `soroban-sdk` 26.1.0 (the workspace pins at that tag) |
/// | Rust | **1.91.1** — this repo's pinned toolchain, NOT upstream's |
/// | Command | `stellar contract build` in each example directory |
/// | Stellar CLI | 27.0.0 |
///
/// Two things about this that are easy to get wrong.
///
/// **The hash depends on the compiler.** Upstream's `rust-toolchain.toml` says
/// `channel = "stable"`, so it floats. Built with rustc 1.97.1 the spending-limit policy
/// hashes to `161cdae2b2f6ae5df8b688e580ff5e4ad25c9adf45f167c0a0cffc2c74a1e932`; with our
/// pinned 1.91.1 it is the value below. Same source, same tag, same SDK. A pinned hash
/// without a pinned compiler is not reproducible, so these are built with *our* toolchain —
/// the same one that builds our generated policies and backs our reproducibility gates.
///
/// **These are not artifacts OpenZeppelin publishes.** The wrapper contracts are theirs
/// (`examples/multisig-smart-account/`), and the library they delegate to is covered by the
/// audits in that repository's `audits/` — but upstream attaches no wasm to its releases and
/// blesses no deployed instance, so any hash is somebody's build. These are ours, from their
/// source, reproducible from the table above. A registry entry may say that and no more.
pub mod pinned_upstream {
    use super::Hash32;

    /// OpenZeppelin's `SpendingLimitPolicyContract` — rolling-window spend cap. Understands
    /// only `transfer`, reads the amount from arg index 2, does not constrain the recipient.
    /// Deployable once and shared: its state is keyed by (smart account, context rule id).
    pub const OZ_SPENDING_LIMIT_POLICY_WASM: Hash32 = Hash32([
        0x4e, 0x67, 0xaa, 0x6c, 0xa2, 0x26, 0xd3, 0xc1, 0x61, 0x06, 0xff, 0x2d, 0x95, 0xf3, 0xb4,
        0x4a, 0x8e, 0xfa, 0xbc, 0x2f, 0x2a, 0x76, 0x55, 0x68, 0x39, 0x57, 0xe3, 0x55, 0x3e, 0xd6,
        0xa4, 0x0c,
    ]);

    /// OpenZeppelin's multisig smart-account example — the `__check_auth` implementation that
    /// invokes installed policies. One instance per user, since it holds their signers and rules.
    pub const OZ_SMART_ACCOUNT_WASM: Hash32 = Hash32([
        0xa1, 0x27, 0x47, 0xff, 0x6c, 0x13, 0x9d, 0xc1, 0x4f, 0xc2, 0xfd, 0x30, 0xd2, 0x00, 0xd6,
        0xbb, 0xb5, 0xda, 0x7b, 0x5d, 0x59, 0x81, 0x2c, 0x04, 0x7c, 0xe1, 0xf9, 0xca, 0xd2, 0x26,
        0xb2, 0x89,
    ]);

    /// OpenZeppelin's ed25519 signature verifier. Immutable and shareable.
    pub const OZ_ED25519_VERIFIER_WASM: Hash32 = Hash32([
        0x60, 0xe8, 0x79, 0x8d, 0xb6, 0x10, 0xbd, 0xaf, 0x33, 0x70, 0xd3, 0x9e, 0xbd, 0xa5, 0x6e,
        0xe1, 0xdc, 0x2c, 0x15, 0xce, 0x1c, 0x3a, 0x9e, 0x28, 0xb5, 0x28, 0xbf, 0xa2, 0x4a, 0x06,
        0xb4, 0x77,
    ]);
}

impl core::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

impl core::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash32::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Domain-separated SHA-256: `sha256(domain || 0x00 || payload)`.
pub fn hash_with_domain(domain: &str, payload: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(payload);
    Hash32(h.finalize().into())
}

/// Plain SHA-256 (used only where an external format fixes the hashing, e.g. network IDs).
pub fn sha256(payload: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(payload);
    Hash32(h.finalize().into())
}

/// Stellar network identity: the SHA-256 of the network passphrase — never a display name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkId(pub Hash32);

impl NetworkId {
    pub fn from_passphrase(passphrase: &str) -> Self {
        NetworkId(sha256(passphrase.as_bytes()))
    }
}

/// Well-known network passphrases (convenience; any passphrase is accepted).
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// A ledger sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LedgerSeq(pub u32);

/// Evidence trust level — architecture §4.1.
///
/// Trust levels are **derived by code from the acquisition path, never selectable by the
/// caller**. The inner discriminant is private; values can only be minted through the
/// constructors below, and `ledger_verified` has **no constructor at all** in Phase 1 —
/// it can only ever be the output of a future inclusion-proof checker (a proof-checking
/// typestate, per §4.11). Deserialization of persisted bundles accepts only levels this
/// toolkit version can mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustLevel(Level);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    RpcReported,
    TrustedIndexer,
    SelfSupplied,
    Incomplete,
}

impl TrustLevel {
    /// Fetched live from the configured RPC endpoint — trusted exactly as far as that
    /// endpoint is trusted ("reported", not proven).
    pub fn rpc_reported() -> Self {
        TrustLevel(Level::RpcReported)
    }

    /// Supplied by an explicitly configured, trusted historical backend.
    pub fn trusted_indexer() -> Self {
        TrustLevel(Level::TrustedIndexer)
    }

    /// User-imported; internally consistent but unverified. The default for pure imports.
    pub fn self_supplied() -> Self {
        TrustLevel(Level::SelfSupplied)
    }

    /// Missing evidence; synthesis restricted or refused.
    pub fn incomplete() -> Self {
        TrustLevel(Level::Incomplete)
    }

    pub fn as_str(&self) -> &'static str {
        match self.0 {
            Level::RpcReported => "rpc_reported",
            Level::TrustedIndexer => "trusted_indexer",
            Level::SelfSupplied => "self_supplied",
            Level::Incomplete => "incomplete",
        }
    }

    /// Whether evidence at this level may drive synthesis at all.
    pub fn allows_synthesis(&self) -> bool {
        !matches!(self.0, Level::Incomplete)
    }
}

impl Serialize for TrustLevel {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TrustLevel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "rpc_reported" => Ok(TrustLevel::rpc_reported()),
            "trusted_indexer" => Ok(TrustLevel::trusted_indexer()),
            "self_supplied" => Ok(TrustLevel::self_supplied()),
            "incomplete" => Ok(TrustLevel::incomplete()),
            other => Err(serde::de::Error::custom(format!(
                "unknown or unmintable trust level: {other}"
            ))),
        }
    }
}

/// How much a user-approved widening unconstrains the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    Low,
    Medium,
    High,
}

/// Constraint provenance — architecture §4.2. Every constraint carries one.
///
/// Externally tagged on purpose: serde ignores `deny_unknown_fields` for internally
/// tagged enums, and closed schemas are an architecture requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Provenance {
    /// Deep exact equality with the observed value: the default and the true minimum.
    ObservedExact,
    /// An explicit user decision naming the semantic role and bound direction.
    UserWidened {
        intent: String,
        blast_radius: BlastRadius,
    },
    /// Derived through a versioned contract adapter bound to a verified target code hash.
    AdapterDerived { adapter: String, code_hash: Hash32 },
}

/// Canonical JSON bytes (canonicalization v1).
///
/// Rules: serde struct-field declaration order is fixed by the type definitions; every
/// map anywhere in a hashed structure MUST be a `BTreeMap` (Rust's `HashMap` iteration
/// order is randomized per process — silent death for canonical hashing); compact
/// separators; UTF-8. Types participating in hashing must derive `Serialize`
/// deterministically under these rules.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, DomainError> {
    serde_json::to_vec(value).map_err(|e| DomainError::Serialization(e.to_string()))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid 32-byte hex hash: {0}")]
    InvalidHash(String),
    #[error("serialization failure: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- domain-separated hashing -------------------------------------------------

    #[test]
    fn same_payload_different_domain_gives_different_hash() {
        let a = hash_with_domain(domains::AUTH_FINGERPRINT, b"payload");
        let b = hash_with_domain(domains::RECORDING, b"payload");
        assert_ne!(a, b, "domain separation must isolate artifact kinds");
    }

    /// The property above, over the whole set rather than one hand-picked pair. Two domains
    /// sharing a string would silently merge two artifact kinds, and a test naming two
    /// constants cannot see it happen between any other two.
    #[test]
    fn all_domains_are_pairwise_distinct() {
        for (i, a) in domains::ALL.iter().enumerate() {
            for b in &domains::ALL[i + 1..] {
                assert_ne!(a, b, "two domains share the string {a:?}");
            }
        }
    }

    /// `ALL` must list every declared constant, or the check above silently stops covering the
    /// ones left out. Counted from the source text because Rust cannot enumerate a module's
    /// constants, and a hand-maintained list that nothing verifies is how it falls behind.
    #[test]
    fn all_domains_are_declared_in_all() {
        let source = include_str!("lib.rs");
        let module = source
            .split_once("pub mod domains {")
            .expect("the domains module must be findable in the source")
            .1;
        let module = module
            .split_once("\n}\n")
            .expect("the domains module must be terminated")
            .0;
        let declared = module.matches("pub const ").count() - 1; // minus ALL itself

        assert_eq!(
            declared,
            domains::ALL.len(),
            "{declared} domain constants are declared but ALL lists {}; a domain missing from \
             ALL is excluded from the distinctness check",
            domains::ALL.len()
        );
    }

    #[test]
    fn hashing_is_stable_across_calls() {
        let a = hash_with_domain(domains::POLICY_SPEC, b"x");
        let b = hash_with_domain(domains::POLICY_SPEC, b"x");
        assert_eq!(a, b);
    }

    #[test]
    fn domain_boundary_is_unambiguous() {
        // The 0x00 separator prevents ("ab", "c") colliding with ("a", "bc").
        let a = hash_with_domain("ab", b"c");
        let b = hash_with_domain("a", b"bc");
        assert_ne!(a, b);
    }

    // --- network id ----------------------------------------------------------------

    #[test]
    fn testnet_network_id_matches_well_known_value() {
        // sha256("Test SDF Network ; September 2015") — the canonical testnet network ID.
        let id = NetworkId::from_passphrase(TESTNET_PASSPHRASE);
        assert_eq!(
            id.0.to_hex(),
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
        );
    }

    // --- Hash32 hex round-trip -------------------------------------------------------

    #[test]
    fn hash32_hex_round_trip() {
        let h = sha256(b"round-trip");
        let parsed = Hash32::from_hex(&h.to_hex()).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn hash32_rejects_bad_hex() {
        assert!(Hash32::from_hex("not-hex").is_err());
        assert!(Hash32::from_hex("abcd").is_err()); // too short
    }

    // --- trust levels ----------------------------------------------------------------

    #[test]
    fn trust_levels_serialize_to_expected_strings() {
        assert_eq!(TrustLevel::rpc_reported().as_str(), "rpc_reported");
        assert_eq!(TrustLevel::self_supplied().as_str(), "self_supplied");
        assert_eq!(TrustLevel::trusted_indexer().as_str(), "trusted_indexer");
        assert_eq!(TrustLevel::incomplete().as_str(), "incomplete");
    }

    #[test]
    fn trust_level_round_trips_through_serde() {
        let l = TrustLevel::rpc_reported();
        let json = serde_json::to_string(&l).unwrap();
        let back: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn ledger_verified_cannot_be_deserialized_in_phase_1() {
        // No proof checker exists yet, so this toolkit version must refuse to mint or
        // accept `ledger_verified` — it would be an unearned trust claim.
        let r: Result<TrustLevel, _> = serde_json::from_str("\"ledger_verified\"");
        assert!(r.is_err());
    }

    #[test]
    fn incomplete_evidence_does_not_allow_synthesis() {
        assert!(!TrustLevel::incomplete().allows_synthesis());
        assert!(TrustLevel::rpc_reported().allows_synthesis());
        assert!(TrustLevel::self_supplied().allows_synthesis());
    }

    // --- provenance -------------------------------------------------------------------

    #[test]
    fn provenance_serializes_with_tag_and_rejects_unknown_fields() {
        let p = Provenance::UserWidened {
            intent: "cap amount at 100".into(),
            blast_radius: BlastRadius::Medium,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"user_widened\""));
        // Unit variants serialize as plain strings.
        assert_eq!(
            serde_json::to_string(&Provenance::ObservedExact).unwrap(),
            "\"observed_exact\""
        );
        let bad = r#"{"user_widened":{"intent":"x","blast_radius":"low","surprise":1}}"#;
        let r: Result<Provenance, _> = serde_json::from_str(bad);
        assert!(r.is_err(), "closed schemas reject unknown fields");
    }

    // --- canonical bytes ---------------------------------------------------------------

    #[test]
    fn canonical_bytes_are_stable_for_btreemap() {
        use std::collections::BTreeMap;
        let mut m = BTreeMap::new();
        m.insert("zeta", 1);
        m.insert("alpha", 2);
        let a = canonical_json_bytes(&m).unwrap();
        let b = canonical_json_bytes(&m).unwrap();
        assert_eq!(a, b);
        assert_eq!(String::from_utf8(a).unwrap(), r#"{"alpha":2,"zeta":1}"#);
    }

    proptest::proptest! {
        #[test]
        fn hashing_never_panics(domain in "\\PC*", payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let _ = hash_with_domain(&domain, &payload);
        }
    }
}
