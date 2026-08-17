//! Capability registries (architecture §4.10) — Phase 1 subset.
//!
//! Signed, versioned snapshots keyed by reviewed wasm hash; the registry is a security
//! root, so it gets real governance: a pinned root key, monotonically increasing
//! versions with rollback/freeze rejection, a canonical root hash that downstream
//! artifacts pin, and **fail-closed** resolution — an unknown hash is an error, never a
//! guess. An address, package version, or claimed kind is never sufficient.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ozpb_domain::pinned_upstream;
use ozpb_domain::{domains, Hash32, NetworkId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const REGISTRY_SCHEMA: &str = "registry/v1";

// ---------------------------------------------------------------------------------------
// Snapshot model (all maps BTreeMap; canonical hashing)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    /// Schema identifier. Named `schema` rather than `$schema`: the value is a plain
    /// identifier, not a JSON-Schema URI, and `$` is not a legal `Symbol` character, so the
    /// old name could not be encoded in a canonical preimage at all.
    pub schema: String,
    /// Monotonically increasing snapshot version (rollback/freeze rejection).
    pub version: u64,
    /// Append-only transparency sequence. A successor must increment this exactly once and
    /// commit to the previously accepted snapshot root.
    pub log_index: u64,
    pub previous_root: Option<Hash32>,
    pub network_id: NetworkId,
    /// Signed validity interval. Consumers supply their trusted current time to `load_at`;
    /// an expired or not-yet-valid snapshot never becomes a capability oracle.
    pub valid_from_unix: i64,
    pub expires_at_unix: i64,
    /// Reviewed policy implementations, keyed by exact wasm hash (hex).
    pub policies: BTreeMap<String, PolicyCapability>,
    /// Recognized account implementations, keyed by exact wasm hash (hex).
    pub accounts: BTreeMap<String, AccountCapability>,
    /// Trusted signature verifiers, keyed by exact wasm hash (hex).
    pub verifiers: BTreeMap<String, VerifierCapability>,
    /// Audited template families (pre-build identity of generated policies).
    pub templates: BTreeMap<String, TemplateCapability>,
    /// Permanently recorded capability revocations, keyed as `policy/<hash>`,
    /// `account/<hash>`, `verifier/<hash>`, or `template/<family>`.
    pub revocations: BTreeMap<String, Revocation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub reason: String,
    pub effective_version: u64,
}

/// What a reviewed policy implementation actually enforces — derived from reviewed
/// source, per exact wasm hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCapability {
    pub kind: String,
    /// Signer predicates this implementation enforces (e.g. "threshold"); an empty list
    /// means it enforces none and can never satisfy a spec's predicate on its own.
    pub signer_predicates: Vec<String>,
    /// Exported security-relevant methods (input to the Phase 2 call-surface algebra).
    pub security_relevant_methods: Vec<String>,
    pub review_reference: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCapability {
    pub release: String,
    /// `onchain_list` | `bounded_next_id` | `verified_event_index` | `none` (§4.8).
    pub rule_enumeration: String,
    /// Release-specific management-ID evidence strategy (Decision D3).
    pub management_evidence: String,
    pub review_reference: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierCapability {
    pub implementation: String,
    pub key_encoding: String,
    pub immutable: bool,
    pub review_reference: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCapability {
    /// Hash of the template pack's declared capability algebra.
    pub capability_schema: Hash32,
    pub signer_predicates: Vec<String>,
    pub constraint_kinds: Vec<String>,
    pub review_reference: String,
}

/// Pinned registry governance roots. Signer identifiers are stable operator-chosen labels;
/// the map shape makes duplicate signer counting impossible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPolicy {
    pub threshold: u32,
    pub keys: BTreeMap<String, [u8; 32]>,
}

/// Durable anti-rollback/equivocation state persisted by the registry consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCheckpoint {
    pub version: u64,
    pub log_index: u64,
    pub root: Hash32,
}

/// A snapshot plus its root signature (ed25519 over the canonical root hash).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSnapshot {
    pub snapshot: RegistrySnapshot,
    pub signatures: BTreeMap<String, String>,
}

/// Canonical root hash of a snapshot (what artifacts pin as `registry_snapshot`).
pub fn snapshot_root(snapshot: &RegistrySnapshot) -> Result<Hash32, RegistryError> {
    ozpb_domain::canonical_hash(domains::REGISTRY_SNAPSHOT, snapshot)
        .map_err(|e| RegistryError::Internal(e.to_string()))
}

/// Sign a snapshot with a root key (bootstrap/ops tooling and tests).
pub fn sign_snapshot(
    key: &SigningKey,
    snapshot: RegistrySnapshot,
) -> Result<SignedSnapshot, RegistryError> {
    sign_snapshot_with_roots(
        &BTreeMap::from([("legacy".to_string(), key.clone())]),
        snapshot,
    )
}

/// Sign with one or more independently identified governance roots. Production release
/// tooling supplies the threshold-approved subset; verification applies the pinned policy.
pub fn sign_snapshot_with_roots(
    keys: &BTreeMap<String, SigningKey>,
    snapshot: RegistrySnapshot,
) -> Result<SignedSnapshot, RegistryError> {
    let root = snapshot_root(&snapshot)?;
    let signatures = keys
        .iter()
        .map(|(id, key)| {
            let signature = key.sign(&root.0);
            (id.clone(), hex::encode(signature.to_bytes()))
        })
        .collect();
    Ok(SignedSnapshot {
        snapshot,
        signatures,
    })
}

// ---------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("E_REGISTRY_SIGNATURE: snapshot signatures do not satisfy the pinned root policy")]
    Signature,
    #[error("E_REGISTRY_ROOT_POLICY: {0}")]
    RootPolicy(String),
    #[error("E_REGISTRY_TRANSPARENCY: {0}")]
    Transparency(String),
    #[error("E_REGISTRY_SCHEMA: expected {REGISTRY_SCHEMA}, got {0}")]
    Schema(String),
    #[error(
        "E_REGISTRY_ROLLBACK: snapshot version {offered} does not advance the current \
         version {current} (rollback/freeze rejected)"
    )]
    Rollback { offered: u64, current: u64 },
    #[error("E_REGISTRY_NETWORK: expected network {expected}, snapshot is for {found}")]
    Network { expected: String, found: String },
    #[error(
        "E_REGISTRY_NOT_YET_VALID: snapshot validity starts at {valid_from}, current time is {now}"
    )]
    NotYetValid { valid_from: i64, now: i64 },
    #[error("E_REGISTRY_EXPIRED: snapshot expired at {expires_at}, current time is {now}")]
    Expired { expires_at: i64, now: i64 },
    #[error(
        "E_REGISTRY_VALIDITY: snapshot valid_from {valid_from} is after expires_at {expires_at}"
    )]
    Validity { valid_from: i64, expires_at: i64 },
    #[error("E_UNREGISTERED_POLICY: no reviewed policy entry for wasm hash {0}")]
    UnknownPolicy(String),
    #[error("E_INCOMPATIBLE_ACCOUNT: no recognized account entry for wasm hash {0}")]
    UnknownAccount(String),
    #[error("E_UNREGISTERED_VERIFIER: no trusted verifier entry for wasm hash {0}")]
    UnknownVerifier(String),
    #[error("E_UNREGISTERED_TEMPLATE: no audited template family named {0}")]
    UnknownTemplate(String),
    #[error("E_REGISTRY_REVOKED: capability {capability} is revoked: {reason}")]
    Revoked { capability: String, reason: String },
    #[error("E_REGISTRY_EMPTY: no snapshot loaded")]
    NotLoaded,
    #[error("E_REGISTRY_PARSE: {0}")]
    Parse(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Registry client with a pinned root key. Fail-closed everywhere.
pub struct Registry {
    root_keys: BTreeMap<String, VerifyingKey>,
    root_threshold: u32,
    expected_network: Option<NetworkId>,
    minimum_version: u64,
    pinned_checkpoint: Option<RegistryCheckpoint>,
    current: Option<Loaded>,
}

struct Loaded {
    snapshot: RegistrySnapshot,
    root: Hash32,
}

impl Registry {
    pub fn with_pinned_root(root_key_bytes: &[u8; 32]) -> Result<Self, RegistryError> {
        Self::with_pinned_roots(RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([("legacy".to_string(), *root_key_bytes)]),
        })
    }

    pub fn with_pinned_roots(policy: RootPolicy) -> Result<Self, RegistryError> {
        if policy.threshold == 0 || policy.threshold as usize > policy.keys.len() {
            return Err(RegistryError::RootPolicy(format!(
                "threshold {} is not within 1..={} trusted roots",
                policy.threshold,
                policy.keys.len()
            )));
        }
        if policy.keys.keys().any(|id| id.is_empty()) {
            return Err(RegistryError::RootPolicy(
                "root signer identifiers must not be empty".to_string(),
            ));
        }
        let unique_keys: std::collections::BTreeSet<[u8; 32]> =
            policy.keys.values().copied().collect();
        if unique_keys.len() != policy.keys.len() {
            return Err(RegistryError::RootPolicy(
                "the same root key must not appear under multiple signer identifiers".to_string(),
            ));
        }
        let root_keys = policy
            .keys
            .into_iter()
            .map(|(id, bytes)| {
                VerifyingKey::from_bytes(&bytes)
                    .map(|key| (id, key))
                    .map_err(|_| RegistryError::RootPolicy("invalid ed25519 root key".to_string()))
            })
            .collect::<Result<_, _>>()?;
        Ok(Registry {
            root_keys,
            root_threshold: policy.threshold,
            expected_network: None,
            minimum_version: 0,
            pinned_checkpoint: None,
            current: None,
        })
    }

    /// Construct a registry verifier pinned to both a governance root and one Stellar
    /// network. Production consumers should use this constructor; the root-only constructor
    /// remains for offline migration tooling that validates network separately.
    pub fn with_pinned_root_for_network(
        root_key_bytes: &[u8; 32],
        expected_network: NetworkId,
    ) -> Result<Self, RegistryError> {
        let mut registry = Self::with_pinned_root(root_key_bytes)?;
        registry.expected_network = Some(expected_network);
        Ok(registry)
    }

    /// Construct with a version floor persisted by the caller across processes. Without a
    /// persisted floor, an old but correctly signed snapshot could be replayed after restart.
    pub fn with_pinned_root_for_network_at_version(
        root_key_bytes: &[u8; 32],
        expected_network: NetworkId,
        minimum_version: u64,
    ) -> Result<Self, RegistryError> {
        Self::with_pinned_roots_for_network_at_version(
            RootPolicy {
                threshold: 1,
                keys: BTreeMap::from([("legacy".to_string(), *root_key_bytes)]),
            },
            expected_network,
            minimum_version,
        )
    }

    pub fn with_pinned_roots_for_network_at_version(
        policy: RootPolicy,
        expected_network: NetworkId,
        minimum_version: u64,
    ) -> Result<Self, RegistryError> {
        let mut registry = Self::with_pinned_roots(policy)?;
        registry.expected_network = Some(expected_network);
        registry.minimum_version = minimum_version;
        Ok(registry)
    }

    pub fn with_pinned_roots_for_network_at_checkpoint(
        policy: RootPolicy,
        expected_network: NetworkId,
        checkpoint: RegistryCheckpoint,
    ) -> Result<Self, RegistryError> {
        let mut registry = Self::with_pinned_roots(policy)?;
        registry.expected_network = Some(expected_network);
        registry.minimum_version = checkpoint.version;
        registry.pinned_checkpoint = Some(checkpoint);
        Ok(registry)
    }

    /// Verify and load a signed snapshot. Enforces schema, signature under the pinned
    /// root, and strictly increasing versions (a re-offered or older snapshot is a
    /// rollback/freeze attempt and is rejected).
    pub fn load(&mut self, signed: &SignedSnapshot) -> Result<Hash32, RegistryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| RegistryError::Internal(error.to_string()))?
            .as_secs()
            .try_into()
            .map_err(|_| RegistryError::Internal("system time exceeds i64".to_string()))?;
        self.load_at(signed, now)
    }

    /// Verify and load at a caller-supplied trusted time. This makes expiry tests and offline
    /// verification deterministic while keeping the validity decision explicit.
    pub fn load_at(
        &mut self,
        signed: &SignedSnapshot,
        now_unix: i64,
    ) -> Result<Hash32, RegistryError> {
        if signed.snapshot.schema != REGISTRY_SCHEMA {
            return Err(RegistryError::Schema(signed.snapshot.schema.clone()));
        }
        let root = snapshot_root(&signed.snapshot)?;
        if signed.signatures.len() < self.root_threshold as usize {
            return Err(RegistryError::Signature);
        }
        let mut valid_signatures = 0u32;
        for (id, encoded) in &signed.signatures {
            let key = self.root_keys.get(id).ok_or(RegistryError::Signature)?;
            let sig_bytes: [u8; 64] = hex::decode(encoded)
                .map_err(|_| RegistryError::Signature)?
                .try_into()
                .map_err(|_| RegistryError::Signature)?;
            let signature = Signature::from_bytes(&sig_bytes);
            key.verify(&root.0, &signature)
                .map_err(|_| RegistryError::Signature)?;
            valid_signatures = valid_signatures.saturating_add(1);
        }
        if valid_signatures < self.root_threshold {
            return Err(RegistryError::Signature);
        }

        if let Some(expected) = self.expected_network {
            if signed.snapshot.network_id != expected {
                return Err(RegistryError::Network {
                    expected: expected.0.to_hex(),
                    found: signed.snapshot.network_id.0.to_hex(),
                });
            }
        }
        if signed.snapshot.valid_from_unix > signed.snapshot.expires_at_unix {
            return Err(RegistryError::Validity {
                valid_from: signed.snapshot.valid_from_unix,
                expires_at: signed.snapshot.expires_at_unix,
            });
        }
        if now_unix < signed.snapshot.valid_from_unix {
            return Err(RegistryError::NotYetValid {
                valid_from: signed.snapshot.valid_from_unix,
                now: now_unix,
            });
        }
        if now_unix > signed.snapshot.expires_at_unix {
            return Err(RegistryError::Expired {
                expires_at: signed.snapshot.expires_at_unix,
                now: now_unix,
            });
        }
        for (capability, revocation) in &signed.snapshot.revocations {
            if capability.is_empty() || revocation.reason.trim().is_empty() {
                return Err(RegistryError::Parse(
                    "revocations require a capability key and non-empty reason".to_string(),
                ));
            }
            if revocation.effective_version > signed.snapshot.version {
                return Err(RegistryError::Parse(format!(
                    "revocation {capability} becomes effective after snapshot version {}",
                    signed.snapshot.version
                )));
            }
        }

        if signed.snapshot.version < self.minimum_version {
            return Err(RegistryError::Rollback {
                offered: signed.snapshot.version,
                current: self.minimum_version,
            });
        }
        if self.current.is_none() {
            if let Some(checkpoint) = self.pinned_checkpoint {
                if signed.snapshot.version == checkpoint.version {
                    if root != checkpoint.root || signed.snapshot.log_index != checkpoint.log_index
                    {
                        return Err(RegistryError::Transparency(format!(
                            "snapshot version {} conflicts with the persisted checkpoint",
                            checkpoint.version
                        )));
                    }
                } else {
                    let expected_index = checkpoint.log_index.checked_add(1).ok_or_else(|| {
                        RegistryError::Transparency("log index overflow".to_string())
                    })?;
                    if signed.snapshot.log_index != expected_index
                        || signed.snapshot.previous_root != Some(checkpoint.root)
                    {
                        return Err(RegistryError::Transparency(format!(
                            "snapshot does not directly extend persisted checkpoint {}",
                            checkpoint.root
                        )));
                    }
                }
            }
        }
        if let Some(current) = &self.current {
            if signed.snapshot.version <= current.snapshot.version {
                return Err(RegistryError::Rollback {
                    offered: signed.snapshot.version,
                    current: current.snapshot.version,
                });
            }
            let expected_index = current
                .snapshot
                .log_index
                .checked_add(1)
                .ok_or_else(|| RegistryError::Transparency("log index overflow".to_string()))?;
            if signed.snapshot.log_index != expected_index {
                return Err(RegistryError::Transparency(format!(
                    "expected log index {expected_index}, got {}",
                    signed.snapshot.log_index
                )));
            }
            if signed.snapshot.previous_root != Some(current.root) {
                return Err(RegistryError::Transparency(format!(
                    "snapshot does not extend the previously accepted root {}",
                    current.root
                )));
            }
        }
        self.current = Some(Loaded {
            snapshot: signed.snapshot.clone(),
            root,
        });
        Ok(root)
    }

    pub fn load_json(&mut self, json: &str) -> Result<Hash32, RegistryError> {
        let signed: SignedSnapshot =
            serde_json::from_str(json).map_err(|e| RegistryError::Parse(e.to_string()))?;
        self.load(&signed)
    }

    pub fn load_json_at(&mut self, json: &str, now_unix: i64) -> Result<Hash32, RegistryError> {
        let signed: SignedSnapshot =
            serde_json::from_str(json).map_err(|e| RegistryError::Parse(e.to_string()))?;
        self.load_at(&signed, now_unix)
    }

    pub fn root(&self) -> Result<Hash32, RegistryError> {
        Ok(self.loaded()?.root)
    }

    pub fn checkpoint(&self) -> Result<RegistryCheckpoint, RegistryError> {
        let loaded = self.loaded()?;
        Ok(RegistryCheckpoint {
            version: loaded.snapshot.version,
            log_index: loaded.snapshot.log_index,
            root: loaded.root,
        })
    }

    pub fn resolve_policy(&self, wasm_hash: &Hash32) -> Result<&PolicyCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("policy", &wasm_hash.to_hex())?;
        l.snapshot
            .policies
            .get(&wasm_hash.to_hex())
            .ok_or_else(|| RegistryError::UnknownPolicy(wasm_hash.to_hex()))
    }

    pub fn resolve_account(&self, wasm_hash: &Hash32) -> Result<&AccountCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("account", &wasm_hash.to_hex())?;
        l.snapshot
            .accounts
            .get(&wasm_hash.to_hex())
            .ok_or_else(|| RegistryError::UnknownAccount(wasm_hash.to_hex()))
    }

    pub fn resolve_verifier(
        &self,
        wasm_hash: &Hash32,
    ) -> Result<&VerifierCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("verifier", &wasm_hash.to_hex())?;
        l.snapshot
            .verifiers
            .get(&wasm_hash.to_hex())
            .ok_or_else(|| RegistryError::UnknownVerifier(wasm_hash.to_hex()))
    }

    pub fn resolve_template(&self, family: &str) -> Result<&TemplateCapability, RegistryError> {
        let l = self.loaded()?;
        self.ensure_active("template", family)?;
        l.snapshot
            .templates
            .get(family)
            .ok_or_else(|| RegistryError::UnknownTemplate(family.to_string()))
    }

    fn loaded(&self) -> Result<&Loaded, RegistryError> {
        self.current.as_ref().ok_or(RegistryError::NotLoaded)
    }

    fn ensure_active(&self, kind: &str, identity: &str) -> Result<(), RegistryError> {
        let capability = format!("{kind}/{identity}");
        if let Some(revocation) = self.loaded()?.snapshot.revocations.get(&capability) {
            return Err(RegistryError::Revoked {
                capability,
                reason: revocation.reason.clone(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Phase 1 development snapshot (deterministic; used by tests and the local toolchain)
// ---------------------------------------------------------------------------------------

pub mod dev {
    use super::*;
    use ozpb_domain::sha256;

    /// Deterministic development root key (NOT a production root; production roots are
    /// threshold-held and pinned at release time).
    pub fn dev_signing_key() -> SigningKey {
        SigningKey::from_bytes(&sha256(b"ozpb-dev-registry-root-key-v1").0)
    }

    /// The two trust documents a caller needs to run the pipeline against this snapshot: the
    /// signed snapshot, and the root policy that authenticates it.
    ///
    /// Returned as text rather than written to disk so the CLI and the drift test share one
    /// source. The copies committed under `docs/examples/` are what a reader actually runs, and
    /// a command that regenerated them immediately before use would repair drift instead of
    /// reporting it — so the demo consumes the committed files and `examples_are_current.rs`
    /// asserts they still match this.
    ///
    /// The signature key id must stay in step with [`crate::sign_snapshot`] (`legacy`), or
    /// verification fails with `E_REGISTRY_SIGNATURE` and no indication why.
    pub fn dev_trust_files(
        network_id: NetworkId,
        version: u64,
    ) -> Result<(String, String), RegistryError> {
        let signed = crate::sign_snapshot(&dev_signing_key(), dev_snapshot(network_id, version))?;
        let snapshot_json = serde_json::to_string_pretty(&signed)
            .map_err(|error| RegistryError::Internal(error.to_string()))?
            + "\n";
        let roots = serde_json::json!({
            "threshold": 1,
            "keys": { "legacy": hex::encode(dev_root_verifying_bytes()) },
        });
        let roots_json = serde_json::to_string_pretty(&roots)
            .map_err(|error| RegistryError::Internal(error.to_string()))?
            + "\n";
        Ok((snapshot_json, roots_json))
    }

    pub fn dev_root_verifying_bytes() -> [u8; 32] {
        dev_signing_key().verifying_key().to_bytes()
    }

    /// A Phase 1 snapshot: the scope template family, a pinned spending-limit hash, a
    /// pinned account hash, and a pinned ed25519 verifier hash. The three wasm hashes are
    /// **real**, built from OpenZeppelin's own example contracts at a pinned tag — see
    /// [`ozpb_domain::pinned_upstream`] for the exact provenance and how to reproduce them.
    /// What remains a development stand-in is the *signing root*: [`dev_signing_key`] is
    /// derived from a fixed string, so this snapshot authenticates against a key anyone can
    /// recompute. A production deployment supplies its own governance root.
    pub fn dev_snapshot(network_id: NetworkId, version: u64) -> RegistrySnapshot {
        let mut policies = BTreeMap::new();
        policies.insert(
            pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM.to_hex(),
            PolicyCapability {
                kind: "oz:spending_limit".to_string(),
                // The reviewed source requires >=1 authenticated signer but enforces no
                // configured predicate — it can never satisfy a spec predicate alone.
                signer_predicates: vec![],
                security_relevant_methods: vec![
                    "install".into(),
                    "enforce".into(),
                    "uninstall".into(),
                    "set_spending_limit".into(),
                ],
                review_reference: "OpenZeppelin/stellar-contracts examples/multisig-smart-account/spending-limit-policy @ v0.7.2 (a9c4216), built here with rustc 1.91.1 — provenance in ozpb_domain::pinned_upstream. Upstream publishes no wasm, so this is our reproducible build of their source, not an artifact they signed."
                    .to_string(),
            },
        );
        let mut accounts = BTreeMap::new();
        accounts.insert(
            pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex(),
            AccountCapability {
                release: "stellar-accounts@0.7.x".to_string(),
                rule_enumeration: "bounded_next_id".to_string(),
                management_evidence: "return_value_and_events_must_agree".to_string(),
                review_reference: "OpenZeppelin/stellar-contracts examples/multisig-smart-account/account @ v0.7.2 (a9c4216), built here with rustc 1.91.1 — provenance in ozpb_domain::pinned_upstream. Our build of their source, not an upstream-published artifact."
                    .to_string(),
            },
        );
        let mut verifiers = BTreeMap::new();
        verifiers.insert(
            pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex(),
            VerifierCapability {
                implementation: "oz ed25519 verifier".to_string(),
                key_encoding: "raw ed25519 public key (32 bytes)".to_string(),
                immutable: true,
                review_reference: "OpenZeppelin/stellar-contracts examples/multisig-smart-account/ed25519-verifier @ v0.7.2 (a9c4216), built here with rustc 1.91.1 — provenance in ozpb_domain::pinned_upstream. Our build of their source, not an upstream-published artifact."
                    .to_string(),
            },
        );
        let mut templates = BTreeMap::new();
        templates.insert(
            "policy-templates/scope@1".to_string(),
            TemplateCapability {
                capability_schema: sha256(b"policy-templates/scope@1:capability-algebra"),
                signer_predicates: vec![
                    "any_of".into(),
                    "all_of".into(),
                    "threshold".into(),
                    "strict_signer_set".into(),
                ],
                constraint_kinds: vec![
                    "eq_address".into(),
                    "eq_i128".into(),
                    "eq_scval".into(),
                    "le_i128".into(),
                    "ge_i128".into(),
                    "call_count_per_installation".into(),
                ],
                review_reference: "audited with the template pack".to_string(),
            },
        );
        RegistrySnapshot {
            schema: REGISTRY_SCHEMA.to_string(),
            version,
            log_index: version,
            previous_root: None,
            network_id,
            valid_from_unix: i64::MIN,
            expires_at_unix: i64::MAX,
            policies,
            accounts,
            verifiers,
            templates,
            revocations: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped snapshot must carry the *pinned upstream* hashes, not values derived
    /// locally. It previously held `sha256("dev:oz:spending_limit:wasm")` — a hash of a text
    /// label, not of any code — so the mechanism worked while recognizing nothing real. A
    /// literal here would drift silently from `domain`, which is why both sides read one
    /// constant; this test asserts the snapshot actually uses it.
    #[test]
    fn the_shipped_snapshot_pins_real_upstream_wasm_hashes() {
        let snapshot = dev::dev_snapshot(
            NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
            1,
        );
        // Each hash must appear in ITS OWN table. Checking the union of the three would pass
        // even with the policy, account and verifier keys swapped between them — and a
        // verifier resolved as a policy is precisely the confusion the registry prevents.
        let policy = pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM.to_hex();
        let account = pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex();
        let verifier = pinned_upstream::OZ_ED25519_VERIFIER_WASM.to_hex();

        assert!(
            snapshot.policies.contains_key(&policy),
            "spending-limit policy {policy} is not in snapshot.policies"
        );
        assert!(
            snapshot.accounts.contains_key(&account),
            "smart account {account} is not in snapshot.accounts"
        );
        assert!(
            snapshot.verifiers.contains_key(&verifier),
            "ed25519 verifier {verifier} is not in snapshot.verifiers"
        );
        // And not cross-registered, which the union check would have allowed.
        assert!(!snapshot.accounts.contains_key(&policy));
        assert!(!snapshot.verifiers.contains_key(&policy));
        assert!(!snapshot.policies.contains_key(&account));
        assert!(!snapshot.policies.contains_key(&verifier));

        // A hash of a label rather than of code is the failure being guarded against, so the
        // old placeholders are spelled out.
        for placeholder in [
            "dev:oz:spending_limit:wasm",
            "dev:stellar-accounts:wasm",
            "dev:ed25519-verifier:wasm",
        ] {
            let stale = sha256(placeholder.as_bytes()).to_hex();
            for (label, real) in [
                ("policy", &policy),
                ("account", &account),
                ("verifier", &verifier),
            ] {
                assert_ne!(
                    real, &stale,
                    "{label} is still the {placeholder:?} placeholder"
                );
            }
        }

        // The shipped provenance must not still call these placeholders.
        for reference in snapshot
            .policies
            .values()
            .map(|c| &c.review_reference)
            .chain(snapshot.accounts.values().map(|c| &c.review_reference))
            .chain(snapshot.verifiers.values().map(|c| &c.review_reference))
        {
            assert!(
                !reference.contains("placeholder"),
                "a pinned entry still describes itself as a placeholder: {reference}"
            );
        }
    }

    use ozpb_domain::{sha256, NetworkId, TESTNET_PASSPHRASE};

    fn network() -> NetworkId {
        NetworkId::from_passphrase(TESTNET_PASSPHRASE)
    }

    fn registry() -> Registry {
        Registry::with_pinned_root(&dev::dev_root_verifying_bytes()).unwrap()
    }

    #[test]
    fn sign_load_resolve_round_trip() {
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let mut r = registry();
        let root = r.load(&signed).unwrap();
        assert_eq!(root, r.root().unwrap());

        let cap = r
            .resolve_policy(&pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM)
            .unwrap();
        assert_eq!(cap.kind, "oz:spending_limit");
        assert!(
            cap.signer_predicates.is_empty(),
            "spending limit enforces no configured predicate"
        );
        let t = r.resolve_template("policy-templates/scope@1").unwrap();
        assert!(t
            .signer_predicates
            .contains(&"strict_signer_set".to_string()));
    }

    #[test]
    fn snapshot_root_is_deterministic_and_content_sensitive() {
        let a = snapshot_root(&dev::dev_snapshot(network(), 1)).unwrap();
        let b = snapshot_root(&dev::dev_snapshot(network(), 1)).unwrap();
        assert_eq!(a, b);
        let c = snapshot_root(&dev::dev_snapshot(network(), 2)).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn bad_signature_is_rejected() {
        let mut signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        // Tamper after signing.
        signed.snapshot.version = 99;
        let mut r = registry();
        assert_eq!(r.load(&signed).unwrap_err(), RegistryError::Signature);

        // Wrong key entirely.
        let other = SigningKey::from_bytes(&sha256(b"attacker-key").0);
        let forged = sign_snapshot(&other, dev::dev_snapshot(network(), 1)).unwrap();
        assert_eq!(r.load(&forged).unwrap_err(), RegistryError::Signature);
    }

    #[test]
    fn threshold_root_policy_requires_distinct_trusted_signers() {
        let first = SigningKey::from_bytes(&sha256(b"registry-root-1").0);
        let second = SigningKey::from_bytes(&sha256(b"registry-root-2").0);
        let third = SigningKey::from_bytes(&sha256(b"registry-root-3").0);
        let roots = RootPolicy {
            threshold: 2,
            keys: BTreeMap::from([
                ("first".to_string(), first.verifying_key().to_bytes()),
                ("second".to_string(), second.verifying_key().to_bytes()),
                ("third".to_string(), third.verifying_key().to_bytes()),
            ]),
        };
        let snapshot = dev::dev_snapshot(network(), 1);
        let under_threshold = sign_snapshot_with_roots(
            &BTreeMap::from([("first".to_string(), first.clone())]),
            snapshot.clone(),
        )
        .unwrap();
        let mut registry = Registry::with_pinned_roots(roots.clone()).unwrap();
        assert_eq!(
            registry.load(&under_threshold).unwrap_err(),
            RegistryError::Signature
        );

        let signed = sign_snapshot_with_roots(
            &BTreeMap::from([("first".to_string(), first), ("second".to_string(), second)]),
            snapshot,
        )
        .unwrap();
        let mut registry = Registry::with_pinned_roots(roots).unwrap();
        registry.load(&signed).unwrap();
    }

    #[test]
    fn threshold_root_policy_rejects_the_same_key_under_multiple_ids() {
        let key = dev::dev_root_verifying_bytes();
        let policy = RootPolicy {
            threshold: 2,
            keys: BTreeMap::from([("alias-a".to_string(), key), ("alias-b".to_string(), key)]),
        };
        assert!(matches!(
            Registry::with_pinned_roots(policy),
            Err(RegistryError::RootPolicy(_))
        ));
    }

    #[test]
    fn rollback_and_freeze_are_rejected() {
        let key = dev::dev_signing_key();
        let v2 = sign_snapshot(&key, dev::dev_snapshot(network(), 2)).unwrap();
        let v1 = sign_snapshot(&key, dev::dev_snapshot(network(), 1)).unwrap();
        let mut r = registry();
        r.load(&v2).unwrap();
        assert_eq!(
            r.load(&v1).unwrap_err(),
            RegistryError::Rollback {
                offered: 1,
                current: 2
            }
        );
        // Re-offering the same version (freeze) is also rejected.
        assert_eq!(
            r.load(&v2).unwrap_err(),
            RegistryError::Rollback {
                offered: 2,
                current: 2
            }
        );
    }

    #[test]
    fn transparency_chain_rejects_a_fork_from_an_old_root() {
        let key = dev::dev_signing_key();
        let v1_snapshot = dev::dev_snapshot(network(), 1);
        let v1_root = snapshot_root(&v1_snapshot).unwrap();
        let v1 = sign_snapshot(&key, v1_snapshot).unwrap();

        let mut v2_snapshot = dev::dev_snapshot(network(), 2);
        v2_snapshot.previous_root = Some(v1_root);
        let v2_root = snapshot_root(&v2_snapshot).unwrap();
        let v2 = sign_snapshot(&key, v2_snapshot).unwrap();

        let mut forked_v3 = dev::dev_snapshot(network(), 3);
        forked_v3.previous_root = Some(v1_root);
        let forked_v3 = sign_snapshot(&key, forked_v3).unwrap();

        let mut registry = registry();
        registry.load(&v1).unwrap();
        registry.load(&v2).unwrap();
        assert_eq!(registry.root().unwrap(), v2_root);
        assert!(matches!(
            registry.load(&forked_v3),
            Err(RegistryError::Transparency(_))
        ));
    }

    #[test]
    fn network_and_snapshot_validity_are_pinned() {
        let root = dev::dev_root_verifying_bytes();
        let mainnet = NetworkId::from_passphrase("Public Global Stellar Network ; September 2015");
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let mut wrong_network = Registry::with_pinned_root_for_network(&root, mainnet).unwrap();
        assert!(
            wrong_network.load_at(&signed, 100).is_err(),
            "a correctly signed snapshot for another network must fail closed"
        );

        let mut snapshot = dev::dev_snapshot(network(), 1);
        snapshot.valid_from_unix = 100;
        snapshot.expires_at_unix = 200;
        let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
        let mut before = Registry::with_pinned_root_for_network(&root, network()).unwrap();
        assert!(matches!(
            before.load_at(&signed, 99),
            Err(RegistryError::NotYetValid { .. })
        ));
        let mut active = Registry::with_pinned_root_for_network(&root, network()).unwrap();
        active.load_at(&signed, 100).unwrap();
        let mut expired = Registry::with_pinned_root_for_network(&root, network()).unwrap();
        assert!(matches!(
            expired.load_at(&signed, 201),
            Err(RegistryError::Expired { .. })
        ));
    }

    #[test]
    fn a_fresh_process_enforces_the_persisted_minimum_version() {
        let root = dev::dev_root_verifying_bytes();
        let v1 = sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let v2 = sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 2)).unwrap();
        let mut registry =
            Registry::with_pinned_root_for_network_at_version(&root, network(), 2).unwrap();
        assert_eq!(
            registry.load(&v1).unwrap_err(),
            RegistryError::Rollback {
                offered: 1,
                current: 2
            }
        );
        registry.load(&v2).unwrap();
    }

    #[test]
    fn a_persisted_checkpoint_rejects_same_version_equivocation_after_restart() {
        let roots = RootPolicy {
            threshold: 1,
            keys: BTreeMap::from([("legacy".to_string(), dev::dev_root_verifying_bytes())]),
        };
        let v1_snapshot = dev::dev_snapshot(network(), 1);
        let v1 = sign_snapshot(&dev::dev_signing_key(), v1_snapshot.clone()).unwrap();
        let mut first = Registry::with_pinned_roots(roots.clone()).unwrap();
        first.load(&v1).unwrap();
        let checkpoint = first.checkpoint().unwrap();

        let mut equivocation = v1_snapshot;
        equivocation.expires_at_unix -= 1;
        let equivocation = sign_snapshot(&dev::dev_signing_key(), equivocation).unwrap();
        let mut restarted =
            Registry::with_pinned_roots_for_network_at_checkpoint(roots, network(), checkpoint)
                .unwrap();
        assert!(matches!(
            restarted.load(&equivocation),
            Err(RegistryError::Transparency(_))
        ));
        restarted.load(&v1).unwrap();
    }

    #[test]
    fn unknown_hashes_fail_closed() {
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let mut r = registry();
        r.load(&signed).unwrap();
        assert!(matches!(
            r.resolve_policy(&sha256(b"unknown")).unwrap_err(),
            RegistryError::UnknownPolicy(_)
        ));
        assert!(matches!(
            r.resolve_account(&sha256(b"unknown")).unwrap_err(),
            RegistryError::UnknownAccount(_)
        ));
        assert!(matches!(
            r.resolve_verifier(&sha256(b"unknown")).unwrap_err(),
            RegistryError::UnknownVerifier(_)
        ));
        assert!(matches!(
            r.resolve_template("no-such-family").unwrap_err(),
            RegistryError::UnknownTemplate(_)
        ));
    }

    #[test]
    fn revoked_capabilities_fail_resolution_with_the_recorded_reason() {
        let account_hash = pinned_upstream::OZ_SMART_ACCOUNT_WASM;
        let mut snapshot = dev::dev_snapshot(network(), 1);
        snapshot.revocations.insert(
            format!("account/{}", account_hash.to_hex()),
            Revocation {
                reason: "critical authorization bypass".to_string(),
                effective_version: 1,
            },
        );
        let signed = sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap();
        let mut registry = registry();
        registry.load(&signed).unwrap();

        assert!(matches!(
            registry.resolve_account(&account_hash),
            Err(RegistryError::Revoked { reason, .. })
                if reason == "critical authorization bypass"
        ));
    }

    #[test]
    fn queries_before_load_fail_closed() {
        let r = registry();
        assert_eq!(
            r.resolve_template("policy-templates/scope@1").unwrap_err(),
            RegistryError::NotLoaded
        );
    }

    #[test]
    fn json_round_trip() {
        let signed =
            sign_snapshot(&dev::dev_signing_key(), dev::dev_snapshot(network(), 1)).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let mut r = registry();
        r.load_json(&json).unwrap();
    }
}
