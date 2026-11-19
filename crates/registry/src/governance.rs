//! Registry governance: the pure half of the release and monitoring tooling (architecture §4.10,
//! `docs/REGISTRY-GOVERNANCE.md`). The CLI reads and writes the files; everything that decides
//! anything is here, and every decision about a snapshot is the one [`Registry::load_at`] makes.
//!
//! The release flow is: build an unsigned successor from the published parent and a declared
//! change set ([`successor`]); show custodians its canonical root ([`snapshot_root`]); each signs
//! that root, locally ([`sign_detached`]) or on a device of their own ([`external_signature`]);
//! assemble the detached signatures ([`combine`]); load-verify the result under the pinned roots
//! before distributing it ([`replay`] for the whole published chain). Consumers check the
//! published head against their persisted checkpoint ([`monitor`]).
//!
//! Nothing here generates or stores keys, and nothing changes what a snapshot is or how it is
//! signed: a signature is ed25519 over the 32 bytes of the snapshot root, exactly what
//! [`sign_snapshot_with_roots`] produces.

use crate::{
    sign_snapshot_with_roots, snapshot_root, AccountCapability, PolicyCapability, Registry,
    RegistryCheckpoint, RegistryError, RegistrySnapshot, Revocation, RootPolicy, SignedSnapshot,
    TargetAdapterCapability, TemplateCapability, VerifierCapability,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ozpb_domain::{Hash32, NetworkId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CHANGE_SCHEMA: &str = "registry-change/v1";
pub const DETACHED_SIGNATURE_SCHEMA: &str = "registry-signature/v1";
pub const MONITOR_SCHEMA: &str = "registry-monitor/v1";

/// The capability kinds a revocation of an exact code hash can name.
const HASH_KINDS: [&str; 4] = ["policy", "account", "verifier", "target_adapter"];

/// Why a governance step refused. These reach only the `ozpb registry` CLI, never the MCP wire:
/// the leading labels name the registry code each fault belongs to, and `E_REGISTRY_PARSE` (a
/// malformed change set or signature file here, a malformed snapshot in [`RegistryError::Parse`])
/// is a message label only — on the wire a registry parse fault is `E_REGISTRY_SIGNATURE`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GovernanceError {
    #[error("{0}")]
    Registry(#[from] RegistryError),
    #[error("E_REGISTRY_PARSE: {0}")]
    Change(String),
    #[error(
        "E_REGISTRY_SIGNATURE: the signature by {key_id:?} is over root {signed}, not this \
         snapshot's root {expected}"
    )]
    WrongRoot {
        key_id: String,
        signed: Hash32,
        expected: Hash32,
    },
    #[error("E_REGISTRY_SIGNATURE: the signature by {0:?} does not verify over the snapshot root")]
    BadSignature(String),
    #[error("E_REGISTRY_SIGNATURE: more than one signature by {0:?}")]
    DuplicateSigner(String),
    #[error(
        "E_REGISTRY_SIGNATURE: {have} valid signature(s); the pinned root policy needs {need}"
    )]
    BelowThreshold { have: usize, need: u32 },
    #[error("E_REGISTRY_SIGNATURE: {0:?} is not a key id of the pinned root policy")]
    UnknownSigner(String),
    #[error("E_REGISTRY_SIGNATURE: the public key for {0:?} is not the key pinned under that id")]
    SignerKeyMismatch(String),
    #[error("E_REGISTRY_TRANSPARENCY: {0}")]
    Chain(String),
}

/// What custodians declare for the next version. Version, log index and parent root are not
/// declared: they follow from the parent. Validity is always declared, because how long the
/// custodians vouch for a snapshot is a decision they make for each one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSet {
    pub schema: String,
    #[serde(with = "ozpb_domain::wide_int")]
    pub valid_from_unix: i64,
    #[serde(with = "ozpb_domain::wide_int")]
    pub expires_at_unix: i64,
    /// Entries added, or replaced whole, by exact code hash (or template family).
    #[serde(default)]
    pub policies: BTreeMap<String, PolicyCapability>,
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountCapability>,
    #[serde(default)]
    pub verifiers: BTreeMap<String, VerifierCapability>,
    #[serde(default)]
    pub target_adapters: BTreeMap<String, TargetAdapterCapability>,
    #[serde(default)]
    pub templates: BTreeMap<String, TemplateCapability>,
    /// New revocations, capability key (`account/<hash>`, `template/<family>`, …) to reason.
    /// Each takes effect at the successor's version; a recorded revocation is never changed.
    #[serde(default)]
    pub revocations: BTreeMap<String, String>,
}

/// One custodian's signature over one snapshot root, carried separately until combined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub schema: String,
    pub key_id: String,
    /// Hex of the custodian's ed25519 public key, checked against the pinned policy on combine.
    pub public_key: String,
    pub root: Hash32,
    /// Hex of the 64-byte ed25519 signature over the 32 root bytes.
    pub signature: String,
}

/// Load a published snapshot as history: signatures, network, chain and revocation succession,
/// checked at its own `valid_from_unix`, since a superseded version is expected to have expired
/// by now. Only the head of a chain is checked at the caller's current time.
fn load_historical(
    registry: &mut Registry,
    signed: &SignedSnapshot,
) -> Result<Hash32, RegistryError> {
    registry.load_at(signed, signed.snapshot.valid_from_unix)
}

/// Build the unsigned successor of a published snapshot.
///
/// The parent is load-verified under the pinned roots first, so a successor is only ever built
/// on a snapshot a consumer would accept. The successor is then put through every check
/// [`Registry::load_at`] applies except signatures, as the next version after the parent, at
/// `now_unix` or at its own start if that is later. Anything a consumer would refuse — an
/// interval that is inverted or already over, a malformed capability key, a hash under two
/// roles — is refused here, before anyone signs it.
pub fn successor(
    roots: RootPolicy,
    network: NetworkId,
    parent: &SignedSnapshot,
    changes: &ChangeSet,
    now_unix: i64,
) -> Result<RegistrySnapshot, GovernanceError> {
    if changes.schema != CHANGE_SCHEMA {
        return Err(GovernanceError::Change(format!(
            "expected change schema {CHANGE_SCHEMA}, got {:?}",
            changes.schema
        )));
    }
    let mut registry = Registry::with_pinned_roots_for_network_at_version(roots, network, 0)?;
    let parent_root = load_historical(&mut registry, parent)?;
    let mut next = parent.snapshot.clone();
    let overflow = || GovernanceError::Chain("version or log index overflow".to_string());
    next.version = next.version.checked_add(1).ok_or_else(overflow)?;
    next.log_index = next.log_index.checked_add(1).ok_or_else(overflow)?;
    next.previous_root = Some(parent_root);
    next.valid_from_unix = changes.valid_from_unix;
    next.expires_at_unix = changes.expires_at_unix;
    next.policies.extend(changes.policies.clone());
    next.accounts.extend(changes.accounts.clone());
    next.verifiers.extend(changes.verifiers.clone());
    next.target_adapters.extend(changes.target_adapters.clone());
    next.templates.extend(changes.templates.clone());
    for (capability, reason) in &changes.revocations {
        if next.revocations.contains_key(capability) {
            return Err(GovernanceError::Change(format!(
                "{capability} is already revoked; a recorded revocation is never changed"
            )));
        }
        next.revocations.insert(
            capability.clone(),
            Revocation {
                reason: reason.clone(),
                effective_version: next.version,
            },
        );
    }
    registry.check_unsigned(&next, now_unix.max(next.valid_from_unix))?;
    Ok(next)
}

/// Sign a snapshot's root with a locally held key, as a detached signature.
pub fn sign_detached(
    key_id: &str,
    key: &SigningKey,
    snapshot: &RegistrySnapshot,
) -> Result<DetachedSignature, GovernanceError> {
    require_key_id(key_id)?;
    let signed = sign_snapshot_with_roots(
        &BTreeMap::from([(key_id.to_string(), key.clone())]),
        snapshot.clone(),
    )?;
    let signature = signed
        .signatures
        .get(key_id)
        .cloned()
        .ok_or_else(|| RegistryError::Internal("the signer produced no signature".into()))?;
    Ok(DetachedSignature {
        schema: DETACHED_SIGNATURE_SCHEMA.to_string(),
        key_id: key_id.to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        root: snapshot_root(snapshot)?,
        signature,
    })
}

/// Accept a signature produced elsewhere — a hardware key, another machine — over this
/// snapshot's root, refusing one that does not verify under the given public key.
pub fn external_signature(
    key_id: &str,
    public_key: &[u8; 32],
    signature_hex: &str,
    snapshot: &RegistrySnapshot,
) -> Result<DetachedSignature, GovernanceError> {
    require_key_id(key_id)?;
    let detached = DetachedSignature {
        schema: DETACHED_SIGNATURE_SCHEMA.to_string(),
        key_id: key_id.to_string(),
        public_key: hex::encode(public_key),
        root: snapshot_root(snapshot)?,
        signature: signature_hex.trim().to_ascii_lowercase(),
    };
    verify_detached(&detached)?;
    Ok(detached)
}

/// Assemble detached signatures into a signed snapshot. Each must be over this snapshot's root,
/// verify, and come from a key pinned under its id; together they must meet the threshold. The
/// result is then loaded as a consumer would load it — under the pinned roots and network, at
/// `now_unix` or at its own start if that is later — so nothing a consumer refuses is returned.
/// Its place in the chain is not checked here: [`replay`] of the published log does that before
/// distribution.
pub fn combine(
    roots: &RootPolicy,
    network: NetworkId,
    snapshot: RegistrySnapshot,
    signatures: &[DetachedSignature],
    now_unix: i64,
) -> Result<SignedSnapshot, GovernanceError> {
    Registry::with_pinned_roots(roots.clone())?;
    let root = snapshot_root(&snapshot)?;
    let mut collected = BTreeMap::new();
    for detached in signatures {
        if detached.root != root {
            return Err(GovernanceError::WrongRoot {
                key_id: detached.key_id.clone(),
                signed: detached.root,
                expected: root,
            });
        }
        let pinned = roots
            .keys
            .get(&detached.key_id)
            .ok_or_else(|| GovernanceError::UnknownSigner(detached.key_id.clone()))?;
        if hex::encode(pinned) != detached.public_key {
            return Err(GovernanceError::SignerKeyMismatch(detached.key_id.clone()));
        }
        verify_detached(detached)?;
        if collected
            .insert(detached.key_id.clone(), detached.signature.clone())
            .is_some()
        {
            return Err(GovernanceError::DuplicateSigner(detached.key_id.clone()));
        }
    }
    if collected.len() < roots.threshold as usize {
        return Err(GovernanceError::BelowThreshold {
            have: collected.len(),
            need: roots.threshold,
        });
    }
    let signed = SignedSnapshot {
        snapshot,
        signatures: collected,
    };
    let at = now_unix.max(signed.snapshot.valid_from_unix);
    Registry::with_pinned_roots_for_network_at_version(roots.clone(), network, 0)?
        .load_at(&signed, at)?;
    Ok(signed)
}

/// Load-verify a published chain from genesis under the pinned roots and network: every version
/// must load as the direct successor of the one before it, and the head must be valid at
/// `now_unix`. Returns the head's checkpoint — what a consumer persists.
///
/// This is stricter than a consumer's load, which needs only a higher version and the next log
/// index: a published log starts at version 1 and log index 1 with no parent, and its versions
/// are consecutive, as [`successor`] produces them.
pub fn replay(
    roots: RootPolicy,
    network: NetworkId,
    chain: &[SignedSnapshot],
    now_unix: i64,
) -> Result<RegistryCheckpoint, GovernanceError> {
    let (head, history) = chain
        .split_last()
        .ok_or_else(|| GovernanceError::Chain("the published chain is empty".to_string()))?;
    let genesis = &chain.first().unwrap_or(head).snapshot;
    if genesis.version != 1 || genesis.log_index != 1 || genesis.previous_root.is_some() {
        return Err(GovernanceError::Chain(format!(
            "a chain starts at a genesis snapshot (version 1, log index 1, no previous root), \
             not version {} at log index {}",
            genesis.version, genesis.log_index
        )));
    }
    let mut registry = Registry::with_pinned_roots_for_network_at_version(roots, network, 0)?;
    for (offset, signed) in history.iter().enumerate() {
        let expected = offset as u64 + 1;
        require_version(signed, expected)?;
        load_historical(&mut registry, signed)?;
    }
    require_version(head, history.len() as u64 + 1)?;
    registry.load_at(head, now_unix)?;
    Ok(registry.checkpoint()?)
}

fn require_version(signed: &SignedSnapshot, expected: u64) -> Result<(), GovernanceError> {
    if signed.snapshot.version != expected {
        return Err(GovernanceError::Chain(format!(
            "expected version {expected} next in the chain, found {}",
            signed.snapshot.version
        )));
    }
    Ok(())
}

/// Where the published head's validity stands at the time of the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityStatus {
    Valid,
    NotYetValid,
    ExpiresSoon,
    Expired,
}

/// The most urgent thing a monitoring run found, in increasing order of urgency. A cron job maps
/// it to an exit status; the report lists every finding regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    Current,
    NewerVersion,
    NotYetValid,
    ExpiresSoon,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedHash {
    pub wasm_hash: Hash32,
    pub capability: String,
    pub reason: String,
    #[serde(with = "ozpb_domain::wide_int")]
    pub effective_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorReport {
    pub schema: String,
    pub status: MonitorStatus,
    #[serde(with = "ozpb_domain::wide_int")]
    pub checked_at_unix: i64,
    #[serde(with = "ozpb_domain::wide_int")]
    pub checkpoint_version: u64,
    /// The verified head: what a consumer persists once it has reviewed the change.
    pub head: RegistryCheckpoint,
    pub newer_version_available: bool,
    pub validity: ValidityStatus,
    #[serde(with = "ozpb_domain::wide_int")]
    pub valid_from_unix: i64,
    #[serde(with = "ozpb_domain::wide_int")]
    pub expires_at_unix: i64,
    /// Every watched hash the head revokes, under any role.
    pub revoked: Vec<RevokedHash>,
}

/// Check the published head against a consumer's persisted checkpoint.
///
/// `published` is the published log, or its head. Versions below the checkpoint are skipped; the
/// checkpoint's own version must match the checkpoint exactly (its signatures are not re-checked,
/// so a consumer that re-pinned after a rotation keeps working); every later version is verified
/// under the pinned roots as one chain extending the checkpoint. A fork, a same-version
/// equivocation, a gap or an older head is an error, not a finding: the published log itself
/// cannot be trusted then, and that is louder than any status. Validity is reported rather than
/// refused, because noticing it is what monitoring is for.
pub fn monitor(
    roots: RootPolicy,
    network: NetworkId,
    checkpoint: RegistryCheckpoint,
    published: &[SignedSnapshot],
    now_unix: i64,
    expiry_window_secs: i64,
    watched: &[Hash32],
) -> Result<MonitorReport, GovernanceError> {
    let checkpoint_version = checkpoint.version;
    let mut relevant: Vec<&SignedSnapshot> = published
        .iter()
        .filter(|signed| signed.snapshot.version >= checkpoint_version)
        .collect();
    relevant.sort_by_key(|signed| signed.snapshot.version);
    let Some(head) = relevant.last().copied() else {
        let offered = published
            .iter()
            .map(|signed| signed.snapshot.version)
            .max()
            .ok_or_else(|| GovernanceError::Chain("nothing is published".to_string()))?;
        return Err(RegistryError::Rollback {
            offered,
            current: checkpoint_version,
        }
        .into());
    };
    let mut registry =
        Registry::with_pinned_roots_for_network_at_checkpoint(roots, network, checkpoint.clone())?;
    let mut head_checkpoint = checkpoint.clone();
    for signed in &relevant {
        if signed.snapshot.version == checkpoint_version {
            require_matches_checkpoint(&signed.snapshot, &checkpoint)?;
        } else {
            load_historical(&mut registry, signed)?;
            head_checkpoint = registry.checkpoint()?;
        }
    }
    let snapshot = &head.snapshot;
    let validity = if now_unix < snapshot.valid_from_unix {
        ValidityStatus::NotYetValid
    } else if now_unix > snapshot.expires_at_unix {
        ValidityStatus::Expired
    } else if snapshot.expires_at_unix.saturating_sub(now_unix) <= expiry_window_secs {
        ValidityStatus::ExpiresSoon
    } else {
        ValidityStatus::Valid
    };
    let mut revoked = Vec::new();
    for hash in watched {
        for kind in HASH_KINDS {
            let capability = format!("{kind}/{}", hash.to_hex());
            if let Some(revocation) = snapshot.revocations.get(&capability) {
                revoked.push(RevokedHash {
                    wasm_hash: *hash,
                    capability,
                    reason: revocation.reason.clone(),
                    effective_version: revocation.effective_version,
                });
            }
        }
    }
    let newer_version_available = snapshot.version > checkpoint_version;
    let status = if !revoked.is_empty() {
        MonitorStatus::Revoked
    } else if validity == ValidityStatus::Expired {
        MonitorStatus::Expired
    } else if validity == ValidityStatus::ExpiresSoon {
        MonitorStatus::ExpiresSoon
    } else if validity == ValidityStatus::NotYetValid {
        MonitorStatus::NotYetValid
    } else if newer_version_available {
        MonitorStatus::NewerVersion
    } else {
        MonitorStatus::Current
    };
    Ok(MonitorReport {
        schema: MONITOR_SCHEMA.to_string(),
        status,
        checked_at_unix: now_unix,
        checkpoint_version,
        head: head_checkpoint,
        newer_version_available,
        validity,
        valid_from_unix: snapshot.valid_from_unix,
        expires_at_unix: snapshot.expires_at_unix,
        revoked,
    })
}

/// The published copy of the version a consumer has already accepted must be exactly what it
/// accepted: the same root, chain position and revocations. Its signatures are not checked again.
/// They were checked when it was accepted, and after a rotation they belong to roots the consumer
/// no longer pins, so re-verifying them would stall every consumer that re-pinned.
fn require_matches_checkpoint(
    snapshot: &RegistrySnapshot,
    checkpoint: &RegistryCheckpoint,
) -> Result<(), GovernanceError> {
    if snapshot_root(snapshot)? != checkpoint.root
        || snapshot.log_index != checkpoint.log_index
        || snapshot.revocations != checkpoint.revocations
    {
        return Err(RegistryError::Transparency(format!(
            "the published version {} conflicts with the persisted checkpoint",
            checkpoint.version
        ))
        .into());
    }
    Ok(())
}

fn require_key_id(key_id: &str) -> Result<(), GovernanceError> {
    if key_id.is_empty() {
        return Err(GovernanceError::Change(
            "a signature needs the key id it is pinned under".to_string(),
        ));
    }
    Ok(())
}

/// Strict ed25519 verification over the root bytes, refusing a weak (small-order) key, the same
/// two protections [`Registry::load_at`] relies on.
fn verify_detached(detached: &DetachedSignature) -> Result<(), GovernanceError> {
    let bad = || GovernanceError::BadSignature(detached.key_id.clone());
    if detached.schema != DETACHED_SIGNATURE_SCHEMA {
        return Err(GovernanceError::Change(format!(
            "expected signature schema {DETACHED_SIGNATURE_SCHEMA}, got {:?}",
            detached.schema
        )));
    }
    let key_bytes: [u8; 32] = hex::decode(&detached.public_key)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| bad())?;
    if key.is_weak() {
        return Err(bad());
    }
    let signature: [u8; 64] = hex::decode(&detached.signature)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    key.verify_strict(&detached.root.0, &Signature::from_bytes(&signature))
        .map_err(|_| bad())
}

#[cfg(test)]
mod tests;
