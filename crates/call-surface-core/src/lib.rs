//! Two-surface account authority check (architecture §4.8, Decisions D4/D6).
//!
//! Pure logic over an in-memory account rule-set model (as if read from
//! `getLedgerEntries`). It answers one question, fail-closed: *at this observed ledger,
//! is it safe to install policies into this account?* — where "safe" means no rule other
//! than the designated administrative rule can reach either the **direct policy surface**
//! (a policy contract's `install`/`enforce`/`uninstall`) or the **account management
//! surface** (`add_context_rule`, `add_signer`, …). `CallContract` scoping discards
//! function names, so any rule matching a bound policy address or the account's own
//! address can call every `require_auth`-gated method there.
//!
//! Enumeration is `bounded_next_id` (D6): read `NextId` + active `Count` + the rule
//! entries and their transitive signer/policy closure; a count deficit or a missing
//! transitive entry fails closed (`E_INCOMPLETE_ACCOUNT_STATE`) rather than yielding a
//! partial verdict — an archived weak rule could be restored and used in the same
//! invocation. Dominance is decided conservatively: only the exact designated admin rule
//! (or a rule a registered implication proves equivalent-or-stronger) is safe; everything
//! else on a protected surface is rejected with remediation. There is no override.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::{domains, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------------------
// In-memory account state (the enumeration input; produced by an acquisition adapter that
// reads ledger entries — kept out of this pure crate).
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountState {
    /// Monotonic rule-id counter (next id to be assigned).
    pub next_id: u32,
    /// Active (non-removed, incl. expired) rule count — the reconciliation target.
    pub active_count: u32,
    /// Live rules by id (ids in 0..next_id that were not removed). Archived-but-not-
    /// removed rules are absent here and MUST cause a count deficit.
    pub rules: BTreeMap<u32, StoredRule>,
    /// Global signer registry (transitive closure target).
    pub signers: BTreeMap<u32, StoredSigner>,
    /// Global policy registry (transitive closure target).
    pub policies: BTreeMap<u32, StoredPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRule {
    pub id: u32,
    pub context_type: StoredContextType,
    pub valid_until: Option<u32>,
    pub signer_ids: Vec<u32>,
    pub policy_ids: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredContextType {
    Default,
    CallContract { address: String },
    CreateContract { wasm_hash: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSigner {
    pub id: u32,
    /// Canonical signer key (delegated address or external verifier+key encoding).
    pub key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPolicy {
    pub id: u32,
    pub address: String,
    /// Wasm hash observed in the same ledger snapshot as the account state.
    pub observed_wasm_hash: String,
}

// ---------------------------------------------------------------------------------------
// Check inputs
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CheckInput<'a> {
    pub account_state: &'a AccountState,
    /// The account's own C-address (management surface).
    pub account_address: String,
    /// Observed account wasm hash (recorded in the verdict; recognition is the caller's).
    pub account_code_hash: String,
    /// Canonical exact binding set the protected policy addresses came from.
    pub binding_set_hash: Hash32,
    /// Whether the account implementation is recognized by the registry.
    pub account_recognized: bool,
    /// The exact policy contract addresses being installed (from the PolicyBindingSet).
    pub bound_policy_addresses: Vec<String>,
    /// Policy addresses recognized by the registry (a rule referencing an unrecognized
    /// policy on a protected surface fails closed).
    pub recognized_policy_addresses: BTreeSet<String>,
    /// The single designated administrative rule id.
    pub admin_rule_id: u32,
    pub current_ledger: u32,
    /// Declared enumeration capability of the account (D6). Only the first two are
    /// supported in verified mode.
    pub enumeration: Enumeration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enumeration {
    OnchainList,
    BoundedNextId,
    VerifiedEventIndex,
    None,
}

// ---------------------------------------------------------------------------------------
// Verdict + errors
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceVerdict {
    /// The verdict is an observation at exactly one ledger (freshness is retry policy,
    /// never a security-validity interval — §4.8).
    pub observed_ledger: u32,
    pub account_address: String,
    pub account_code_hash: String,
    pub binding_set_hash: Hash32,
    pub bound_policy_addresses: Vec<String>,
    /// Hash over the ordered enumerated state (rules + transitive closure) that this
    /// verdict was computed from; pins the verdict to a coherent snapshot.
    pub ordered_state_digest: Hash32,
    pub result: CheckResult,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Safe,
    Unsafe { findings: Vec<Finding> },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub surface: Surface,
    pub offending_rule_id: u32,
    pub code: String,
    pub reason: String,
    pub remediation: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    DirectPolicy,
    AccountManagement,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    #[error(
        "E_ACCOUNT_RULE_ENUMERATION_UNSUPPORTED: account enumeration capability is \
         '{0:?}'; verified mode requires onchain_list or bounded_next_id"
    )]
    EnumerationUnsupported(Enumeration),
    #[error(
        "E_INCOMPLETE_ACCOUNT_STATE: {cause:?}: {detail} — a complete verdict is \
         unavailable; restore the missing state and re-run the check"
    )]
    IncompleteState {
        cause: IncompleteCause,
        detail: String,
    },
    #[error("E_INCOMPATIBLE_ACCOUNT: account implementation {0} is not recognized")]
    IncompatibleAccount(String),
    #[error("E_ADMIN_RULE_NOT_FOUND: designated admin rule {0} is not a live rule")]
    AdminRuleNotFound(u32),
    #[error("E_ADMIN_RULE_UNSAFE: designated admin rule {0} is not a strong recognized rule: {1}")]
    AdminRuleUnsafe(u32, String),
    #[error("E_UNREGISTERED_POLICY: bound policy address {0} is not recognized")]
    UnrecognizedBoundPolicy(String),
    #[error("E_POLICY_BINDING_INVALID: {0}")]
    InvalidBindingSet(String),
    #[error("E_INTERNAL: {0}")]
    Internal(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteCause {
    /// Fewer decoded live rules than the active count — some rule entry is archived.
    Archived,
    /// A referenced signer/policy registry entry is absent.
    Missing,
    /// A snapshot inconsistency (ids beyond next_id, duplicate ids, …).
    SnapshotMismatch,
}

// ---------------------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------------------

pub fn check(input: &CheckInput) -> Result<SurfaceVerdict, CheckError> {
    // Enumeration capability gate (D6).
    match input.enumeration {
        Enumeration::OnchainList | Enumeration::BoundedNextId => {}
        other => return Err(CheckError::EnumerationUnsupported(other)),
    }
    if !input.account_recognized {
        return Err(CheckError::IncompatibleAccount(
            input.account_code_hash.clone(),
        ));
    }
    if input.bound_policy_addresses.is_empty() {
        return Err(CheckError::InvalidBindingSet(
            "at least one exact bound policy address is required".to_string(),
        ));
    }
    let unique_bound: BTreeSet<&String> = input.bound_policy_addresses.iter().collect();
    if unique_bound.len() != input.bound_policy_addresses.len() {
        return Err(CheckError::InvalidBindingSet(
            "bound policy addresses must be unique".to_string(),
        ));
    }
    if let Some(unrecognized) = input
        .bound_policy_addresses
        .iter()
        .find(|address| !input.recognized_policy_addresses.contains(*address))
    {
        return Err(CheckError::UnrecognizedBoundPolicy(unrecognized.clone()));
    }

    let st = input.account_state;

    // Enumerate live rules over 0..next_id and reconcile against active_count.
    let mut live: Vec<&StoredRule> = Vec::new();
    for (id, rule) in &st.rules {
        if *id >= st.next_id {
            return Err(CheckError::IncompleteState {
                cause: IncompleteCause::SnapshotMismatch,
                detail: format!("rule id {id} >= next_id {}", st.next_id),
            });
        }
        if rule.id != *id {
            return Err(CheckError::IncompleteState {
                cause: IncompleteCause::SnapshotMismatch,
                detail: format!("rule keyed {id} carries id {}", rule.id),
            });
        }
        live.push(rule);
    }
    if live.len() as u32 != st.active_count {
        // Fewer decoded live rules than extant count ⇒ archived/inconsistent state.
        // Archived weak rules can be restored-and-used in the same invocation, so this
        // must fail closed — a live-only scan is not a completeness proof (D6).
        return Err(CheckError::IncompleteState {
            cause: IncompleteCause::Archived,
            detail: format!(
                "decoded {} live rules but active_count is {}",
                live.len(),
                st.active_count
            ),
        });
    }

    // Transitive closure: every referenced signer/policy must be present.
    for rule in &live {
        let signer_ids: BTreeSet<&u32> = rule.signer_ids.iter().collect();
        let policy_ids: BTreeSet<&u32> = rule.policy_ids.iter().collect();
        if signer_ids.len() != rule.signer_ids.len() || policy_ids.len() != rule.policy_ids.len() {
            return Err(CheckError::IncompleteState {
                cause: IncompleteCause::SnapshotMismatch,
                detail: format!("rule {} contains duplicate signer or policy ids", rule.id),
            });
        }
        for sid in &rule.signer_ids {
            match st.signers.get(sid) {
                None => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::Missing,
                        detail: format!("rule {} references absent signer id {sid}", rule.id),
                    })
                }
                Some(signer) if signer.id != *sid => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::SnapshotMismatch,
                        detail: format!("signer keyed {sid} carries id {}", signer.id),
                    });
                }
                Some(_) => {}
            }
        }
        for pid in &rule.policy_ids {
            match st.policies.get(pid) {
                None => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::Missing,
                        detail: format!("rule {} references absent policy id {pid}", rule.id),
                    })
                }
                Some(policy) if policy.id != *pid => {
                    return Err(CheckError::IncompleteState {
                        cause: IncompleteCause::SnapshotMismatch,
                        detail: format!("policy keyed {pid} carries id {}", policy.id),
                    });
                }
                Some(_) => {}
            }
        }
    }

    // The designated admin rule must be live.
    let admin = live
        .iter()
        .find(|r| r.id == input.admin_rule_id)
        .ok_or(CheckError::AdminRuleNotFound(input.admin_rule_id))?;
    if admin.signer_ids.is_empty() {
        return Err(CheckError::AdminRuleUnsafe(
            admin.id,
            "a verified administrative rule must require at least one signer".to_string(),
        ));
    }
    if let Some(unrecognized) = admin.policy_ids.iter().find_map(|policy_id| {
        st.policies.get(policy_id).and_then(|policy| {
            (!input.recognized_policy_addresses.contains(&policy.address))
                .then_some(policy.address.clone())
        })
    }) {
        return Err(CheckError::AdminRuleUnsafe(
            admin.id,
            format!("it references unrecognized policy {unrecognized}"),
        ));
    }

    let ordered_state_digest = state_digest(st)?;
    let mut findings = Vec::new();

    // Protected addresses: every bound policy contract (direct surface) and the account
    // itself (management surface).
    let policy_set: BTreeSet<&String> = input.bound_policy_addresses.iter().collect();

    for rule in &live {
        if rule.id == input.admin_rule_id {
            continue;
        }
        // Expired rules cannot authorize anything now. Reviving one is itself a
        // management-surface action, gated by this same check on the admin path.
        if is_expired(rule, input.current_ledger) {
            continue;
        }

        let touches_direct = match &rule.context_type {
            StoredContextType::Default => true,
            StoredContextType::CallContract { address } => policy_set.contains(&address),
            StoredContextType::CreateContract { .. } => false,
        };
        let touches_mgmt = match &rule.context_type {
            StoredContextType::Default => true,
            StoredContextType::CallContract { address } => *address == input.account_address,
            StoredContextType::CreateContract { .. } => false,
        };

        if !touches_direct && !touches_mgmt {
            continue;
        }

        // A rule referencing an unrecognized policy is unknown semantics → fail closed.
        let references_unrecognized_policy = rule.policy_ids.iter().any(|pid| {
            st.policies
                .get(pid)
                .map(|p| !input.recognized_policy_addresses.contains(&p.address))
                .unwrap_or(true)
        });

        // This core has no registry-backed, parameter-aware implication evidence. Set
        // inclusion is not sufficient for composed policies, so alternate rules on a
        // protected surface conservatively fail closed.
        let dominated = false;

        if touches_direct {
            if references_unrecognized_policy {
                findings.push(unrecognized_finding(Surface::DirectPolicy, rule.id));
            } else if !dominated {
                findings.push(weak_finding(Surface::DirectPolicy, rule.id));
            }
        }
        if touches_mgmt {
            if references_unrecognized_policy {
                findings.push(unrecognized_finding(Surface::AccountManagement, rule.id));
            } else if !dominated {
                findings.push(weak_finding(Surface::AccountManagement, rule.id));
            }
        }
    }

    let result = if findings.is_empty() {
        CheckResult::Safe
    } else {
        CheckResult::Unsafe { findings }
    };

    Ok(SurfaceVerdict {
        observed_ledger: input.current_ledger,
        account_address: input.account_address.clone(),
        account_code_hash: input.account_code_hash.clone(),
        binding_set_hash: input.binding_set_hash,
        bound_policy_addresses: input.bound_policy_addresses.clone(),
        ordered_state_digest,
        result,
    })
}

fn is_expired(rule: &StoredRule, ledger: u32) -> bool {
    matches!(rule.valid_until, Some(v) if ledger > v)
}

fn weak_finding(surface: Surface, rule_id: u32) -> Finding {
    let (what, methods, code) = match surface {
        Surface::DirectPolicy => (
            "a bound policy contract",
            "install / enforce / uninstall",
            "E_UNSAFE_CALL_SURFACE",
        ),
        Surface::AccountManagement => (
            "the smart account's own address",
            "add_context_rule / add_signer / add_policy / remove_* / update_context_rule_valid_until",
            "E_UNSAFE_MANAGEMENT_SURFACE",
        ),
    };
    Finding {
        surface,
        offending_rule_id: rule_id,
        code: code.to_string(),
        reason: format!(
            "rule {rule_id} matches {what} and is not provably equivalent-or-stronger \
             than the designated admin rule, so it could authorize {methods} with weaker \
             requirements"
        ),
        remediation: format!(
            "strengthen rule {rule_id} to the admin rule's requirements, or remove it, \
             then re-run the check (there is no verified-mode override)"
        ),
    }
}

fn unrecognized_finding(surface: Surface, rule_id: u32) -> Finding {
    Finding {
        surface,
        offending_rule_id: rule_id,
        code: "E_UNREGISTERED_POLICY".to_string(),
        reason: format!(
            "rule {rule_id} on a protected surface references a policy whose \
             implementation is not registry-recognized; its authorization semantics \
             cannot be proven"
        ),
        remediation: format!(
            "remove rule {rule_id} or get its policy implementation reviewed and \
             registered, then re-run the check"
        ),
    }
}

/// Identity of the enumerated state a verdict was computed over, so a consumer can tell
/// whether the verdict still describes the account it is holding.
///
/// **Domain.** `ACCOUNT_STATE`, which names this structure. Not `REGISTRY_SNAPSHOT`, which names
/// another one — two structures under one domain forfeit the separation the domains exist for.
/// Not `SURFACE_VERDICT` either: that names the verdict, and the verdict is a different value
/// that will need its own digest when `InstallationRecord` records it.
///
/// **Version prefix.** Present, matching `spec_hash`, `recording_hash`, `BuildManifest::hash`
/// and `snapshot_root`. The workspace is not uniform here — `signer_set_hash`,
/// `codegen_input_hash`, `binding_set_hash` and `auth_fingerprint` omit it, so a
/// canonicalization bump would move four of the eight preimages and leave four still. That
/// inconsistency is real and is not this function's to resolve; the prefix is included because
/// the alternative is to add a fifth omission.
///
/// **Ordering.** The maps in `AccountState` are `BTreeMap`, but `StoredRule::signer_ids` and
/// `policy_ids` are `Vec<u32>`, so their order is part of the digest. `check` does not depend on
/// that order — it reads both as sets — so permuting a rule's ids yields a different digest for
/// a state the verdict logic treats as identical. The direction is safe: the consumer sees
/// "state changed" and re-runs a check that returns the same verdict. Normalizing the vecs into
/// the preimage would remove the spurious difference, and would also silently equate two stored
/// states that the account itself stores differently.
///
/// **Fallible rather than lossy.** A serialization failure must not resolve to a digest. Falling
/// back to empty bytes would hand every failing state the same identity, and a consumer
/// comparing digests would read that as a match.
fn state_digest(st: &AccountState) -> Result<Hash32, CheckError> {
    ozpb_domain::canonical_hash(domains::ACCOUNT_STATE, st)
        .map_err(|error| CheckError::Internal(format!("digesting account state: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "CACCOUNT";
    const POLICY: &str = "CPOLICY";
    const TOKEN: &str = "CTOKEN";

    fn signer(id: u32) -> StoredSigner {
        StoredSigner {
            id,
            key: format!("delegated:G{id}"),
        }
    }
    fn policy(id: u32, addr: &str) -> StoredPolicy {
        StoredPolicy {
            id,
            address: addr.to_string(),
            observed_wasm_hash: format!("policy-hash-{id}"),
        }
    }

    /// A healthy account: rule 0 = admin (Default, 2 signers), rule 1 = the grant rule
    /// (CallContract(token), the generated policy attached). Nothing else touches a
    /// protected surface.
    fn healthy_state() -> AccountState {
        AccountState {
            next_id: 2,
            active_count: 2,
            rules: BTreeMap::from([
                (
                    0,
                    StoredRule {
                        id: 0,
                        context_type: StoredContextType::Default,
                        valid_until: None,
                        signer_ids: vec![0, 1],
                        policy_ids: vec![],
                    },
                ),
                (
                    1,
                    StoredRule {
                        id: 1,
                        context_type: StoredContextType::CallContract {
                            address: TOKEN.to_string(),
                        },
                        valid_until: Some(5_000_000),
                        signer_ids: vec![2],
                        policy_ids: vec![0],
                    },
                ),
            ]),
            signers: BTreeMap::from([(0, signer(0)), (1, signer(1)), (2, signer(2))]),
            policies: BTreeMap::from([(0, policy(0, POLICY))]),
        }
    }

    fn base_input(state: &AccountState) -> CheckInput<'_> {
        CheckInput {
            account_state: state,
            account_address: ACCOUNT.to_string(),
            account_code_hash: "recognized-account-hash".to_string(),
            binding_set_hash: ozpb_domain::canonical_hash(
                domains::POLICY_BINDING_SET,
                &"test-bindings",
            )
            .expect("the fixture binding-set hash must encode"),
            account_recognized: true,
            bound_policy_addresses: vec![POLICY.to_string()],
            recognized_policy_addresses: BTreeSet::from([POLICY.to_string()]),
            admin_rule_id: 0,
            current_ledger: 4_000_000,
            enumeration: Enumeration::BoundedNextId,
        }
    }

    #[test]
    fn healthy_account_is_safe() {
        let st = healthy_state();
        let v = check(&base_input(&st)).unwrap();
        assert_eq!(v.result, CheckResult::Safe);
        assert_eq!(v.observed_ledger, 4_000_000);
    }

    #[test]
    fn weak_default_rule_flags_both_surfaces() {
        let mut st = healthy_state();
        st.next_id = 3;
        st.active_count = 3;
        st.signers.insert(9, signer(9));
        st.rules.insert(
            2,
            StoredRule {
                id: 2,
                context_type: StoredContextType::Default,
                valid_until: None,
                signer_ids: vec![9],
                policy_ids: vec![],
            },
        );
        let v = check(&base_input(&st)).unwrap();
        match v.result {
            CheckResult::Unsafe { findings } => {
                assert_eq!(findings.len(), 2, "a Default rule threatens both surfaces");
                assert!(findings.iter().any(|f| f.surface == Surface::DirectPolicy));
                assert!(findings
                    .iter()
                    .any(|f| f.surface == Surface::AccountManagement));
                assert!(findings.iter().all(|f| f.offending_rule_id == 2));
            }
            other => panic!("expected unsafe, got {other:?}"),
        }
    }

    #[test]
    fn weak_account_address_rule_flags_management_surface() {
        // The exact §4.8 bypass: a weak rule scoped to the account's OWN address can call
        // add_context_rule etc. even with no Default and no policy-address rule.
        let mut st = healthy_state();
        st.next_id = 3;
        st.active_count = 3;
        st.signers.insert(9, signer(9));
        st.rules.insert(
            2,
            StoredRule {
                id: 2,
                context_type: StoredContextType::CallContract {
                    address: ACCOUNT.to_string(),
                },
                valid_until: None,
                signer_ids: vec![9],
                policy_ids: vec![],
            },
        );
        let v = check(&base_input(&st)).unwrap();
        match v.result {
            CheckResult::Unsafe { findings } => {
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].surface, Surface::AccountManagement);
                assert_eq!(findings[0].code, "E_UNSAFE_MANAGEMENT_SURFACE");
            }
            other => panic!("expected unsafe management, got {other:?}"),
        }
    }

    #[test]
    fn weak_policy_address_rule_flags_direct_surface() {
        let mut st = healthy_state();
        st.next_id = 3;
        st.active_count = 3;
        st.signers.insert(9, signer(9));
        st.rules.insert(
            2,
            StoredRule {
                id: 2,
                context_type: StoredContextType::CallContract {
                    address: POLICY.to_string(),
                },
                valid_until: None,
                signer_ids: vec![9],
                policy_ids: vec![],
            },
        );
        let v = check(&base_input(&st)).unwrap();
        match v.result {
            CheckResult::Unsafe { findings } => {
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].surface, Surface::DirectPolicy);
                assert_eq!(findings[0].code, "E_UNSAFE_CALL_SURFACE");
            }
            other => panic!("expected unsafe direct, got {other:?}"),
        }
    }

    #[test]
    fn expired_weak_rule_is_not_a_current_threat() {
        let mut st = healthy_state();
        st.next_id = 3;
        st.active_count = 3;
        st.signers.insert(9, signer(9));
        st.rules.insert(
            2,
            StoredRule {
                id: 2,
                context_type: StoredContextType::Default,
                valid_until: Some(1_000), // long past current_ledger 4_000_000
                signer_ids: vec![9],
                policy_ids: vec![],
            },
        );
        let v = check(&base_input(&st)).unwrap();
        assert_eq!(v.result, CheckResult::Safe);
    }

    #[test]
    fn count_deficit_fails_closed_archived() {
        // active_count says 3 but only 2 rules decoded → an archived rule is invisible.
        let mut st = healthy_state();
        st.next_id = 3;
        st.active_count = 3;
        let err = check(&base_input(&st)).unwrap_err();
        assert!(matches!(
            err,
            CheckError::IncompleteState {
                cause: IncompleteCause::Archived,
                ..
            }
        ));
    }

    #[test]
    fn missing_transitive_signer_fails_closed() {
        let mut st = healthy_state();
        st.signers.remove(&2); // rule 1 references signer 2
        let err = check(&base_input(&st)).unwrap_err();
        assert!(matches!(
            err,
            CheckError::IncompleteState {
                cause: IncompleteCause::Missing,
                ..
            }
        ));
    }

    #[test]
    fn unrecognized_policy_on_surface_fails_closed() {
        let mut st = healthy_state();
        st.next_id = 3;
        st.active_count = 3;
        st.policies.insert(5, policy(5, "CUNKNOWNPOLICY"));
        st.rules.insert(
            2,
            StoredRule {
                id: 2,
                context_type: StoredContextType::Default,
                valid_until: None,
                signer_ids: vec![0, 1], // strong signer set...
                policy_ids: vec![5],    // ...but an unrecognized policy
            },
        );
        let v = check(&base_input(&st)).unwrap();
        match v.result {
            CheckResult::Unsafe { findings } => {
                assert!(findings.iter().any(|f| f.code == "E_UNREGISTERED_POLICY"));
            }
            other => panic!("expected unsafe, got {other:?}"),
        }
    }

    #[test]
    fn alternate_admin_without_registered_implication_is_unsafe() {
        // Signer/policy set inclusion is not a method-level implication proof. Until a
        // registry-backed, parameter-aware implication is supplied, alternate rules on a
        // protected surface fail closed.
        let mut st = healthy_state();
        st.next_id = 3;
        st.active_count = 3;
        st.rules.insert(
            2,
            StoredRule {
                id: 2,
                context_type: StoredContextType::Default,
                valid_until: None,
                signer_ids: vec![0, 1, 2], // superset of admin {0,1}
                policy_ids: vec![],
            },
        );
        let v = check(&base_input(&st)).unwrap();
        assert!(matches!(v.result, CheckResult::Unsafe { .. }));
    }

    #[test]
    fn none_enumeration_is_unsupported() {
        let st = healthy_state();
        let mut input = base_input(&st);
        input.enumeration = Enumeration::None;
        assert!(matches!(
            check(&input).unwrap_err(),
            CheckError::EnumerationUnsupported(Enumeration::None)
        ));
    }

    #[test]
    fn unrecognized_account_fails_closed() {
        let st = healthy_state();
        let mut input = base_input(&st);
        input.account_recognized = false;
        assert!(matches!(
            check(&input).unwrap_err(),
            CheckError::IncompatibleAccount(_)
        ));
    }

    #[test]
    fn missing_admin_rule_fails_closed() {
        let st = healthy_state();
        let mut input = base_input(&st);
        input.admin_rule_id = 99;
        assert!(matches!(
            check(&input).unwrap_err(),
            CheckError::AdminRuleNotFound(99)
        ));
    }

    #[test]
    fn empty_designated_admin_rule_fails_closed() {
        let mut st = healthy_state();
        st.rules.get_mut(&0).unwrap().signer_ids.clear();
        let err = check(&base_input(&st)).unwrap_err();
        assert!(matches!(err, CheckError::AdminRuleUnsafe(0, _)));
    }

    #[test]
    fn bound_policy_must_be_recognized() {
        let st = healthy_state();
        let mut input = base_input(&st);
        input.recognized_policy_addresses.clear();
        let err = check(&input).unwrap_err();
        assert!(matches!(err, CheckError::UnrecognizedBoundPolicy(_)));
    }

    #[test]
    fn duplicate_transitive_ids_are_snapshot_mismatches() {
        let mut st = healthy_state();
        st.rules.get_mut(&1).unwrap().signer_ids.push(2);
        assert!(matches!(
            check(&base_input(&st)).unwrap_err(),
            CheckError::IncompleteState {
                cause: IncompleteCause::SnapshotMismatch,
                ..
            }
        ));
    }

    #[test]
    fn verdict_is_deterministic_and_snapshot_pinned() {
        let st = healthy_state();
        let a = check(&base_input(&st)).unwrap();
        let b = check(&base_input(&st)).unwrap();
        assert_eq!(a.ordered_state_digest, b.ordered_state_digest);
    }

    /// The whole preimage, pinned in one assertion: domain, canonicalization version, the
    /// version's width and byte order, its position before the payload, and the canonical bytes.
    ///
    /// The expected value is rebuilt from the primitives rather than obtained from the function
    /// under test, so the assertion cannot agree with whatever the implementation happens to do.
    /// `domains::ACCOUNT_STATE` is named literally, so changing the implementation's domain fails
    /// here — which is the point: the earlier version of this code hashed account state under a
    /// domain belonging to another structure, and nothing objected.
    ///
    /// One assertion rather than several on purpose. A complete pin subsumes every weaker
    /// assertion about the same value, so a second test naming one component — "this one checks
    /// the version prefix" — cannot fail where this one passes. Such a test reads as extra
    /// coverage while adding none; the earlier attempt at one was worse than redundant, because
    /// it built its comparison under a hardcoded domain and so held against the very code it was
    /// written to reject.
    #[test]
    fn the_state_digest_is_domain_separated_and_version_prefixed() {
        let st = healthy_state();

        // Assembled from the canonical preimage rather than by calling the same helper the
        // implementation calls: the value has to come from somewhere other than the code under
        // test, or the assertion is a restatement. `canonical_preimage_bytes` is the published
        // encoding, so this is the computation a reader following the specification performs.
        let expected = ozpb_domain::sha256(
            &ozpb_domain::canonical_preimage_bytes(domains::ACCOUNT_STATE, &st)
                .expect("plain-data state must encode"),
        );

        assert_eq!(
            state_digest(&st).expect("plain-data state must digest"),
            expected,
            "the digest must be taken under domains::ACCOUNT_STATE over the canonical preimage"
        );
    }
}
