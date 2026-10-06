//! Candidate account-method map for the pinned OpenZeppelin multisig example source.
//!
//! The `SmartAccount` trait alone is incomplete: the example wrapper also exposes a
//! constructor, authorization hook, batch signer helper, arbitrary execution entrypoint,
//! and upgrade method. This source-reviewed candidate is associated with
//! `OZ_SMART_ACCOUNT_WASM`, but the exact pinned Wasm export set has not yet been inspected.
//! This module is separate from the signed snapshot and cannot establish a complete management
//! surface. No live account or rule state is inferred.

use ozpb_domain::{pinned_upstream, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Candidate export map and effects from source associated with a pinned account hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountMethodInventory {
    pub methods: BTreeMap<String, AccountMethod>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountMethod {
    pub invocation: AccountMethodInvocation,
    /// Identifies both the guard and its authorized address. A method without a
    /// `require_auth` call is represented explicitly, never inferred safe.
    pub authorization: AccountMethodAuthorization,
    /// Conservative authorization-relevant effects. An empty set means no effect was
    /// identified in the reviewed method body and its account-library calls.
    pub effects: BTreeSet<AccountMethodEffect>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountMethodInvocation {
    Ordinary,
    Constructor,
    AuthorizationHook,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountMethodAuthorization {
    NoRequireAuth,
    /// `e.current_contract_address().require_auth()` before the method body mutates state.
    RequireCurrentContractAuth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountMethodEffect {
    Rules,
    Signers,
    Policies,
    Code,
    Authorization,
    /// A persistent-storage read refreshes the entry's TTL and may preserve authority state.
    StorageTtl,
    /// Installs, uninstalls, or enforces a policy. Its transitive effects require a separate
    /// reviewed policy capability and cannot be inferred from this account manifest.
    PolicyCallback,
    /// Verifies or canonicalizes an external signer through its verifier contract.
    VerifierCallback,
    /// `execute` can invoke an arbitrary contract and function chosen by its arguments;
    /// downstream analysis must treat its transitive state effects as unbounded.
    ArbitraryContractCall,
}

/// Source-reviewed method inventory candidate for the pinned example account build.
///
/// Sources: `stellar-accounts = 0.7.2` `smart_account/mod.rs` and
/// `OpenZeppelin/stellar-contracts@a9c4216`
/// `examples/multisig-smart-account/account/src/contract.rs` (the actual wrapper).
/// The claimed Wasm hash is `pinned_upstream::OZ_SMART_ACCOUNT_WASM`. The actual binary's
/// exports still require independent inspection before this can support a complete verdict.
pub fn source_reviewed_oz_multisig_candidate() -> AccountMethodInventory {
    use AccountMethodAuthorization::{
        NoRequireAuth as None, RequireCurrentContractAuth as SelfAuth,
    };
    use AccountMethodEffect::{
        ArbitraryContractCall as Arbitrary, Authorization as Auth, Code, Policies,
        PolicyCallback as Callback, Rules, Signers, StorageTtl as Ttl,
        VerifierCallback as Verifier,
    };
    use AccountMethodInvocation::{AuthorizationHook as Hook, Constructor, Ordinary as Call};

    let entries: [(
        &str,
        AccountMethodInvocation,
        AccountMethodAuthorization,
        &[AccountMethodEffect],
    ); 17] = [
        (
            "__constructor",
            Constructor,
            None,
            &[Rules, Signers, Policies, Callback, Verifier],
        ),
        ("__check_auth", Hook, None, &[Auth, Callback, Verifier, Ttl]),
        ("get_context_rules_count", Call, None, &[]),
        ("get_context_rule", Call, None, &[Ttl]),
        ("get_signer_id", Call, None, &[Ttl]),
        ("get_policy_id", Call, None, &[Ttl]),
        (
            "add_context_rule",
            Call,
            SelfAuth,
            &[Rules, Signers, Policies, Callback, Verifier],
        ),
        ("update_context_rule_name", Call, SelfAuth, &[Rules]),
        ("update_context_rule_valid_until", Call, SelfAuth, &[Rules]),
        (
            "remove_context_rule",
            Call,
            SelfAuth,
            &[Rules, Signers, Policies, Callback],
        ),
        ("add_signer", Call, SelfAuth, &[Rules, Signers, Verifier]),
        ("remove_signer", Call, SelfAuth, &[Rules, Signers]),
        ("add_policy", Call, SelfAuth, &[Rules, Policies, Callback]),
        (
            "remove_policy",
            Call,
            SelfAuth,
            &[Rules, Policies, Callback],
        ),
        (
            "batch_add_signer",
            Call,
            SelfAuth,
            &[Rules, Signers, Verifier],
        ),
        ("execute", Call, SelfAuth, &[Arbitrary]),
        ("upgrade", Call, SelfAuth, &[Code]),
    ];
    AccountMethodInventory {
        methods: entries
            .into_iter()
            .map(|(name, invocation, authorization, effects)| {
                (
                    name.to_string(),
                    AccountMethod {
                        invocation,
                        authorization,
                        effects: effects.iter().copied().collect(),
                    },
                )
            })
            .collect(),
    }
}

/// Errors while comparing a candidate with the source-reviewed methods for a known code hash.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountMethodReviewError {
    #[error("no source-reviewed method candidate for wasm hash {0}")]
    UnsupportedCode(String),
    #[error("source-reviewed method candidate is missing {0}")]
    MissingMethod(String),
    #[error("source-reviewed method candidate contains unknown method {0}")]
    UnknownMethod(String),
    #[error("source-reviewed method candidate has changed guard or effects for {0}")]
    ChangedMethod(String),
}

/// Check a candidate against the reviewed source map associated with a known code hash.
/// This is a source-consistency check, not binary export attestation or registry recognition.
pub fn validate_source_reviewed_candidate(
    wasm_hash: &Hash32,
    supplied: &AccountMethodInventory,
) -> Result<(), AccountMethodReviewError> {
    if *wasm_hash != pinned_upstream::OZ_SMART_ACCOUNT_WASM {
        return Err(AccountMethodReviewError::UnsupportedCode(
            wasm_hash.to_hex(),
        ));
    }
    let reviewed = source_reviewed_oz_multisig_candidate();
    if let Some(missing) = reviewed
        .methods
        .keys()
        .find(|name| !supplied.methods.contains_key(*name))
    {
        return Err(AccountMethodReviewError::MissingMethod(missing.clone()));
    }
    if let Some(unknown) = supplied
        .methods
        .keys()
        .find(|name| !reviewed.methods.contains_key(*name))
    {
        return Err(AccountMethodReviewError::UnknownMethod(unknown.clone()));
    }
    if let Some((name, _)) = supplied
        .methods
        .iter()
        .find(|(name, method)| reviewed.methods.get(*name) != Some(*method))
    {
        return Err(AccountMethodReviewError::ChangedMethod(name.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_domain::sha256;

    #[test]
    fn wrapper_methods_and_transitive_calls_are_in_the_source_review() {
        let candidate = source_reviewed_oz_multisig_candidate();
        assert_eq!(candidate.methods.len(), 17);
        for name in [
            "__constructor",
            "__check_auth",
            "batch_add_signer",
            "execute",
            "upgrade",
        ] {
            assert!(candidate.methods.contains_key(name), "missing {name}");
        }
        assert_eq!(
            candidate.methods["upgrade"].authorization,
            AccountMethodAuthorization::RequireCurrentContractAuth
        );
        assert!(candidate.methods["upgrade"]
            .effects
            .contains(&AccountMethodEffect::Code));
        assert!(candidate.methods["execute"]
            .effects
            .contains(&AccountMethodEffect::ArbitraryContractCall));
        assert!(candidate.methods["__check_auth"]
            .effects
            .contains(&AccountMethodEffect::VerifierCallback));
        assert!(candidate.methods["add_context_rule"]
            .effects
            .contains(&AccountMethodEffect::PolicyCallback));
        assert!(candidate.methods["get_context_rule"]
            .effects
            .contains(&AccountMethodEffect::StorageTtl));
    }

    #[test]
    fn source_review_rejects_missing_unknown_and_weakened_methods() {
        let hash = pinned_upstream::OZ_SMART_ACCOUNT_WASM;
        let candidate = source_reviewed_oz_multisig_candidate();
        assert_eq!(
            validate_source_reviewed_candidate(&hash, &candidate),
            Ok(())
        );

        let mut missing = candidate.clone();
        missing.methods.remove("batch_add_signer");
        assert_eq!(
            validate_source_reviewed_candidate(&hash, &missing),
            Err(AccountMethodReviewError::MissingMethod(
                "batch_add_signer".into()
            ))
        );

        let mut unknown = candidate.clone();
        unknown.methods.insert(
            "admin_bypass".into(),
            candidate.methods["add_signer"].clone(),
        );
        assert_eq!(
            validate_source_reviewed_candidate(&hash, &unknown),
            Err(AccountMethodReviewError::UnknownMethod(
                "admin_bypass".into()
            ))
        );

        let mut weakened = candidate.clone();
        weakened.methods.get_mut("upgrade").unwrap().authorization =
            AccountMethodAuthorization::NoRequireAuth;
        assert_eq!(
            validate_source_reviewed_candidate(&hash, &weakened),
            Err(AccountMethodReviewError::ChangedMethod("upgrade".into()))
        );

        let mut omitted_effect = candidate.clone();
        omitted_effect
            .methods
            .get_mut("execute")
            .unwrap()
            .effects
            .clear();
        assert_eq!(
            validate_source_reviewed_candidate(&hash, &omitted_effect),
            Err(AccountMethodReviewError::ChangedMethod("execute".into()))
        );

        assert!(matches!(
            validate_source_reviewed_candidate(&sha256(b"different account code"), &candidate),
            Err(AccountMethodReviewError::UnsupportedCode(_))
        ));
    }
}
