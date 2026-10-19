//! The live authority check, split around the read so this crate never reaches a network.
//!
//! A shell calls [`plan_call_surface_read`] to learn exactly what to read and within which
//! signed bounds, reads it through an operator-configured endpoint with
//! `ozpb_source_rpc::scan_authority_state`, and hands the scan to
//! [`finish_call_surface_check`]. Planning verifies the request and bindings under the pinned
//! registry trust. Finishing rechecks that snapshot's validity at the current trusted time
//! and binds the observation to the prepared request, without rebuilding its policies.
//!
//! The result is advisory wherever it is delivered: the wallet that holds the owner key
//! recomputes it against its own endpoint and decides (Decision D7).

use super::call_surface::{
    check_prepared, prepare_call_surface_check, CallSurfaceObservation, PreparedCallSurfaceCheck,
};
use super::{map_registry_err, RegistryTrust};
use crate::authority_text::render_authority_text;
use ozpb_api_types::{
    CheckPolicyCallSurfaceInput, CheckPolicyCallSurfaceOutput, ErrorCode as EC,
    PolicyAuthorityEvidence, PolicyCallSurfaceVerdict, PolicyRuleEnumerationEvidence, ToolError,
};
use ozpb_call_surface_core::{BoundPolicy, StoredSignerKey};
use ozpb_source_rpc::{project_account_state, AccountScanBounds, AccountStateScan, SignerIdentity};
use std::collections::{BTreeMap, BTreeSet};

/// What to read for one check, and the signed bounds to read it within. It carries the
/// request it was made for, already validated against the pinned trust (spec, registry,
/// bindings — generated ones rebuilt — and the grant), so the read happens only for a request
/// that can be answered and nothing is rebuilt after it.
pub struct CallSurfaceReadPlan {
    pub account_address: String,
    /// Hex network ID; the shell's configured source must be for exactly this network.
    pub network_id: String,
    /// Contracts whose code to read in the same capture: the bound policy instances and the
    /// verifiers the new rule's own external signers name.
    pub contract_addresses: Vec<String>,
    /// The new rule's own classic-account signers, read in the same capture.
    pub classic_addresses: Vec<String>,
    /// From the signed account capability, never from the request.
    pub bounds: AccountScanBounds,
    input: CheckPolicyCallSurfaceInput,
    prepared: PreparedCallSurfaceCheck,
}

impl CallSurfaceReadPlan {
    /// The contract the new rule targets, from the validated spec.
    pub fn grant_target(&self) -> &str {
        &self.prepared.grant.target
    }
}

/// Validate the request against the pinned trust and say what to read.
pub fn plan_call_surface_read(
    input: &CheckPolicyCallSurfaceInput,
    registry_trust: &RegistryTrust,
    build_config: &ozpb_build_runner::BuildConfig,
) -> Result<CallSurfaceReadPlan, ToolError> {
    let prepared = prepare_call_surface_check(input, registry_trust, build_config)?;
    let authority = prepared
        .registry
        .resolve_account_authority(&prepared.spec.spec().smart_account.observed_code_hash)
        .map_err(map_registry_err)?;
    let mut contracts: BTreeSet<String> = input
        .binding_set
        .bindings
        .iter()
        .map(|binding| binding.contract_address.clone())
        .collect();
    let mut classic_addresses = Vec::new();
    for signer in &prepared.grant.signers {
        match signer {
            StoredSignerKey::Delegated { address }
                if matches!(
                    stellar_strkey::Strkey::from_string(address),
                    Ok(stellar_strkey::Strkey::PublicKeyEd25519(_))
                ) =>
            {
                classic_addresses.push(address.clone());
            }
            StoredSignerKey::External { verifier, .. }
                if matches!(
                    stellar_strkey::Strkey::from_string(verifier),
                    Ok(stellar_strkey::Strkey::Contract(_))
                ) =>
            {
                contracts.insert(verifier.clone());
            }
            _ => {}
        }
    }
    Ok(CallSurfaceReadPlan {
        account_address: input.account_address.clone(),
        network_id: input.network_id.clone(),
        contract_addresses: contracts.into_iter().collect(),
        classic_addresses,
        bounds: AccountScanBounds {
            max_scan_ids: authority.scan.max_scan_ids,
            max_rpc_batches: authority.scan.max_rpc_batches,
            max_transitive_entries: authority.scan.max_transitive_entries as usize,
            max_attempts: authority.scan.max_attempts,
        },
        input: input.clone(),
        prepared,
    })
}

/// Turn one scan into the wire answer for the plan's request. `source_name` is the operator's
/// label for the endpoint the scan came from; it is recorded as evidence, never trusted.
pub fn finish_call_surface_check(
    plan: &CallSurfaceReadPlan,
    source_name: &str,
    scan: &AccountStateScan,
) -> Result<CheckPolicyCallSurfaceOutput, ToolError> {
    finish_call_surface_check_at(plan, source_name, scan, std::time::SystemTime::now())
}

fn finish_call_surface_check_at(
    plan: &CallSurfaceReadPlan,
    source_name: &str,
    scan: &AccountStateScan,
    now: std::time::SystemTime,
) -> Result<CheckPolicyCallSurfaceOutput, ToolError> {
    let now_unix = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| ToolError::new(EC::EInternal, format!("invalid trusted time: {error}")))?
        .as_secs()
        .try_into()
        .map_err(|_| ToolError::new(EC::EInternal, "trusted time exceeds i64"))?;
    plan.prepared
        .registry
        .ensure_valid_at(now_unix)
        .map_err(map_registry_err)?;
    let incomplete = |message: &str| ToolError::new(EC::EIncompleteAccountState, message);
    if scan.account_address != plan.account_address || scan.network_id.0.to_hex() != plan.network_id
    {
        return Err(incomplete(
            "the scan is of a different account or network than the request",
        ));
    }
    if plan
        .classic_addresses
        .iter()
        .any(|classic| !scan.classic_accounts.contains_key(classic))
    {
        return Err(incomplete(
            "the scan did not read the new rule's own classic signer",
        ));
    }
    let projection = project_account_state(scan)
        .map_err(|error| ToolError::new(EC::EIncompleteAccountState, error.to_string()))?;
    let bound_policies = plan
        .input
        .binding_set
        .bindings
        .iter()
        .map(|binding| {
            let observed = scan
                .observed_code_hashes
                .get(&binding.contract_address)
                .ok_or_else(|| incomplete("the scan observed no code at a bound policy address"))?;
            Ok(BoundPolicy {
                address: binding.contract_address.clone(),
                observed_wasm_hash: observed.to_hex(),
            })
        })
        .collect::<Result<Vec<_>, ToolError>>()?;
    // The code at every verifier a stored signer or the new rule's own signers name, as the
    // scan observed it. One the scan did not read stays absent: an evidence gap, not a guess.
    let named_verifiers = scan
        .signers
        .values()
        .filter_map(|record| match &record.signer {
            SignerIdentity::External { verifier, .. } => Some(verifier.clone()),
            SignerIdentity::Delegated(_) => None,
        })
        .chain(
            plan.prepared
                .grant
                .signers
                .iter()
                .filter_map(|key| match key {
                    StoredSignerKey::External { verifier, .. } => Some(verifier.clone()),
                    StoredSignerKey::Delegated { .. } => None,
                }),
        );
    let mut verifier_code_hashes = BTreeMap::new();
    for verifier in named_verifiers {
        if let Some(code) = scan.observed_code_hashes.get(&verifier) {
            verifier_code_hashes.insert(verifier, code.to_hex());
        }
    }
    let observation = CallSurfaceObservation {
        observed_ledger: scan.reported_latest_ledger.0,
        network_id: plan.network_id.clone(),
        account_address: plan.account_address.clone(),
        account_code_hash: scan.account_wasm_hash.to_hex(),
        account_state: projection.account_state,
        bound_policies,
        classic_accounts: projection.classic_accounts,
        verifier_code_hashes,
    };
    let checked = check_prepared(&plan.input, &plan.prepared, &observation)?;

    let mut verdict = serde_json::to_value(&checked.verdict)
        .map_err(|error| ToolError::new(EC::EInternal, error.to_string()))?;
    let evidence = PolicyAuthorityEvidence {
        enumeration_evidence: PolicyRuleEnumerationEvidence::BoundedNextId {
            next_id: scan.next_id,
            active_count: scan.extant_count,
            rule_ids: scan.rules.keys().copied().collect(),
            signer_ids: scan.signers.keys().copied().collect(),
            policy_ids: scan.policies.keys().copied().collect(),
        },
        source: source_name.to_string(),
        evidence_trust: "rpc_reported".to_string(),
        raw_ordered_entry_digest: scan.ordered_entry_digest.to_hex(),
        rpc_batches: scan.rpc_batches,
        attempts: scan.attempts,
    };
    verdict["evidence"] = serde_json::to_value(&evidence)
        .map_err(|error| ToolError::new(EC::EInternal, error.to_string()))?;
    let verdict: PolicyCallSurfaceVerdict = serde_json::from_value(verdict)
        .map_err(|error| ToolError::new(EC::EInternal, format!("wire verdict: {error}")))?;
    let mut output = CheckPolicyCallSurfaceOutput {
        spec_hash: checked.spec_hash.to_hex(),
        binding_set_hash: checked.binding_set_hash.to_hex(),
        registry_snapshot_root: checked.registry_snapshot_root.to_hex(),
        verdict,
        summary: String::new(),
    };
    output.summary = render_authority_text(&output);
    Ok(output)
}

/// One operator-configured RPC source: where to read, and for which network.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSource {
    pub rpc_url: String,
    pub network_passphrase: String,
}

/// Parse the operator's source map, `{"<name>": {"rpc_url": …, "network_passphrase": …}}`.
/// This is configuration a shell reads from its operator, never from a request.
pub fn rpc_sources_from_json(json: &str) -> Result<BTreeMap<String, RpcSource>, ToolError> {
    let sources: BTreeMap<String, RpcSource> = serde_json::from_str(json).map_err(|error| {
        ToolError::new(
            EC::ERpc,
            format!("invalid RPC source configuration: {error}"),
        )
    })?;
    if sources.is_empty()
        || sources
            .iter()
            .any(|(name, source)| name.trim().is_empty() || source.rpc_url.trim().is_empty())
    {
        return Err(ToolError::new(
            EC::ERpc,
            "RPC source configuration must name at least one source, each with a URL",
        ));
    }
    Ok(sources)
}

/// The configured source a request names, which must be for the request's network.
pub fn resolve_rpc_source<'a>(
    sources: &'a BTreeMap<String, RpcSource>,
    name: &str,
    network_id_hex: &str,
) -> Result<&'a RpcSource, ToolError> {
    let source = sources.get(name).ok_or_else(|| {
        ToolError::new(
            EC::ERpc,
            format!("no RPC source named {name:?} is configured on this server"),
        )
    })?;
    if ozpb_domain::NetworkId::from_passphrase(&source.network_passphrase)
        .0
        .to_hex()
        != network_id_hex
    {
        return Err(ToolError::new(
            EC::ENetworkMismatch,
            format!("RPC source {name:?} is configured for a different network"),
        ));
    }
    Ok(source)
}

/// A failed scan as a stable tool error. Endpoint-controlled strings can echo the operator's
/// URL or credentials, including JSON-RPC errors, response IDs and reported network names.
/// Preserve the error category, but expose only static descriptions and numeric diagnostics.
pub fn scan_tool_error(error: &ozpb_source_rpc::AccountScanError) -> ToolError {
    let code = match error.code() {
        "E_SCAN_BUDGET_EXCEEDED" => EC::EScanBudgetExceeded,
        "E_INCOMPLETE_ACCOUNT_STATE" => EC::EIncompleteAccountState,
        "E_NETWORK_MISMATCH" => EC::ENetworkMismatch,
        _ => EC::ERpc,
    };
    let message = match error {
        ozpb_source_rpc::AccountScanError::Rpc(ozpb_source_rpc::RpcError::Transport(_)) => {
            "E_RPC: the configured RPC source could not be reached (endpoint detail withheld)"
                .to_string()
        }
        ozpb_source_rpc::AccountScanError::Rpc(ozpb_source_rpc::RpcError::NetworkMismatch { .. }) =>
            "E_NETWORK_MISMATCH: the configured RPC source reports a different network (endpoint detail withheld)".to_string(),
        ozpb_source_rpc::AccountScanError::Rpc(ozpb_source_rpc::RpcError::UnsupportedProtocol { reported, supported }) =>
            format!("E_RPC: unsupported protocol {reported}; this build supports at most {supported}"),
        ozpb_source_rpc::AccountScanError::Rpc(_) =>
            "E_RPC: the configured RPC source could not provide a valid response (endpoint detail withheld)".to_string(),
        ozpb_source_rpc::AccountScanError::Incomplete(_) =>
            "E_INCOMPLETE_ACCOUNT_STATE: the account scan is incomplete (endpoint detail withheld)".to_string(),
        ozpb_source_rpc::AccountScanError::Archived(_) =>
            "E_INCOMPLETE_ACCOUNT_STATE: the scan returned archived state (endpoint detail withheld)".to_string(),
        ozpb_source_rpc::AccountScanError::Undecodable(_) =>
            "E_INCOMPLETE_ACCOUNT_STATE: the account state could not be decoded (endpoint detail withheld)".to_string(),
        ozpb_source_rpc::AccountScanError::InvalidBounds(_)
        | ozpb_source_rpc::AccountScanError::Budget(_)
        | ozpb_source_rpc::AccountScanError::SnapshotChanged => error.to_string(),
    };
    ToolError::new(code, message)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_support::{build_config, registry_trust, wire_spec};
    use crate::{generate_code_with_build_config, GenerateCodeInput};
    use ozpb_api_types::{
        PolicyBinding, PolicyBindingSet, PolicyRecognition, POLICY_BINDING_SET_SCHEMA,
    };
    use ozpb_call_surface_core::ClassicAccount;
    use ozpb_domain::{LedgerSeq, NetworkId, TESTNET_PASSPHRASE};
    use ozpb_policy_spec::{PolicyRef, SignerSpec};
    use ozpb_source_rpc::{ContextRuleRecord, ContextType, SignerRecord};

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn classic(byte: u8) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
    }

    fn master_key_only() -> ClassicAccount {
        ClassicAccount::Found {
            master_weight: 1,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        }
    }

    /// A request against the version-3 signed example (which binds the account's scan bounds
    /// and recognizes the owner verifiers), and a scan of an account owned by one classic key.
    pub(crate) fn fixture() -> (CheckPolicyCallSurfaceInput, AccountStateScan) {
        fixture_with_expiry(i64::MAX)
    }

    fn fixture_with_expiry(expires_at: i64) -> (CheckPolicyCallSurfaceInput, AccountStateScan) {
        let network = NetworkId::from_passphrase(TESTNET_PASSPHRASE);
        let mut snapshot = ozpb_registry::dev::verifier_successor(network).unwrap();
        if expires_at != i64::MAX {
            snapshot.valid_from_unix = 1;
        }
        snapshot.expires_at_unix = expires_at;
        let signed =
            ozpb_registry::sign_snapshot(&ozpb_registry::dev::dev_signing_key(), snapshot).unwrap();
        let mut spec = wire_spec().spec().clone();
        spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
        let spec = spec.validate().unwrap();
        let spec_json = serde_json::to_value(spec.spec()).unwrap();
        let generated = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: spec_json.clone(),
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap();
        let PolicyRef::Reviewed { capability, .. } = &spec.spec().rules[0].policies[0] else {
            panic!("fixture needs a reviewed policy at index 0");
        };
        let binding_set = PolicyBindingSet {
            schema: POLICY_BINDING_SET_SCHEMA.to_string(),
            spec_hash: spec.hash().to_hex(),
            network_id: network.0.to_hex(),
            bindings: vec![
                PolicyBinding {
                    rule_index: 0,
                    policy_index: 0,
                    contract_address: address(40),
                    observed_wasm_hash: capability.to_hex(),
                    recognition: PolicyRecognition::ReviewedRegistry,
                    resolution_reference: "reviewed instance".to_string(),
                },
                PolicyBinding {
                    rule_index: 0,
                    policy_index: 1,
                    contract_address: address(41),
                    observed_wasm_hash: generated.wasm_hash.clone(),
                    recognition: PolicyRecognition::VerifiedGeneratedManifest {
                        build_manifest: generated.build_manifest,
                    },
                    resolution_reference: "generated instance".to_string(),
                },
            ],
        };
        let mut classic_accounts = BTreeMap::from([(classic(10), master_key_only())]);
        for signer in &spec.spec().rules[0].authorization.signers {
            if let SignerSpec::Delegated { address } = signer {
                classic_accounts.insert(address.clone(), master_key_only());
            }
        }
        let scan = AccountStateScan {
            network_id: network,
            account_address: spec.spec().smart_account.address.clone(),
            reported_latest_ledger: LedgerSeq(4_200_000),
            account_wasm_hash: spec.spec().smart_account.observed_code_hash,
            next_id: 1,
            extant_count: 1,
            rules: BTreeMap::from([(
                0,
                ContextRuleRecord {
                    id: 0,
                    name: "owner".into(),
                    context_type: ContextType::Default,
                    valid_until: None,
                    signer_ids: vec![0],
                    policy_ids: vec![],
                },
            )]),
            signers: BTreeMap::from([(
                0,
                SignerRecord {
                    id: 0,
                    signer: SignerIdentity::Delegated(classic(10)),
                    reference_count: 1,
                },
            )]),
            policies: BTreeMap::new(),
            observed_code_hashes: binding_set
                .bindings
                .iter()
                .map(|binding| {
                    (
                        binding.contract_address.clone(),
                        ozpb_domain::Hash32::from_hex(&binding.observed_wasm_hash).unwrap(),
                    )
                })
                .collect(),
            classic_accounts,
            ordered_entry_digest: ozpb_domain::Hash32([0x21; 32]),
            rpc_batches: 5,
            attempts: 1,
        };
        (
            CheckPolicyCallSurfaceInput {
                spec: spec_json,
                rule_index: 0,
                binding_set,
                signed_registry_snapshot: serde_json::to_value(signed).unwrap(),
                account_address: spec.spec().smart_account.address.clone(),
                network_id: network.0.to_hex(),
                rpc_source: "testnet".to_string(),
            },
            scan,
        )
    }

    #[test]
    fn a_snapshot_that_expires_after_planning_cannot_produce_an_answer() {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let (input, scan) = fixture_with_expiry(expires_at as i64);
        let plan = plan_call_surface_read(&input, &registry_trust(), &build_config()).unwrap();
        let at_expiry = UNIX_EPOCH + Duration::from_secs(expires_at);
        let valid = finish_call_surface_check_at(&plan, "testnet", &scan, at_expiry).unwrap();
        assert!(valid.verdict.refusals.is_empty());
        assert!(crate::prepare_install_intent_from_scan(&plan, "testnet", &scan).is_ok());
        let expired = finish_call_surface_check_at(
            &plan,
            "testnet",
            &scan,
            at_expiry + Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(expired.code, EC::ERegistryExpired);
        assert!(expired.message.contains("E_REGISTRY_EXPIRED"));
        let premature =
            finish_call_surface_check_at(&plan, "testnet", &scan, UNIX_EPOCH).unwrap_err();
        assert_eq!(premature.code, EC::ERegistryExpired);
    }

    #[test]
    fn the_plan_takes_its_bounds_from_the_signed_account_capability() {
        let (input, _) = fixture();
        let plan = plan_call_surface_read(&input, &registry_trust(), &build_config()).unwrap();
        assert_eq!(plan.bounds.max_rpc_batches, 16);
        assert_eq!(plan.contract_addresses, vec![address(40), address(41)]);
        assert!(!plan.classic_addresses.is_empty());

        // A version-1 snapshot recognizes the account but binds no scan protocol: no read.
        let mut v1 = input.clone();
        let mut spec: ozpb_policy_spec::PolicySpec =
            serde_json::from_value(v1.spec.clone()).unwrap();
        let signed: ozpb_registry::SignedSnapshot =
            serde_json::from_value(crate::test_support::signed_registry_json()).unwrap();
        spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
        v1.spec = serde_json::to_value(&spec).unwrap();
        v1.signed_registry_snapshot = serde_json::to_value(signed).unwrap();
        assert!(plan_call_surface_read(&v1, &registry_trust(), &build_config()).is_err());
    }

    #[test]
    fn a_scan_becomes_the_wire_answer_with_evidence_outside_the_commitment() {
        let (input, scan) = fixture();
        let plan = plan_call_surface_read(&input, &registry_trust(), &build_config()).unwrap();
        let output = finish_call_surface_check(&plan, "testnet", &scan).unwrap();
        let verdict = &output.verdict;
        assert!(verdict.refusals.is_empty() && verdict.unresolved.is_empty());
        assert_eq!(verdict.authority_list.len(), 1);
        assert_eq!(verdict.observed_ledger, 4_200_000);
        assert_eq!(verdict.evidence.source, "testnet");
        assert_eq!(verdict.evidence.rpc_batches, 5);
        assert!(output
            .summary
            .contains("Who can remove or change this limit"));
        assert!(!output.summary.to_lowercase().contains("safe"));

        // Evidence moves without moving the commitment.
        let mut again = scan.clone();
        again.ordered_entry_digest = ozpb_domain::Hash32([0x22; 32]);
        again.reported_latest_ledger = LedgerSeq(4_200_050);
        again.rpc_batches = 6;
        let second = finish_call_surface_check(&plan, "other", &again).unwrap();
        assert_eq!(
            second.verdict.authority_commitment,
            output.verdict.authority_commitment
        );
        assert_ne!(
            second.verdict.evidence.raw_ordered_entry_digest,
            output.verdict.evidence.raw_ordered_entry_digest
        );
    }

    #[test]
    fn a_scan_of_something_else_is_refused() {
        let (input, scan) = fixture();
        let plan = plan_call_surface_read(&input, &registry_trust(), &build_config()).unwrap();
        let finish = |scan: &AccountStateScan| {
            finish_call_surface_check(&plan, "testnet", scan)
                .unwrap_err()
                .code
        };
        let mut other_account = scan.clone();
        other_account.account_address = address(99);
        assert_eq!(finish(&other_account), EC::EIncompleteAccountState);
        let mut no_agent_account = scan.clone();
        no_agent_account
            .classic_accounts
            .retain(|address, _| *address == classic(10));
        assert_eq!(finish(&no_agent_account), EC::EIncompleteAccountState);
        let mut no_policy_code = scan.clone();
        no_policy_code.observed_code_hashes.clear();
        assert_eq!(finish(&no_policy_code), EC::EIncompleteAccountState);
        let mut other_code = scan;
        other_code.account_wasm_hash = ozpb_domain::Hash32([7; 32]);
        assert_eq!(finish(&other_code), EC::EIncompleteAccountState);
    }

    /// A canned endpoint serving exactly one account: an instance with one rule, its classic
    /// owner signer, the bound policies' instances and master-key-only classic accounts. It
    /// records every key it was asked for.
    struct Endpoint {
        account: [u8; 32],
        account_code: [u8; 32],
        policies: BTreeMap<[u8; 32], [u8; 32]>,
        requested: std::cell::RefCell<Vec<stellar_xdr::LedgerKey>>,
    }

    impl ozpb_source_rpc::RpcTransport for Endpoint {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, ozpb_source_rpc::RpcError> {
            use stellar_xdr::*;
            if method == "getNetwork" {
                return Ok(serde_json::json!({
                    "passphrase": TESTNET_PASSPHRASE, "protocolVersion": 28
                }));
            }
            assert_eq!(method, "getLedgerEntries");
            let symbol = |name: &str| ScVal::Symbol(name.try_into().unwrap());
            let vector = |items: Vec<ScVal>| ScVal::Vec(Some(items.try_into().unwrap()));
            let map = |mut entries: Vec<(ScVal, ScVal)>| {
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                ScVal::Map(Some(
                    entries
                        .into_iter()
                        .map(|(key, val)| ScMapEntry { key, val })
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                ))
            };
            let mut entries = Vec::new();
            for encoded in params["keys"].as_array().unwrap() {
                let encoded = encoded.as_str().unwrap();
                let key = LedgerKey::from_xdr_base64(encoded, Limits::none()).unwrap();
                self.requested.borrow_mut().push(key.clone());
                let data = match &key {
                    LedgerKey::Account(LedgerKeyAccount {
                        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(id)),
                    }) => LedgerEntryData::Account(AccountEntry {
                        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(id.clone())),
                        balance: 1,
                        seq_num: SequenceNumber(1),
                        num_sub_entries: 0,
                        inflation_dest: None,
                        flags: 0,
                        home_domain: String32::default(),
                        thresholds: Thresholds([1, 0, 0, 0]),
                        signers: VecM::default(),
                        ext: AccountEntryExt::V0,
                    }),
                    LedgerKey::ContractData(LedgerKeyContractData {
                        contract: ScAddress::Contract(ContractId(Hash(contract))),
                        key: data_key,
                        durability,
                    }) => {
                        let val = if *data_key == ScVal::LedgerKeyContractInstance {
                            let (code, storage) = if *contract == self.account {
                                (
                                    self.account_code,
                                    Some(
                                        match map(vec![
                                            (vector(vec![symbol("NextId")]), ScVal::U32(1)),
                                            (vector(vec![symbol("Count")]), ScVal::U32(1)),
                                        ]) {
                                            ScVal::Map(Some(map)) => map,
                                            _ => unreachable!(),
                                        },
                                    ),
                                )
                            } else {
                                (*self.policies.get(contract).expect("a bound policy"), None)
                            };
                            ScVal::ContractInstance(ScContractInstance {
                                executable: ContractExecutable::Wasm(Hash(code)),
                                storage,
                            })
                        } else if *data_key
                            == vector(vec![symbol("ContextRuleData"), ScVal::U32(0)])
                        {
                            map(vec![
                                (symbol("context_type"), vector(vec![symbol("Default")])),
                                (
                                    symbol("name"),
                                    ScVal::String(ScString("owner".try_into().unwrap())),
                                ),
                                (symbol("policy_ids"), vector(vec![])),
                                (symbol("signer_ids"), vector(vec![ScVal::U32(0)])),
                                (symbol("valid_until"), ScVal::Void),
                            ])
                        } else if *data_key == vector(vec![symbol("SignerData"), ScVal::U32(0)]) {
                            map(vec![
                                (symbol("count"), ScVal::U32(1)),
                                (
                                    symbol("signer"),
                                    vector(vec![
                                        symbol("Delegated"),
                                        ScVal::Address(ScAddress::Account(AccountId(
                                            PublicKey::PublicKeyTypeEd25519(Uint256([10; 32])),
                                        ))),
                                    ]),
                                ),
                            ])
                        } else {
                            continue;
                        };
                        LedgerEntryData::ContractData(ContractDataEntry {
                            ext: ExtensionPoint::V0,
                            contract: ScAddress::Contract(ContractId(Hash(*contract))),
                            key: data_key.clone(),
                            durability: *durability,
                            val,
                        })
                    }
                    other => panic!("unexpected key {other:?}"),
                };
                let mut entry = serde_json::json!({
                    "key": encoded,
                    "xdr": data.to_xdr_base64(Limits::none()).unwrap(),
                    "lastModifiedLedgerSeq": 9,
                });
                if !matches!(key, LedgerKey::Account(_)) {
                    entry["liveUntilLedgerSeq"] = serde_json::json!(20_000_000);
                }
                entries.push(entry);
            }
            Ok(serde_json::json!({"latestLedger": 4_200_000, "entries": entries}))
        }
    }

    /// Plan → the real bounded scanner → finish, over a canned endpoint: the read covers every
    /// bound policy and the new rule's own classic signer, and the answer lists the owner.
    #[test]
    fn plan_scan_and_finish_through_the_real_scanner() {
        let (input, fixture_scan) = fixture();
        let plan = plan_call_surface_read(&input, &registry_trust(), &build_config()).unwrap();
        let contract = |address: &str| address.parse::<stellar_strkey::Contract>().unwrap().0;
        let endpoint = Endpoint {
            account: contract(&plan.account_address),
            account_code: fixture_scan.account_wasm_hash.0,
            policies: fixture_scan
                .observed_code_hashes
                .iter()
                .map(|(address, hash)| (contract(address), hash.0))
                .collect(),
            requested: Default::default(),
        };
        let scan = ozpb_source_rpc::scan_authority_state(
            &endpoint,
            TESTNET_PASSPHRASE,
            &plan.account_address,
            &plan.contract_addresses,
            &plan.classic_addresses,
            plan.bounds,
        )
        .unwrap();
        let output = finish_call_surface_check(&plan, "canned", &scan).unwrap();
        assert!(output.verdict.refusals.is_empty() && output.verdict.unresolved.is_empty());
        assert_eq!(output.verdict.authority_list.len(), 1);
        assert_eq!(output.verdict.evidence.source, "canned");

        let requested = endpoint.requested.borrow();
        for address in &plan.contract_addresses {
            let id = contract(address);
            assert!(requested.iter().any(|key| matches!(
                key,
                stellar_xdr::LedgerKey::ContractData(data)
                    if data.contract == stellar_xdr::ScAddress::Contract(
                        stellar_xdr::ContractId(stellar_xdr::Hash(id)))
            )));
        }
        for classic in &plan.classic_addresses {
            let key = classic
                .parse::<stellar_strkey::ed25519::PublicKey>()
                .unwrap()
                .0;
            assert!(requested.iter().any(|requested| matches!(
                requested,
                stellar_xdr::LedgerKey::Account(account)
                    if account.account_id == stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(key)))
            )));
        }

        // A bound policy whose code at the address is not the bound code is refused.
        let mut other_code = endpoint.policies.clone();
        for code in other_code.values_mut() {
            *code = [0x77; 32];
        }
        let moved = Endpoint {
            policies: other_code,
            requested: Default::default(),
            ..endpoint
        };
        let scan = ozpb_source_rpc::scan_authority_state(
            &moved,
            TESTNET_PASSPHRASE,
            &plan.account_address,
            &plan.contract_addresses,
            &plan.classic_addresses,
            plan.bounds,
        )
        .unwrap();
        assert!(finish_call_surface_check(&plan, "canned", &scan).is_err());
    }

    /// The development root's signing key is public: anyone, an agent included, can sign a
    /// snapshot under it. Outside testnet it must not bound or recognize anything.
    #[test]
    fn the_public_development_root_is_refused_outside_testnet() {
        let (mut input, _) = fixture();
        let mainnet = NetworkId::from_passphrase(ozpb_domain::MAINNET_PASSPHRASE);
        let signed = ozpb_registry::sign_snapshot(
            &ozpb_registry::dev::dev_signing_key(),
            ozpb_registry::dev::dev_snapshot(mainnet, 3),
        )
        .unwrap();
        let mut spec: ozpb_policy_spec::PolicySpec =
            serde_json::from_value(input.spec.clone()).unwrap();
        spec.network_id = mainnet;
        spec.registry_snapshot = ozpb_registry::snapshot_root(&signed.snapshot).unwrap();
        input.spec = serde_json::to_value(&spec).unwrap();
        input.network_id = mainnet.0.to_hex();
        input.signed_registry_snapshot = serde_json::to_value(signed).unwrap();
        let Err(error) = plan_call_surface_read(&input, &registry_trust(), &build_config()) else {
            panic!("the development root must be refused on mainnet")
        };
        assert!(error.message.contains("only on testnet"), "{error}");
        // Also when the dev key is one of several roots.
        let mut mixed = registry_trust();
        mixed.root_policy.keys.insert("governance".into(), [3; 32]);
        let Err(error) = plan_call_surface_read(&input, &mixed, &build_config()) else {
            panic!("a root policy that includes the development key must be refused")
        };
        assert!(error.message.contains("only on testnet"), "{error}");
        // Another root is not refused for being on mainnet (its signature fails instead).
        let mut other = registry_trust();
        other.root_policy.keys = BTreeMap::from([("governance".to_string(), [3; 32])]);
        if let Err(error) = plan_call_surface_read(&input, &other, &build_config()) {
            assert!(!error.message.contains("only on testnet"), "{error}");
        }
    }

    #[test]
    fn a_transport_failure_never_reveals_the_endpoint() {
        let error = scan_tool_error(&ozpb_source_rpc::AccountScanError::Rpc(
            ozpb_source_rpc::RpcError::Transport(
                "https://rpc.example/?apikey=SECRET: connection refused".into(),
            ),
        ));
        assert_eq!(error.code, EC::ERpc);
        assert!(!error.message.contains("SECRET") && !error.message.contains("rpc.example"));
    }

    #[test]
    fn rpc_sources_come_from_configuration_and_must_match_the_network() {
        let sources = rpc_sources_from_json(
            r#"{"testnet": {"rpc_url": "https://rpc.example", "network_passphrase": "Test SDF Network ; September 2015"}}"#,
        )
        .unwrap();
        let testnet = NetworkId::from_passphrase(TESTNET_PASSPHRASE).0.to_hex();
        assert_eq!(
            resolve_rpc_source(&sources, "testnet", &testnet)
                .unwrap()
                .rpc_url,
            "https://rpc.example"
        );
        assert_eq!(
            resolve_rpc_source(&sources, "mainnet", &testnet)
                .unwrap_err()
                .code,
            EC::ERpc
        );
        assert_eq!(
            resolve_rpc_source(&sources, "testnet", &"00".repeat(32))
                .unwrap_err()
                .code,
            EC::ENetworkMismatch
        );
        assert!(rpc_sources_from_json("{}").is_err());
        assert!(
            rpc_sources_from_json(r#"{"x": {"rpc_url": "", "network_passphrase": "n"}}"#).is_err()
        );
        assert!(rpc_sources_from_json(r#"{"x": {"url": "u"}}"#).is_err());
    }
}
