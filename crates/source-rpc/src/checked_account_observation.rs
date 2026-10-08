//! Registry-checked, endpoint-reported account evidence for an operator's RPC source.
//!
//! The operator pins the endpoint, network and governance checkpoint. The signed registry
//! supplies scan ceilings and exact code capabilities; the endpoint supplies storage and
//! observed executable hashes. Matching `latestLedger` metadata and a final instance read
//! detect ordinary races, but do not prove that separate RPC replies came from one coherent
//! ledger state. No wallet administrator is selected here, and this is not an install verdict.

use super::{
    project_account_state, scan_account_state_with_targets, AccountProjectionError,
    AccountScanBounds, AccountScanError, AccountStateProjection, AccountStateScan, HttpTransport,
    RpcTransport,
};
use ozpb_call_surface_core::BoundPolicy;
use ozpb_domain::{Hash32, NetworkId};
use ozpb_registry::{
    account_methods::AccountMethodInventory, Registry, RegistryCheckpoint, RegistryError,
    RootPolicy, SignedSnapshot,
};
use std::collections::BTreeSet;

/// Operator-owned configuration. Shells must not populate these fields from a tool request.
pub struct OperatorAccountSourceConfig {
    pub source_name: String,
    pub rpc_url: String,
    pub network_passphrase: String,
    pub registry_roots: RootPolicy,
    /// Persisted, independently pinned governance checkpoint; never derive it from the
    /// untrusted signed snapshot presented for this read.
    pub registry_checkpoint: RegistryCheckpoint,
    pub signed_registry_snapshot: SignedSnapshot,
}

/// An exact policy-address/hash expectation. Only reviewed registry policy hashes are
/// accepted in this narrow reader; generated artifacts need a separate reproduction path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedPolicyBinding {
    pub address: String,
    pub expected_wasm_hash: Hash32,
}

/// An internal, checked observation, still only as trustworthy as its configured RPC.
/// The source name is an operator label, not a cryptographic proof of endpoint behavior.
#[derive(Clone, Debug)]
pub struct CheckedAccountObservation {
    pub source_name: String,
    pub registry_snapshot_root: Hash32,
    pub scan: AccountStateScan,
    pub projection: AccountStateProjection,
    pub account_methods: AccountMethodInventory,
    pub bound_policies: Vec<BoundPolicy>,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckedAccountObservationError {
    #[error("{0}")]
    Registry(#[from] RegistryError),
    #[error("{0}")]
    Scan(#[from] AccountScanError),
    #[error("{0}")]
    Projection(#[from] AccountProjectionError),
    #[error("E_INCOMPLETE_ACCOUNT_STATE: {0}")]
    Identity(&'static str),
}

/// The URL and trust roots live in operator configuration, not in a client request.
pub struct OperatorAccountSource {
    config: OperatorAccountSourceConfig,
    transport: HttpTransport,
}

impl OperatorAccountSource {
    pub fn new(
        config: OperatorAccountSourceConfig,
    ) -> Result<Self, CheckedAccountObservationError> {
        if config.source_name.is_empty() || config.network_passphrase.is_empty() {
            return Err(CheckedAccountObservationError::Identity(
                "operator source name and network passphrase must be nonempty",
            ));
        }
        // Validate the signed snapshot and durable checkpoint before constructing a source.
        let _ = verified_registry(&config)?;
        let transport = HttpTransport::new(config.rpc_url.clone());
        Ok(Self { config, transport })
    }

    /// Read and check one account against signed capabilities and reviewed binding hashes.
    /// Revalidation on each call rejects a snapshot that expired after source construction.
    pub fn inspect(
        &self,
        account_address: &str,
        expected_account_wasm_hash: Hash32,
        bindings: &[ReviewedPolicyBinding],
    ) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
        let registry = verified_registry(&self.config)?;
        inspect_with_transport(
            &self.transport,
            &self.config,
            &registry,
            account_address,
            expected_account_wasm_hash,
            bindings,
        )
    }
}

fn verified_registry(
    config: &OperatorAccountSourceConfig,
) -> Result<Registry, CheckedAccountObservationError> {
    let mut registry = Registry::with_pinned_roots_for_network_at_checkpoint(
        config.registry_roots.clone(),
        NetworkId::from_passphrase(&config.network_passphrase),
        config.registry_checkpoint.clone(),
    )?;
    registry.load(&config.signed_registry_snapshot)?;
    Ok(registry)
}

fn inspect_with_transport<T: RpcTransport>(
    transport: &T,
    config: &OperatorAccountSourceConfig,
    registry: &Registry,
    account_address: &str,
    expected_account_wasm_hash: Hash32,
    bindings: &[ReviewedPolicyBinding],
) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
    let account = account_address
        .parse::<stellar_strkey::Contract>()
        .map_err(|_| CheckedAccountObservationError::Identity("invalid account C-address"))?;
    if account.to_string() != account_address {
        return Err(CheckedAccountObservationError::Identity(
            "noncanonical account C-address",
        ));
    }
    let authority = registry.resolve_account_authority(&expected_account_wasm_hash)?;
    let mut unique = BTreeSet::new();
    let mut targets = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let address = binding
            .address
            .parse::<stellar_strkey::Contract>()
            .map_err(|_| CheckedAccountObservationError::Identity("invalid policy C-address"))?;
        if format!("{address}") != binding.address || binding.address == account_address {
            return Err(CheckedAccountObservationError::Identity(
                "policy address is noncanonical or equals account address",
            ));
        }
        if !unique.insert(address.0) {
            return Err(CheckedAccountObservationError::Identity(
                "duplicate policy binding address",
            ));
        }
        registry.resolve_policy(&binding.expected_wasm_hash)?;
        targets.push(binding.address.clone());
    }
    let scan = scan_account_state_with_targets(
        transport,
        &config.network_passphrase,
        account_address,
        &targets,
        AccountScanBounds {
            max_scan_ids: authority.scan.max_scan_ids,
            max_rpc_batches: authority.scan.max_rpc_batches,
            max_transitive_entries: authority.scan.max_transitive_entries as usize,
            max_attempts: authority.scan.max_attempts,
        },
    )?;
    check_scan(
        scan,
        config,
        registry,
        account_address,
        expected_account_wasm_hash,
        bindings,
        authority.methods,
    )
}

fn check_scan(
    scan: AccountStateScan,
    config: &OperatorAccountSourceConfig,
    registry: &Registry,
    expected_account_address: &str,
    expected_account_wasm_hash: Hash32,
    bindings: &[ReviewedPolicyBinding],
    account_methods: AccountMethodInventory,
) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
    if scan.account_address != expected_account_address
        || scan.network_id != NetworkId::from_passphrase(&config.network_passphrase)
        || scan.account_wasm_hash != expected_account_wasm_hash
    {
        return Err(CheckedAccountObservationError::Identity(
            "observed account, network, or code differs from the requested identity",
        ));
    }
    let projection = project_account_state(&scan)?;
    // Recognition is by the observed code at each address, including existing policies
    // outside the requested binding set. An unknown or revoked implementation fails closed.
    for policy in scan.policies.values() {
        let observed = scan.observed_code_hashes.get(&policy.address).ok_or(
            CheckedAccountObservationError::Identity("installed policy has no observed code"),
        )?;
        registry.resolve_policy(observed)?;
    }
    let mut bound_policies = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if scan.observed_code_hashes.get(&binding.address) != Some(&binding.expected_wasm_hash) {
            return Err(CheckedAccountObservationError::Identity(
                "bound policy code differs from its reviewed identity",
            ));
        }
        bound_policies.push(BoundPolicy {
            address: binding.address.clone(),
            observed_wasm_hash: binding.expected_wasm_hash.to_hex(),
        });
    }
    Ok(CheckedAccountObservation {
        source_name: config.source_name.clone(),
        registry_snapshot_root: registry.root()?,
        scan,
        projection,
        account_methods,
        bound_policies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContextRuleRecord, ContextType, PolicyRecord, SignerIdentity, SignerRecord};
    use ozpb_domain::{canonical_hash, domains, pinned_upstream, LedgerSeq};
    use ozpb_registry::{
        account_methods, dev, sign_snapshot, snapshot_root, AccountArchivePolicy,
        AccountSnapshotPolicy, BoundedNextIdCapability, RegistrySnapshot,
    };
    use std::collections::BTreeMap;
    use stellar_xdr::{
        ContractDataEntry, ContractExecutable, ExtensionPoint, Hash, LedgerEntryData, LedgerKey,
        ReadXdr, ScAddress, ScContractInstance, ScMapEntry, ScVal, WriteXdr,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";

    fn address(byte: u8) -> String {
        format!("{}", stellar_strkey::Contract([byte; 32]))
    }

    fn signed_snapshot() -> ozpb_registry::SignedSnapshot {
        let mut snapshot: RegistrySnapshot =
            dev::dev_snapshot(NetworkId::from_passphrase(NETWORK), 1);
        let account = snapshot
            .accounts
            .get_mut(&pinned_upstream::OZ_SMART_ACCOUNT_WASM.to_hex())
            .unwrap();
        account.bounded_next_id = Some(BoundedNextIdCapability {
            schema_version: 1,
            max_scan_ids: 10,
            max_rpc_batches: 6,
            max_transitive_entries: 10,
            max_attempts: 1,
            archive_policy: AccountArchivePolicy::RejectUnresolved,
            snapshot_policy: AccountSnapshotPolicy::SameLedgerAndInstance,
        });
        account.method_inventory_digest = Some(
            canonical_hash(
                domains::ACCOUNT_METHOD_INVENTORY,
                &account_methods::source_reviewed_oz_multisig_candidate(),
            )
            .unwrap(),
        );
        sign_snapshot(&dev::dev_signing_key(), snapshot).unwrap()
    }

    fn config(signed: ozpb_registry::SignedSnapshot) -> OperatorAccountSourceConfig {
        OperatorAccountSourceConfig {
            source_name: "operator-testnet".into(),
            rpc_url: "http://operator.example.invalid/rpc".into(),
            network_passphrase: NETWORK.into(),
            registry_roots: RootPolicy {
                threshold: 1,
                keys: BTreeMap::from([("legacy".into(), dev::dev_root_verifying_bytes())]),
            },
            registry_checkpoint: RegistryCheckpoint {
                version: 1,
                log_index: 1,
                root: snapshot_root(&signed.snapshot).unwrap(),
                revocations: BTreeMap::new(),
            },
            signed_registry_snapshot: signed,
        }
    }

    fn scan() -> AccountStateScan {
        AccountStateScan {
            network_id: NetworkId::from_passphrase(NETWORK),
            account_address: address(7),
            reported_latest_ledger: LedgerSeq(10),
            account_wasm_hash: pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            next_id: 2,
            extant_count: 2,
            rules: BTreeMap::from([
                (
                    0,
                    ContextRuleRecord {
                        id: 0,
                        name: "candidate".into(),
                        context_type: ContextType::Default,
                        valid_until: None,
                        signer_ids: vec![10],
                        policy_ids: vec![],
                    },
                ),
                (
                    1,
                    ContextRuleRecord {
                        id: 1,
                        name: "grant".into(),
                        context_type: ContextType::CallContract(address(14)),
                        valid_until: None,
                        signer_ids: vec![10],
                        policy_ids: vec![11],
                    },
                ),
            ]),
            signers: BTreeMap::from([(
                10,
                SignerRecord {
                    id: 10,
                    signer: SignerIdentity::Delegated(address(12)),
                    reference_count: 2,
                },
            )]),
            policies: BTreeMap::from([(
                11,
                PolicyRecord {
                    id: 11,
                    address: address(13),
                    reference_count: 1,
                },
            )]),
            observed_code_hashes: BTreeMap::from([
                (address(13), pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM),
                (address(14), pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM),
            ]),
            ordered_entry_digest: Hash32([20; 32]),
            rpc_batches: 5,
            attempts: 1,
        }
    }

    fn bindings() -> Vec<ReviewedPolicyBinding> {
        vec![ReviewedPolicyBinding {
            address: address(14),
            expected_wasm_hash: pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM,
        }]
    }

    fn check(
        scan: AccountStateScan,
        config: &OperatorAccountSourceConfig,
        bindings: &[ReviewedPolicyBinding],
    ) -> Result<CheckedAccountObservation, CheckedAccountObservationError> {
        let registry = verified_registry(config)?;
        let authority = registry
            .resolve_account_authority(&pinned_upstream::OZ_SMART_ACCOUNT_WASM)
            .unwrap();
        check_scan(
            scan,
            config,
            &registry,
            &address(7),
            pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            bindings,
            authority.methods,
        )
    }

    #[test]
    fn signed_identity_and_live_code_are_kept_separate_from_admin_intent() {
        let config = config(signed_snapshot());
        let observed = check(scan(), &config, &bindings()).unwrap();
        assert_eq!(
            observed.registry_snapshot_root,
            config.registry_checkpoint.root
        );
        assert_eq!(observed.projection.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(observed.projection.admin_candidates.len(), 1);
        assert_eq!(observed.bound_policies.len(), 1);
        assert!(observed.account_methods.methods.contains_key("upgrade"));
        assert_eq!(observed.source_name, "operator-testnet");
    }

    #[test]
    fn operator_source_acquires_account_and_binding_at_one_reported_ledger() {
        struct Endpoint;
        impl RpcTransport for Endpoint {
            fn call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> Result<serde_json::Value, super::super::RpcError> {
                if method == "getNetwork" {
                    return Ok(serde_json::json!({"passphrase": NETWORK, "protocolVersion": 28}));
                }
                assert_eq!(method, "getLedgerEntries");
                let mut entries = Vec::new();
                for encoded in params["keys"].as_array().unwrap() {
                    let encoded = encoded.as_str().unwrap();
                    let LedgerKey::ContractData(key) =
                        LedgerKey::from_xdr_base64(encoded, crate::xdr_limits()).unwrap()
                    else {
                        panic!("contract-data key expected");
                    };
                    assert_eq!(key.key, ScVal::LedgerKeyContractInstance);
                    let account = matches!(
                        &key.contract,
                        ScAddress::Contract(contract) if contract.0.0 == [7; 32]
                    );
                    let expected = if account {
                        pinned_upstream::OZ_SMART_ACCOUNT_WASM
                    } else {
                        assert!(matches!(
                            &key.contract,
                            ScAddress::Contract(contract) if contract.0.0 == [14; 32]
                        ));
                        pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM
                    };
                    let storage = if account {
                        let mut values = vec![
                            ScMapEntry {
                                key: ScVal::Vec(Some(
                                    vec![ScVal::Symbol("Count".try_into().unwrap())]
                                        .try_into()
                                        .unwrap(),
                                )),
                                val: ScVal::U32(0),
                            },
                            ScMapEntry {
                                key: ScVal::Vec(Some(
                                    vec![ScVal::Symbol("NextId".try_into().unwrap())]
                                        .try_into()
                                        .unwrap(),
                                )),
                                val: ScVal::U32(0),
                            },
                        ];
                        values.sort_by(|a, b| a.key.cmp(&b.key));
                        Some(values.try_into().unwrap())
                    } else {
                        None
                    };
                    entries.push(serde_json::json!({
                        "key": encoded,
                        "xdr": LedgerEntryData::ContractData(ContractDataEntry {
                            ext: ExtensionPoint::V0,
                            contract: key.contract,
                            key: key.key,
                            durability: key.durability,
                            val: ScVal::ContractInstance(ScContractInstance {
                                executable: ContractExecutable::Wasm(Hash(expected.0)),
                                storage,
                            }),
                        }).to_xdr_base64(crate::xdr_limits()).unwrap(),
                        "lastModifiedLedgerSeq": 9,
                        "liveUntilLedgerSeq": 20,
                    }));
                }
                Ok(serde_json::json!({"latestLedger": 10, "entries": entries}))
            }
        }
        let config = config(signed_snapshot());
        let registry = verified_registry(&config).unwrap();
        let observed = inspect_with_transport(
            &Endpoint,
            &config,
            &registry,
            &address(7),
            pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            &bindings(),
        )
        .unwrap();
        assert_eq!(observed.scan.reported_latest_ledger, LedgerSeq(10));
        assert_eq!(observed.scan.rpc_batches, 3);
        assert_eq!(observed.bound_policies[0].address, address(14));
        assert!(observed.projection.admin_candidates.is_empty());
    }

    #[test]
    fn rejects_wrong_network_account_and_policy_code() {
        let config = config(signed_snapshot());
        let mut wrong = scan();
        wrong.network_id = NetworkId(Hash32([42; 32]));
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let mut wrong = scan();
        wrong.account_wasm_hash = Hash32([42; 32]);
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let mut wrong = scan();
        wrong.account_address = address(8);
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let mut wrong = scan();
        wrong
            .observed_code_hashes
            .insert(address(14), Hash32([42; 32]));
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let mut wrong = scan();
        wrong
            .observed_code_hashes
            .insert(address(13), Hash32([42; 32]));
        assert!(matches!(
            check(wrong, &config, &bindings()),
            Err(CheckedAccountObservationError::Registry(_))
        ));
    }

    #[test]
    fn untrusted_roots_checkpoint_and_binding_claims_fail_before_acceptance() {
        let mut bad_signature = config(signed_snapshot());
        bad_signature.signed_registry_snapshot.signatures.clear();
        assert!(matches!(
            verified_registry(&bad_signature),
            Err(CheckedAccountObservationError::Registry(
                RegistryError::Signature
            ))
        ));
        let mut bad_checkpoint = config(signed_snapshot());
        bad_checkpoint.registry_checkpoint.root = Hash32([42; 32]);
        assert!(matches!(
            verified_registry(&bad_checkpoint),
            Err(CheckedAccountObservationError::Registry(
                RegistryError::Transparency(_)
            ))
        ));
        let good = config(signed_snapshot());
        let registry = verified_registry(&good).unwrap();
        let duplicate = vec![bindings()[0].clone(), bindings()[0].clone()];
        assert!(matches!(
            inspect_with_transport(
                &NoCalls,
                &good,
                &registry,
                &address(7),
                pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                &duplicate,
            ),
            Err(CheckedAccountObservationError::Identity(_))
        ));
        let unknown = vec![ReviewedPolicyBinding {
            address: address(14),
            expected_wasm_hash: Hash32([42; 32]),
        }];
        assert!(matches!(
            inspect_with_transport(
                &NoCalls,
                &good,
                &registry,
                &address(7),
                pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                &unknown,
            ),
            Err(CheckedAccountObservationError::Registry(
                RegistryError::UnknownPolicy(_)
            ))
        ));
    }

    #[test]
    fn endpoint_error_cannot_echo_requested_account_keys() {
        struct Echo;
        impl RpcTransport for Echo {
            fn call(
                &self,
                method: &str,
                _: serde_json::Value,
            ) -> Result<serde_json::Value, super::super::RpcError> {
                if method == "getNetwork" {
                    Ok(serde_json::json!({"passphrase": NETWORK, "protocolVersion": 28}))
                } else {
                    Err(super::super::RpcError::Rpc(
                        "echoed ledger key: confidential-marker".into(),
                    ))
                }
            }
        }
        let good = config(signed_snapshot());
        let registry = verified_registry(&good).unwrap();
        let error = inspect_with_transport(
            &Echo,
            &good,
            &registry,
            &address(7),
            pinned_upstream::OZ_SMART_ACCOUNT_WASM,
            &[],
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            CheckedAccountObservationError::Scan(AccountScanError::Rpc(
                super::super::RpcError::Rpc(_)
            ))
        ));
        assert!(!error.to_string().contains("confidential-marker"));
        let code_error = crate::read_contract_wasm_hashes(&Echo, NETWORK, &[address(13)])
            .expect_err("a reflected code-read error must fail");
        assert!(matches!(code_error, super::super::RpcError::Rpc(_)));
        assert!(!code_error.to_string().contains("confidential-marker"));
    }

    struct NoCalls;
    impl RpcTransport for NoCalls {
        fn call(
            &self,
            _: &str,
            _: serde_json::Value,
        ) -> Result<serde_json::Value, super::super::RpcError> {
            panic!("invalid identity should fail before endpoint access")
        }
    }
}
