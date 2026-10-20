use super::*;
use crate::{xdr_limits, RpcTransport};
use ozpb_domain::{sha256, NetworkId};
use ozpb_recorder_core::{fixtures, record, RecordOptions};
use serde_json::{json, Value};
use std::cell::RefCell;
use stellar_xdr::*;

const NETWORK: &str = "Test SDF Network ; September 2015";
const LEDGER: u32 = 1000;

struct Fixture {
    envelope: String,
    simulation: Value,
    entries: Value,
    header: Value,
    nonce_key: String,
    calls: RefCell<Vec<String>>,
}
impl RpcTransport for Fixture {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push(method.into());
        Ok(match method {
            "getNetwork" => json!({"passphrase": NETWORK, "protocolVersion": 29}),
            "simulateTransaction" => {
                assert_eq!(params["authMode"], "record");
                assert_eq!(params["transaction"], self.envelope);
                self.simulation.clone()
            }
            "getLedgerEntries" => {
                // The recorded authorization's fresh nonce key is never requested.
                assert!(!params["keys"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(self.nonce_key)));
                self.entries.clone()
            }
            "getLedgers" => {
                assert_eq!(params["startLedger"], LEDGER);
                assert_eq!(params["pagination"]["limit"], 1);
                self.header.clone()
            }
            _ => panic!("unexpected RPC method {method}"),
        })
    }
}
fn encode<T: WriteXdr>(v: &T) -> String {
    v.to_xdr_base64(xdr_limits()).unwrap()
}
fn fixture() -> Fixture {
    let network = NetworkId::from_passphrase(NETWORK);
    let native = sha256(
        &HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(network.0 .0),
            contract_id_preimage: ContractIdPreimage::Asset(Asset::Native),
        })
        .to_xdr(xdr_limits())
        .unwrap(),
    );
    let token = ScAddress::Contract(ContractId(Hash(native.0)));
    let account = ScAddress::Contract(ContractId(Hash([1; 32])));
    let recipient = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([3; 32])));
    let call = InvokeContractArgs {
        contract_address: token.clone(),
        function_name: "transfer".try_into().unwrap(),
        args: vec![
            ScVal::Address(account.clone()),
            ScVal::Address(ScAddress::Account(recipient.clone())),
            ScVal::I128(Int128Parts {
                hi: 0,
                lo: 1_000_000,
            }),
        ]
        .try_into()
        .unwrap(),
    };
    let mut envelope = TransactionEnvelope::from_xdr_base64(
        &record(&fixtures::executed_snapshot(), RecordOptions::default())
            .unwrap()
            .raw
            .envelope_xdr_base64,
        xdr_limits(),
    )
    .unwrap();
    let TransactionEnvelope::Tx(v1) = &mut envelope else {
        panic!()
    };
    v1.signatures = Default::default();
    v1.tx.operations = vec![Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(call.clone()),
            auth: Default::default(),
        }),
    }]
    .try_into()
    .unwrap();
    v1.tx.ext = TransactionExt::V0;
    let instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: token.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::StellarAsset,
            storage: None,
        }),
    });
    let balance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: token,
        key: ScVal::Vec(Some(
            vec![
                ScVal::Symbol("Balance".try_into().unwrap()),
                ScVal::Address(account.clone()),
            ]
            .try_into()
            .unwrap(),
        )),
        durability: ContractDataDurability::Persistent,
        val: ScVal::I128(Int128Parts {
            hi: 0,
            lo: 100_000_000,
        }),
    });
    let classic = LedgerEntryData::Account(AccountEntry {
        account_id: recipient,
        balance: 100_000_000,
        ..Default::default()
    });
    let archival =
        LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(StateArchivalSettings {
            max_entry_ttl: 631200,
            min_temporary_ttl: 16,
            min_persistent_ttl: 4096,
            ..Default::default()
        }));
    let code = b"\0asm\x01\0\0\0".to_vec();
    let code_hash = Hash(sha256(&code).0);
    let account_instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: account.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(code_hash.clone()),
            storage: None,
        }),
    });
    let account_code = LedgerEntryData::ContractCode(ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash: code_hash,
        code: code.try_into().unwrap(),
    });
    let nonce = LedgerKey::ContractData(LedgerKeyContractData {
        contract: account.clone(),
        key: ScVal::LedgerKeyNonce(ScNonceKey { nonce: 17 }),
        durability: ContractDataDurability::Temporary,
    });
    // The shape a real record-mode simulation reports (see target_capture_conformance.rs).
    let footprint = LedgerFootprint {
        read_only: vec![
            account_instance.to_key(),
            instance.to_key(),
            account_code.to_key(),
        ]
        .try_into()
        .unwrap(),
        read_write: vec![classic.to_key(), nonce.clone(), balance.to_key()]
            .try_into()
            .unwrap(),
    };
    let data = SorobanTransactionData {
        resources: SorobanResources {
            footprint,
            ..Default::default()
        },
        ..Default::default()
    };
    let auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account,
            nonce: 17,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(call),
            sub_invocations: Default::default(),
        },
    };
    let mut header = LedgerHeader {
        ledger_version: 29,
        ledger_seq: LEDGER,
        base_reserve: 5_000_000,
        ..Default::default()
    };
    header.scp_value.close_time = TimePoint(100_000);
    let hash = sha256(&header.to_xdr(xdr_limits()).unwrap());
    let header = LedgerHeaderHistoryEntry {
        hash: Hash(hash.0),
        header,
        ext: LedgerHeaderHistoryEntryExt::V0,
    };
    Fixture {
        envelope: encode(&envelope),
        simulation: json!({"latestLedger":LEDGER,"transactionData":encode(&data),"results":[{"xdr":encode(&ScVal::Void),"auth":[encode(&auth)]}]}),
        entries: json!({"latestLedger":LEDGER,"entries":([instance,balance,classic,archival,account_instance,account_code].into_iter().map(|entry|json!({"key":encode(&entry.to_key()),"xdr":encode(&entry),"lastModifiedLedgerSeq":999,"liveUntilLedgerSeq":if matches!(entry,LedgerEntryData::ContractData(_)|LedgerEntryData::ContractCode(_)){Some(900000)}else{None}})).collect::<Vec<_>>())}),
        header: json!({"ledgers":[{"sequence":LEDGER,"hash":hash.to_hex(),"ledgerCloseTime":"100000","headerXdr":encode(&header)}]}),
        nonce_key: encode(&nonce),
        calls: RefCell::new(vec![]),
    }
}
#[test]
fn native_target_capture_binds_recorded_call_header_config_and_exact_entries() {
    let fixture = fixture();
    let capture = capture_native_target(&fixture, NETWORK, &fixture.envelope).unwrap();
    assert_eq!(capture.observed_ledger, LEDGER);
    assert_eq!(capture.provenance, "rpc_reported");
    assert_eq!(capture.entries.len(), 3);
    assert_eq!(capture.read_only_keys.len(), 1);
    assert_eq!(capture.read_write_keys.len(), 2);
    assert_eq!(
        capture.header_xdr,
        fixture.header["ledgers"][0]["headerXdr"]
    );
    assert_eq!(
        capture.recording_auth_xdr,
        fixture.simulation["results"][0]["auth"][0]
    );
    assert_eq!(
        capture.account_code_hash,
        sha256(b"\0asm\x01\0\0\0").to_hex()
    );
}
#[test]
fn native_target_capture_refuses_incoherence_archive_and_unrelated_recording() {
    for mutate in [
        |f: &mut Fixture| f.entries["latestLedger"] = json!(LEDGER + 1),
        |f: &mut Fixture| f.header["ledgers"][0]["hash"] = json!("ff".repeat(32)),
        |f: &mut Fixture| f.header["ledgers"][0]["sequence"] = json!(LEDGER + 1),
        |f: &mut Fixture| f.entries["entries"][0]["liveUntilLedgerSeq"] = json!(LEDGER - 1),
        |f: &mut Fixture| {
            f.entries["entries"].as_array_mut().unwrap().remove(1);
        },
        |f: &mut Fixture| f.simulation["results"][0]["auth"] = json!([]),
        |f: &mut Fixture| f.simulation["restorePreamble"] = json!({}),
        |f: &mut Fixture| f.simulation["results"][0]["xdr"] = json!(encode(&ScVal::Bool(true))),
        |f: &mut Fixture| {
            let mut auth = SorobanAuthorizationEntry::from_xdr_base64(
                f.simulation["results"][0]["auth"][0].as_str().unwrap(),
                xdr_limits(),
            )
            .unwrap();
            let child = auth.root_invocation.clone();
            auth.root_invocation.sub_invocations = vec![child].try_into().unwrap();
            f.simulation["results"][0]["auth"][0] = json!(encode(&auth));
        },
        |f: &mut Fixture| {
            let mut header = LedgerHeaderHistoryEntry::from_xdr_base64(
                f.header["ledgers"][0]["headerXdr"].as_str().unwrap(),
                xdr_limits(),
            )
            .unwrap();
            header.header.ledger_version = 28;
            let hash = sha256(&header.header.to_xdr(xdr_limits()).unwrap());
            header.hash = Hash(hash.0);
            f.header["ledgers"][0]["hash"] = json!(hash.to_hex());
            f.header["ledgers"][0]["headerXdr"] = json!(encode(&header));
        },
        |f: &mut Fixture| f.entries["entries"][3]["liveUntilLedgerSeq"] = json!(LEDGER + 10),
        // Account code missing from the response.
        |f: &mut Fixture| {
            f.entries["entries"].as_array_mut().unwrap().remove(5);
        },
        // The target footprint reads account storage beyond its instance.
        |f: &mut Fixture| {
            let mut data = SorobanTransactionData::from_xdr_base64(
                f.simulation["transactionData"].as_str().unwrap(),
                xdr_limits(),
            )
            .unwrap();
            let LedgerKey::ContractData(instance) = data.resources.footprint.read_only[0].clone()
            else {
                panic!()
            };
            let mut read_only = data.resources.footprint.read_only.to_vec();
            read_only.push(LedgerKey::ContractData(LedgerKeyContractData {
                key: ScVal::Symbol("Signers".try_into().unwrap()),
                ..instance
            }));
            data.resources.footprint.read_only = read_only.try_into().unwrap();
            f.simulation["transactionData"] = json!(encode(&data));
        },
    ] {
        let mut fixture = fixture();
        mutate(&mut fixture);
        assert!(capture_native_target(&fixture, NETWORK, &fixture.envelope).is_err());
        assert!(fixture.calls.borrow().len() <= 10);
    }
}

#[test]
fn native_target_capture_refuses_unsupported_envelopes_before_any_rpc() {
    let fixture = fixture();
    let envelope = TransactionEnvelope::from_xdr_base64(&fixture.envelope, xdr_limits()).unwrap();
    let with_call = |mutate: fn(&mut InvokeContractArgs)| {
        let mut changed = envelope.clone();
        let TransactionEnvelope::Tx(v1) = &mut changed else {
            panic!()
        };
        let mut operations = v1.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!()
        };
        let HostFunction::InvokeContract(call) = &mut op.host_function else {
            panic!()
        };
        mutate(call);
        v1.tx.operations = operations.try_into().unwrap();
        encode(&changed)
    };
    let signed = {
        let mut changed = envelope.clone();
        let TransactionEnvelope::Tx(v1) = &mut changed else {
            panic!()
        };
        v1.signatures = vec![DecoratedSignature {
            hint: SignatureHint([0; 4]),
            signature: Signature(vec![1; 64].try_into().unwrap()),
        }]
        .try_into()
        .unwrap();
        encode(&changed)
    };
    for candidate in [
        signed,
        with_call(|call| call.contract_address = ScAddress::Contract(ContractId(Hash([9; 32])))),
        with_call(|call| call.function_name = "approve".try_into().unwrap()),
        with_call(|call| {
            let mut args = call.args.to_vec();
            args[2] = ScVal::I128(Int128Parts { hi: 0, lo: 0 });
            call.args = args.try_into().unwrap();
        }),
    ] {
        assert!(capture_native_target(&fixture, NETWORK, &candidate).is_err());
        assert!(fixture.calls.borrow().is_empty());
    }
}
