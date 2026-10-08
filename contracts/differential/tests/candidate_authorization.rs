//! Signed account/policy authorization while a captured target Wasm executes.
//!
//! The target's instance, code, and complete fixed-key storage closure are
//! supplied by one checked fixture RPC reply at ledger 101. Account and policy
//! state are freshly constructed in a separate local snapshot, then combined
//! without overlap behind a strict source. This is an executable candidate
//! fixture, not a historical network replay or a complete live-state proof.

#[path = "support/captured_snapshot.rs"]
mod captured_snapshot;
#[path = "support/signed_auth.rs"]
mod signed_auth;

use captured_snapshot::reconstruct;
use ed25519_dalek::SigningKey;
use generated_sub_transfer_r0::contract::PolicyStorageKey;
use ozpb_domain::{pinned_upstream::OZ_SMART_ACCOUNT_WASM, NetworkId};
use ozpb_recorder_core::{fixtures, record, RecordOptions};
use ozpb_source_rpc::{read_invocation_footprint, RpcError, RpcTransport};
use ozpb_synthesizer::fixtures as fx;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signed_auth::{as_sc_address, bytes_vec, insert_account, signed_delegate_auth};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{
    testutils::Ledger,
    vec as svec,
    xdr::{
        self as sdk_xdr, FromXdr as _, ReadXdr as _, ScErrorCode, ScErrorType, ToXdr as _,
        WriteXdr as _,
    },
    Address, Bytes, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec as SVec,
};
use std::cell::RefCell;
use stellar_accounts::smart_account::{AuthPayload, Signer};
use stellar_xdr::{
    ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, ContractDataEntry,
    ContractExecutable, ContractId, ExtensionPoint, Hash, HostFunction, InvokeContractArgs,
    LedgerEntryData, LedgerFootprint, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData,
    OperationBody, ReadXdr as _, ScAddress, ScContractInstance, ScVal, SorobanTransactionData,
    TransactionEnvelope, TransactionExt, WriteXdr as _,
};

const NETWORK: &str = "Test SDF Network ; September 2015";
const START_BALANCE: i128 = 2_000_000_000;
const AMOUNT: i128 = 500_000_000;
const EXPECTED_TARGET_HASH: &str =
    "d3766fbdf07170a55da903b75ef2262e3e84541e0304ac93425261c812032098";
const EXPECTED_POLICY_HASH: &str =
    "27980fdd1b892397fdd25ea511eccc1825b1209c2a9ae8e48359a1d70a22287d";

fn sdk_scval<T: IntoVal<Env, Val>>(env: &Env, value: T) -> sdk_xdr::ScVal {
    <sdk_xdr::ScVal as sdk_xdr::ReadXdr>::from_xdr(
        bytes_vec(&value.to_xdr(env)),
        sdk_xdr::Limits::none(),
    )
    .unwrap()
}

fn rebind_address(source: &Env, destination: &Env, address: &Address) -> Address {
    let bytes = bytes_vec(&address.clone().to_xdr(source));
    Address::from_xdr(destination, &Bytes::from_slice(destination, &bytes)).unwrap()
}

fn rpc_scval<T: IntoVal<Env, Val>>(env: &Env, value: T) -> ScVal {
    ScVal::from_xdr(bytes_vec(&value.to_xdr(env)), stellar_xdr::Limits::none()).unwrap()
}

fn contract() -> ScAddress {
    ScAddress::Contract(ContractId(Hash(
        stellar_strkey::Contract::from_string(&fx::golden_token_strkey())
            .unwrap()
            .0,
    )))
}

fn nonce_key(env: &Env, address: &Address, nonce: i64) -> sdk_xdr::LedgerKey {
    sdk_xdr::LedgerKey::ContractData(sdk_xdr::LedgerKeyContractData {
        contract: as_sc_address(env, address),
        key: sdk_xdr::ScVal::LedgerKeyNonce(sdk_xdr::ScNonceKey { nonce }),
        durability: sdk_xdr::ContractDataDurability::Temporary,
    })
}

fn rpc_entry(key: LedgerKey, data: LedgerEntryData) -> Value {
    json!({
        "key": key.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
        "xdr": data.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
        "lastModifiedLedgerSeq": 100,
        "liveUntilLedgerSeq": 2000
    })
}

fn target_capture_envelope(
    env: &Env,
    account: &Address,
    merchant: &Address,
    wasm: &[u8],
) -> (String, Vec<Value>) {
    let hash = Hash(Sha256::digest(wasm).into());
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let instance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(hash.clone()),
            storage: None,
        }),
    });
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: hash.clone() });
    let code = LedgerEntryData::ContractCode(ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash,
        code: wasm.try_into().unwrap(),
    });
    let balance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract(),
        key: rpc_scval(env, Symbol::new(env, "balance")),
        durability: ContractDataDurability::Persistent,
    });
    let balance = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: contract(),
        key: rpc_scval(env, Symbol::new(env, "balance")),
        durability: ContractDataDurability::Persistent,
        val: rpc_scval(env, START_BALANCE),
    });
    let raw = record(&fixtures::executed_snapshot(), RecordOptions::default())
        .unwrap()
        .raw
        .envelope_xdr_base64;
    let mut envelope =
        TransactionEnvelope::from_xdr_base64(&raw, stellar_xdr::Limits::none()).unwrap();
    let TransactionEnvelope::Tx(v1) = &mut envelope else {
        panic!("v1 envelope")
    };
    let mut operations: Vec<_> = v1.tx.operations.iter().cloned().collect();
    let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
        panic!("host function")
    };
    op.host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract(),
        function_name: "transfer".as_bytes().to_vec().try_into().unwrap(),
        args: vec![
            rpc_scval(env, account.clone()),
            rpc_scval(env, merchant.clone()),
            rpc_scval(env, AMOUNT),
        ]
        .try_into()
        .unwrap(),
    });
    op.auth = Default::default();
    v1.tx.operations = operations.try_into().unwrap();
    let mut data = SorobanTransactionData::default();
    data.resources.footprint = LedgerFootprint {
        read_only: vec![instance_key.clone(), code_key.clone()]
            .try_into()
            .unwrap(),
        read_write: vec![balance_key.clone()].try_into().unwrap(),
    };
    v1.tx.ext = TransactionExt::V1(data);
    (
        envelope.to_xdr_base64(stellar_xdr::Limits::none()).unwrap(),
        vec![
            rpc_entry(instance_key, instance),
            rpc_entry(code_key, code),
            rpc_entry(balance_key, balance),
        ],
    )
}

struct FixtureRpc {
    entries: Vec<Value>,
    calls: RefCell<Vec<String>>,
}

impl RpcTransport for FixtureRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push(method.to_string());
        match method {
            "getNetwork" => Ok(json!({"passphrase": NETWORK, "protocolVersion": 26})),
            "getLedgerEntries" => {
                assert_eq!(params["xdrFormat"], "base64");
                assert_eq!(params["keys"].as_array().unwrap().len(), 3);
                Ok(json!({"latestLedger": 101, "entries": self.entries}))
            }
            other => panic!("unexpected method: {other}"),
        }
    }
}

struct SigningInputs<'a> {
    env: &'a Env,
    account: &'a Address,
    target: &'a Address,
    merchant: &'a Address,
    delegate: &'a Address,
    key: &'a SigningKey,
}

fn signed_entries(
    input: &SigningInputs<'_>,
    amount: i128,
    nonce: i64,
) -> [sdk_xdr::SorobanAuthorizationEntry; 2] {
    let SigningInputs {
        env,
        account,
        target,
        merchant,
        delegate,
        key,
    } = *input;
    let mut signers = Map::new(env);
    signers.set(Signer::Delegated(delegate.clone()), Bytes::new(env));
    let rule_ids = svec![env, 0u32];
    let payload = AuthPayload {
        signers,
        context_rule_ids: rule_ids.clone(),
    };
    let root_invocation = sdk_xdr::SorobanAuthorizedInvocation {
        function: sdk_xdr::SorobanAuthorizedFunction::ContractFn(sdk_xdr::InvokeContractArgs {
            contract_address: as_sc_address(env, target),
            function_name: "transfer".try_into().unwrap(),
            args: vec![
                sdk_scval(env, account.clone()),
                sdk_scval(env, merchant.clone()),
                sdk_scval(env, amount),
            ]
            .try_into()
            .unwrap(),
        }),
        sub_invocations: sdk_xdr::VecM::default(),
    };
    let signature_expiration_ledger = 2000;
    let preimage = sdk_xdr::HashIdPreimage::SorobanAuthorization(
        sdk_xdr::HashIdPreimageSorobanAuthorization {
            network_id: sdk_xdr::Hash(env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger,
            invocation: root_invocation.clone(),
        },
    );
    let payload_digest: [u8; 32] =
        Sha256::digest(preimage.to_xdr(sdk_xdr::Limits::none()).unwrap()).into();
    let mut delegate_preimage = Bytes::from_array(env, &payload_digest);
    delegate_preimage.append(&rule_ids.to_xdr(env));
    let delegate_digest = env
        .crypto()
        .sha256(&delegate_preimage)
        .to_bytes()
        .to_bytes();
    let account_entry = sdk_xdr::SorobanAuthorizationEntry {
        credentials: sdk_xdr::SorobanCredentials::Address(sdk_xdr::SorobanAddressCredentials {
            address: as_sc_address(env, account),
            nonce,
            signature_expiration_ledger,
            signature: <sdk_xdr::ScVal as sdk_xdr::ReadXdr>::from_xdr(
                bytes_vec(&payload.to_xdr(env)),
                sdk_xdr::Limits::none(),
            )
            .unwrap(),
        }),
        root_invocation,
    };
    let delegate_entry = signed_delegate_auth(env, account, key, &delegate_digest, nonce + 1000);
    [account_entry, delegate_entry]
}

fn balance(env: &Env, target: &Address) -> i128 {
    env.invoke_contract(target, &Symbol::new(env, "balance"), svec![env])
}

fn remaining_calls(env: &Env, policy: &Address, account: &Address) -> u32 {
    env.invoke_contract(
        policy,
        &Symbol::new(env, "remaining_calls"),
        svec![env, 0u32.into_val(env), account.clone().into_val(env)],
    )
}

#[test]
#[ignore = "requires source-built account, generated policy, and target Wasm; run scripts/test-pinned-account-authorization.sh"]
fn signed_candidate_executes_captured_target_and_denies_adjacent_amount() {
    let account_wasm = std::fs::read(std::env::var("OZPB_ACCOUNT_WASM").unwrap()).unwrap();
    let policy_wasm = std::fs::read(std::env::var("OZPB_POLICY_WASM").unwrap()).unwrap();
    let target_wasm = std::fs::read(std::env::var("OZPB_TARGET_WASM").unwrap()).unwrap();
    let account_hash: [u8; 32] = Sha256::digest(&account_wasm).into();
    assert_eq!(account_hash, OZ_SMART_ACCOUNT_WASM.0);
    assert_eq!(
        hex::encode(Sha256::digest(&policy_wasm)),
        EXPECTED_POLICY_HASH
    );
    assert_eq!(
        hex::encode(Sha256::digest(&target_wasm)),
        EXPECTED_TARGET_HASH
    );

    let setup = Env::default();
    setup.ledger().with_mut(|ledger| {
        ledger.sequence_number = 101;
        ledger.network_id = NetworkId::from_passphrase(NETWORK).0 .0;
    });
    let signer = SigningKey::from_bytes(&[42u8; 32]);
    insert_account(&setup, signer.verifying_key().to_bytes());
    let policy = setup.register(policy_wasm.as_slice(), ());
    let delegate = Address::from_str(
        &setup,
        "GAMX62ZD4FWIKMWGVPEDR6WNL2TYTPQMO2ZJEAZUAON7VCZ5G2GWDF7W",
    );
    let mut policies: Map<Address, Val> = Map::new(&setup);
    policies.set(policy.clone(), 0u32.into_val(&setup));
    let account = setup.register(
        account_wasm.as_slice(),
        (svec![&setup, Signer::Delegated(delegate.clone())], policies),
    );
    let merchant = Address::from_str(&setup, &fx::golden_merchant_strkey());
    let candidate = setup.to_ledger_snapshot();
    let (envelope, entries) = target_capture_envelope(&setup, &account, &merchant, &target_wasm);
    let rpc = FixtureRpc {
        entries,
        calls: RefCell::new(Vec::new()),
    };
    let capture = read_invocation_footprint(&rpc, NETWORK, &envelope).unwrap();
    assert_eq!(*rpc.calls.borrow(), ["getNetwork", "getLedgerEntries"]);
    assert_eq!(capture.validated_wasm_instances, 1);
    assert_eq!(capture.entries.len(), 3);
    let call = capture.invocation.as_ref().unwrap();
    assert_eq!(call.contract_address, fx::golden_token_strkey());
    assert_eq!(call.function_name, "transfer");
    assert_eq!(call.args_xdr_base64.len(), 3);
    let count_key = sdk_xdr::LedgerKey::ContractData(sdk_xdr::LedgerKeyContractData {
        contract: as_sc_address(&setup, &policy),
        key: sdk_scval(&setup, PolicyStorageKey::CallCount(account.clone(), 0)),
        durability: sdk_xdr::ContractDataDurability::Persistent,
    });
    let mut missing_candidate = candidate.clone();
    let original_len = missing_candidate.ledger_entries.len();
    missing_candidate
        .ledger_entries
        .retain(|(key, _)| key.as_ref() != &count_key);
    assert_eq!(missing_candidate.ledger_entries.len(), original_len - 1);
    let incomplete = reconstruct(&capture, Some(&missing_candidate), vec![]);
    let incomplete_policy = rebind_address(&setup, &incomplete.env, &policy);
    let incomplete_account = rebind_address(&setup, &incomplete.env, &account);
    let missing_read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        remaining_calls(&incomplete.env, &incomplete_policy, &incomplete_account)
    }));
    assert!(
        missing_read.is_err(),
        "missing candidate policy state must refuse"
    );
    assert!(*incomplete.rejected.borrow() > 0);

    let unrelated = reconstruct(&capture, Some(&candidate), vec![]);
    let unrelated_account = rebind_address(&setup, &unrelated.env, &account);
    let unknown_read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unrelated.env.as_contract(&unrelated_account, || {
            unrelated
                .env
                .storage()
                .persistent()
                .has(&Symbol::new(&unrelated.env, "unexpected"))
        })
    }));
    assert!(
        unknown_read.is_err(),
        "an undeclared candidate key must refuse"
    );
    assert!(*unrelated.rejected.borrow() > 0);

    let allowed_absent = vec![
        nonce_key(&setup, &account, 500),
        nonce_key(&setup, &delegate, 1500),
        nonce_key(&setup, &delegate, 1600),
        nonce_key(&setup, &account, 501),
        nonce_key(&setup, &delegate, 1501),
    ];
    let world = reconstruct(&capture, Some(&candidate), allowed_absent);
    assert_eq!(world.captured_entry_count, 3);
    assert!(world.candidate_entry_count > 3);
    let env = &world.env;
    let account = rebind_address(&setup, env, &account);
    let policy = rebind_address(&setup, env, &policy);
    let target = Address::from_str(env, &call.contract_address);
    let merchant = rebind_address(&setup, env, &merchant);
    let delegate = rebind_address(&setup, env, &delegate);
    assert_eq!(balance(env, &target), START_BALANCE);
    assert_eq!(remaining_calls(env, &policy, &account), 12);

    let signing = SigningInputs {
        env,
        account: &account,
        target: &target,
        merchant: &merchant,
        delegate: &delegate,
        key: &signer,
    };

    env.set_auths(&signed_entries(&signing, AMOUNT, 500));
    let expected_args = svec![
        env,
        account.clone().into_val(env),
        merchant.clone().into_val(env),
        AMOUNT.into_val(env),
    ];
    let captured_args = SVec::from_iter(
        env,
        call.args_xdr_base64.iter().map(|encoded| {
            let value = sdk_xdr::ScVal::from_xdr_base64(encoded, sdk_xdr::Limits::none()).unwrap();
            Val::try_from_val(env, &value).unwrap()
        }),
    );
    assert_eq!(
        captured_args, expected_args,
        "locally signed invocation must equal captured call"
    );
    let result = env.try_invoke_contract::<(), soroban_sdk::Error>(
        &target,
        &Symbol::new(env, &call.function_name),
        captured_args,
    );
    assert_eq!(
        result,
        Ok(Ok(())),
        "signed account path must permit target call"
    );
    assert_eq!(balance(env, &target), START_BALANCE - AMOUNT);
    assert_eq!(remaining_calls(env, &policy, &account), 11);
    assert_eq!(*world.rejected.borrow(), 0);

    // Adjacent amount remains within the target balance, so only the account
    // policy can explain this denial. The failed call cannot spend policy state.
    // First ask the complete account path for the exact mutated context and
    // assert its specific policy error. The host wraps that error as a context
    // failure when the target calls require_auth, so this control preserves the
    // denial's attribution rather than accepting any target failure.
    let mut signers = Map::new(env);
    signers.set(Signer::Delegated(delegate.clone()), Bytes::new(env));
    let rule_ids = svec![env, 0u32];
    let mut digest_preimage = env
        .crypto()
        .sha256(&Bytes::from_array(env, &[77; 32]))
        .to_bytes()
        .to_bytes();
    digest_preimage.append(&rule_ids.clone().to_xdr(env));
    let digest = env.crypto().sha256(&digest_preimage).to_bytes().to_bytes();
    env.set_auths(&[signed_delegate_auth(env, &account, &signer, &digest, 1600)]);
    let context = Context::Contract(ContractContext {
        contract: target.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args: svec![
            env,
            account.clone().into_val(env),
            merchant.clone().into_val(env),
            (AMOUNT + 1).into_val(env),
        ],
    });
    let direct = env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
        &account,
        &env.crypto()
            .sha256(&Bytes::from_array(env, &[77; 32]))
            .to_bytes(),
        AuthPayload {
            signers,
            context_rule_ids: rule_ids,
        }
        .into_val(env),
        &svec![env, context],
    );
    assert_eq!(direct, Err(Ok(soroban_sdk::Error::from_contract_error(6))));
    assert_eq!(remaining_calls(env, &policy, &account), 11);

    env.set_auths(&signed_entries(&signing, AMOUNT + 1, 501));
    let denied = env.try_invoke_contract::<(), soroban_sdk::Error>(
        &target,
        &Symbol::new(env, "transfer"),
        svec![
            env,
            account.clone().into_val(env),
            merchant.clone().into_val(env),
            (AMOUNT + 1).into_val(env),
        ],
    );
    assert_eq!(
        denied,
        Err(Ok(soroban_sdk::Error::from_type_and_code(
            ScErrorType::Context,
            ScErrorCode::InvalidAction,
        ))),
        "host must refuse the policy-denied target authorization"
    );
    assert_eq!(balance(env, &target), START_BALANCE - AMOUNT);
    assert_eq!(remaining_calls(env, &policy, &account), 11);
    assert_eq!(*world.rejected.borrow(), 0);

    env.ledger().with_mut(|ledger| ledger.sequence_number += 1);
    let committed = env.to_ledger_snapshot();
    assert_eq!(committed.sequence_number, 102);
    let later = Env::from_ledger_snapshot(committed);
    let later_target = Address::from_str(&later, &call.contract_address);
    assert_eq!(balance(&later, &later_target), START_BALANCE - AMOUNT);
    let later_policy = rebind_address(env, &later, &policy);
    let later_account = rebind_address(env, &later, &account);
    assert_eq!(remaining_calls(&later, &later_policy, &later_account), 11);
}
