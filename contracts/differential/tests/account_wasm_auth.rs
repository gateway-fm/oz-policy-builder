//! The pinned account's complete authorization path through a generated policy Wasm.
//!
//! `scripts/test-pinned-account-authorization.sh` builds both artifacts from pinned
//! public sources and runs this ignored test. The ordinary contracts suite leaves it
//! ignored because its prerequisite is a real Wasm build; the script fails if any
//! prerequisite is unavailable or either artifact has an unexpected hash.

use ed25519_dalek::{Signer as _, SigningKey};
use ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM;
use ozpb_synthesizer::fixtures as fx;
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::xdr::{
    AccountEntry, AccountEntryExt, AccountId, Hash as XdrHash, HashIdPreimage,
    HashIdPreimageSorobanAuthorization, InvokeContractArgs, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, ScAddress,
    ScErrorCode, ScErrorType, ScVal, SequenceNumber, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, Thresholds, Uint256, VecM, WriteXdr,
};
use soroban_sdk::{
    contracttype, vec as svec, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, Val,
};
use std::rc::Rc;
use stellar_accounts::smart_account::{AuthPayload, Signer};

#[derive(Clone)]
#[contracttype]
struct AccountEd25519Signature {
    public_key: BytesN<32>,
    signature: BytesN<64>,
}

fn bytes_vec(bytes: &Bytes) -> Vec<u8> {
    let mut out = vec![0; bytes.len() as usize];
    bytes.copy_into_slice(&mut out);
    out
}

fn as_sc_address(env: &Env, address: &Address) -> ScAddress {
    match ScVal::from_xdr(bytes_vec(&address.to_xdr(env)), Limits::none()).unwrap() {
        ScVal::Address(value) => value,
        other => panic!("expected address, got {other:?}"),
    }
}

fn insert_account(env: &Env, public_key: [u8; 32]) {
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key)));
    let key = Rc::new(LedgerKey::Account(LedgerKeyAccount {
        account_id: account_id.clone(),
    }));
    let entry = Rc::new(LedgerEntry {
        last_modified_ledger_seq: 0,
        data: LedgerEntryData::Account(AccountEntry {
            account_id,
            balance: 100_000_000,
            seq_num: SequenceNumber(0),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: Default::default(),
            thresholds: Thresholds([1, 1, 1, 1]),
            signers: VecM::default(),
            ext: AccountEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    });
    env.host().add_ledger_entry(&key, &entry, None).unwrap();
}

fn signed_delegate_auth(
    env: &Env,
    account: &Address,
    key: &SigningKey,
    auth_digest: &Bytes,
    nonce: i64,
) -> SorobanAuthorizationEntry {
    let signature_expiration_ledger = 2000;
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: as_sc_address(env, account),
            function_name: "__check_auth".try_into().unwrap(),
            args: vec![ScVal::Bytes(bytes_vec(auth_digest).try_into().unwrap())]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: VecM::default(),
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: XdrHash(env.ledger().network_id().to_array()),
        nonce,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let payload = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap());
    let sig = AccountEd25519Signature {
        public_key: BytesN::from_array(env, &key.verifying_key().to_bytes()),
        signature: BytesN::from_array(env, &key.sign(&payload).to_bytes()),
    };
    let signature =
        ScVal::from_xdr(bytes_vec(&svec![env, sig].to_xdr(env)), Limits::none()).unwrap();
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                key.verifying_key().to_bytes(),
            )))),
            nonce,
            signature_expiration_ledger,
            signature,
        }),
        root_invocation,
    }
}

struct AuthHarness<'a> {
    env: &'a Env,
    account: &'a Address,
    signer: &'a SigningKey,
    delegate: &'a Address,
    context: &'a Context,
}

impl AuthHarness<'_> {
    fn check_auth(
        &self,
        count: u32,
        nonce: i64,
        signed_payload: &Bytes,
        actual_payload: &Bytes,
    ) -> Result<(), Result<soroban_sdk::Error, soroban_sdk::InvokeError>> {
        let env = self.env;
        let account = self.account;
        let signer = self.signer;
        let delegate = self.delegate;
        let context = self.context;
        let mut authenticated = Map::new(env);
        authenticated.set(Signer::Delegated(delegate.clone()), Bytes::new(env));
        let mut context_rule_ids = soroban_sdk::Vec::new(env);
        let mut contexts = soroban_sdk::Vec::new(env);
        for _ in 0..count {
            context_rule_ids.push_back(0u32);
            contexts.push_back(context.clone());
        }
        let auth_payload = AuthPayload {
            signers: authenticated,
            context_rule_ids,
        };
        let mut preimage = env.crypto().sha256(signed_payload).to_bytes().to_bytes();
        preimage.append(&auth_payload.context_rule_ids.clone().to_xdr(env));
        let auth_digest = env.crypto().sha256(&preimage);
        env.set_auths(&[signed_delegate_auth(
            env,
            account,
            signer,
            &auth_digest.to_bytes().to_bytes(),
            nonce,
        )]);
        let signature_payload = env.crypto().sha256(actual_payload);
        env.try_invoke_contract_check_auth::<soroban_sdk::Error>(
            account,
            &signature_payload.to_bytes(),
            auth_payload.into_val(env),
            &contexts,
        )
    }
}

fn remaining_calls(env: &Env, policy: &Address, account: &Address) -> u32 {
    env.invoke_contract(
        policy,
        &Symbol::new(env, "remaining_calls"),
        svec![env, 0u32.into_val(env), account.clone().into_val(env)],
    )
}

#[test]
#[ignore = "requires the pinned account and generated policy Wasm; run scripts/test-pinned-account-authorization.sh"]
fn pinned_account_wasm_full_authorization() {
    let wasm_path = std::env::var("OZPB_ACCOUNT_WASM").expect("account wasm path is required");
    let wasm = std::fs::read(wasm_path).expect("read account wasm");
    let account_hash: [u8; 32] = Sha256::digest(&wasm).into();
    assert_eq!(
        account_hash, OZ_SMART_ACCOUNT_WASM.0,
        "account Wasm hash differs from pin"
    );
    let policy_wasm_path = std::env::var("OZPB_POLICY_WASM").expect("policy wasm path is required");
    let policy_wasm = std::fs::read(policy_wasm_path).expect("read policy wasm");
    let policy_hash: [u8; 32] = Sha256::digest(&policy_wasm).into();
    // The script changes only the golden spec's signer to the fixed Ed25519
    // test key, then builds with the repository's pinned rustc and stellar CLI.
    // A changed source, dependency, or build input must be reviewed here.
    assert_eq!(
        policy_hash,
        ozpb_domain::Hash32::from_hex(
            "27980fdd1b892397fdd25ea511eccc1825b1209c2a9ae8e48359a1d70a22287d"
        )
        .unwrap()
        .0,
        "generated policy Wasm hash differs from reviewed fixture"
    );
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 1000);
    let signer = SigningKey::from_bytes(&[42u8; 32]);
    insert_account(&env, signer.verifying_key().to_bytes());
    let policy = env.register(policy_wasm.as_slice(), ());
    let delegate = Address::from_str(
        &env,
        "GAMX62ZD4FWIKMWGVPEDR6WNL2TYTPQMO2ZJEAZUAON7VCZ5G2GWDF7W",
    );
    let mut policies: Map<Address, Val> = Map::new(&env);
    policies.set(policy.clone(), 0u32.into_val(&env));
    let account = env.register(
        wasm.as_slice(),
        (svec![&env, Signer::Delegated(delegate.clone())], policies),
    );

    let token = Address::from_str(&env, &fx::golden_token_strkey());
    let merchant = Address::from_str(&env, &fx::golden_merchant_strkey());
    let args = svec![
        &env,
        account.clone().into_val(&env),
        merchant.into_val(&env),
        500_000_000i128.into_val(&env)
    ];
    let context = Context::Contract(ContractContext {
        contract: token,
        fn_name: Symbol::new(&env, "transfer"),
        args,
    });
    let harness = AuthHarness {
        env: &env,
        account: &account,
        signer: &signer,
        delegate: &delegate,
        context: &context,
    };
    assert_eq!(remaining_calls(&env, &policy, &account), 12);
    let signed_payload = Bytes::from_array(&env, &[1u8; 32]);
    let wrong_payload = Bytes::from_array(&env, &[2u8; 32]);
    let invalid = harness.check_auth(1, 100, &signed_payload, &wrong_payload);
    assert_eq!(
        invalid,
        Err(Ok(soroban_sdk::Error::from_type_and_code(
            ScErrorType::Auth,
            ScErrorCode::InvalidAction
        ))),
        "signature must bind to the supplied payload"
    );
    assert_eq!(remaining_calls(&env, &policy, &account), 12);

    for i in 0..11 {
        let payload = Bytes::from_array(&env, &[i as u8 + 1; 32]);
        let result = harness.check_auth(1, 200 + i, &payload, &payload);
        assert_eq!(result, Ok(()), "successful call {i}");
        assert_eq!(remaining_calls(&env, &policy, &account), 11 - i as u32);
        env.ledger().with_mut(|l| l.sequence_number += 1);
    }
    // Two contexts would spend the last call, then exceed the cap; the entire host
    // authorization must roll back to one remaining call.
    let payload = Bytes::from_array(&env, &[99u8; 32]);
    let denied = harness.check_auth(2, 400, &payload, &payload);
    assert_eq!(
        denied,
        Err(Ok(soroban_sdk::Error::from_contract_error(7))),
        "N+1 context must be denied"
    );
    assert_eq!(remaining_calls(&env, &policy, &account), 1);

    let result = harness.check_auth(1, 401, &payload, &payload);
    assert_eq!(result, Ok(()));
    assert_eq!(remaining_calls(&env, &policy, &account), 0);
    let denied = harness.check_auth(1, 402, &payload, &payload);
    assert_eq!(
        denied,
        Err(Ok(soroban_sdk::Error::from_contract_error(7))),
        "N+1 call must be denied"
    );
    assert_eq!(remaining_calls(&env, &policy, &account), 0);
}
