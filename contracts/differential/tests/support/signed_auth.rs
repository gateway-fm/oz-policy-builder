//! Shared exact Soroban authorization entries for the fixed test-only G signer.

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::xdr::{
    AccountEntry, AccountEntryExt, AccountId, Hash as XdrHash, HashIdPreimage,
    HashIdPreimageSorobanAuthorization, InvokeContractArgs, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, ScAddress, ScVal,
    SequenceNumber, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, Thresholds,
    Uint256, VecM, WriteXdr,
};
use soroban_sdk::{contracttype, vec as svec, Address, Bytes, BytesN, Env};
use std::rc::Rc;

#[derive(Clone)]
#[contracttype]
struct AccountEd25519Signature {
    public_key: BytesN<32>,
    signature: BytesN<64>,
}

pub fn bytes_vec(bytes: &Bytes) -> Vec<u8> {
    let mut out = vec![0; bytes.len() as usize];
    bytes.copy_into_slice(&mut out);
    out
}

pub fn as_sc_address(env: &Env, address: &Address) -> ScAddress {
    match ScVal::from_xdr(bytes_vec(&address.to_xdr(env)), Limits::none()).unwrap() {
        ScVal::Address(value) => value,
        other => panic!("expected address, got {other:?}"),
    }
}

pub fn insert_account(env: &Env, public_key: [u8; 32]) {
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

pub fn signed_delegate_auth(
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
