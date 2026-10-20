#![no_std]
//! Installs one candidate context rule and makes one native-asset transfer under it, inside a
//! single invocation, so that a single enforce-mode simulation exercises the generated policy
//! against current network state without anything being installed on chain.
//!
//! The helper holds no storage, keys or administrator and has no upgrade, relay or arbitrary
//! call surface. It cannot authorize anything itself: the installation needs the account
//! owner's authorization and the transfer needs the delegate's, exactly as when called
//! directly. A failed transfer rolls the installation back with it.
//!
//! None of those authorizations names the helper. They are rooted at the account's
//! `add_context_rule` and at the asset's `transfer`, so the same set is a valid, submittable
//! installation followed by a real transfer without the helper. Nothing here limits what a
//! signature authorizes; the signer has to bound amount, recipient and expiry before signing.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, vec, Address, Bytes,
    BytesN, Env, Executable, IntoVal, Map, String, Symbol, Val, Vec,
};

/// SHA-256 of the pinned OpenZeppelin `stellar-accounts` 0.7.2 smart-account Wasm
/// (`ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM`). Any other account code is refused.
const PINNED_ACCOUNT_WASM: [u8; 32] = [
    0xa1, 0x27, 0x47, 0xff, 0x6c, 0x13, 0x9d, 0xc1, 0x4f, 0xc2, 0xfd, 0x30, 0xd2, 0x00, 0xd6, 0xbb,
    0xb5, 0xda, 0x7b, 0x5d, 0x59, 0x81, 0x2c, 0x04, 0x7c, 0xe1, 0xf9, 0xca, 0xd2, 0x26, 0xb2, 0x89,
];

/// The sample permit is 1,000,000 stroops and its adjacent denial case one stroop more. This
/// bounds only the transfer the helper itself executes, not what any signature authorizes.
pub const MAX_AMOUNT: i128 = 1_000_001;

/// `Asset::Native` in canonical XDR.
const NATIVE_ASSET_XDR: [u8; 4] = [0, 0, 0, 0];

/// Wire mirrors of the `stellar-accounts` 0.7.2 types the helper exchanges with the account.
/// Declared here, rather than imported, so the helper's own contract spec describes its return
/// value; the encoding is checked against the shared protocol vector and the real account Wasm.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    Delegated(Address),
    External(Address, Bytes),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextRuleType {
    Default,
    CallContract(Address),
    CreateContract(BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextRule {
    pub id: u32,
    pub context_type: ContextRuleType,
    pub name: String,
    pub signers: Vec<Signer>,
    pub signer_ids: Vec<u32>,
    pub policies: Vec<Address>,
    pub policy_ids: Vec<u32>,
    pub valid_until: Option<u32>,
}

/// The candidate grant and the one call it is tested with. There is no token or function
/// field: the target is always the native asset contract of the executing network.
#[contracttype]
#[derive(Clone)]
pub struct Candidate {
    pub account: Address,
    pub policy: Address,
    pub policy_hash: BytesN<32>,
    pub delegate: Address,
    pub expected_rule_id: u32,
    pub name: String,
    pub valid_until: u32,
    pub recipient: Address,
    pub amount: i128,
}

/// Codes start at 7001 so they do not collide with the asset contract's or a policy's small
/// codes. Attribute a refusal by the contract ID of its diagnostic error event, not by code.
// A called contract's own error keeps its code (the account's `add_context_rule` input checks,
// a failing asset transfer), but the host turns any failure inside an account's `__check_auth`
// — a policy denial included — into `Error(Auth, InvalidAction)`, and the helper's failed call
// then reaches its caller as `Error(Context, InvalidAction)`.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum HelperError {
    /// The amount is not in `1..=MAX_AMOUNT`.
    AmountOutOfScope = 7001,
    /// Two roles (helper, account, policy, delegate, recipient, asset) share an address.
    AliasedIdentity = 7002,
    /// The delegate is not an existing classic account.
    UnsupportedDelegate = 7003,
    /// The account is not running the pinned smart-account Wasm.
    UnrecognizedAccount = 7004,
    /// The policy is not running the expected candidate Wasm.
    PolicyCodeMismatch = 7005,
    /// The account allocated a different rule ID than the one reviewed.
    UnexpectedRuleId = 7006,
    /// The installed rule differs from the requested one in any field.
    InstalledRuleMismatch = 7007,
}

#[contract]
pub struct AtomicLiveHelper;

#[contractimpl]
impl AtomicLiveHelper {
    /// Installs the candidate rule through the account's own `add_context_rule`, then transfers
    /// `amount` of the native asset from the account to `recipient` under that rule. Returns
    /// the installed rule only after the transfer succeeds.
    pub fn install_and_transfer(env: Env, candidate: Candidate) -> ContextRule {
        if candidate.amount <= 0 || candidate.amount > MAX_AMOUNT {
            panic_with_error!(&env, HelperError::AmountOutOfScope);
        }
        let token = env
            .deployer()
            .with_stellar_asset(Bytes::from_array(&env, &NATIVE_ASSET_XDR))
            .deployed_address();
        let roles = [
            env.current_contract_address(),
            candidate.account.clone(),
            candidate.policy.clone(),
            candidate.delegate.clone(),
            candidate.recipient.clone(),
            token.clone(),
        ];
        for (i, a) in roles.iter().enumerate() {
            if roles[i + 1..].contains(a) {
                panic_with_error!(&env, HelperError::AliasedIdentity);
            }
        }
        // Scope choice: the supported delegate is an existing classic (G) account. Contract
        // signers with their own `__check_auth` are valid for the account but not supported here.
        if candidate.delegate.executable() != Some(Executable::Account) {
            panic_with_error!(&env, HelperError::UnsupportedDelegate);
        }
        if candidate.account.executable()
            != Some(Executable::Wasm(BytesN::from_array(
                &env,
                &PINNED_ACCOUNT_WASM,
            )))
        {
            panic_with_error!(&env, HelperError::UnrecognizedAccount);
        }
        if candidate.policy.executable() != Some(Executable::Wasm(candidate.policy_hash.clone())) {
            panic_with_error!(&env, HelperError::PolicyCodeMismatch);
        }

        let context_type = ContextRuleType::CallContract(token.clone());
        let signers = vec![&env, Signer::Delegated(candidate.delegate.clone())];
        // The generated policy's installation parameter is a `u32` it does not interpret.
        let mut policies = Map::<Address, Val>::new(&env);
        policies.set(candidate.policy.clone(), 0u32.into_val(&env));
        let installed: ContextRule = env.invoke_contract(
            &candidate.account,
            &Symbol::new(&env, "add_context_rule"),
            vec![
                &env,
                context_type.clone().into_val(&env),
                candidate.name.clone().into_val(&env),
                Some(candidate.valid_until).into_val(&env),
                signers.clone().into_val(&env),
                policies.into_val(&env),
            ],
        );
        if installed.id != candidate.expected_rule_id {
            panic_with_error!(&env, HelperError::UnexpectedRuleId);
        }
        // Registry IDs are allocated by the account; only their count is fixed here.
        if installed.context_type != context_type
            || installed.name != candidate.name
            || installed.signers != signers
            || installed.signer_ids.len() != 1
            || installed.policies != vec![&env, candidate.policy.clone()]
            || installed.policy_ids.len() != 1
            || installed.valid_until != Some(candidate.valid_until)
        {
            panic_with_error!(&env, HelperError::InstalledRuleMismatch);
        }

        // A denial here aborts the whole invocation, installation included; it is never caught.
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![
                &env,
                candidate.account.into_val(&env),
                candidate.recipient.into_val(&env),
                candidate.amount.into_val(&env),
            ],
        );
        installed
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::{ContextRule, ContextRuleType, Signer};
    use soroban_sdk::xdr::{Limits, ScVal, WriteXdr};
    use soroban_sdk::{vec, Address, Env, IntoVal, String, TryFromVal, Val};

    /// The mirrors encode exactly as the account types do in the vector the SDK-26 account
    /// types and the SDK-29 runtime are already checked against.
    #[test]
    fn wire_mirrors_match_the_shared_protocol_vector() {
        let env = Env::default();
        let contract =
            |n| Address::from_str(&env, stellar_strkey::Contract([n; 32]).to_string().as_str());
        let delegate = Address::from_str(
            &env,
            stellar_strkey::ed25519::PublicKey([6; 32])
                .to_string()
                .as_str(),
        );
        let signer = Signer::Delegated(delegate);
        let context_type = ContextRuleType::CallContract(contract(5));
        let rule = ContextRule {
            id: 7,
            context_type: context_type.clone(),
            name: String::from_str(&env, "candidate"),
            signers: vec![&env, signer.clone()],
            signer_ids: vec![&env, 9u32],
            policies: vec![&env, contract(8)],
            policy_ids: vec![&env, 11u32],
            valid_until: Some(123),
        };
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/examples/native-runtime-abi.json"
        ))
        .unwrap();
        for (name, value) in [
            ("signer", signer.into_val(&env)),
            ("context_rule_type", context_type.into_val(&env)),
            ("context_rule", rule.into_val(&env)),
        ] {
            let value: Val = value;
            let encoded = ScVal::try_from_val(&env, &value)
                .unwrap()
                .to_xdr_base64(Limits {
                    depth: 64,
                    len: 4096,
                })
                .unwrap();
            assert_eq!(encoded, fixture[name].as_str().unwrap(), "{name}");
        }
    }
}
