//! Canonical wire types from the public stellar-accounts 0.7.2 ABI.
//! No account or policy authorization logic is implemented here.
use soroban_sdk::{contracttype, Address, Bytes, BytesN, Map, String, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Signer {
    Delegated(Address),
    External(Address, Bytes),
}
#[contracttype]
#[derive(Clone)]
pub struct AuthPayload {
    pub signers: Map<Signer, Bytes>,
    pub context_rule_ids: Vec<u32>,
}
#[contracttype]
#[derive(Clone)]
pub enum ContextRuleType {
    Default,
    CallContract(Address),
    CreateContract(BytesN<32>),
}
#[contracttype]
#[derive(Clone)]
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
#[contracttype]
#[derive(Clone)]
pub struct AccountEd25519Signature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}
#[contracttype]
pub enum PolicyStorageKey {
    Installed(Address, u32),
    CallCount(Address, u32),
}

#[cfg(test)]
#[path = "../../contracts/differential/tests/support/native_runtime_abi.rs"]
mod compatibility;
