#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

/// Test-only target whose storage and account authorization are exercised by
/// the disposable execution fixture. Its balance is deliberately a single
/// fixed key so the captured key closure can be enumerated exactly. It does
/// not credit the recipient, so it cannot stand in for token transfer behavior.
#[contract]
pub struct AuthorizedTarget;

#[contractimpl]
impl AuthorizedTarget {
    pub fn transfer(env: Env, from: Address, _to: Address, amount: i128) {
        from.require_auth();
        assert!(amount > 0, "amount must be positive");
        let key = Symbol::new(&env, "balance");
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&key)
            .expect("balance is required");
        assert!(balance >= amount, "insufficient balance");
        env.storage().persistent().set(&key, &(balance - amount));
    }

    pub fn balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "balance"))
            .unwrap_or(0)
    }
}
