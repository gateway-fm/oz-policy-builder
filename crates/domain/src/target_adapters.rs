//! Locally implemented target semantics. A signed registry binding is required before
//! these declarations may describe an observed target implementation.

use crate::{canonical_hash, domains, DomainError, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentType {
    I128,
    U64,
    Address,
    AddressVector,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentRole {
    MaxInput,
    MinOutput,
    CallerChosen,
    ExactOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionSemantics {
    pub fn_name: String,
    /// Exact arity is the length of both ordered lists.
    pub arg_types: Vec<ArgumentType>,
    pub arg_roles: Vec<ArgumentRole>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterSemantics {
    pub name: String,
    pub functions: BTreeMap<String, FunctionSemantics>,
}

impl AdapterSemantics {
    pub fn digest(&self) -> Result<Hash32, DomainError> {
        canonical_hash(domains::TARGET_ADAPTER_SEMANTICS, self)
    }
}

/// The code of the Soroswap router deployed on testnet at
/// `CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD`, read from the network. It is
/// not reproduced from source: a rebuild of the public router source (`soroswap/core` tag
/// `v1.0`, unchanged since) differs from it in the order of internal functions only, so the
/// development registry binds it as a labeled assertion (`docs/TARGET-ADAPTERS.md`).
pub const SOROSWAP_ROUTER_TESTNET_WASM: Hash32 = Hash32([
    0x4b, 0x95, 0xbb, 0xf9, 0xca, 0xec, 0x2c, 0x6e, 0x00, 0xc7, 0x86, 0xf5, 0x3c, 0x5f, 0x39, 0x2c,
    0x2f, 0xcd, 0xb8, 0x43, 0x5a, 0xc0, 0xa8, 0x62, 0xab, 0x5e, 0x06, 0x45, 0xeb, 0x65, 0x82, 0x4c,
]);

pub fn soroswap_router() -> AdapterSemantics {
    use ArgumentRole::{CallerChosen, ExactOnly, MaxInput, MinOutput};
    use ArgumentType::{Address, AddressVector, I128, U64};
    let name = "swap_exact_tokens_for_tokens".to_string();
    AdapterSemantics {
        name: "soroswap-router@1".to_string(),
        functions: BTreeMap::from([(
            name.clone(),
            FunctionSemantics {
                fn_name: name,
                arg_types: vec![I128, I128, AddressVector, Address, U64],
                arg_roles: vec![MaxInput, MinOutput, ExactOnly, ExactOnly, CallerChosen],
            },
        )]),
    }
}

/// Version 2 keeps the approved, recorded deadline exact. Version 1 remains supported
/// for historical registries; changing it would reinterpret previously signed bindings.
pub fn soroswap_router_v2() -> AdapterSemantics {
    let mut semantics = soroswap_router();
    semantics.name = "soroswap-router@2".to_string();
    for function in semantics.functions.values_mut() {
        function.arg_roles[4] = ArgumentRole::ExactOnly;
    }
    semantics
}

pub fn implemented(name: &str) -> Option<AdapterSemantics> {
    match name {
        "soroswap-router@1" => Some(soroswap_router()),
        "soroswap-router@2" => Some(soroswap_router_v2()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_v2_does_not_reinterpret_v1() {
        let old = soroswap_router();
        let new = soroswap_router_v2();
        assert_eq!(
            old.digest().unwrap().to_hex(),
            "da6b4c209e48dac98d9473599622c3c17ec52101d2b3bca4bea7ecdf081a2f13"
        );
        assert_eq!(
            new.digest().unwrap().to_hex(),
            "69f4ec7627ec27a1fa07eac40f3f127004ac13d8933900400f66107b9da94215"
        );
        assert_eq!(
            old.functions.values().next().unwrap().arg_roles[4],
            ArgumentRole::CallerChosen
        );
        assert_eq!(
            new.functions.values().next().unwrap().arg_roles[4],
            ArgumentRole::ExactOnly
        );
    }

    #[test]
    fn digest_commits_to_identity_function_arity_types_and_role_order() {
        let original = soroswap_router();
        let hash = original.digest().unwrap();
        for mutation in 0..5 {
            let mut changed = original.clone();
            let function = changed.functions.values_mut().next().unwrap();
            match mutation {
                0 => changed.name.push_str("-changed"),
                1 => function.fn_name.push_str("_changed"),
                2 => {
                    function.arg_types.pop();
                    function.arg_roles.pop();
                }
                3 => function.arg_types[0] = ArgumentType::U64,
                _ => function.arg_roles.swap(0, 1),
            }
            assert_ne!(hash, changed.digest().unwrap());
        }
    }
}
