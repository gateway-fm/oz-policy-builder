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

pub fn implemented(name: &str) -> Option<AdapterSemantics> {
    match name {
        "soroswap-router@1" => Some(soroswap_router()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
