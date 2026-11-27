//! Code-hash-bound contract adapters (architecture §4.3 / §6.1).
//!
//! An adapter declares the *semantic role* of each argument of a specific target
//! contract function, bound to a verified target wasm code hash. This is the only way,
//! besides an explicit user decision, that a widening may enter a spec — because the XDR
//! type alone never determines bound direction (lowering a `min_output` makes a swap
//! *less* safe). Adapter-derived constraints carry `Provenance::AdapterDerived` with the
//! adapter identity and the code hash it is bound to, and the effect claim they enable is
//! only "effect-minimal" while the target's on-chain code hash still matches.

use crate::WideningBound;
use ozpb_domain::{
    target_adapters::{AdapterSemantics, ArgumentRole, ArgumentType},
    Hash32,
};
use ozpb_recorder_core::ArgSummary;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stellar_xdr::{Limits, ReadXdr, ScVal};

/// The declared role of an argument, which fixes the safe widening direction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgRole {
    /// A maximum input/spend: safe to cap from above (`<=`).
    MaxInput,
    /// A minimum output: safe to floor from below (`>=`); lowering it is UNSAFE.
    MinOutput,
    /// A caller-chosen deadline/nonce/identifier: leaving it unconstrained is a
    /// deliberate, high-blast-radius choice.
    CallerChosen,
    /// A value that must stay exactly as observed (recipient, path, asset, …).
    ExactOnly,
}

impl ArgRole {
    /// The widening this role permits given the observed value, if any. `None` means the
    /// argument must stay exact.
    pub fn widening(&self, observed_i128: Option<i128>) -> Option<WideningBound> {
        match self {
            ArgRole::MaxInput => {
                observed_i128.map(|v| WideningBound::LeI128 { max: v.to_string() })
            }
            // A min-output floor cannot be derived from one observed value alone — it
            // needs a trusted quote. The adapter only *permits* a user-supplied floor; it
            // does not invent one. So no automatic widening here.
            ArgRole::MinOutput => None,
            ArgRole::CallerChosen => Some(WideningBound::AnyValue),
            ArgRole::ExactOnly => None,
        }
    }
}

/// One recognized function of a recognized target contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FnRoles {
    pub fn_name: String,
    pub arg_types: Vec<ArgumentType>,
    /// Role per argument index (0..n-1).
    pub arg_roles: Vec<ArgRole>,
}

/// An adapter bound to a specific target wasm code hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adapter {
    pub name: String,
    pub target_code_hash: Hash32,
    pub functions: BTreeMap<String, FnRoles>,
}

impl Adapter {
    pub fn from_semantics(target_code_hash: Hash32, semantics: AdapterSemantics) -> Self {
        Self {
            name: semantics.name,
            target_code_hash,
            functions: semantics
                .functions
                .into_iter()
                .map(|(name, f)| {
                    (
                        name,
                        FnRoles {
                            fn_name: f.fn_name,
                            arg_types: f.arg_types,
                            arg_roles: f
                                .arg_roles
                                .into_iter()
                                .map(|role| match role {
                                    ArgumentRole::MaxInput => ArgRole::MaxInput,
                                    ArgumentRole::MinOutput => ArgRole::MinOutput,
                                    ArgumentRole::CallerChosen => ArgRole::CallerChosen,
                                    ArgumentRole::ExactOnly => ArgRole::ExactOnly,
                                })
                                .collect(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Semantic roles are meaningful only for the complete recognized function signature.
    /// A partial prefix or differently typed call must not inherit automatic widenings.
    pub fn matches_call(&self, name: &str, args: &[ArgSummary]) -> bool {
        let Some(f) = self.functions.get(name) else {
            return false;
        };
        f.fn_name == name && args.len() == f.arg_roles.len() && args.len() == f.arg_types.len()
            && args.iter().zip(&f.arg_types).all(|(arg, kind)| match (arg, kind) {
                (ArgSummary::I128(_), ArgumentType::I128)
                | (ArgSummary::U64(_), ArgumentType::U64)
                | (ArgSummary::Address(_), ArgumentType::Address) => true,
                (ArgSummary::Other { xdr_base64 }, ArgumentType::AddressVector) => {
                    if xdr_base64.len() > 1024 * 1024 { return false; }
                    matches!(ScVal::from_xdr_base64(xdr_base64, Limits { depth: 64, len: 1024 * 1024 }),
                        Ok(ScVal::Vec(Some(values))) if values.iter().all(|v| matches!(v, ScVal::Address(_))))
                }
                _ => false,
            })
    }

    pub fn role(&self, fn_name: &str, arg_index: usize) -> Option<&ArgRole> {
        self.functions
            .get(fn_name)
            .and_then(|f| f.arg_roles.get(arg_index))
    }
}

/// The reviewed Soroswap router adapter (architecture W3). Bound to a code hash so that
/// if the router is upgraded, the adapter no longer applies and the report falls back to
/// exact-only + user decisions.
pub fn soroswap_router_adapter(target_code_hash: Hash32) -> Adapter {
    Adapter::from_semantics(
        target_code_hash,
        ozpb_domain::target_adapters::soroswap_router_v2(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_domain::sha256;

    #[test]
    fn soroswap_roles_are_declared_per_arg() {
        let a = soroswap_router_adapter(sha256(b"soroswap-router-wasm"));
        assert_eq!(
            a.role("swap_exact_tokens_for_tokens", 0),
            Some(&ArgRole::MaxInput)
        );
        assert_eq!(
            a.role("swap_exact_tokens_for_tokens", 1),
            Some(&ArgRole::MinOutput)
        );
        assert_eq!(
            a.role("swap_exact_tokens_for_tokens", 4),
            Some(&ArgRole::ExactOnly)
        );
        assert_eq!(a.role("unknown_fn", 0), None);
    }

    /// A swap call whose address-vector path is `contracts` contract addresses followed by
    /// `accounts` account addresses, as the recorder summarizes it (base64 XDR).
    fn swap_with_path(contracts: usize, accounts: usize) -> Vec<ArgSummary> {
        use stellar_xdr::{AccountId, ContractId, Hash, PublicKey, ScAddress, Uint256, WriteXdr};
        let contract = ScVal::Address(ScAddress::Contract(ContractId(Hash([1; 32]))));
        let account = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([2; 32])),
        )));
        let mut path = vec![contract; contracts];
        path.extend(vec![account; accounts]);
        let path = ScVal::Vec(Some(path.try_into().unwrap()));
        vec![
            ArgSummary::I128(1),
            ArgSummary::I128(1),
            ArgSummary::Other {
                xdr_base64: path.to_xdr_base64(Limits::none()).unwrap(),
            },
            ArgSummary::Address(
                "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526".to_string(),
            ),
            ArgSummary::U64(1),
        ]
    }

    #[test]
    fn an_address_vector_path_is_bounded_at_one_mebibyte_of_text() {
        const BOUND: usize = 1024 * 1024;
        let a = soroswap_router_adapter(sha256(b"soroswap-router-wasm"));
        let path_len = |args: &[ArgSummary]| match &args[2] {
            ArgSummary::Other { xdr_base64 } => xdr_base64.len(),
            _ => unreachable!(),
        };

        // 12 bytes of vector header + 19655 × 40 (contract) + 5 × 44 (account) = 786432 bytes
        // of XDR, whose base64 is exactly the bound.
        let at_bound = swap_with_path(19_655, 5);
        assert_eq!(path_len(&at_bound), BOUND);
        assert!(a.matches_call("swap_exact_tokens_for_tokens", &at_bound));

        // One more address is past the text bound yet still decodes within the 1 MiB XDR
        // limit, so only the text bound refuses it.
        let past_bound = swap_with_path(19_656, 5);
        assert!(path_len(&past_bound) > BOUND);
        assert!(!a.matches_call("swap_exact_tokens_for_tokens", &past_bound));

        // An ordinary short path is recognized.
        assert!(a.matches_call("swap_exact_tokens_for_tokens", &swap_with_path(2, 0)));
    }

    #[test]
    fn max_input_permits_upper_bound_min_output_does_not_invent_a_floor() {
        assert_eq!(
            ArgRole::MaxInput.widening(Some(1000)),
            Some(WideningBound::LeI128 {
                max: "1000".to_string()
            })
        );
        // A min-output floor requires a trusted quote — never auto-derived (§6.1, W3).
        assert_eq!(ArgRole::MinOutput.widening(Some(950)), None);
        assert_eq!(
            ArgRole::CallerChosen.widening(None),
            Some(WideningBound::AnyValue)
        );
        assert_eq!(ArgRole::ExactOnly.widening(Some(1)), None);
    }
}
