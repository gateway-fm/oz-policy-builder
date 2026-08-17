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
use ozpb_domain::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    let mut functions = BTreeMap::new();
    functions.insert(
        "swap_exact_tokens_for_tokens".to_string(),
        FnRoles {
            fn_name: "swap_exact_tokens_for_tokens".to_string(),
            arg_roles: vec![
                ArgRole::MaxInput,     // amount_in — cap from above
                ArgRole::MinOutput,    // amount_out_min — user-supplied absolute floor only
                ArgRole::ExactOnly,    // path — whitelisted route
                ArgRole::ExactOnly,    // to — recipient (SELF)
                ArgRole::CallerChosen, // deadline — caller-chosen, may be left unconstrained
            ],
        },
    );
    Adapter {
        name: "soroswap-router@1".to_string(),
        target_code_hash,
        functions,
    }
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
            Some(&ArgRole::CallerChosen)
        );
        assert_eq!(a.role("unknown_fn", 0), None);
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
