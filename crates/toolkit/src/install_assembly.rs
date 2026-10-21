//! Encoding and presentation for unsigned installation assembly. Network I/O stays in shells.

use ozpb_api_types::{
    AssembleInstallTransactionInput, AssembleInstallTransactionOutput, ErrorCode,
    InstallAssemblyRestoration, InstallPolicyParams, PolicySignerKey, PrepareInstallIntentOutput,
    ToolError,
};
use ozpb_source_rpc::{AssemblyRestoration, InstallAssemblyObservation, InstallAssemblyRequest};
use stellar_xdr::*;

fn invalid(message: &str) -> ToolError {
    ToolError::new(ErrorCode::ESpecInvalid, message)
}

/// Encode only the freshly prepared, internally coherent intent. The shells obtain it by
/// running the authority check themselves; there is no wire field for a caller's verdict.
pub fn install_assembly_request(
    input: &AssembleInstallTransactionInput,
    intent: &PrepareInstallIntentOutput,
) -> Result<InstallAssemblyRequest, ToolError> {
    let verdict = &intent.authority.verdict;
    let grant = &verdict.grant;
    if !verdict.refusals.is_empty()
        || !verdict.unresolved.is_empty()
        || verdict.network_id != input.intent_request.network_id
        || intent.account_contract != input.intent_request.account_address
        || intent.account_contract != verdict.account_address
        || usize::try_from(grant.rule_index).ok() != Some(input.intent_request.rule_index)
        || intent.context_contract != grant.target
        || intent.rule_name != grant.name
        || intent.valid_until_ledger != grant.valid_until
        || intent.delegate_signers != grant.signers
        || intent.policies.len() != grant.policies.len()
    {
        return Err(invalid(
            "install intent does not match its authority grant and request",
        ));
    }
    for (index, (policy, granted)) in intent.policies.iter().zip(&grant.policies).enumerate() {
        if policy.policy_index != index
            || policy.address != granted.address
            || policy.install_params != granted.install_params
        {
            return Err(invalid("install policy does not match the authority grant"));
        }
    }
    let invocation = encode_install_invocation(intent)?;
    Ok(InstallAssemblyRequest {
        invocation,
        fee_payer: input.fee_payer.clone(),
        max_fee_stroops: input.max_fee_stroops,
        validity_ledgers: input.validity_ledgers,
        authority_observed_ledger: verdict.observed_ledger,
    })
}

fn address(value: &str, contract_only: bool) -> Result<ScAddress, ToolError> {
    match stellar_strkey::Strkey::from_string(value) {
        Ok(stellar_strkey::Strkey::Contract(key)) if format!("{key}") == value => {
            Ok(ScAddress::Contract(ContractId(Hash(key.0))))
        }
        Ok(stellar_strkey::Strkey::PublicKeyEd25519(key))
            if !contract_only && format!("{key}") == value =>
        {
            Ok(ScAddress::Account(AccountId(
                PublicKey::PublicKeyTypeEd25519(Uint256(key.0)),
            )))
        }
        _ => Err(invalid("invalid canonical install address")),
    }
}

fn vector(values: Vec<ScVal>) -> Result<ScVal, ToolError> {
    Ok(ScVal::Vec(Some(ScVec(values.try_into().map_err(
        |_| invalid("install vector exceeds XDR bounds"),
    )?))))
}

fn symbol(value: &str) -> Result<ScVal, ToolError> {
    Ok(ScVal::Symbol(value.try_into().map_err(|_| {
        invalid("install symbol exceeds XDR bounds")
    })?))
}

fn params(value: &InstallPolicyParams) -> Result<ScVal, ToolError> {
    match value {
        InstallPolicyParams::Generated => Ok(ScVal::U32(0)),
        InstallPolicyParams::SpendingLimit {
            spending_limit,
            period_ledgers,
        } => {
            let limit = spending_limit
                .parse::<i128>()
                .map_err(|_| invalid("invalid spending limit"))?;
            if limit <= 0 || limit.to_string() != *spending_limit || *period_ledgers == 0 {
                return Err(invalid(
                    "spending limit requires a positive canonical amount and period",
                ));
            }
            Ok(ScVal::Map(Some(ScMap(
                vec![
                    ScMapEntry {
                        key: symbol("period_ledgers")?,
                        val: ScVal::U32(*period_ledgers),
                    },
                    ScMapEntry {
                        key: symbol("spending_limit")?,
                        val: ScVal::I128(Int128Parts {
                            hi: (limit >> 64) as i64,
                            lo: limit as u64,
                        }),
                    },
                ]
                .try_into()
                .map_err(|_| invalid("install parameter map exceeds bounds"))?,
            ))))
        }
    }
}

fn encode_install_invocation(
    intent: &PrepareInstallIntentOutput,
) -> Result<InvokeContractArgs, ToolError> {
    if intent.delegate_signers.is_empty() || intent.policies.is_empty() {
        return Err(invalid("verified install requires signers and policies"));
    }
    let mut signers = Vec::new();
    let mut seen_signers = std::collections::BTreeSet::new();
    for signer in &intent.delegate_signers {
        let value = match signer {
            PolicySignerKey::Delegated { address: id } => vector(vec![
                symbol("Delegated")?,
                ScVal::Address(address(id, false)?),
            ])?,
            PolicySignerKey::External { verifier, key_hex } => {
                let bytes =
                    hex::decode(key_hex).map_err(|_| invalid("invalid verifier key hex"))?;
                if bytes.is_empty() || hex::encode(&bytes) != *key_hex {
                    return Err(invalid("verifier key must be canonical nonempty hex"));
                }
                vector(vec![
                    symbol("External")?,
                    ScVal::Address(address(verifier, true)?),
                    ScVal::Bytes(ScBytes(
                        bytes
                            .try_into()
                            .map_err(|_| invalid("verifier key exceeds XDR bounds"))?,
                    )),
                ])?
            }
        };
        if !seen_signers.insert(value.clone()) {
            return Err(invalid("duplicate install signer"));
        }
        signers.push(value);
    }
    let mut policies = std::collections::BTreeMap::new();
    for policy in &intent.policies {
        let key = ScVal::Address(address(&policy.address, true)?);
        if policies
            .insert(key, params(&policy.install_params)?)
            .is_some()
        {
            return Err(invalid("duplicate install policy address"));
        }
    }
    let policy_map: Vec<_> = policies
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect();
    let args = vec![
        vector(vec![
            symbol("CallContract")?,
            ScVal::Address(address(&intent.context_contract, true)?),
        ])?,
        ScVal::String(ScString(
            intent
                .rule_name
                .as_bytes()
                .to_vec()
                .try_into()
                .map_err(|_| invalid("rule name exceeds XDR bounds"))?,
        )),
        intent.valid_until_ledger.map_or(ScVal::Void, ScVal::U32),
        vector(signers)?,
        ScVal::Map(Some(ScMap(
            policy_map
                .try_into()
                .map_err(|_| invalid("policy map exceeds XDR bounds"))?,
        ))),
    ];
    Ok(InvokeContractArgs {
        contract_address: address(&intent.account_contract, true)?,
        function_name: "add_context_rule"
            .try_into()
            .map_err(|_| invalid("function name"))?,
        args: args.try_into().map_err(|_| invalid("argument bounds"))?,
    })
}

pub fn install_assembly_output(
    input: &AssembleInstallTransactionInput,
    intent: PrepareInstallIntentOutput,
    observation: InstallAssemblyObservation,
) -> Result<AssembleInstallTransactionOutput, ToolError> {
    if observation.network_id != input.intent_request.network_id {
        return Err(ToolError::new(
            ErrorCode::ENetworkMismatch,
            "assembly is for a different network",
        ));
    }
    let restoration = match observation.restoration {
        AssemblyRestoration::None => InstallAssemblyRestoration::None,
        AssemblyRestoration::Automatic => InstallAssemblyRestoration::AutomaticWithinInvocation,
        AssemblyRestoration::SeparateTransaction => {
            InstallAssemblyRestoration::SeparateTransactionReassembleRequired
        }
    };
    Ok(AssembleInstallTransactionOutput {
        intent,
        envelope_xdr_base64: observation.envelope_xdr_base64,
        envelope_xdr_sha256: observation.envelope_xdr_sha256,
        network_id: observation.network_id,
        fee_payer: input.fee_payer.clone(),
        source_sequence: observation.source_sequence.to_string(),
        fee_stroops: observation.fee_stroops,
        sequence_read_ledger: observation.sequence_read_ledger,
        simulation_ledger: observation.simulation_ledger,
        min_ledger: observation.min_ledger,
        max_ledger: observation.max_ledger,
        restoration,
        simulation_auth_mode: "record".into(),
        evidence_trust: "rpc_reported".into(),
        state_dependent: true,
        writes_committed: false,
        wallet_requirements: vec![
            "Independently decode and compare every transaction field with the intended grant, network, fee payer and fee ceiling using the wallet's own RPC".into(),
            "Re-run the authority check, match listed authorities to the user's trusted identities, and obtain protected user approval of the authority commitment before constructing owner authorization".into(),
            "Recording mode does not run the account's authorization. Construct owner authorization in the wallet, re-simulate with enforcement using its own RPC, and revalidate the exact resulting XDR before requesting transaction signatures".into(),
            "For a separate restoration envelope, review and execute restoration first, then acquire a fresh intent and assemble again; no install envelope is supplied in that response".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_surface_live::tests::fixture;
    use crate::test_support::{build_config, registry_trust};

    fn prepared() -> (AssembleInstallTransactionInput, PrepareInstallIntentOutput) {
        let (input, scan) = fixture();
        let plan =
            crate::plan_install_intent_read(&input, &registry_trust(), &build_config()).unwrap();
        let intent = crate::prepare_install_intent_from_scan(&plan, "testnet", &scan).unwrap();
        (
            AssembleInstallTransactionInput {
                intent_request: input,
                fee_payer: format!("{}", stellar_strkey::ed25519::PublicKey([7; 32])),
                max_fee_stroops: 100_000,
                validity_ledgers: 20,
            },
            intent,
        )
    }

    #[test]
    fn exact_grant_encodes_context_expiry_signers_and_every_policy() {
        let (input, intent) = prepared();
        let request = install_assembly_request(&input, &intent).unwrap();
        assert_eq!(
            request.invocation.contract_address,
            address(&intent.account_contract, true).unwrap()
        );
        assert_eq!(
            request.invocation.function_name,
            "add_context_rule".try_into().unwrap()
        );
        let args = &request.invocation.args;
        assert_eq!(args.len(), 5);
        assert_eq!(
            args[0],
            vector(vec![
                symbol("CallContract").unwrap(),
                ScVal::Address(address(&intent.context_contract, true).unwrap())
            ])
            .unwrap()
        );
        assert_eq!(
            args[2],
            intent.valid_until_ledger.map_or(ScVal::Void, ScVal::U32)
        );
        let ScVal::Vec(Some(signers)) = &args[3] else {
            panic!("signers")
        };
        assert_eq!(signers.len(), intent.delegate_signers.len());
        let ScVal::Map(Some(policies)) = &args[4] else {
            panic!("policies")
        };
        assert_eq!(policies.len(), intent.policies.len());
        assert_eq!(policies.len(), 2, "fixture covers composition");
        assert!(policies.windows(2).all(|pair| pair[0].key < pair[1].key));
        for p in &intent.policies {
            let got = policies
                .iter()
                .find(|v| v.key == ScVal::Address(address(&p.address, true).unwrap()))
                .unwrap();
            match p.install_params {
                InstallPolicyParams::Generated => assert_eq!(got.val, ScVal::U32(0)),
                InstallPolicyParams::SpendingLimit {
                    ref spending_limit,
                    period_ledgers,
                } => {
                    let ScVal::Map(Some(params)) = &got.val else {
                        panic!("spending parameters")
                    };
                    assert_eq!(params.len(), 2);
                    assert_eq!(
                        params[0],
                        ScMapEntry {
                            key: symbol("period_ledgers").unwrap(),
                            val: ScVal::U32(period_ledgers)
                        }
                    );
                    let amount = spending_limit.parse::<i128>().unwrap();
                    assert_eq!(
                        params[1],
                        ScMapEntry {
                            key: symbol("spending_limit").unwrap(),
                            val: ScVal::I128(Int128Parts {
                                hi: (amount >> 64) as i64,
                                lo: amount as u64
                            })
                        }
                    );
                }
            }
        }
        assert_eq!(
            request.authority_observed_ledger,
            intent.authority.verdict.observed_ledger
        );
    }

    #[test]
    fn altered_intent_fields_cannot_change_the_committed_call() {
        for change in 0..8 {
            let (input, mut intent) = prepared();
            match change {
                0 => intent.context_contract = intent.account_contract.clone(),
                1 => intent.rule_name.push('!'),
                2 => intent.valid_until_ledger = None,
                3 => intent.delegate_signers.clear(),
                4 => intent.policies[0].policy_index += 1,
                5 => intent.policies[0].address = intent.account_contract.clone(),
                6 => {
                    intent.policies[0].install_params = InstallPolicyParams::SpendingLimit {
                        spending_limit: "1".into(),
                        period_ledgers: 1,
                    }
                }
                _ => intent.authority.verdict.network_id = "0".repeat(64),
            }
            assert!(
                install_assembly_request(&input, &intent).is_err(),
                "change {change}"
            );
        }
    }

    #[test]
    fn invalid_spending_limits_cannot_be_encoded() {
        for (limit, period) in [
            ("-1", 1),
            ("0", 1),
            ("01", 1),
            ("1", 0),
            ("99999999999999999999999999999999999999999", 1),
        ] {
            assert!(params(&InstallPolicyParams::SpendingLimit {
                spending_limit: limit.into(),
                period_ledgers: period
            })
            .is_err());
        }
    }

    #[test]
    fn duplicated_policy_address_is_refused_even_in_a_coherently_altered_intent() {
        let (input, mut intent) = prepared();
        let first = intent.policies[0].address.clone();
        intent.policies[1].address = first.clone();
        intent.authority.verdict.grant.policies[1].address = first;
        assert!(install_assembly_request(&input, &intent).is_err());
    }
}
