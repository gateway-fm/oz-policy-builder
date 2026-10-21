//! Recognition-scoped prediction for one installed rule. Candidate identities are not signatures.

use crate::{
    call_surface::{registry_for, validate_bindings},
    from_value, map_registry_err, spec_error, RegistryTrust,
};
use ozpb_api_types::*;
use ozpb_domain::{pinned_upstream, Hash32, LedgerSeq};
use ozpb_evaluator::spending_limit::{
    evaluate_spending_limit, SpendingEntry, SpendingLimitState, SpendingVerdict,
};
use ozpb_evaluator::{evaluate_generated_rule, ArgValue, EvalContext, Invocation, Verdict};
use ozpb_policy_spec::{
    DriftResponse, PolicyRef, PolicySpec, PredicateKind, ReviewedParams, SignerSpec, StateSpec,
    TargetHashRole, ValidatedSpec,
};
use ozpb_registry::{Registry, SignedSnapshot, VerifierKeyScheme};
use ozpb_source_rpc::{
    decode_account_storage, xdr_limits, AccountStorageEntry, CapturedPolicyEntry, ContextType,
    PolicyStateCapture, SignerIdentity,
};
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::{
    AccountId, ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData,
    LedgerKey, LedgerKeyAccount, LedgerKeyContractData, PublicKey, ReadXdr, ScAddress, ScVal,
    Uint256, Validate, WriteXdr,
};

pub struct PolicyCheckReadPlan {
    pub account_address: String,
    pub network_id: String,
    pub installed_context_rule_id: u32,
    pub contract_addresses: Vec<String>,
    pub additional_keys: Vec<LedgerKey>,
    input: CheckAgainstPolicyInput,
    spec: ValidatedSpec,
    registry: Registry,
    registry_root: Hash32,
    binding_hash: Hash32,
    invocation: Invocation,
}

/// Validate recognition before the shell performs any ledger read. Generated artifacts are
/// reproduced using the operator's configured runner, never a caller-selected compiler.
pub fn plan_policy_check_read(
    input: &CheckAgainstPolicyInput,
    trust: &RegistryTrust,
    build: &ozpb_build_runner::BuildConfig,
) -> Result<PolicyCheckReadPlan, ToolError> {
    let raw: PolicySpec = from_value(&input.spec)?;
    let spec = raw.validate().map_err(|errors| spec_error(&errors))?;
    if input.account_address != spec.spec().smart_account.address
        || input.network_id != spec.spec().network_id.0.to_hex()
    {
        return Err(error(
            ErrorCode::EPolicyBindingInvalid,
            "request account/network differs from spec",
        ));
    }
    let rule = spec
        .spec()
        .rules
        .get(input.rule_index)
        .ok_or_else(|| error(ErrorCode::ESpecInvalid, "rule_index is out of range"))?;
    if input.candidate_signers.len() > 15 {
        return Err(error(
            ErrorCode::EResourceLimit,
            "too many candidate signers",
        ));
    }
    let mut candidates = BTreeSet::new();
    for candidate in &input.candidate_signers {
        let key = candidate_identity(candidate)
            .map_err(|reason| error(ErrorCode::ESpecInvalid, reason))?;
        if !candidates.insert(key) {
            return Err(error(ErrorCode::ESpecInvalid, "duplicate candidate signer"));
        }
    }
    let invocation: Invocation = from_value(&input.invocation)?;
    address(&invocation.contract).map_err(|reason| error(ErrorCode::ESpecInvalid, reason))?;
    if invocation.fn_name.is_empty() || invocation.fn_name.len() > 32 || invocation.args.len() > 32
    {
        return Err(error(
            ErrorCode::ESpecInvalid,
            "unsupported invocation shape",
        ));
    }
    // The independent evaluator understands typed address/i128 arguments. Other values are
    // retained as canonical XDR; it does not guess what an unmodeled argument means.
    for arg in &invocation.args {
        match arg {
            ArgValue::Address(value) => {
                if !matches!(
                    stellar_strkey::Strkey::from_string(value),
                    Ok(stellar_strkey::Strkey::PublicKeyEd25519(_)
                        | stellar_strkey::Strkey::Contract(_))
                ) {
                    return Err(error(ErrorCode::ESpecInvalid, "invalid invocation address"));
                }
            }
            ArgValue::ScvalXdr(value) if value.len() > ozpb_source_rpc::MAX_XDR_BASE64_BYTES => {
                return Err(error(
                    ErrorCode::EResourceLimit,
                    "invocation XDR exceeds limit",
                ));
            }
            ArgValue::ScvalXdr(value) => {
                let decoded = ScVal::from_xdr_base64(value, xdr_limits())
                    .map_err(|_| error(ErrorCode::ESpecInvalid, "invalid invocation XDR"))?;
                decoded
                    .validate()
                    .map_err(|_| error(ErrorCode::ESpecInvalid, "invalid invocation ScVal"))?;
                if matches!(decoded, ScVal::Address(_) | ScVal::I128(_))
                    || encode(&decoded)? != *value
                {
                    return Err(error(
                        ErrorCode::ESpecInvalid,
                        "use typed address/i128 arguments and canonical XDR for other values",
                    ));
                }
            }
            _ => {}
        }
    }
    let signed: SignedSnapshot = from_value(&input.signed_registry_snapshot)?;
    let mut registry = registry_for(trust, spec.spec().network_id)?;
    let registry_root = registry.load(&signed).map_err(map_registry_err)?;
    if registry_root != spec.spec().registry_snapshot {
        return Err(error(
            ErrorCode::EPolicyBindingInvalid,
            "registry root differs from spec",
        ));
    }
    registry
        .resolve_account(&spec.spec().smart_account.observed_code_hash)
        .map_err(map_registry_err)?;
    if spec.spec().smart_account.observed_code_hash != pinned_upstream::OZ_SMART_ACCOUNT_WASM {
        return Err(error(
            ErrorCode::EUnsupportedPattern,
            "account storage/authentication model is unsupported",
        ));
    }
    let (binding_hash, _) = validate_bindings(&spec, &input.binding_set, &registry, build)?;
    let mut contract_addresses = BTreeSet::from([rule.context.contract.clone()]);
    let mut additional_keys = Vec::new();
    for (index, policy) in rule.policies.iter().enumerate() {
        let binding = input
            .binding_set
            .bindings
            .iter()
            .find(|binding| binding.rule_index == input.rule_index && binding.policy_index == index)
            .ok_or_else(|| {
                error(
                    ErrorCode::EPolicyBindingInvalid,
                    "missing selected policy binding",
                )
            })?;
        contract_addresses.insert(binding.contract_address.clone());
        let tags = match policy {
            PolicyRef::Generated { .. } => {
                if rule.state.is_empty() {
                    vec!["Installed"]
                } else {
                    vec!["Installed", "CallCount"]
                }
            }
            PolicyRef::Reviewed {
                kind, capability, ..
            } if kind == "oz:spending_limit"
                && *capability == pinned_upstream::OZ_SPENDING_LIMIT_POLICY_WASM =>
            {
                vec!["AccountContext"]
            }
            _ => {
                return Err(error(
                    ErrorCode::EUnsupportedPattern,
                    "recognized policy has no exact state model",
                ))
            }
        };
        for tag in tags {
            additional_keys.push(
                policy_key(
                    &binding.contract_address,
                    tag,
                    &input.account_address,
                    input.installed_context_rule_id,
                )
                .map_err(|reason| error(ErrorCode::ESpecInvalid, reason))?,
            );
        }
    }
    Ok(PolicyCheckReadPlan {
        account_address: input.account_address.clone(),
        network_id: input.network_id.clone(),
        installed_context_rule_id: input.installed_context_rule_id,
        contract_addresses: contract_addresses.into_iter().collect(),
        additional_keys,
        input: input.clone(),
        spec,
        registry,
        registry_root,
        binding_hash,
        invocation,
    })
}

/// Recognition failures have an honest unsupported result; malformed requests and operator
/// configuration/build failures keep their normal machine-readable error codes.
pub fn policy_check_unavailable(error: ToolError) -> Result<CheckAgainstPolicyOutput, ToolError> {
    match error.code {
        ErrorCode::EUnsupportedPattern
        | ErrorCode::EUnregisteredPolicy
        | ErrorCode::EUnregisteredVerifier
        | ErrorCode::EUnregisteredTemplate
        | ErrorCode::EIncompatibleAccount
        | ErrorCode::EPolicyBindingInvalid => Ok(CheckAgainstPolicyOutput::Unsupported {
            reason: error.message,
            evidence: None,
        }),
        _ => Err(error),
    }
}

pub fn finish_policy_check(
    plan: &PolicyCheckReadPlan,
    capture: &PolicyStateCapture,
) -> Result<CheckAgainstPolicyOutput, ToolError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| error(ErrorCode::EInternal, "trusted time is before Unix epoch"))?
        .as_secs();
    plan.registry
        .ensure_valid_at(
            now.try_into()
                .map_err(|_| error(ErrorCode::EInternal, "trusted time overflow"))?,
        )
        .map_err(map_registry_err)?;
    if capture.account_address != plan.account_address
        || capture.network_id.0.to_hex() != plan.network_id
        || capture.installed_context_rule_id != plan.installed_context_rule_id
        || capture.observed_ledger == 0
    {
        return Err(error(
            ErrorCode::EIncompleteAccountState,
            "capture identity differs from prepared request",
        ));
    }
    let mut evidence = evidence(plan, capture)?;
    let result = evaluate_observed(plan, capture, &mut evidence);
    Ok(match result {
        Ok(None) => CheckAgainstPolicyOutput::Permit { evidence },
        Ok(Some(deny_reason)) => CheckAgainstPolicyOutput::Deny {
            deny_reason,
            evidence,
        },
        Err(reason) => CheckAgainstPolicyOutput::Unsupported {
            reason: reason.into(),
            evidence: Some(Box::new(evidence)),
        },
    })
}

fn evaluate_observed(
    plan: &PolicyCheckReadPlan,
    capture: &PolicyStateCapture,
    evidence: &mut PolicyCheckEvidence,
) -> Result<Option<String>, &'static str> {
    if capture.entries.values().any(|entry| {
        entry.as_ref().is_some_and(|entry| {
            entry
                .live_until_ledger
                .is_some_and(|ttl| ttl < capture.observed_ledger)
        })
    }) {
        return Err("archived_state_requires_restoration");
    }
    if capture.entries.values().any(Option::is_none) {
        return Err("required_state_unavailable");
    }
    let account_hash = code_hash(capture, &plan.account_address)?;
    if account_hash != plan.spec.spec().smart_account.observed_code_hash {
        return Err("account_code_changed");
    }
    let rule_key = account_key(
        &plan.account_address,
        "ContextRuleData",
        plan.installed_context_rule_id,
    )?;
    let AccountStorageEntry::ContextRule(live) = account_record(capture, &rule_key)? else {
        return Err("invalid_rule_record");
    };
    let expected = &plan.spec.spec().rules[plan.input.rule_index];
    if live.context_type != ContextType::CallContract(expected.context.contract.clone())
        || live.name != plan.spec.spec().name
        || live.valid_until != expected.valid_until.as_ref().map(|until| until.ledger.0)
    {
        return Err("installed_rule_configuration_differs_from_spec");
    }
    let selected: Vec<_> = plan
        .input
        .binding_set
        .bindings
        .iter()
        .filter(|binding| binding.rule_index == plan.input.rule_index)
        .collect();
    let mut live_policies = BTreeSet::new();
    for id in &live.policy_ids {
        let key = account_key(&plan.account_address, "PolicyData", *id)?;
        let AccountStorageEntry::Policy(policy) = account_record(capture, &key)? else {
            return Err("invalid_policy_record");
        };
        if !live_policies.insert(policy.address) {
            return Err("duplicate_live_policy");
        }
    }
    if live_policies
        != selected
            .iter()
            .map(|binding| binding.contract_address.clone())
            .collect()
    {
        return Err("installed_policy_set_differs_from_bindings");
    }
    for binding in &selected {
        if code_hash(capture, &binding.contract_address)?.to_hex() != binding.observed_wasm_hash {
            return Err("policy_code_changed");
        }
    }
    let mut live_signers = Vec::new();
    for id in &live.signer_ids {
        let key = account_key(&plan.account_address, "SignerData", *id)?;
        let AccountStorageEntry::Signer(signer) = account_record(capture, &key)? else {
            return Err("invalid_signer_record");
        };
        live_signers.push(signer.signer);
    }
    if !candidates_belong_to_rule(&plan.input.candidate_signers, &live_signers) {
        return Ok(Some("unauthorized_signer".into()));
    }
    let mut resolved = Vec::new();
    for identity in &live_signers {
        resolved.push(resolve_signer(plan, capture, identity)?);
    }
    let mut live_set = BTreeSet::new();
    for signer in &resolved {
        if !live_set.insert(
            signer
                .to_stored_scval()
                .map_err(|_| "invalid_signer_identity")?,
        ) {
            return Err("duplicate_live_signer");
        }
    }
    if !matches!(
        expected.authorization.kind,
        PredicateKind::AnyOfCurrentRuleSigners
    ) && ozpb_policy_spec::signer_set_hash(&resolved).map_err(|_| "invalid_live_signers")?
        != ozpb_policy_spec::signer_set_hash(&expected.authorization.signers)
            .map_err(|_| "invalid_spec_signers")?
    {
        return Err("installed_signer_set_differs_from_spec");
    }
    // Code identity is intentionally not in the stored Signer value; check it separately.
    for signer in &expected.authorization.signers {
        if let SignerSpec::External {
            verifier,
            verifier_code_hash,
            ..
        } = signer
        {
            if code_hash(capture, verifier)? != *verifier_code_hash {
                return Err("verifier_code_changed");
            }
        }
    }
    let authenticated_signers = resolved
        .iter()
        .zip(&live_signers)
        .filter(|(_, signer)| {
            plan.input
                .candidate_signers
                .iter()
                .any(|candidate| identity_matches(candidate, signer))
        })
        .map(|(signer, _)| signer.clone())
        .collect();
    if let Some(target) = &expected.context.target_code_hash {
        let observed = code_hash(capture, &expected.context.contract)?;
        if observed != target.hash {
            let refusal = target.role == TargetHashRole::AdapterRequired
                || target.on_drift == DriftResponse::Refuse;
            evidence.target_drift = Some(PolicyTargetDrift {
                expected_hash: target.hash.to_hex(),
                observed_hash: observed.to_hex(),
                refusal_required: refusal,
            });
            if refusal {
                return Err("required_target_code_changed");
            }
        }
    }
    let mut call_count = None;
    for binding in &selected {
        if matches!(
            expected.policies[binding.policy_index],
            PolicyRef::Generated { .. }
        ) {
            let marker = policy_key(
                &binding.contract_address,
                "Installed",
                &plan.account_address,
                plan.installed_context_rule_id,
            )?;
            // The generated contract uses has(), not the Boolean payload, for this marker.
            let _ = value(capture, &marker)?;
            if expected
                .state
                .iter()
                .any(|state| matches!(state, StateSpec::CallCountPerInstallation { .. }))
            {
                let counter = policy_key(
                    &binding.contract_address,
                    "CallCount",
                    &plan.account_address,
                    plan.installed_context_rule_id,
                )?;
                let ScVal::U32(count) = value(capture, &counter)? else {
                    return Err("invalid_call_counter");
                };
                call_count = Some(*count);
            }
        }
    }
    let context = EvalContext {
        smart_account: plan.account_address.clone(),
        current_ledger: LedgerSeq(capture.observed_ledger),
        authenticated_signers,
        rule_live_signers: resolved,
        call_count_so_far: call_count,
    };
    // Fully recognized, usable state is required before any conclusive prediction.
    let mut spending = Vec::new();
    for binding in &selected {
        if let PolicyRef::Reviewed {
            params:
                ReviewedParams::SpendingLimit {
                    limit,
                    period_ledgers,
                },
            ..
        } = &expected.policies[binding.policy_index]
        {
            let key = policy_key(
                &binding.contract_address,
                "AccountContext",
                &plan.account_address,
                plan.installed_context_rule_id,
            )?;
            let state = spending_state(value(capture, &key)?)?;
            if state.spending_limit.to_string() != *limit || state.period_ledgers != *period_ledgers
            {
                return Err("installed_spending_configuration_differs_from_spec");
            }
            let amount = match plan.invocation.args.get(2) {
                Some(ArgValue::I128(n)) => *n,
                _ => 0,
            };
            let verdict = evaluate_spending_limit(&state, capture.observed_ledger, amount);
            if verdict == SpendingVerdict::Unsupported {
                return Err("invalid_spending_history");
            }
            spending.push(verdict);
        }
    }
    match evaluate_generated_rule(expected, &context, &plan.invocation) {
        Verdict::Deny(reason) => return Ok(Some(reason.to_string())),
        Verdict::Indeterminate(_) => return Err("generated_model_incomplete"),
        Verdict::Permit => {}
    }
    if !spending.is_empty()
        && (plan.invocation.fn_name != "transfer"
            || !matches!(plan.invocation.args.get(2), Some(ArgValue::I128(_)))
            || spending.contains(&SpendingVerdict::Deny))
    {
        return Ok(Some("spending_limit_denied".into()));
    }
    Ok(None)
}

// Authentication validates the full payload before policies receive their matched subset.
// For this one selected rule a stranger invalidates even an otherwise sufficient signer set.
fn candidates_belong_to_rule(candidates: &[PolicyCheckSigner], live: &[SignerIdentity]) -> bool {
    candidates.iter().all(|candidate| {
        live.iter()
            .any(|signer| identity_matches(candidate, signer))
    })
}

fn identity_matches(candidate: &PolicyCheckSigner, live: &SignerIdentity) -> bool {
    match (candidate, live) {
        (PolicyCheckSigner::Delegated { address }, SignerIdentity::Delegated(stored)) => {
            address == stored
        }
        (
            PolicyCheckSigner::External { verifier, key_hex },
            SignerIdentity::External {
                verifier: stored,
                key,
            },
        ) => verifier == stored && hex::decode(key_hex).is_ok_and(|bytes| &bytes == key),
        _ => false,
    }
}

fn resolve_signer(
    plan: &PolicyCheckReadPlan,
    capture: &PolicyStateCapture,
    identity: &SignerIdentity,
) -> Result<SignerSpec, &'static str> {
    match identity {
        SignerIdentity::Delegated(address) => {
            let key = address
                .parse::<stellar_strkey::ed25519::PublicKey>()
                .map_err(|_| "delegated_contract_signer_unsupported")?;
            let key = LedgerKey::Account(LedgerKeyAccount {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0))),
            });
            let LedgerEntryData::Account(account) = &entry(capture, &key)?.data else {
                return Err("invalid_classic_account");
            };
            if !account.signers.is_empty()
                || account.thresholds.0[0] == 0
                || account.thresholds.0[0] < account.thresholds.0[2]
            {
                return Err("classic_multisig_unsupported");
            }
            Ok(SignerSpec::Delegated {
                address: address.clone(),
            })
        }
        SignerIdentity::External { verifier, key } => {
            let hash = code_hash(capture, verifier)?;
            let scheme = plan
                .registry
                .resolve_signature_verifier(&hash)
                .map_err(|_| "verifier_model_unsupported")?;
            if !match scheme {
                VerifierKeyScheme::Ed25519 => key.len() == 32,
                VerifierKeyScheme::WebauthnP256 => key.len() >= 65 && key.first() == Some(&4),
            } {
                return Err("invalid_external_signer_key");
            }
            Ok(SignerSpec::External {
                verifier: verifier.clone(),
                verifier_code_hash: hash,
                key_hex: hex::encode(key),
            })
        }
    }
}

fn evidence(
    plan: &PolicyCheckReadPlan,
    capture: &PolicyStateCapture,
) -> Result<PolicyCheckEvidence, ToolError> {
    let mut storage_reads = Vec::new();
    let mut configuration_reads = Vec::new();
    let mut classic_account_reads = Vec::new();
    let mut code_addresses = BTreeMap::<Hash, Vec<String>>::new();
    for entry in capture.entries.values().flatten() {
        if let LedgerEntryData::ContractData(data) = &entry.data {
            if let ScVal::ContractInstance(instance) = &data.val {
                if let (ScAddress::Contract(id), ContractExecutable::Wasm(hash)) =
                    (&data.contract, &instance.executable)
                {
                    code_addresses
                        .entry(hash.clone())
                        .or_default()
                        .push(format!("{}", stellar_strkey::Contract(id.0 .0)));
                }
            }
        }
    }
    let mut restoration = PolicyStateRestoration::NotRequired;
    for (key, observed) in &capture.entries {
        let key_xdr_base64 = encode(key)?;
        if let LedgerKey::Account(account) = key {
            let AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(id))) = account.account_id;
            classic_account_reads.push(PolicyClassicAccountRead {
                account_address: format!("{}", stellar_strkey::ed25519::PublicKey(id)),
                key_xdr_base64,
                value_xdr_base64: observed
                    .as_ref()
                    .map(|entry| encode(&entry.data))
                    .transpose()?,
                last_modified_ledger: observed.as_ref().map(|entry| entry.last_modified_ledger),
            });
            continue;
        }
        let observation = match observed {
            None => {
                if !matches!(restoration, PolicyStateRestoration::Required) {
                    restoration = PolicyStateRestoration::Unknown;
                }
                PolicyStateObservation::Absent
            }
            Some(entry) => {
                let ttl = entry.live_until_ledger.ok_or_else(|| {
                    error(
                        ErrorCode::EIncompleteAccountState,
                        "Soroban observation lacks TTL",
                    )
                })?;
                if ttl < capture.observed_ledger {
                    restoration = PolicyStateRestoration::Required;
                }
                PolicyStateObservation::Present {
                    value_xdr_base64: encode(&entry.data)?,
                    last_modified_ledger: entry.last_modified_ledger,
                    live_until_ledger: ttl,
                }
            }
        };
        let addresses = match key {
            LedgerKey::ContractData(data) => match &data.contract {
                ScAddress::Contract(id) => vec![format!("{}", stellar_strkey::Contract(id.0 .0))],
                _ => {
                    return Err(error(
                        ErrorCode::EIncompleteAccountState,
                        "non-contract storage key",
                    ))
                }
            },
            LedgerKey::ContractCode(code) => {
                let mut addresses = code_addresses.get(&code.hash).cloned().ok_or_else(|| {
                    error(ErrorCode::EIncompleteAccountState, "unreferenced code key")
                })?;
                // The instances retain every code reference; include the potentially large
                // shared code witness once, attributed to the first canonical address.
                addresses.sort();
                addresses.truncate(1);
                addresses
            }
            _ => {
                return Err(error(
                    ErrorCode::EIncompleteAccountState,
                    "unexpected captured key",
                ))
            }
        };
        for contract_address in addresses {
            let read = PolicyStateRead {
                contract_address,
                key_xdr_base64: key_xdr_base64.clone(),
                observation: observation.clone(),
            };
            if plan.additional_keys.contains(key) {
                if matches!(key,LedgerKey::ContractData(data) if matches!(&data.key,
                    ScVal::Vec(Some(parts)) if matches!(parts.first(),Some(ScVal::Symbol(tag)) if tag.as_slice()==b"AccountContext" || tag.as_slice()==b"Installed")))
                {
                    configuration_reads.push(read.clone());
                }
                storage_reads.push(read);
            } else {
                configuration_reads.push(read);
            }
        }
    }
    Ok(PolicyCheckEvidence {
        evidence_trust: PolicyCheckTrust::RpcReported,
        authentication_assumption: PolicyAuthenticationAssumption::CandidateSignersMustAuthenticate,
        account_address: plan.account_address.clone(),
        network_id: plan.network_id.clone(),
        rule_index: plan.input.rule_index,
        installed_context_rule_id: plan.installed_context_rule_id,
        spec_hash: plan.spec.hash().to_hex(),
        binding_set_hash: plan.binding_hash.to_hex(),
        registry_snapshot_root: plan.registry_root.to_hex(),
        request_hash: plan
            .input
            .request_hash()
            .map_err(|_| error(ErrorCode::EInternal, "request hash"))?
            .to_hex(),
        observed_ledger: capture.observed_ledger,
        ledger_hash: capture.ledger_hash.to_hex(),
        storage_reads,
        configuration_reads,
        classic_account_reads,
        target_drift: None,
        restoration,
        recheck_before_signing: RecheckBeforeSigning::Required,
    })
}

fn spending_state(value: &ScVal) -> Result<SpendingLimitState, &'static str> {
    let fields = map(value, 4)?;
    let spending_limit = i128_value(field(fields, b"spending_limit")?)?;
    let period_ledgers = u32_value(field(fields, b"period_ledgers")?)?;
    let cached_total_spent = i128_value(field(fields, b"cached_total_spent")?)?;
    let ScVal::Vec(Some(history)) = field(fields, b"spending_history")? else {
        return Err("invalid_spending_history");
    };
    if history.len() > 1000 {
        return Err("spending_history_limit");
    }
    let mut spending_history = Vec::new();
    for entry in history.iter() {
        let fields = map(entry, 2)?;
        spending_history.push(SpendingEntry {
            amount: i128_value(field(fields, b"amount")?)?,
            ledger_sequence: u32_value(field(fields, b"ledger_sequence")?)?,
        });
    }
    Ok(SpendingLimitState {
        spending_limit,
        period_ledgers,
        spending_history,
        cached_total_spent,
    })
}
fn map(value: &ScVal, len: usize) -> Result<&stellar_xdr::ScMap, &'static str> {
    match value {
        ScVal::Map(Some(map)) if map.len() == len => Ok(map),
        _ => Err("invalid_spending_state"),
    }
}
fn field<'a>(map: &'a stellar_xdr::ScMap, name: &[u8]) -> Result<&'a ScVal, &'static str> {
    map.iter()
        .find_map(|entry| match &entry.key {
            ScVal::Symbol(tag) if tag.as_slice() == name => Some(&entry.val),
            _ => None,
        })
        .ok_or("invalid_spending_field")
}
fn i128_value(value: &ScVal) -> Result<i128, &'static str> {
    match value {
        ScVal::I128(parts) => Ok(((parts.hi as i128) << 64) | parts.lo as i128),
        _ => Err("invalid_i128_state"),
    }
}
fn u32_value(value: &ScVal) -> Result<u32, &'static str> {
    match value {
        ScVal::U32(value) => Ok(*value),
        _ => Err("invalid_u32_state"),
    }
}
fn address(text: &str) -> Result<ScAddress, &'static str> {
    let value = text
        .parse::<stellar_strkey::Contract>()
        .map_err(|_| "invalid_contract_address")?;
    if value.to_string() != text {
        return Err("noncanonical_contract_address");
    }
    Ok(ScAddress::Contract(ContractId(Hash(value.0))))
}
fn data_key(contract: &str, key: ScVal) -> Result<LedgerKey, &'static str> {
    Ok(LedgerKey::ContractData(LedgerKeyContractData {
        contract: address(contract)?,
        key,
        durability: ContractDataDurability::Persistent,
    }))
}
fn tagged(tag: &str, args: Vec<ScVal>) -> Result<ScVal, &'static str> {
    let mut parts = vec![ScVal::Symbol(tag.try_into().map_err(|_| "storage_tag")?)];
    parts.extend(args);
    Ok(ScVal::Vec(Some(
        parts.try_into().map_err(|_| "storage_key")?,
    )))
}
fn policy_key(
    contract: &str,
    tag: &str,
    account: &str,
    id: u32,
) -> Result<LedgerKey, &'static str> {
    data_key(
        contract,
        tagged(tag, vec![ScVal::Address(address(account)?), ScVal::U32(id)])?,
    )
}
fn account_key(account: &str, tag: &str, id: u32) -> Result<LedgerKey, &'static str> {
    data_key(account, tagged(tag, vec![ScVal::U32(id)])?)
}
fn entry<'a>(
    capture: &'a PolicyStateCapture,
    key: &LedgerKey,
) -> Result<&'a CapturedPolicyEntry, &'static str> {
    capture
        .entries
        .get(key)
        .and_then(Option::as_ref)
        .ok_or("required_state_unavailable")
}
fn value<'a>(capture: &'a PolicyStateCapture, key: &LedgerKey) -> Result<&'a ScVal, &'static str> {
    match &entry(capture, key)?.data {
        LedgerEntryData::ContractData(data) => Ok(&data.val),
        _ => Err("invalid_contract_data"),
    }
}
fn code_hash(capture: &PolicyStateCapture, contract: &str) -> Result<Hash32, &'static str> {
    match value(
        capture,
        &data_key(contract, ScVal::LedgerKeyContractInstance)?,
    )? {
        ScVal::ContractInstance(instance) => match &instance.executable {
            ContractExecutable::Wasm(hash) => Ok(Hash32(hash.0)),
            _ => Err("native_executable_unsupported"),
        },
        _ => Err("invalid_instance"),
    }
}
fn account_record(
    capture: &PolicyStateCapture,
    key: &LedgerKey,
) -> Result<AccountStorageEntry, &'static str> {
    let LedgerKey::ContractData(data) = key else {
        return Err("account_key");
    };
    decode_account_storage(data, value(capture, key)?).map_err(|_| "invalid_account_storage")
}
fn candidate_identity(candidate: &PolicyCheckSigner) -> Result<(String, Vec<u8>), &'static str> {
    match candidate {
        PolicyCheckSigner::Delegated { address } => {
            if !matches!(
                stellar_strkey::Strkey::from_string(address),
                Ok(stellar_strkey::Strkey::PublicKeyEd25519(_)
                    | stellar_strkey::Strkey::Contract(_))
            ) {
                return Err("invalid_candidate_address");
            }
            Ok((format!("delegated:{address}"), vec![]))
        }
        PolicyCheckSigner::External { verifier, key_hex } => {
            address(verifier)?;
            let key = hex::decode(key_hex).map_err(|_| "invalid_candidate_key")?;
            if key.len() > 256 {
                return Err("candidate_key_too_large");
            }
            Ok((format!("external:{verifier}"), key))
        }
    }
}
fn encode<T: WriteXdr>(value: &T) -> Result<String, ToolError> {
    value
        .to_xdr_base64(xdr_limits())
        .map_err(|_| error(ErrorCode::EInternal, "evidence XDR"))
}
fn error(code: ErrorCode, reason: &str) -> ToolError {
    ToolError::new(code, reason)
}

#[cfg(test)]
mod tests;
