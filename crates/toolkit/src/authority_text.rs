//! The authority answer in plain words, for a person deciding whether to sign.
//!
//! The structured output is the contract; this is its reading. It states the scope, says
//! "refused" or "not answered" before anything else when either applies, lists who can change
//! the account or reset the policies with exactly who must sign, and ends with what was not
//! checked. It never says the account is safe: that is for the wallet holding the owner key.

use ozpb_api_types::{
    CheckPolicyCallSurfaceOutput, InstallPolicyParams, PolicyIdentity, PolicyReach,
    PolicyRequirement, PolicyRuleContext, PolicySignerKey, PolicySurfaceFinding,
};
use std::fmt::Write;

/// Render the answer for a person. Deterministic: the same output renders the same text.
pub fn render_authority_text(output: &CheckPolicyCallSurfaceOutput) -> String {
    let verdict = &output.verdict;
    let mut text = String::new();
    let line = |text: &mut String, value: String| {
        let _ = writeln!(text, "{value}");
    };

    line(
        &mut text,
        format!(
            "Account {} — read at ledger {} (as the RPC endpoint reported it).",
            verdict.account_address, verdict.observed_ledger
        ),
    );
    line(
        &mut text,
        "Advisory: only the wallet that holds the owner key can decide. It must re-read this \
         itself and confirm every rule below."
            .to_string(),
    );
    line(
        &mut text,
        format!(
            "Covers: the account's own management, the policies being installed ({}), and calls \
             to {}. Rules for other contracts are not analysed.",
            verdict.scope.bound_policies.join(", "),
            verdict.scope.targets.join(", ")
        ),
    );
    let _ = writeln!(text);

    let grant = &verdict.grant;
    let signers: Vec<String> = grant.signers.iter().map(signer_key).collect();
    let until = match grant.valid_until {
        Some(ledger) => format!("until ledger {ledger}"),
        None => "with no expiry".to_string(),
    };
    let policies: Vec<String> = grant.policies.iter().map(grant_policy).collect();
    let limited_by = if policies.is_empty() {
        "no policy at all".to_string()
    } else {
        policies.join(" and ")
    };
    line(
        &mut text,
        format!(
            "The new rule (spec rule {}, \"{}\") lets {} call {} {until}, limited by {}{}.",
            grant.rule_index,
            grant.name,
            signers.join(" and "),
            grant.target,
            limited_by,
            if grant.stateful {
                " (it keeps its own counters)"
            } else {
                ""
            }
        ),
    );
    let _ = writeln!(text);

    if !verdict.refusals.is_empty() {
        line(
            &mut text,
            "REFUSED — do not install. Nobody's approval overrides these:".to_string(),
        );
        for finding in &verdict.refusals {
            line(&mut text, finding_line(finding));
        }
        let _ = writeln!(text);
    }
    if !verdict.unresolved.is_empty() {
        line(
            &mut text,
            "NOT ANSWERED — evidence is missing; re-read before deciding:".to_string(),
        );
        for finding in &verdict.unresolved {
            line(&mut text, finding_line(finding));
        }
        let _ = writeln!(text);
    }

    line(
        &mut text,
        format!(
            "Who can remove or change this limit at ledger {} (the wallet must recognise at \
             least one required identity on every line as its own or as trusted):",
            verdict.observed_ledger
        ),
    );
    if verdict.authority_list.is_empty() {
        line(
            &mut text,
            "  • no live rule on these surfaces (nobody could even install this rule)".to_string(),
        );
    }
    for entry in &verdict.authority_list {
        line(
            &mut text,
            format!(
                "  • Rule {} ({}): {}",
                entry.rule_id,
                reach(&entry.reach),
                requirement(&entry.requirement)
            ),
        );
    }

    if !verdict.notes.target_rules.is_empty() {
        let _ = writeln!(text);
        line(
            &mut text,
            format!(
                "Who else can call {} (their own access, shown for information):",
                grant.target
            ),
        );
        for entry in &verdict.notes.target_rules {
            line(
                &mut text,
                format!(
                    "  • Rule {}: {}",
                    entry.rule_id,
                    requirement(&entry.requirement)
                ),
            );
        }
    }
    if !verdict.notes.restricted_key_rules.is_empty() {
        let _ = writeln!(text);
        line(&mut text, "The agent's key already appears on:".to_string());
        for rule in &verdict.notes.restricted_key_rules {
            line(
                &mut text,
                format!(
                    "  • Rule {} ({}){}",
                    rule.rule_id,
                    context(&rule.context),
                    if rule.usable_alone {
                        ", usable by the agent alone"
                    } else {
                        ", only with other signers"
                    }
                ),
            );
        }
    }
    if !verdict.notes.expired_rules.is_empty() {
        let _ = writeln!(text);
        let expired: Vec<String> = verdict
            .notes
            .expired_rules
            .iter()
            .map(|rule| {
                format!(
                    "rule {} ({}, expired after ledger {})",
                    rule.rule_id,
                    context(&rule.context),
                    rule.valid_until
                )
            })
            .collect();
        line(
            &mut text,
            format!(
                "Expired (reviving one needs a rule above): {}.",
                expired.join("; ")
            ),
        );
    }
    if !verdict.coverage_exclusions.is_empty() {
        let ids: Vec<String> = verdict
            .coverage_exclusions
            .iter()
            .map(|rule| rule.rule_id.to_string())
            .collect();
        line(
            &mut text,
            format!(
                "Not analysed (rules for other contracts): {}.",
                ids.join(", ")
            ),
        );
    }
    let _ = writeln!(text);
    line(
        &mut text,
        format!(
            "Commitment {} — approval binds to it; re-read immediately before signing, and \
             ask again if it changed.",
            verdict.authority_commitment
        ),
    );
    line(
        &mut text,
        "Not checked: whether the RPC endpoint answered honestly; anything outside the scope \
         above."
            .to_string(),
    );
    text
}

fn finding_line(finding: &PolicySurfaceFinding) -> String {
    let rule = match finding.rule_id {
        Some(id) => format!("rule {id}"),
        None => "the new rule".to_string(),
    };
    format!(
        "  • {} ({rule}): {} Fix: {}",
        finding.code.as_str(),
        sentence(&finding.reason),
        sentence(&finding.remediation)
    )
}

/// A finding's text with a capital and a full stop, so lines read as sentences.
fn sentence(value: &str) -> String {
    let mut chars = value.chars();
    let mut out = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
        None => String::new(),
    };
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

fn reach(reach: &PolicyReach) -> String {
    match reach {
        PolicyReach::AnyCall => "any call the account makes".to_string(),
        PolicyReach::AccountCalls => "the account's own management".to_string(),
        PolicyReach::Policy { address } => format!("direct calls to policy {address}"),
        PolicyReach::Target { address } => format!("calls to {address}"),
    }
}

fn context(context: &PolicyRuleContext) -> String {
    match context {
        PolicyRuleContext::Default => "any call".to_string(),
        PolicyRuleContext::CallContract { address } => format!("calls to {address}"),
        PolicyRuleContext::CreateContract { wasm_hash } => {
            format!("deploying code {wasm_hash}")
        }
    }
}

fn requirement(requirement: &PolicyRequirement) -> String {
    match requirement {
        PolicyRequirement::AllOf { signers } => {
            let names: Vec<String> = signers.iter().map(identity).collect();
            format!("needs ALL of {}", names.join(", "))
        }
        PolicyRequirement::AnyOf { signers, policies } => {
            let names: Vec<String> = signers.iter().map(identity).collect();
            format!(
                "needs ANY ONE of {}, within policies {}",
                names.join(", "),
                policies.join(", ")
            )
        }
    }
}

fn identity(identity: &PolicyIdentity) -> String {
    match identity {
        PolicyIdentity::ClassicAccount {
            address,
            aliases_restricted_key,
            ..
        } => {
            let mut name = format!("classic account {address} (its master key alone)");
            if *aliases_restricted_key {
                name.push_str(" [the agent's own key — never an owner]");
            }
            name
        }
        PolicyIdentity::External {
            verifier,
            scheme,
            public_key,
            aliases_restricted_key,
            ..
        } => {
            let kind = match scheme {
                ozpb_api_types::PolicyKeyScheme::Ed25519 => "ed25519 key",
                ozpb_api_types::PolicyKeyScheme::WebauthnP256 => "passkey (P-256)",
            };
            let mut name = format!("{kind} {public_key} (checked by {verifier})");
            if *aliases_restricted_key {
                name.push_str(" [the agent's own key — never an owner]");
            }
            name
        }
    }
}

fn signer_key(key: &PolicySignerKey) -> String {
    match key {
        PolicySignerKey::Delegated { address } => address.clone(),
        PolicySignerKey::External { verifier, key_hex } => {
            format!("key {key_hex} checked by verifier {verifier}")
        }
    }
}

fn grant_policy(policy: &ozpb_api_types::PolicyGrantPolicy) -> String {
    match &policy.install_params {
        InstallPolicyParams::Generated => format!("the generated policy {}", policy.address),
        InstallPolicyParams::SpendingLimit {
            spending_limit,
            period_ledgers,
        } => format!(
            "the spending limit {} ({spending_limit} per {period_ledgers} ledgers)",
            policy.address
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused answer with every list populated, built from the wire JSON a client sees.
    fn output(refused: bool) -> CheckPolicyCallSurfaceOutput {
        let refusals = if refused {
            serde_json::json!([{
                "code": "E_DELEGATE_HAS_AUTHORITY",
                "rule_id": 2,
                "reason": "rule 2 lets the agent's key act on the account alone",
                "remediation": "remove the agent's key from rule 2"
            }])
        } else {
            serde_json::json!([])
        };
        serde_json::from_value(serde_json::json!({
            "spec_hash": "spec",
            "binding_set_hash": "bindings",
            "registry_snapshot_root": "root",
            "summary": "",
            "verdict": {
                "observed_ledger": 123456,
                "network_id": "network",
                "account_address": "CACCOUNT",
                "account_code_hash": "code",
                "spec_hash": "spec",
                "binding_set_hash": "bindings",
                "bound_policy_addresses": ["CPOLICY"],
                "grant": {
                    "rule_index": 0,
                    "target": "CUSDC",
                    "stateful": true,
                    "signers": [{"kind": "delegated", "address": "GAGENT"}],
                    "name": "transfer-cap",
                    "valid_until": 140000,
                    "policies": [{"address": "CPOLICY", "install_params": {"kind": "generated"}}]
                },
                "scope": {"targets": ["CUSDC"], "account": "CACCOUNT", "bound_policies": ["CPOLICY"]},
                "authority_list": [{
                    "rule_id": 0,
                    "reach": {"kind": "any_call"},
                    "valid_until": null,
                    "requirement": {"kind": "all_of", "signers": [{
                        "kind": "external",
                        "verifier": "CVERIFIER",
                        "verifier_code_hash": "vcode",
                        "scheme": "webauthn_p256",
                        "public_key": "04aabbccddeeff0011",
                        "aliases_restricted_key": false
                    }]}
                }, {
                    "rule_id": 2,
                    "reach": {"kind": "account_calls"},
                    "valid_until": 900,
                    "requirement": {"kind": "all_of", "signers": [{
                        "kind": "classic_account",
                        "address": "GAGENT",
                        "ed25519_public_key": "aa",
                        "aliases_restricted_key": true
                    }]}
                }],
                "refusals": refusals,
                "unresolved": [],
                "coverage_exclusions": [{"rule_id": 3, "context": {"call_contract": {"address": "COTHER"}}, "policy_addresses": []}],
                "notes": {
                    "restricted_key_rules": [{"rule_id": 3, "context": {"call_contract": {"address": "COTHER"}}, "valid_until": null, "usable_alone": true, "policy_addresses": []}],
                    "target_rules": [],
                    "expired_rules": [{"rule_id": 5, "context": "default", "valid_until": 100}]
                },
                "authority_state": {"ordered_state_digest": "state", "classic_accounts": {}, "verifiers": {}},
                "evidence": {
                    "enumeration_evidence": {"method": "bounded_next_id", "next_id": 6, "active_count": 4, "rule_ids": [0, 2, 3, 5], "signer_ids": [0], "policy_ids": []},
                    "source": "testnet",
                    "evidence_trust": "rpc_reported",
                    "raw_ordered_entry_digest": "raw",
                    "rpc_batches": 5,
                    "attempts": 1
                },
                "authority_commitment": "commitment"
            }
        }))
        .unwrap()
    }

    #[test]
    fn the_reading_names_the_scope_the_owners_and_what_was_not_checked() {
        let text = render_authority_text(&output(false));
        for expected in [
            "Account CACCOUNT — read at ledger 123456",
            "Advisory",
            "Covers: the account's own management, the policies being installed (CPOLICY), and \
             calls to CUSDC",
            "lets GAGENT call CUSDC until ledger 140000",
            "Rule 0 (any call the account makes): needs ALL of passkey (P-256) 04aabbccddeeff0011",
            "Rule 2 (the account's own management): needs ALL of classic account GAGENT",
            "[the agent's own key — never an owner]",
            "usable by the agent alone",
            "Expired (reviving one needs a rule above): rule 5",
            "Not analysed (rules for other contracts): 3.",
            "Commitment commitment",
            "Not checked:",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("REFUSED"));
    }

    #[test]
    fn a_refusal_comes_first_and_nothing_says_safe() {
        for refused in [false, true] {
            let text = render_authority_text(&output(refused));
            assert!(
                !text.to_lowercase().contains("safe"),
                "the reading must never call anything safe:\n{text}"
            );
            if refused {
                let refusal = text.find("REFUSED").unwrap();
                let owners = text.find("Who can remove").unwrap();
                assert!(refusal < owners, "{text}");
                assert!(text.contains("E_DELEGATE_HAS_AUTHORITY (rule 2)"));
            }
        }
    }
}
