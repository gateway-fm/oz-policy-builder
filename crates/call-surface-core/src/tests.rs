use super::*;

const LEDGER: u32 = 4_000_000;

fn contract(byte: u8) -> String {
    format!("{}", stellar_strkey::Contract([byte; 32]))
}
fn classic(byte: u8) -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey([byte; 32]))
}
fn account() -> String {
    contract(1)
}
fn bound_policy() -> String {
    contract(2)
}
fn target() -> String {
    contract(3)
}
fn other_contract() -> String {
    contract(4)
}
/// A deployed policy recognized as demanding at least one of its rule's signers (the shape
/// of OZ's spending limit).
fn readable_policy() -> String {
    contract(5)
}
/// A policy nobody recognized.
fn unknown_policy() -> String {
    contract(9)
}
/// The agent's key: the new grant's only signer.
const AGENT: u8 = 0xA0;
const OWNER: u8 = 0x10;
const OWNER_2: u8 = 0x11;
const STRANGER: u8 = 0x5E;

fn delegated(byte: u8) -> StoredSignerKey {
    StoredSignerKey::Delegated {
        address: classic(byte),
    }
}
fn external(verifier: u8, key: Vec<u8>) -> StoredSignerKey {
    StoredSignerKey::External {
        verifier: contract(verifier),
        key_hex: hex::encode(key),
    }
}

/// Builds account states rule by rule; signer and policy ids are allocated as they appear.
struct StateBuilder {
    state: AccountState,
}

impl StateBuilder {
    fn new() -> Self {
        StateBuilder {
            state: AccountState {
                next_id: 0,
                active_count: 0,
                rules: BTreeMap::new(),
                signers: BTreeMap::new(),
                policies: BTreeMap::new(),
            },
        }
    }

    fn rule(
        mut self,
        context_type: StoredContextType,
        valid_until: Option<u32>,
        signers: Vec<StoredSignerKey>,
        policies: Vec<String>,
    ) -> Self {
        let id = self.state.next_id;
        let signer_ids = signers
            .into_iter()
            .map(|key| {
                let sid = self.state.signers.len() as u32;
                self.state
                    .signers
                    .insert(sid, StoredSigner { id: sid, key });
                sid
            })
            .collect();
        let policy_ids = policies
            .into_iter()
            .map(|address| {
                let pid = self.state.policies.len() as u32;
                let observed_wasm_hash = if address == bound_policy() {
                    "bb".repeat(32)
                } else if address == readable_policy() {
                    "55".repeat(32)
                } else {
                    "99".repeat(32)
                };
                self.state.policies.insert(
                    pid,
                    StoredPolicy {
                        id: pid,
                        address,
                        observed_wasm_hash,
                    },
                );
                pid
            })
            .collect();
        self.state.rules.insert(
            id,
            StoredRule {
                id,
                context_type,
                valid_until,
                signer_ids,
                policy_ids,
            },
        );
        self.state.next_id += 1;
        self.state.active_count += 1;
        self
    }

    fn owner_rule(self, signers: Vec<StoredSignerKey>) -> Self {
        self.rule(StoredContextType::Default, None, signers, vec![])
    }

    fn build(self) -> AccountState {
        self.state
    }
}

fn call(address: String) -> StoredContextType {
    StoredContextType::CallContract { address }
}

/// One owner on one `Default` rule; nothing else.
fn owned() -> AccountState {
    StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .build()
}

fn master_key_only() -> ClassicAccount {
    ClassicAccount::Found {
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 0,
        high_threshold: 0,
        signers: vec![],
    }
}

fn input(state: &AccountState) -> CheckInput<'_> {
    CheckInput {
        network_id: "ab".repeat(32),
        spec_hash: ozpb_domain::Hash32([0x5c; 32]),
        account_state: state,
        account_address: account(),
        account_code_hash: "recognized-account-hash".to_string(),
        binding_set_hash: ozpb_domain::canonical_hash(
            domains::POLICY_BINDING_SET,
            &"test-bindings",
        )
        .expect("the fixture binding-set hash must encode"),
        account_recognized: true,
        bound_policies: vec![BoundPolicy {
            address: bound_policy(),
            observed_wasm_hash: "bb".repeat(32),
        }],
        recognized_policies: BTreeMap::from([
            (
                bound_policy(),
                VerifiedPolicy {
                    wasm_hash: "bb".repeat(32),
                    path: PolicyRecognitionPath::VerifiedGeneratedManifest,
                    signers: PolicySignerSemantics::Unknown,
                },
            ),
            (
                readable_policy(),
                VerifiedPolicy {
                    wasm_hash: "55".repeat(32),
                    path: PolicyRecognitionPath::ReviewedRegistry,
                    signers: PolicySignerSemantics::AtLeastOneRuleSigner,
                },
            ),
        ]),
        classic_accounts: BTreeMap::from([
            (classic(OWNER), master_key_only()),
            (classic(OWNER_2), master_key_only()),
            (classic(STRANGER), master_key_only()),
            (classic(AGENT), master_key_only()),
        ]),
        grant: Grant {
            rule_index: 0,
            target: target(),
            stateful: true,
            signers: vec![delegated(AGENT)],
            name: "transfer-cap".to_string(),
            valid_until: Some(LEDGER + 1_000),
            policies: vec![GrantPolicy {
                address: bound_policy(),
                install_params: GrantPolicyParams::Generated,
            }],
        },
        current_ledger: LEDGER,
        enumeration: Enumeration::BoundedNextId,
    }
}

fn owner(byte: u8, aliases_restricted_key: bool) -> Identity {
    Identity::ClassicAccount {
        address: classic(byte),
        ed25519_public_key: hex::encode([byte; 32]),
        aliases_restricted_key,
    }
}

fn all_of(signers: Vec<Identity>) -> Requirement {
    Requirement::AllOf { signers }
}

/// Nothing blocks: the answer is the list alone, for the wallet to match.
fn assert_open(verdict: &SurfaceVerdict) {
    assert!(
        verdict.refusals.is_empty() && verdict.unresolved.is_empty(),
        "refusals {:?}, unresolved {:?}",
        verdict.refusals,
        verdict.unresolved
    );
}

fn only_refusal(verdict: &SurfaceVerdict) -> &Finding {
    assert!(verdict.unresolved.is_empty(), "{:?}", verdict.unresolved);
    let [finding] = verdict.refusals.as_slice() else {
        panic!("expected one refusal, got {:?}", verdict.refusals)
    };
    finding
}

fn has_refusal(verdict: &SurfaceVerdict, code: FindingCode) -> bool {
    verdict.refusals.iter().any(|finding| finding.code == code)
}

/// A shape this version refuses by name.
fn only_unsupported(verdict: &SurfaceVerdict) -> &Finding {
    let finding = only_refusal(verdict);
    assert_eq!(finding.code, FindingCode::UnsupportedAuthority);
    finding
}

/// Missing evidence inside the scope.
fn only_unresolved(verdict: &SurfaceVerdict) -> &Finding {
    assert!(verdict.refusals.is_empty(), "{:?}", verdict.refusals);
    let [finding] = verdict.unresolved.as_slice() else {
        panic!("expected one unresolved item, got {:?}", verdict.unresolved)
    };
    assert_eq!(finding.code, FindingCode::IncompleteAccountState);
    finding
}

// --- Ivan's six cases --------------------------------------------------------------------

#[test]
fn case_1_several_owners_on_one_rule_must_all_sign() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER), delegated(OWNER_2)])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    assert_eq!(
        verdict.authority_list,
        vec![AuthorityEntry {
            rule_id: 0,
            reach: Reach::AnyCall,
            valid_until: None,
            requirement: all_of(vec![owner(OWNER, false), owner(OWNER_2, false)]),
        }]
    );
    assert!(verdict.notes.restricted_key_rules.is_empty());
}

#[test]
fn case_2_threshold_owner_rule_is_refused_by_name() {
    let st = StateBuilder::new()
        .rule(
            StoredContextType::Default,
            None,
            vec![delegated(OWNER), delegated(OWNER_2)],
            vec![unknown_policy()],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    let finding = only_unsupported(&verdict);
    assert_eq!(finding.unsupported, Some(UnsupportedReason::PolicyGuarded));
    assert_eq!(finding.rule_id, Some(0));
    assert!(verdict.authority_list.is_empty());
}

#[test]
fn case_3_one_rule_per_owner_lists_every_rule() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(account()), None, vec![delegated(OWNER_2)], vec![])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    let reaches: Vec<(u32, Reach)> = verdict
        .authority_list
        .iter()
        .map(|entry| (entry.rule_id, entry.reach.clone()))
        .collect();
    assert_eq!(reaches, vec![(0, Reach::AnyCall), (1, Reach::AccountCalls)]);
    assert_eq!(
        verdict.authority_list[1].requirement,
        all_of(vec![owner(OWNER_2, false)])
    );
}

#[test]
fn case_4_plain_recovery_is_listed_and_any_policy_on_it_is_refused() {
    let plain = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .owner_rule(vec![delegated(OWNER_2)])
        .build();
    let verdict = check(&input(&plain)).unwrap();
    assert_open(&verdict);
    assert_eq!(verdict.authority_list.len(), 2);

    // On a rule that can change the account, even a recognized policy is refused: its
    // signer semantics there are not projected to anyone.
    for policy in [readable_policy(), unknown_policy()] {
        let guarded = StateBuilder::new()
            .owner_rule(vec![delegated(OWNER)])
            .rule(
                StoredContextType::Default,
                None,
                vec![delegated(OWNER_2)],
                vec![policy.clone()],
            )
            .build();
        let verdict = check(&input(&guarded)).unwrap();
        let finding = only_unsupported(&verdict);
        assert_eq!(finding.rule_id, Some(1), "{policy}");
        assert_eq!(finding.unsupported, Some(UnsupportedReason::PolicyGuarded));
        // The describable owner rule is still listed; the refusal blocks regardless.
        assert_eq!(verdict.authority_list.len(), 1);
    }
}

#[test]
fn case_5_external_owner_is_refused_until_its_verifier_is_recognized() {
    let st = StateBuilder::new()
        .owner_rule(vec![external(0xEE, vec![4; 65])])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_eq!(
        only_unsupported(&verdict).unsupported,
        Some(UnsupportedReason::ExternalSigner)
    );
}

#[test]
fn case_6_restricted_key_that_can_manage_alone_is_refused() {
    for context in [StoredContextType::Default, call(account())] {
        let st = StateBuilder::new()
            .owner_rule(vec![delegated(OWNER)])
            .rule(context.clone(), None, vec![delegated(AGENT)], vec![])
            .build();
        let verdict = check(&input(&st)).unwrap();
        let finding = only_refusal(&verdict);
        assert_eq!(
            finding.code,
            FindingCode::DelegateHasAuthority,
            "{context:?}"
        );
        assert_eq!(finding.rule_id, Some(1));
        // Still described, with the agent marked, so a display can say whose rule it is.
        assert_eq!(
            verdict.authority_list[1].requirement,
            all_of(vec![owner(AGENT, true)])
        );
    }
}

// --- key aliasing ------------------------------------------------------------------------

#[test]
fn restricted_key_beside_an_owner_is_marked_but_not_refused() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER), delegated(AGENT)])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    assert_eq!(
        verdict.authority_list[0].requirement,
        all_of(vec![owner(OWNER, false), owner(AGENT, true)])
    );
    assert_eq!(
        verdict.notes.restricted_key_rules,
        vec![RestrictedKeyRule {
            rule_id: 0,
            context: StoredContextType::Default,
            valid_until: None,
            usable_alone: false,
            policy_addresses: vec![],
        }]
    );
}

#[test]
fn restricted_key_named_through_a_verifier_is_still_the_restricted_key() {
    // The grant names the agent as a classic account; the account stores the same ed25519
    // key behind some verifier on a policy-guarded management rule.
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            StoredContextType::Default,
            None,
            vec![external(0xEE, vec![AGENT; 32])],
            vec![unknown_policy()],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    let finding = only_refusal(&verdict);
    assert_eq!(finding.code, FindingCode::DelegateHasAuthority);
    assert_eq!(finding.rule_id, Some(1));

    // And the other way round: the grant names the key behind a verifier, the account has
    // the classic account on a management rule.
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .owner_rule(vec![delegated(AGENT)])
        .build();
    let mut request = input(&st);
    request.grant.signers = vec![external(0xEF, vec![AGENT; 32])];
    let verdict = check(&request).unwrap();
    assert!(has_refusal(&verdict, FindingCode::DelegateHasAuthority));
    // A restricted key behind a verifier this check does not recognize is itself refused.
    assert!(verdict
        .refusals
        .iter()
        .any(|finding| finding.rule_id.is_none()
            && finding.unsupported == Some(UnsupportedReason::ExternalSigner)));
}

#[test]
fn key_data_that_starts_with_the_restricted_key_is_treated_as_it() {
    // Until a verifier's key encoding is recognized, key data whose leading 32 bytes are the
    // agent's ed25519 key is assumed to be the agent. Over-approximation can only add a
    // refusal or remove an owner.
    let mut key = vec![AGENT; 32];
    key.push(7);
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(target()), None, vec![external(0xEE, key)], vec![])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_eq!(
        only_refusal(&verdict).code,
        FindingCode::DelegateGrantOverlap
    );
}

#[test]
fn webauthn_style_keys_with_different_credential_ids_are_one_key() {
    // A WebAuthn verifier reads only the leading public key; a credential-id suffix does not
    // make a second key.
    let mut agent_a = vec![4u8; 65];
    agent_a.extend_from_slice(b"credential-a");
    let mut agent_b = vec![4u8; 65];
    agent_b.extend_from_slice(b"credential-b");
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(target()), None, vec![external(0xEE, agent_b)], vec![])
        .build();
    let mut request = input(&st);
    request.grant.signers = vec![external(0xEE, agent_a)];
    let verdict = check(&request).unwrap();
    assert!(has_refusal(&verdict, FindingCode::DelegateGrantOverlap));
}

#[test]
fn policy_guarded_management_rule_naming_the_restricted_key_is_its_authority() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(account()),
            None,
            vec![delegated(AGENT), delegated(OWNER_2)],
            vec![readable_policy()],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    // Even a readable policy that wants one rule signer accepts the agent's alone.
    let finding = only_refusal(&verdict);
    assert_eq!(finding.code, FindingCode::DelegateHasAuthority);
    assert_eq!(finding.rule_id, Some(1));
}

// --- the new rule's target (R1) ----------------------------------------------------------

#[test]
fn stateful_grant_beside_another_usable_rule_on_the_target_is_refused() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(target()),
            Some(LEDGER + 10),
            vec![delegated(AGENT)],
            vec![],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    let finding = only_refusal(&verdict);
    assert_eq!(finding.code, FindingCode::DelegateGrantOverlap);
    assert_eq!(finding.rule_id, Some(1));

    // A stateless grant beside an unrestricted rule adds no limit, but breaks none either:
    // the screen shows that the agent already has more, and nothing blocks.
    let mut request = input(&st);
    request.grant.stateful = false;
    let verdict = check(&request).unwrap();
    assert_open(&verdict);
    assert_eq!(verdict.authority_list.len(), 1);
    assert_eq!(
        verdict.notes.restricted_key_rules,
        vec![RestrictedKeyRule {
            rule_id: 1,
            context: call(target()),
            valid_until: Some(LEDGER + 10),
            usable_alone: true,
            policy_addresses: vec![],
        }]
    );
}

#[test]
fn unreadable_policy_on_the_target_refuses_whoever_it_names_even_nobody() {
    // OZ skips the signer check on a rule with policies and lets the submitter pick the rule,
    // so an empty signer set reaches `enforce`; a rule may even have policies and no signers.
    for signers in [vec![delegated(OWNER_2)], vec![]] {
        let st = StateBuilder::new()
            .owner_rule(vec![delegated(OWNER)])
            .rule(
                call(target()),
                None,
                signers.clone(),
                vec![unknown_policy()],
            )
            .build();
        let mut request = input(&st);
        request.grant.stateful = false;
        let verdict = check(&request).unwrap();
        let finding = only_refusal(&verdict);
        assert_eq!(
            finding.code,
            FindingCode::DelegateGrantOverlap,
            "{signers:?}"
        );
        assert_eq!(finding.rule_id, Some(1));
        assert!(finding.reason.contains(&unknown_policy()));
    }
}

#[test]
fn readable_target_rule_is_listed_for_its_signers_and_refused_for_the_agent() {
    let owners = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(target()),
            None,
            vec![delegated(OWNER)],
            vec![readable_policy()],
        )
        .build();
    let verdict = check(&input(&owners)).unwrap();
    assert_open(&verdict);
    assert_eq!(verdict.authority_list.len(), 1);
    assert_eq!(
        verdict.notes.target_rules[0],
        AuthorityEntry {
            rule_id: 1,
            reach: Reach::Target { address: target() },
            valid_until: None,
            requirement: Requirement::AnyOf {
                signers: vec![owner(OWNER, false)],
                policies: vec![readable_policy()],
            },
        }
    );

    let agent = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(target()),
            None,
            vec![delegated(OWNER), delegated(AGENT)],
            vec![readable_policy()],
        )
        .build();
    let mut request = input(&agent);
    request.grant.stateful = false;
    let verdict = check(&request).unwrap();
    assert_eq!(
        only_refusal(&verdict).code,
        FindingCode::DelegateGrantOverlap
    );
}

#[test]
fn target_rule_needing_an_owner_beside_the_agent_is_listed_not_refused() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(target()),
            None,
            vec![delegated(AGENT), delegated(OWNER)],
            vec![],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    // Who else can call the target is shown; it is not part of the wallet's decision.
    assert_eq!(verdict.authority_list.len(), 1);
    assert_eq!(
        verdict.notes.target_rules[0].requirement,
        all_of(vec![owner(AGENT, true), owner(OWNER, false)])
    );
    assert!(!verdict.notes.restricted_key_rules[0].usable_alone);
}

#[test]
fn a_rule_already_carrying_a_bound_policy_is_named_as_installed() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(target()),
            None,
            vec![delegated(AGENT)],
            vec![bound_policy()],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    let finding = only_refusal(&verdict);
    assert_eq!(finding.code, FindingCode::DelegateGrantOverlap);
    assert!(finding.reason.contains("already"), "{}", finding.reason);
}

#[test]
fn restricted_key_rules_elsewhere_are_listed_not_refused() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(other_contract()),
            None,
            vec![delegated(AGENT)],
            vec![unknown_policy()],
        )
        .rule(
            StoredContextType::CreateContract {
                wasm_hash: "cc".repeat(32),
            },
            None,
            vec![delegated(AGENT)],
            vec![],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    let listed: Vec<(u32, bool, Vec<String>)> = verdict
        .notes
        .restricted_key_rules
        .iter()
        .map(|rule| {
            (
                rule.rule_id,
                rule.usable_alone,
                rule.policy_addresses.clone(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        vec![(1, true, vec![unknown_policy()]), (2, true, vec![])]
    );
    assert_eq!(verdict.authority_list.len(), 1);
}

#[test]
fn rules_for_other_contracts_are_coverage_exclusions_not_gaps() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(other_contract()), None, vec![], vec![unknown_policy()])
        .rule(call(other_contract()), None, vec![delegated(AGENT)], vec![])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    assert_eq!(
        verdict.coverage_exclusions,
        vec![
            ExcludedRule {
                rule_id: 1,
                context: call(other_contract()),
                policy_addresses: vec![unknown_policy()],
            },
            ExcludedRule {
                rule_id: 2,
                context: call(other_contract()),
                policy_addresses: vec![],
            },
        ]
    );
    assert_eq!(
        verdict.scope,
        Scope {
            targets: vec![target()],
            account: account(),
            bound_policies: vec![bound_policy()],
        }
    );
}

// --- the bound policies (R4) and the new rule ---------------------------------------------

#[test]
fn owner_rule_scoped_to_a_bound_policy_is_listed_for_the_wallet() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(bound_policy()), None, vec![delegated(OWNER_2)], vec![])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    assert_eq!(
        verdict.authority_list[1],
        AuthorityEntry {
            rule_id: 1,
            reach: Reach::Policy {
                address: bound_policy()
            },
            valid_until: None,
            requirement: all_of(vec![owner(OWNER_2, false)]),
        }
    );

    let agent = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(bound_policy()), None, vec![delegated(AGENT)], vec![])
        .build();
    let verdict = check(&input(&agent)).unwrap();
    let finding = only_refusal(&verdict);
    assert_eq!(finding.code, FindingCode::DelegateHasAuthority);
    assert!(finding.reason.contains(&bound_policy()));
}

#[test]
fn new_rule_cannot_target_the_account_or_a_bound_policy() {
    let st = owned();
    let mut request = input(&st);
    request.grant.target = account();
    let verdict = check(&request).unwrap();
    let finding = only_refusal(&verdict);
    assert_eq!(finding.code, FindingCode::UnsafeManagementSurface);
    assert_eq!(finding.rule_id, None);

    request.grant.target = bound_policy();
    let verdict = check(&request).unwrap();
    let finding = only_refusal(&verdict);
    assert_eq!(finding.code, FindingCode::UnsafeCallSurface);
    assert_eq!(finding.rule_id, None);
}

#[test]
fn new_rule_cannot_target_a_contract_the_account_trusts() {
    // Policies, verifiers and contract signers the account already uses are guarded by the
    // account's own authorization; a grant on one would let the agent reset another rule's
    // state or act as the account towards it.
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(other_contract()),
            None,
            vec![
                external(0xEE, vec![7; 32]),
                StoredSignerKey::Delegated {
                    address: contract(8),
                },
            ],
            vec![unknown_policy()],
        )
        .build();
    for trusted in [unknown_policy(), contract(0xEE), contract(8)] {
        let mut request = input(&st);
        request.grant.target = trusted.clone();
        let verdict = check(&request).unwrap();
        assert!(
            verdict
                .refusals
                .iter()
                .any(|finding| finding.code == FindingCode::UnsafeCallSurface
                    && finding.rule_id.is_none()
                    && finding.reason.contains(&trusted)),
            "{trusted}: {:?}",
            verdict.refusals
        );
    }
}

#[test]
fn contract_restricted_key_is_refused_by_name() {
    let st = owned();
    let mut request = input(&st);
    request.grant.signers = vec![StoredSignerKey::Delegated {
        address: contract(8),
    }];
    let verdict = check(&request).unwrap();
    let finding = only_unsupported(&verdict);
    assert_eq!(finding.unsupported, Some(UnsupportedReason::ContractSigner));
    assert_eq!(finding.rule_id, None);
}

// --- classic accounts (R2) ---------------------------------------------------------------

fn with_classic(st: &AccountState, byte: u8, entry: Option<ClassicAccount>) -> SurfaceVerdict {
    let mut request = input(st);
    match entry {
        Some(entry) => request.classic_accounts.insert(classic(byte), entry),
        None => request.classic_accounts.remove(&classic(byte)),
    };
    check(&request).unwrap()
}

#[test]
fn classic_owner_is_described_only_when_its_master_key_alone_controls_it() {
    let st = owned();
    assert_open(&with_classic(&st, OWNER, Some(master_key_only())));

    // The agent's key added as a signer of the owner's classic account: the agent could
    // authorize for the owner. Not analysed, refused.
    let agent_added = ClassicAccount::Found {
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 1,
        high_threshold: 1,
        signers: vec![ClassicSigner {
            key: classic(AGENT),
            weight: 1,
        }],
    };
    assert_eq!(
        only_unsupported(&with_classic(&st, OWNER, Some(agent_added))).unsupported,
        Some(UnsupportedReason::ClassicMultisig)
    );

    // A master key with no weight, or below the medium threshold, decides nothing alone.
    for (master_weight, medium_threshold) in [(0, 0), (1, 2)] {
        let entry = ClassicAccount::Found {
            master_weight,
            low_threshold: 0,
            medium_threshold,
            high_threshold: 0,
            signers: vec![],
        };
        assert_eq!(
            only_unsupported(&with_classic(&st, OWNER, Some(entry))).unsupported,
            Some(UnsupportedReason::ClassicMultisig),
            "{master_weight}/{medium_threshold}"
        );
    }

    // A missing account cannot authenticate now (the host fails to load it).
    let missing = with_classic(&st, OWNER, Some(ClassicAccount::NotFound));
    let finding = only_unsupported(&missing);
    assert_eq!(
        finding.unsupported,
        Some(UnsupportedReason::ClassicAccountMissing)
    );
    assert!(finding.reason.contains("does not exist"));

    // Not read at all: an evidence gap, not a refusal.
    let unread = with_classic(&st, OWNER, None);
    assert_eq!(only_unresolved(&unread).rule_id, Some(0));
}

#[test]
fn the_agents_own_classic_account_is_read_like_any_other() {
    let st = owned();
    assert_eq!(
        only_unsupported(&with_classic(&st, AGENT, Some(ClassicAccount::NotFound))).unsupported,
        Some(UnsupportedReason::ClassicAccountMissing)
    );
    let shared = ClassicAccount::Found {
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 1,
        high_threshold: 1,
        signers: vec![ClassicSigner {
            key: classic(STRANGER),
            weight: 1,
        }],
    };
    assert_eq!(
        only_unsupported(&with_classic(&st, AGENT, Some(shared))).unsupported,
        Some(UnsupportedReason::ClassicMultisig)
    );
    assert_eq!(
        only_unresolved(&with_classic(&st, AGENT, None)).rule_id,
        None
    );
}

// --- shapes the check refuses ------------------------------------------------------------

#[test]
fn contract_signer_on_a_management_rule_is_refused_by_name() {
    let st = StateBuilder::new()
        .owner_rule(vec![StoredSignerKey::Delegated {
            address: contract(8),
        }])
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_eq!(
        only_unsupported(&verdict).unsupported,
        Some(UnsupportedReason::ContractSigner)
    );
}

#[test]
fn rules_outside_every_surface_are_ignored_whatever_they_contain() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(other_contract()),
            None,
            vec![StoredSignerKey::Delegated {
                address: contract(8),
            }],
            vec![readable_policy()],
        )
        .rule(
            StoredContextType::CreateContract {
                wasm_hash: "cc".repeat(32),
            },
            None,
            vec![delegated(0x77)],
            vec![],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    assert_eq!(verdict.authority_list.len(), 1);
    assert!(verdict.notes.restricted_key_rules.is_empty());
    let excluded: Vec<u32> = verdict
        .coverage_exclusions
        .iter()
        .map(|rule| rule.rule_id)
        .collect();
    assert_eq!(excluded, vec![1, 2]);
}

// --- expiry ------------------------------------------------------------------------------

#[test]
fn expired_rules_are_noted_apart_and_the_boundary_ledger_is_still_live() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            StoredContextType::Default,
            Some(LEDGER - 1),
            vec![delegated(STRANGER)],
            vec![],
        )
        .rule(
            call(bound_policy()),
            Some(LEDGER - 1),
            vec![delegated(AGENT)],
            vec![],
        )
        .rule(
            StoredContextType::Default,
            Some(LEDGER),
            vec![delegated(OWNER_2)],
            vec![],
        )
        .build();
    let verdict = check(&input(&st)).unwrap();
    assert_open(&verdict);
    assert_eq!(
        verdict.notes.expired_rules,
        vec![
            ExpiredRule {
                rule_id: 1,
                context: StoredContextType::Default,
                valid_until: LEDGER - 1,
            },
            ExpiredRule {
                rule_id: 2,
                context: call(bound_policy()),
                valid_until: LEDGER - 1,
            },
        ]
    );
    // OZ rejects a rule only when valid_until < ledger, so rule 3 still manages the account.
    let ids: Vec<u32> = verdict
        .authority_list
        .iter()
        .map(|entry| entry.rule_id)
        .collect();
    assert_eq!(ids, vec![0, 3]);
    // An expired rule is nothing the agent can use now.
    assert!(verdict.notes.restricted_key_rules.is_empty());
}

// --- the digest --------------------------------------------------------------------------

#[test]
fn commitment_survives_a_later_ledger_and_moves_with_state_and_intent() {
    let st = owned();
    let first = check(&input(&st)).unwrap();
    let commitment = |request: &CheckInput<'_>| {
        let verdict = check(request).unwrap();
        assert_open(&verdict);
        verdict.authority_commitment
    };

    // The same authority state read at a later ledger (TTLs are not in the model at all).
    let mut later = input(&st);
    later.current_ledger = LEDGER + 50;
    assert_eq!(commitment(&later), first.authority_commitment);

    // A real rule change.
    let mut changed = owned();
    changed.rules.get_mut(&0).unwrap().signer_ids.push(9);
    changed.signers.insert(
        9,
        StoredSigner {
            id: 9,
            key: delegated(OWNER_2),
        },
    );
    assert_ne!(commitment(&input(&changed)), first.authority_commitment);

    // A code change at the account, or at an installed policy.
    let mut other_code = input(&st);
    other_code.account_code_hash = "another-account-hash".to_string();
    assert_ne!(commitment(&other_code), first.authority_commitment);
    let with_policy = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(other_contract()), None, vec![], vec![unknown_policy()])
        .build();
    let mut upgraded = with_policy.clone();
    upgraded.policies.get_mut(&0).unwrap().observed_wasm_hash = "98".repeat(32);
    assert_ne!(
        commitment(&input(&with_policy)),
        commitment(&input(&upgraded))
    );

    // A classic account the answer never consulted (a reader fetched more than it needed)
    // does not move it.
    let mut fetched_more = input(&st);
    fetched_more
        .classic_accounts
        .insert(classic(0x77), ClassicAccount::NotFound);
    assert_eq!(commitment(&fetched_more), first.authority_commitment);

    // Nor does a change to the classic account of a signer outside the scope, or on an
    // expired rule.
    let with_others = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(other_contract()),
            None,
            vec![delegated(STRANGER)],
            vec![],
        )
        .rule(
            StoredContextType::Default,
            Some(LEDGER - 1),
            vec![delegated(OWNER_2)],
            vec![],
        )
        .build();
    let base = commitment(&input(&with_others));
    for byte in [STRANGER, OWNER_2] {
        let mut changed = input(&with_others);
        changed
            .classic_accounts
            .insert(classic(byte), ClassicAccount::NotFound);
        assert_eq!(commitment(&changed), base);
    }

    // A classic signer configuration change that leaves the owner resolvable.
    let mut reweighted = input(&st);
    reweighted.classic_accounts.insert(
        classic(OWNER),
        ClassicAccount::Found {
            master_weight: 2,
            low_threshold: 0,
            medium_threshold: 2,
            high_threshold: 2,
            signers: vec![],
        },
    );
    assert_ne!(commitment(&reweighted), first.authority_commitment);

    // Every part of the intent: network, spec, rule, and each add_context_rule argument.
    type Edit = Box<dyn Fn(&mut CheckInput<'_>)>;
    let edits: Vec<Edit> = vec![
        Box::new(|r| r.network_id = "cd".repeat(32)),
        Box::new(|r| r.spec_hash = ozpb_domain::Hash32([0x5d; 32])),
        Box::new(|r| r.grant.rule_index = 1),
        Box::new(|r| r.grant.stateful = false),
        Box::new(|r| r.grant.name = "another-name".to_string()),
        Box::new(|r| r.grant.valid_until = Some(LEDGER + 2_000)),
        Box::new(|r| {
            r.grant.policies[0].install_params = GrantPolicyParams::SpendingLimit {
                spending_limit: "100".to_string(),
                period_ledgers: 17_280,
            }
        }),
        Box::new(|r| r.grant.policies[0].address = other_contract()),
        Box::new(|r| r.grant.target = contract(6)),
        Box::new(|r| r.grant.signers = vec![delegated(STRANGER)]),
        // The bound policy's code moved (and was re-validated as such).
        Box::new(|r| {
            r.bound_policies[0].observed_wasm_hash = "bc".repeat(32);
            r.recognized_policies
                .get_mut(&bound_policy())
                .unwrap()
                .wasm_hash = "bc".repeat(32);
        }),
    ];
    for edit in edits {
        let mut request = input(&st);
        edit(&mut request);
        assert_ne!(commitment(&request), first.authority_commitment);
    }
}

#[test]
fn the_result_never_says_safe() {
    // No field, tag or sentence of the answer calls the account safe — open or refused. Error
    // codes (`E_UNSAFE_*`) are the only place the word appears.
    fn walk(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    assert!(!key.to_lowercase().contains("safe"), "{path}.{key}");
                    walk(child, &format!("{path}.{key}"));
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, path)),
            serde_json::Value::String(text) if !text.starts_with("E_") => {
                assert!(!text.to_lowercase().contains("safe"), "{path}: {text}");
            }
            _ => {}
        }
    }
    let open = owned();
    let refused = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(call(account()), None, vec![delegated(AGENT)], vec![])
        .rule(
            StoredContextType::Default,
            None,
            vec![delegated(OWNER_2)],
            vec![unknown_policy()],
        )
        .rule(call(target()), None, vec![], vec![unknown_policy()])
        .build();
    for st in [open, refused] {
        let mut request = input(&st);
        request.grant.target = target();
        walk(&serde_json::to_value(check(&request).unwrap()).unwrap(), "");
        request.grant.target = account();
        walk(&serde_json::to_value(check(&request).unwrap()).unwrap(), "");
    }
}

// --- enumeration and recognition gates (unchanged behaviour) ----------------------------

#[test]
fn upgraded_bound_policy_fails_even_when_its_address_is_recognized() {
    let st = owned();
    let mut request = input(&st);
    request.bound_policies[0].observed_wasm_hash = "cd".repeat(32);
    assert!(matches!(
        check(&request).unwrap_err(),
        CheckError::UnrecognizedBoundPolicy(address) if address == bound_policy()
    ));
}

#[test]
fn upgraded_readable_policy_is_no_longer_readable() {
    let st = StateBuilder::new()
        .owner_rule(vec![delegated(OWNER)])
        .rule(
            call(target()),
            None,
            vec![delegated(OWNER_2)],
            vec![readable_policy()],
        )
        .build();
    assert_open(&check(&input(&st)).unwrap());
    let mut request = input(&st);
    request
        .recognized_policies
        .get_mut(&readable_policy())
        .unwrap()
        .wasm_hash = "56".repeat(32);
    assert_eq!(
        only_refusal(&check(&request).unwrap()).code,
        FindingCode::DelegateGrantOverlap
    );
}

#[test]
fn bound_policy_must_be_recognized() {
    let st = owned();
    let mut request = input(&st);
    request.recognized_policies.clear();
    assert!(matches!(
        check(&request).unwrap_err(),
        CheckError::UnrecognizedBoundPolicy(_)
    ));
}

#[test]
fn bindings_and_grant_must_be_well_formed() {
    let st = owned();
    let mut request = input(&st);
    request.bound_policies.clear();
    assert!(matches!(
        check(&request).unwrap_err(),
        CheckError::InvalidBindingSet(_)
    ));

    let mut request = input(&st);
    request
        .bound_policies
        .push(request.bound_policies[0].clone());
    assert!(matches!(
        check(&request).unwrap_err(),
        CheckError::InvalidBindingSet(_)
    ));

    let mut request = input(&st);
    request.grant.signers.clear();
    assert!(matches!(
        check(&request).unwrap_err(),
        CheckError::InvalidBindingSet(reason) if reason.contains("signer")
    ));
}

#[test]
fn count_deficit_fails_closed_without_guessing_why() {
    let mut st = owned();
    st.next_id = 2;
    st.active_count = 2;
    assert!(matches!(
        check(&input(&st)).unwrap_err(),
        CheckError::IncompleteState {
            cause: IncompleteCause::UnresolvedRule,
            ..
        }
    ));
}

#[test]
fn count_surplus_fails_closed_as_snapshot_mismatch() {
    let mut st = owned();
    st.active_count = 0;
    assert!(matches!(
        check(&input(&st)).unwrap_err(),
        CheckError::IncompleteState {
            cause: IncompleteCause::SnapshotMismatch,
            ..
        }
    ));
}

#[test]
fn missing_transitive_signer_fails_closed() {
    let mut st = owned();
    st.signers.clear();
    assert!(matches!(
        check(&input(&st)).unwrap_err(),
        CheckError::IncompleteState {
            cause: IncompleteCause::Missing,
            ..
        }
    ));
}

#[test]
fn duplicate_transitive_ids_are_snapshot_mismatches() {
    let mut st = owned();
    st.rules.get_mut(&0).unwrap().signer_ids.push(0);
    assert!(matches!(
        check(&input(&st)).unwrap_err(),
        CheckError::IncompleteState {
            cause: IncompleteCause::SnapshotMismatch,
            ..
        }
    ));
}

#[test]
fn rule_beyond_next_id_is_a_snapshot_mismatch() {
    let mut st = owned();
    st.next_id = 0;
    assert!(matches!(
        check(&input(&st)).unwrap_err(),
        CheckError::IncompleteState {
            cause: IncompleteCause::SnapshotMismatch,
            ..
        }
    ));
}

#[test]
fn only_bounded_next_id_enumeration_is_supported() {
    let st = owned();
    for enumeration in [
        Enumeration::None,
        Enumeration::OnchainList,
        Enumeration::VerifiedEventIndex,
    ] {
        let mut request = input(&st);
        request.enumeration = enumeration;
        assert_eq!(
            check(&request).unwrap_err(),
            CheckError::EnumerationUnsupported(enumeration)
        );
    }
}

#[test]
fn unrecognized_account_fails_closed() {
    let st = owned();
    let mut request = input(&st);
    request.account_recognized = false;
    assert!(matches!(
        check(&request).unwrap_err(),
        CheckError::IncompatibleAccount(_)
    ));
}

/// The whole preimage, pinned in one assertion: domain, canonicalization version, the
/// version's width and byte order, its position before the payload, and the canonical bytes.
///
/// The expected value is rebuilt from the primitives rather than obtained from the function
/// under test, so the assertion cannot agree with whatever the implementation happens to do.
/// `domains::ACCOUNT_STATE` is named literally, so changing the implementation's domain fails
/// here — which is the point: an earlier version of this code hashed account state under a
/// domain belonging to another structure, and nothing objected.
#[test]
fn the_state_digest_is_domain_separated_and_version_prefixed() {
    let st = owned();
    let expected = ozpb_domain::sha256(
        &ozpb_domain::canonical_preimage_bytes(domains::ACCOUNT_STATE, &st)
            .expect("plain-data state must encode"),
    );
    assert_eq!(
        state_digest(&st).expect("plain-data state must digest"),
        expected,
        "the digest must be taken under domains::ACCOUNT_STATE over the canonical preimage"
    );
    assert_eq!(
        check(&input(&st))
            .unwrap()
            .authority_state
            .ordered_state_digest,
        expected
    );
}
