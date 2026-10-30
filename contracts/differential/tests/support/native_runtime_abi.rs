//! One known XDR vector is consumed by both SDK 28 policy/account-library types and SDK 29
//! runtime wire types. The fixture follows protocol XDR, independent of serde.
use super::{AuthPayload, ContextRule, ContextRuleType, PolicyStorageKey, Signer};
use soroban_sdk::xdr::{Limits, ScVal, WriteXdr};
use soroban_sdk::{vec, Address, Bytes, Env, IntoVal, Map, String, TryFromVal, Val};

#[test]
fn account_and_policy_abi_matches_the_shared_protocol_vector() {
    let env = Env::default();
    let contract =
        |n| Address::from_str(&env, stellar_strkey::Contract([n; 32]).to_string().as_str());
    let delegate = Address::from_str(
        &env,
        stellar_strkey::ed25519::PublicKey([6; 32])
            .to_string()
            .as_str(),
    );
    let signer = Signer::Delegated(delegate);
    let context_type = ContextRuleType::CallContract(contract(5));
    let mut signers = Map::new(&env);
    signers.set(signer.clone(), Bytes::new(&env));
    let auth = AuthPayload {
        signers,
        context_rule_ids: vec![&env, 7u32],
    };
    let rule = ContextRule {
        id: 7,
        context_type: context_type.clone(),
        name: String::from_str(&env, "candidate"),
        signers: vec![&env, signer.clone()],
        signer_ids: vec![&env, 9u32],
        policies: vec![&env, contract(8)],
        policy_ids: vec![&env, 11u32],
        valid_until: Some(123),
    };
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/examples/native-runtime-abi.json"
    ))
    .unwrap();
    for (name, value) in [
        ("signer", signer.into_val(&env)),
        ("context_rule_type", context_type.into_val(&env)),
        ("auth_payload", auth.into_val(&env)),
        ("context_rule", rule.into_val(&env)),
        (
            "policy_counter_key",
            PolicyStorageKey::CallCount(contract(5), 7).into_val(&env),
        ),
    ] {
        let value: Val = value;
        let encoded = ScVal::try_from_val(&env, &value)
            .unwrap()
            .to_xdr_base64(Limits {
                depth: 64,
                len: 4096,
            })
            .unwrap();
        assert_eq!(encoded, fixture[name].as_str().unwrap(), "{name}");
    }
}
