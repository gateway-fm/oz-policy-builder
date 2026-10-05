//! Independent accepted-tuple matcher for labeling generated harness cases.
//!
//! This module reads `Constraint` directly and owns its small input value view.
//! It has no dependency on the reference evaluator or generated contract code.

use ozpb_policy_spec::{AddressRef, Constraint, RuleSpec};

pub(super) enum Value<'a> {
    Address(&'a str),
    I128(i128),
    ScvalXdr(&'a str),
}

pub(super) fn accepts(
    rule: &RuleSpec,
    smart_account: &str,
    fn_name: &str,
    args: &[Value<'_>],
) -> bool {
    rule.allowed_calls.iter().any(|call| {
        call.fn_name == fn_name
            && call.args.len() == args.len()
            && call.args.iter().all(|arg| {
                args.get(arg.index as usize)
                    .is_some_and(|value| matches_constraint(&arg.constraint, smart_account, value))
            })
    })
}

fn matches_constraint(constraint: &Constraint, smart_account: &str, value: &Value<'_>) -> bool {
    match constraint {
        Constraint::EqAddress { value: address } => match (address, value) {
            (AddressRef::SelfAccount(_), Value::Address(actual)) => *actual == smart_account,
            (AddressRef::Address(expected), Value::Address(actual)) => *actual == expected,
            _ => false,
        },
        Constraint::EqScval { xdr_base64 } => {
            matches!(value, Value::ScvalXdr(actual) if *actual == xdr_base64)
        }
        Constraint::EqI128 { value: expected } => {
            matches!(value, Value::I128(actual) if expected.parse::<i128>() == Ok(*actual))
        }
        Constraint::LeI128 { max } => {
            matches!(value, Value::I128(actual) if max.parse::<i128>().is_ok_and(|bound| *actual <= bound))
        }
        Constraint::GeI128 { min } => {
            matches!(value, Value::I128(actual) if min.parse::<i128>().is_ok_and(|bound| *actual >= bound))
        }
        Constraint::AnyValue => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_domain::Provenance;
    use ozpb_policy_spec::{AllowedCall, ArgConstraint};

    #[test]
    fn matcher_decides_each_constraint_without_reference_evaluation() {
        // These assertions call this module directly. No evaluator verdict is used to
        // build the expected answers; the later layer-1 test compares them separately.
        let cases = [
            (
                Constraint::EqI128 { value: "10".into() },
                Value::I128(10),
                true,
            ),
            (
                Constraint::EqI128 { value: "10".into() },
                Value::I128(11),
                false,
            ),
            (
                Constraint::LeI128 { max: "20".into() },
                Value::I128(20),
                true,
            ),
            (
                Constraint::LeI128 { max: "20".into() },
                Value::I128(21),
                false,
            ),
            (
                Constraint::GeI128 { min: "20".into() },
                Value::I128(19),
                false,
            ),
            (
                Constraint::GeI128 { min: "20".into() },
                Value::I128(20),
                true,
            ),
            (Constraint::AnyValue, Value::Address("A"), true),
            (
                Constraint::EqScval {
                    xdr_base64: "xdr".into(),
                },
                Value::ScvalXdr("xdr"),
                true,
            ),
            (
                Constraint::EqScval {
                    xdr_base64: "xdr".into(),
                },
                Value::ScvalXdr("other"),
                false,
            ),
            (
                Constraint::EqAddress {
                    value: AddressRef::address("A"),
                },
                Value::Address("A"),
                true,
            ),
            (
                Constraint::EqAddress {
                    value: AddressRef::address("A"),
                },
                Value::I128(0),
                false,
            ),
        ];
        for (constraint, value, expected) in cases {
            assert_eq!(matches_constraint(&constraint, "SELF", &value), expected);
        }
        assert!(matches_constraint(
            &Constraint::EqAddress {
                value: AddressRef::self_account()
            },
            "ACCOUNT",
            &Value::Address("ACCOUNT"),
        ));
        assert!(!matches_constraint(
            &Constraint::EqAddress {
                value: AddressRef::self_account()
            },
            "ACCOUNT",
            &Value::Address("OTHER"),
        ));
    }

    #[test]
    fn matcher_has_no_evaluator_call_path() {
        // This module may not even import the evaluator; case labels must not be
        // computed by the same implementation the differential checks.
        let source = include_str!("accepted_tuple.rs");
        for forbidden in [
            ["ozpb_", "evaluator"].concat(),
            ["evaluate_generated_", "rule("].concat(),
            ["constraint_", "satisfied("].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
    }

    #[test]
    fn one_of_multiple_tuples_can_accept_a_candidate() {
        let mut rule = ozpb_policy_spec::fixtures::subscription_spec()
            .rules
            .remove(0);
        rule.allowed_calls = vec![
            AllowedCall {
                fn_name: "f".into(),
                args: vec![arg(0, Constraint::EqI128 { value: "10".into() })],
                justified_by: vec!["fixture".into()],
            },
            AllowedCall {
                fn_name: "f".into(),
                args: vec![arg(0, Constraint::EqI128 { value: "11".into() })],
                justified_by: vec!["fixture".into()],
            },
        ];
        assert!(accepts(&rule, "ACCOUNT", "f", &[Value::I128(11)]));
        assert!(!accepts(&rule, "ACCOUNT", "f", &[Value::I128(12)]));
        assert!(!accepts(&rule, "ACCOUNT", "g", &[Value::I128(11)]));
        assert!(!accepts(&rule, "ACCOUNT", "f", &[]));
    }

    fn arg(index: u32, constraint: Constraint) -> ArgConstraint {
        ArgConstraint {
            index,
            constraint,
            provenance: Provenance::ObservedExact,
        }
    }
}
