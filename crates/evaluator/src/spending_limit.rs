//! Pure model of the reviewed spending-limit window. No ledger acquisition or mutation.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendingEntry {
    pub amount: i128,
    pub ledger_sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendingLimitState {
    pub spending_limit: i128,
    pub period_ledgers: u32,
    pub spending_history: Vec<SpendingEntry>,
    pub cached_total_spent: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendingVerdict {
    Permit,
    Deny,
    Unsupported,
}

/// Prediction for a nonnegative transfer at one observed ledger. Invalid/incomplete state
/// is unsupported; this function cannot establish that the state came from a ledger.
pub fn evaluate_spending_limit(
    state: &SpendingLimitState,
    current_ledger: u32,
    amount: i128,
) -> SpendingVerdict {
    if state.spending_limit <= 0
        || state.period_ledgers == 0
        || state.spending_history.len() > 1000
        || current_ledger == 0
    {
        return SpendingVerdict::Unsupported;
    }
    let cutoff = current_ledger.saturating_sub(state.period_ledgers);
    let mut total = 0i128;
    let mut remaining = 0i128;
    let mut count = 0usize;
    let mut previous = 0u32;
    for entry in &state.spending_history {
        if entry.amount < 0
            || entry.ledger_sequence < previous
            || entry.ledger_sequence > current_ledger
        {
            return SpendingVerdict::Unsupported;
        }
        previous = entry.ledger_sequence;
        let Some(sum) = total.checked_add(entry.amount) else {
            return SpendingVerdict::Unsupported;
        };
        total = sum;
        if entry.ledger_sequence > cutoff {
            // Every amount is nonnegative and the full sum was checked above.
            remaining += entry.amount;
            count += 1;
        }
    }
    if total != state.cached_total_spent {
        return SpendingVerdict::Unsupported;
    }
    if amount < 0
        || count >= 1000
        || remaining
            .checked_add(amount)
            .is_none_or(|sum| sum > state.spending_limit)
    {
        SpendingVerdict::Deny
    } else {
        SpendingVerdict::Permit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SpendingLimitState {
        SpendingLimitState {
            spending_limit: 100,
            period_ledgers: 10,
            spending_history: vec![SpendingEntry {
                amount: 60,
                ledger_sequence: 11,
            }],
            cached_total_spent: 60,
        }
    }

    #[test]
    fn exact_amount_limit_and_window_cutoff() {
        assert_eq!(
            evaluate_spending_limit(&state(), 20, 40),
            SpendingVerdict::Permit
        );
        assert_eq!(
            evaluate_spending_limit(&state(), 20, 41),
            SpendingVerdict::Deny
        );
        assert_eq!(
            evaluate_spending_limit(&state(), 21, 100),
            SpendingVerdict::Permit
        );
        assert_eq!(
            evaluate_spending_limit(&state(), 21, 101),
            SpendingVerdict::Deny
        );
    }

    #[test]
    fn malformed_history_cannot_become_unused_allowance() {
        for mutate in [
            |s: &mut SpendingLimitState| s.cached_total_spent = 0,
            |s: &mut SpendingLimitState| s.spending_history[0].amount = -1,
            |s: &mut SpendingLimitState| s.spending_history[0].ledger_sequence = 21,
            |s: &mut SpendingLimitState| s.period_ledgers = 0,
            |s: &mut SpendingLimitState| s.spending_limit = 0,
        ] {
            let mut s = state();
            mutate(&mut s);
            assert_eq!(
                evaluate_spending_limit(&s, 20, 1),
                SpendingVerdict::Unsupported
            );
        }
        let mut s = state();
        s.spending_history.push(SpendingEntry {
            amount: 1,
            ledger_sequence: 10,
        });
        s.cached_total_spent += 1;
        assert_eq!(
            evaluate_spending_limit(&s, 20, 1),
            SpendingVerdict::Unsupported
        );
    }

    #[test]
    fn history_limit_is_checked_after_cleanup() {
        let mut s = state();
        s.spending_history = vec![
            SpendingEntry {
                amount: 0,
                ledger_sequence: 11
            };
            1000
        ];
        s.cached_total_spent = 0;
        assert_eq!(evaluate_spending_limit(&s, 20, 0), SpendingVerdict::Deny);
        assert_eq!(evaluate_spending_limit(&s, 21, 0), SpendingVerdict::Permit);
        s.spending_history.push(SpendingEntry {
            amount: 0,
            ledger_sequence: 11,
        });
        assert_eq!(
            evaluate_spending_limit(&s, 21, 0),
            SpendingVerdict::Unsupported
        );
    }

    #[test]
    fn negative_amount_and_i128_overflow_never_permit() {
        assert_eq!(
            evaluate_spending_limit(&state(), 20, -1),
            SpendingVerdict::Deny
        );
        let mut s = state();
        s.spending_limit = i128::MAX;
        s.spending_history[0].amount = i128::MAX;
        s.cached_total_spent = i128::MAX;
        assert_eq!(evaluate_spending_limit(&s, 20, 1), SpendingVerdict::Deny);
        s.spending_history.push(SpendingEntry {
            amount: 1,
            ledger_sequence: 12,
        });
        assert_eq!(
            evaluate_spending_limit(&s, 20, 0),
            SpendingVerdict::Unsupported
        );
    }
}
