// The installation consent: what the owner's passkey signature does, derived independently in the
// browser and the backend from the reviewed grant and the validated unsigned assembly. Both must
// produce the same display before the passkey is asked.
import { NETWORK_ID, freezeCopy } from './approval.mjs';

/**
 * The installation transaction's ledger window, from the CLI's sequence read: the owner's signature
 * is valid until one ledger before its end. Until then no other installation is released.
 */
export const INSTALL_VALIDITY_LEDGERS = 60;
const refuse = () => { throw new Error('wallet installation display refused; refresh and review again'); };
const integer = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;
const stroops = (n) => `${n} stroops (${n / 10_000_000} testnet XLM)`;

/**
 * `approval` is the reviewed approval (`reviewIntent`), `checked` the validated assembly
 * (`validateAssembly`), `spec` the retained specification, `ruleId` the context rule ID the
 * installation will create (the one every layer ran with) and `maxFeeStroops` the fee payer's
 * ceiling after enforce-mode re-simulation.
 */
export function installConsent({ approval, checked, spec, maxFeeStroops, ruleId }) {
  try {
    const intent = approval.intent;
    const rule = spec?.rules?.[0];
    const signers = intent.delegate_signers;
    const delegates = rule?.authorization?.signers;
    const maxCalls = rule?.state?.[0]?.call_count_per_installation?.max_calls;
    if (spec.rules.length !== 1 || signers.length !== 1 || signers[0].kind !== 'delegated' || delegates?.length !== 1
      || delegates[0].delegated?.address !== signers[0].address || rule.context?.contract !== intent.context_contract
      || (rule.valid_until?.ledger ?? null) !== intent.valid_until_ledger || intent.policies.length !== 1
      || spec.smart_account?.address !== intent.account_contract || !integer(maxCalls, 1, 0xffffffff)
      || !integer(ruleId, 1, 0xffffffff) || ruleId === checked.ownerRuleId || checked.authorityCommitment !== approval.commitment
      || checked.ownerRuleId !== approval.ownerRuleId || !integer(checked.feeStroops, 100, maxFeeStroops)
      || !integer(maxFeeStroops, 100, 0xffffffff) || !Array.isArray(rule.allowed_calls) || !rule.allowed_calls.length) refuse();
    const delegate = signers[0].address;
    const until = intent.valid_until_ledger;
    const calls = rule.allowed_calls.map((call) => ({ function: call.fn,
      args: (call.args ?? []).map((arg) => ({ index: arg.i, constraint: arg.c })) }));
    return freezeCopy({
      schema: 'ozpb-install-consent/v1', network: 'testnet', network_id: NETWORK_ID,
      owner_signs: { contract: intent.account_contract, function: 'add_context_rule', context: `CallContract(${intent.context_contract})`,
        name: intent.rule_name, valid_until: until, signers: [`Delegated(${delegate})`], policies: intent.policies.map((p) => p.address),
        context_rule_ids: [checked.ownerRuleId], authenticator: 'owner passkey' },
      grant: { rule_id: ruleId, delegate, target: intent.context_contract, allowed_calls: calls, max_calls: maxCalls,
        valid_until_ledger: until, policy: intent.policies[0].address, authority_commitment: approval.commitment },
      transaction: { min_ledger: checked.minLedger, max_ledger: checked.maxLedger, signature_expiration_ledger: checked.expirationLedger },
      fee: { prepared_fee_stroops: checked.feeStroops, max_fee_stroops: maxFeeStroops, paid_by: 'the local testnet fee payer, not this account' },
      warning: `Your passkey signs one transaction that installs rule "${intent.rule_name}" (rule ID ${ruleId}) on account `
        + `${intent.account_contract}. Once it is confirmed, the delegate ${delegate}, whose key this wallet backend holds as its `
        + `automation delegate, can make the calls listed here to ${intent.context_contract} on this account's behalf without your `
        + `passkey, at most ${maxCalls} time${maxCalls === 1 ? '' : 's'}, until ledger ${until}. The rule stays installed until it `
        + 'expires or you revoke it, which is a separate transaction signed with your passkey. Your signature is a complete '
        + `installation until ledger ${checked.expirationLedger}, even if this wallet refuses to submit it; until then it releases `
        + 'no other installation, and afterwards it checks that the account did not change. Before the fee payer submits it, the '
        + 'backend re-reads the account\'s authority, checks that the live check\'s signatures were not used and that the evidence '
        + `is recent. The fee payer pays at most ${stroops(maxFeeStroops)}; the prepared fee is an estimate.`,
      labels: ['owner_passkey_signs_installation', 'human_approval_attested:false'],
    });
  } catch { return refuse(); }
}
