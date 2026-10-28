// The harness wallet's approval of one install, in order:
//
//   1. ask for the install intent (the tool runs the check itself and returns arguments only
//      when nothing is refused or unresolved; an error is a refusal);
//   2. require the intent's arguments to be exactly the grant the check covered;
//   3. decide on the check's answer with this wallet's trust (`wallet-decision.mjs`);
//   4. show the confirmation screen and ask;
//   5. just before signing, run the check again (a fresh read) and require the identical
//      `authority_commitment`, with the fresh answer itself accepted.
//
//      The intent's arguments must also equal the grant that fresh answer reports (the intent's
//      own first instruction): the wallet cannot recompute the commitment, so it compares the
//      grant itself as well.
//
// Only then are the arguments returned for signing, and `signedRuleArgs` turns them into the
// exact `add_context_rule` arguments, refusing unless they equal the rule built from the spec.
// `runner` is the check seam (`check-runner.mjs`, or a fake in tests), `confirm(screen)` resolves
// to true or false, and `log` prints. The tool never says "safe"; this wallet decides, under trust
// that in the harness is operator-supplied test configuration.
import { addContextRuleArgs } from './lib.mjs';
import { TRUST_OPERATOR, confirmationScreen, decide, intentMismatches, recheck } from './wallet-decision.mjs';

const refusal = (stage, reasons) => ({ approved: false, stage, reasons });

export async function approveInstall({ runner, request, trust, expect, confirm, log }) {
  let intent;
  try {
    intent = await runner.prepareInstallIntent(request);
  } catch (e) {
    if (!e.code) throw e;
    // A refused intent returns no answer to decide on, only its findings: show them.
    log([`The authority check returned nothing to sign: ${e.message}`, ...(e.details ?? []).map((d) => `  - ${d}`),
      'REFUSED by this wallet.'].join('\n'));
    return refusal('intent', [`the check refused or could not answer: ${e.message}`, ...(e.details ?? [])]);
  }

  const mismatches = intentMismatches(intent);
  if (mismatches.length) return refusal('intent_mismatch', mismatches.map((m) => `intent: ${m}`));

  const check = intent.authority;
  const decision = decide(check, { trust, expect });
  const screen = confirmationScreen({ check, decision });
  log(screen);
  if (!decision.accept) return refusal('authority_decision', decision.reasons);
  if (!(await confirm(screen))) return refusal('confirmation', ['the operator declined']);

  let fresh;
  try {
    fresh = await runner.checkPolicyCallSurface(request);
  } catch (e) {
    if (!e.code) throw e;
    return refusal('recheck_error', [`the pre-sign re-check could not answer: ${e.message}`, ...(e.details ?? [])]);
  }
  const again = recheck(decision, fresh, { trust, expect });
  if (!again.accept) return refusal('recheck_decision', again.reasons);
  const drift = intentMismatches({ ...intent, authority: fresh });
  if (drift.length) return refusal('recheck_intent_mismatch', drift.map((m) => `the re-check's grant differs from the intent: ${m}`));

  return {
    approved: true,
    commitment: decision.commitment,
    args: {
      account: intent.account_contract,
      context: intent.context_contract,
      name: intent.rule_name,
      validUntil: intent.valid_until_ledger,
      signers: intent.delegate_signers,
      policies: intent.policies,
    },
    evidence: {
      trust_basis: TRUST_OPERATOR,
      authority_commitment: decision.commitment,
      checked_at_ledger: check.verdict.observed_ledger,
      rechecked_at_ledger: fresh.verdict.observed_ledger,
      accepted_entries: decision.entries,
    },
  };
}

/**
 * The `add_context_rule` arguments to sign: the approved intent's, encoded, and only when they
 * are byte for byte the rule built from the spec (`fromSpec`) for this account. Anything else
 * throws, so nothing is signed.
 */
export function signedRuleArgs({ approved, fromSpec, account }) {
  if (approved.account !== account) throw new Error('the approved intent is for another account; nothing was signed');
  const intentArgs = addContextRuleArgs(approved);
  const asXdr = (args) => args.map((v) => Buffer.from(v.toXDR()).toString('hex')).join('|');
  if (asXdr(intentArgs) !== asXdr(addContextRuleArgs(fromSpec))) {
    throw new Error('the approved intent is not the rule this spec asks for; nothing was signed');
  }
  return intentArgs;
}
