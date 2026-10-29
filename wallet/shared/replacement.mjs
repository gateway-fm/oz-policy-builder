import { StrKey } from '#wallet-stellar-sdk';
import { freezeCopy } from './approval.mjs';
const HASH = /^[0-9a-f]{64}$/;
/** No authority is added by this consent; the next grant still needs fresh review and owner signing. */
export function replacementConsent({ installation, removal }) {
  if (!installation || !StrKey.isValidContract(installation.account) || !HASH.test(installation.installationId ?? '')
    || !HASH.test(installation.transactionHash ?? '') || !Number.isSafeInteger(installation.ruleId)
    || installation.ruleId < 1 || installation.ruleId > 0xffffffff
    || removal?.status !== 'removed' || removal.event !== 'verified' || removal.ruleReadback !== 'absent'
    || removal.ruleId !== installation.ruleId || !HASH.test(removal.transactionHash ?? '')) {
    throw new Error('wallet replacement refused; verify removal first');
  }
  return freezeCopy({ schema: 'wallet-revoke-first-replacement/v1', account: installation.account,
    previousInstallationId: installation.installationId, previousRuleId: installation.ruleId,
    installationTransactionHash: installation.transactionHash, removalTransactionHash: removal.transactionHash,
    budget: 'previously_used_authority_plus_new_cap',
    warning: 'The old rule is removed. A replacement starts a fresh per-installation budget; authority already used '
      + 'under the old rule is additional to the new grant. Review and run all checks again before installing.' });
}
