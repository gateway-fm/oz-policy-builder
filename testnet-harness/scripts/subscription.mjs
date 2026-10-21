// Exact W2 composition. The short period is an explicit test setting, not a billing default.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { StrKey } from '@stellar/stellar-sdk';
import { isMainModule } from './cli-entry.mjs';
import * as rpc from './rpc.mjs';

export const SPENDING_LIMIT_WASM = '4e67aa6ca226d3c16106ff2d95f3b44a8efabc2f2a7655683957e3553ed6a40c';
export const SPENDING_MODEL_GAP = ['rule[0]: oz:spending_limit'];
const requireThat = (condition, message) => { if (!condition) throw new Error(message); };

export function subscriptionConfig(run) {
  if (run.subscription === undefined) return null;
  const config = run.subscription;
  requireThat(config?.schema_version === 1 && config.mode === 'short_test_window', 'invalid subscription configuration');
  requireThat(Number.isSafeInteger(config.period_ledgers) && config.period_ledgers >= 12
    && config.period_ledgers <= 120, 'subscription test period must be 12..120 ledgers');
  requireThat(StrKey.isValidContract(config.policy_address) && ![run.account, run.sac, run.policy].includes(config.policy_address),
    'subscription policy must be a separate contract');
  requireThat(config.policy_code_hash === SPENDING_LIMIT_WASM, 'unrecognized subscription policy code');
  return config;
}

/** Full binding in spec order, independent of the address ordering required by Soroban maps. */
export function composedPolicies(run, spec, generatedAddress) {
  const config = subscriptionConfig(run);
  const policies = spec.rules?.[0]?.policies;
  const expected = config ? 2 : 1;
  requireThat(Array.isArray(policies) && policies.length === expected, 'unexpected policy composition');
  let generated = 0; let spending = 0;
  const result = policies.map((policy) => {
    if (policy.generated?.kind === 'gen:scope+count' && Object.keys(policy).length === 1) {
      generated++;
      return { address: generatedAddress, install_params: { kind: 'generated' } };
    }
    if (config && policy.reviewed?.kind === 'oz:spending_limit' && Object.keys(policy).length === 1) {
      spending++;
      assert.equal(policy.reviewed.capability, SPENDING_LIMIT_WASM, 'subscription capability differs');
      assert.deepEqual(policy.reviewed.params, { spending_limit: { limit: run.amount, period_ledgers: config.period_ledgers } },
        'subscription parameters differ');
      return { address: config.policy_address, install_params: { kind: 'spending_limit',
        spending_limit: run.amount, period_ledgers: config.period_ledgers } };
    }
    throw new Error('unsupported policy composition');
  });
  requireThat(generated === 1 && spending === (config ? 1 : 0), 'duplicate or missing composed policy');
  requireThat(new Set(result.map((p) => p.address)).size === result.length, 'duplicate policy address');
  return result;
}

export async function configureSubscription(dir, { policy, period }, deps = rpc) {
  const path = join(dir, 'run.json');
  const run = deps.readJson(path);
  requireThat(run.subscription === undefined, 'subscription is already configured');
  run.subscription = { schema_version: 1, mode: 'short_test_window', period_ledgers: Number(period),
    policy_address: policy, policy_code_hash: SPENDING_LIMIT_WASM };
  subscriptionConfig(run);
  requireThat(run.network === rpc.NETWORK_PASSPHRASE && run.sac === rpc.NATIVE_SAC, 'W2 requires the testnet native SEP-41 contract');
  await deps.assertTestnet();
  const observed = await deps.contractCodeObservation(policy);
  requireThat(observed.value === SPENDING_LIMIT_WASM, 'live spending policy code differs');
  run.subscription.code_observed_ledger = observed.ledger;
  deps.writeJson(path, run);
  return run.subscription;
}

if (isMainModule(import.meta.url)) {
  const options = rpc.args();
  requireThat(options['run-dir'] && options.policy && options['period-ledgers'],
    'usage: subscription.mjs --run-dir DIRECTORY --policy CONTRACT --period-ledgers 12..120');
  await configureSubscription(options['run-dir'], { policy: options.policy, period: options['period-ledgers'] });
}
