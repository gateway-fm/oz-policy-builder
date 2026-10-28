// Shared browser-compatible authority decision; harness-only request construction follows.
export { TRUST_OWN, TRUST_OPERATOR, identityKey, walletTrust, decide, intentMismatches, recheck, confirmationScreen } from '../../wallet/shared/authority.mjs';
import { RawJson } from './raw-json.mjs';
import { StrKey } from '@stellar/stellar-sdk';
const isHash = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);

/** Throw if `value` holds a number JSON.stringify would not write back exactly. */
function assertExactNumbers(value, what) {
  if (typeof value === 'number' && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) {
    throw new Error(`${what} holds ${value}, a number this harness cannot pass on exactly`);
  }
  if (value && typeof value === 'object') for (const v of Object.values(value)) assertExactNumbers(v, what);
}

/**
 * The `CheckPolicyCallSurfaceInput` (= `PrepareInstallIntentInput`) for one generated policy,
 * bound by its own build manifest. Everything the tool would refuse with
 * `E_POLICY_BINDING_INVALID` before reading is refused here first, so a misconfigured run fails
 * with a reason rather than a code:
 *   - the spec must name a signed registry root (`registry_snapshot`), and the check must be given
 *     that signed snapshot; a zero root is refused;
 *   - the spec must be the one the manifest was generated from (same root and rule), sent as is;
 *   - the manifest goes unmodified, with its canonical `spec_hash`, not recomputed here;
 *   - each binding carries a non-empty `resolution_reference` (here, the policy's deploy tx);
 *   - account and network are the spec's own;
 *   - the signed snapshot goes as raw JSON, byte for byte, and nothing else re-serialized here
 *     may hold a number JavaScript cannot represent exactly.
 */
export function checkRequest({ spec, ruleIndex, manifest, policyAddress, resolutionReference, signedRegistrySnapshot, rpcSource,
  reviewedPolicies = [] }) {
  if (!(signedRegistrySnapshot instanceof RawJson)) throw new Error('the signed registry snapshot must be passed as raw JSON (RawJson)');
  assertExactNumbers(spec, 'the spec');
  assertExactNumbers(manifest, 'the build manifest');
  if (manifest.rule_index !== ruleIndex) throw new Error(`the manifest is for rule ${manifest.rule_index}, not rule ${ruleIndex}`);
  if (!isHash(manifest.spec_hash) || !isHash(manifest.wasm_hash)) throw new Error('the manifest lacks a lowercase spec or wasm hash');
  if (!isHash(spec.registry_snapshot) || /^0+$/.test(spec.registry_snapshot)) {
    throw new Error('the spec names no signed registry root (registry_snapshot); the check refuses a zero root');
  }
  if (manifest.registry_snapshot !== spec.registry_snapshot) throw new Error('the spec is not the one the manifest was generated from');
  const account = spec.smart_account?.address;
  if (!StrKey.isValidContract(policyAddress) || !StrKey.isValidContract(account ?? '')) throw new Error('policy and account must be contract addresses');
  if (policyAddress === account) throw new Error('the policy binding is at the account address');
  if (!String(resolutionReference ?? '').trim()) throw new Error('a binding needs a non-empty resolution reference');
  if (!isHash(spec.network_id)) throw new Error('the spec has no network id');
  const policies = spec.rules?.[ruleIndex]?.policies;
  if (!Array.isArray(policies)) throw new Error('missing spec policies');
  const used = new Set();
  let generated = 0;
  const bindings = policies.map((policy, policyIndex) => {
    const reviewed = reviewedPolicies.find((p) => p.policy_index === policyIndex);
    if (policy.generated?.kind === 'gen:scope+count') {
      if (reviewed) throw new Error('reviewed binding supplied for generated policy');
      generated++;
      return { rule_index: ruleIndex, policy_index: policyIndex, contract_address: policyAddress,
        observed_wasm_hash: manifest.wasm_hash, recognition: { kind: 'verified_generated_manifest', build_manifest: manifest },
        resolution_reference: resolutionReference };
    }
    if (!reviewed || policy.reviewed?.kind !== 'oz:spending_limit'
      || reviewed.observed_wasm_hash !== policy.reviewed.capability || !isHash(reviewed.observed_wasm_hash)
      || !StrKey.isValidContract(reviewed.contract_address) || reviewed.contract_address === account
      || !String(reviewed.resolution_reference ?? '').trim()) throw new Error('missing or mismatched reviewed binding');
    used.add(reviewed);
    return { rule_index: ruleIndex, policy_index: policyIndex, contract_address: reviewed.contract_address,
      observed_wasm_hash: reviewed.observed_wasm_hash, resolution_reference: reviewed.resolution_reference,
      recognition: { kind: 'reviewed_registry' } };
  });
  if (generated !== 1 || used.size !== reviewedPolicies.length
    || new Set(bindings.map((p) => p.contract_address)).size !== bindings.length) throw new Error('duplicate or extra policy binding');
  return {
    spec,
    rule_index: ruleIndex,
    binding_set: {
      schema: 'policy-binding-set/v1',
      spec_hash: manifest.spec_hash,
      network_id: spec.network_id,
      bindings,
    },
    signed_registry_snapshot: signedRegistrySnapshot,
    account_address: account,
    network_id: spec.network_id,
    rpc_source: rpcSource,
  };
}
