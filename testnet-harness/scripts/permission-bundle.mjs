// Preserve the full synthesized spec and every indexed policy binding for each separate install.
// W1 has one capability; W3 has two independent capabilities, never an atomic workflow grant.
import { createHash } from 'node:crypto';
import { cliSpecHash } from './check-runner.mjs';
import { checkRequest } from './wallet-decision.mjs';
const requireThat = (condition) => { if (!condition) throw new Error('invalid permission bundle'); };
const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
function shape(spec, artifacts) {
  requireThat(Array.isArray(spec?.rules) && spec.rules.length >= 1 && spec.rules.length <= 2
    && Array.isArray(artifacts) && artifacts.length === spec.rules.length);
  for (const [i, rule] of spec.rules.entries()) {
    requireThat(rule.policies?.length === 1 && rule.policies[0].generated?.kind === 'gen:scope+count');
    const manifest = artifacts[i]?.manifest;
    requireThat(manifest?.rule_index === i && hash(manifest.spec_hash) && hash(manifest.wasm_hash)
      && manifest.registry_snapshot === spec.registry_snapshot && manifest.spec_hash === artifacts[0].manifest.spec_hash);
  }
}

export async function checkBundleArtifacts(spec, artifacts, { hashSpec = cliSpecHash } = {}) {
  shape(spec, artifacts);
  const specHash = await hashSpec(spec);
  requireThat(hash(specHash));
  return artifacts.map(({ wasm, manifest }, index) => {
    requireThat(manifest.spec_hash === specHash && Buffer.isBuffer(wasm)
      && createHash('sha256').update(wasm).digest('hex') === manifest.wasm_hash);
    return { rule_index: index, wasm_hash: manifest.wasm_hash, spec_hash: specHash };
  });
}

export function bundleCheckRequest({ spec, artifacts, policies, ruleIndex, signedRegistrySnapshot, rpcSource }) {
  shape(spec, artifacts);
  requireThat(Number.isInteger(ruleIndex) && ruleIndex >= 0 && ruleIndex < spec.rules.length
    && Array.isArray(policies) && policies.length === spec.rules.length && new Set(policies).size === policies.length);
  const requests = artifacts.map(({ manifest }, index) => {
    try {
      return checkRequest({ spec, manifest, ruleIndex: index, policyAddress: policies[index], signedRegistrySnapshot, rpcSource,
        resolutionReference: `permission bundle generated policy at rule ${index}` });
    } catch { throw new Error('invalid permission bundle binding'); }
  });
  const selected = requests[ruleIndex];
  return { ...selected, binding_set: { ...selected.binding_set,
    bindings: requests.flatMap((request) => request.binding_set.bindings) } };
}
