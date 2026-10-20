import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { StrKey } from '@stellar/stellar-sdk';
import { RawJson } from './raw-json.mjs';
import { checkBundleArtifacts, bundleCheckRequest } from './permission-bundle.mjs';
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
function fixture() {
  const spec = JSON.parse(readFileSync(new URL('../native-sac-policy-spec.json', import.meta.url)));
  spec.registry_snapshot = 'ab'.repeat(32);
  spec.rules.push(structuredClone(spec.rules[0]));
  spec.rules[1].context.contract = C(2);
  const specHash = 'cd'.repeat(32);
  const artifacts = spec.rules.map((_rule, rule_index) => {
    const wasm = Buffer.from([0, 97, 115, 109, rule_index]);
    return { wasm, manifest: { rule_index, wasm_hash: createHash('sha256').update(wasm).digest('hex'),
      spec_hash: specHash, registry_snapshot: spec.registry_snapshot } };
  });
  const policies = [C(3), C(4)];
  return { spec, artifacts, policies, specHash, hashSpec: async () => specHash };
}
for (const change of ['matching', 'missing artifact', 'extra artifact', 'duplicate index', 'reordered artifacts', 'wrong spec', 'wrong root', 'wrong bytes']) {
  test(`permission bundle verifies every indexed artifact against the full spec: ${change}`, async () => {
    const f = fixture();
    if (change === 'missing artifact') f.artifacts.pop();
    if (change === 'extra artifact') f.artifacts.push(f.artifacts[0]);
    if (change === 'duplicate index') f.artifacts[1].manifest.rule_index = 0;
    if (change === 'reordered artifacts') f.artifacts.reverse();
    if (change === 'wrong spec') f.artifacts[1].manifest.spec_hash = 'ef'.repeat(32);
    if (change === 'wrong root') f.artifacts[1].manifest.registry_snapshot = 'ef'.repeat(32);
    if (change === 'wrong bytes') f.artifacts[1].wasm = Buffer.from('different');
    const pending = checkBundleArtifacts(f.spec, f.artifacts, { hashSpec: f.hashSpec });
    if (change === 'matching') assert.equal((await pending).length, 2);
    else await assert.rejects(pending, /bundle/);
  });
}
for (const change of ['matching', 'duplicate policy', 'missing policy', 'foreign spec hash', 'selected index', 'reviewed policy']) {
  test(`each bundle intent retains the complete indexed binding set: ${change}`, () => {
    const f = fixture();
    if (change === 'duplicate policy') f.policies[1] = f.policies[0];
    if (change === 'missing policy') f.policies.pop();
    if (change === 'foreign spec hash') f.artifacts[1].manifest.spec_hash = 'ef'.repeat(32);
    if (change === 'reviewed policy') f.spec.rules[1].policies = [{ reviewed: { kind: 'unknown' } }];
    const make = () => bundleCheckRequest({ ...f, ruleIndex: change === 'selected index' ? 2 : 1,
      signedRegistrySnapshot: new RawJson('{}'), rpcSource: 'testnet' });
    if (change === 'matching') {
      const request = make();
      assert.equal(request.spec, f.spec, 'the full spec is preserved');
      assert.equal(request.rule_index, 1);
      assert.deepEqual(request.binding_set.bindings.map((b) => [b.rule_index, b.policy_index, b.contract_address]), [[0, 0, C(3)], [1, 0, C(4)]]);
      assert.equal(request.binding_set.spec_hash, f.specHash);
    } else assert.throws(make, /bundle/);
  });
}
