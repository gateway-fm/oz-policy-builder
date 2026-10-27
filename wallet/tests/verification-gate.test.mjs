import test from 'node:test';
import assert from 'node:assert/strict';
import { verificationGate } from '../overlay/files/src/policy-builder/client/verification.mjs';
const bindings = { specHash: 'a'.repeat(64), wasmHash: 'b'.repeat(64), bindingSetHash: 'c'.repeat(64) };
function report() {
  return { ...bindings, runId: 'd'.repeat(64), complete: true, layers: [
    'reference', 'account_wasm', 'captured_target', 'live_enforcement',
  ].map((layer) => ({ layer, status: 'passed' })) };
}
test('only the exact four passed bound layers enable final acceptance', () => {
  const value = report();
  assert.deepEqual(verificationGate(value, bindings), { localReady: true, acceptanceReady: true });
  for (const layer of value.layers) {
    layer.status = 'unavailable';
    assert.equal(verificationGate(value, bindings).acceptanceReady, false);
    layer.status = 'passed';
  }
});
test('first three layers remain distinct from unavailable live enforcement', () => {
  const value = report();
  value.complete = false;
  value.layers[3].status = 'unavailable';
  assert.deepEqual(verificationGate(value, bindings), { localReady: true, acceptanceReady: false });
});
test('forged complete flag, duplicates, unknown layers or mismatched evidence fail closed', () => {
  for (const change of [
    (v) => v.layers.pop(),
    (v) => v.layers.push(v.layers[0]),
    (v) => { v.layers[3].layer = 'installation_preflight'; },
    (v) => { v.layers[2].status = 'unsupported'; },
    (v) => { v.specHash = 'd'.repeat(64); },
    (v) => { delete v.wasmHash; },
    (v) => { delete v.bindingSetHash; },
    (v) => { delete v.runId; },
    (v) => { v.complete = 'true'; },
  ]) {
    const value = report(); change(value);
    assert.equal(verificationGate(value, bindings).acceptanceReady, false);
  }
  assert.equal(verificationGate(report(), { ...bindings, bindingSetHash: undefined }).acceptanceReady, false);
});
