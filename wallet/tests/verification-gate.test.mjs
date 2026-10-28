import test from 'node:test';
import assert from 'node:assert/strict';
import { verificationGate } from '../overlay/files/src/policy-builder/client/verification.mjs';
const bindings = { specHash: 'a'.repeat(64), wasmHash: 'b'.repeat(64), bindingSetHash: 'c'.repeat(64) };
function report() {
  return { ...bindings, runId: 'd'.repeat(64), complete: true, acceptance: { requiredRevertedDenials: 5, originalPermitted: true, meetsMinimum: true,
    executedLayers: [{ layer: 'account_wasm', status: 'passed', originalPermitted: true, revertedDenials: 5 },
      { layer: 'captured_target', status: 'passed', originalPermitted: true, revertedDenials: 2 }] }, layers: [
    'reference', 'account_wasm', 'captured_target', 'live_enforcement',
  ].map((layer) => ({ layer, status: 'passed' })) };
}
test('only the exact four passed bound layers enable final acceptance', () => {
  const value = report();
  assert.deepEqual(verificationGate(value, bindings), { localReady: true, offlineAcceptanceReady: true, acceptanceReady: true });
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
  assert.deepEqual(verificationGate(value, bindings), { localReady: true, offlineAcceptanceReady: true, acceptanceReady: false });
});
test('forged complete flag, duplicates, unknown layers or mismatched evidence fail closed', () => {
  for (const change of [
    (v) => { delete v.acceptance; },
    (v) => { v.acceptance.executedLayers = [null]; },
    (v) => { v.acceptance.executedLayers[0].layer = 'live_enforcement'; },
    (v) => { v.acceptance.executedLayers[1].layer = 'account_wasm'; },
    (v) => { v.acceptance.executedLayers[0].revertedDenials = -1; },
    (v) => { v.acceptance.executedLayers[0].revertedDenials = 5.5; },
    (v) => { v.acceptance.executedLayers[1].status = 'failed'; },
    (v) => { v.acceptance.executedLayers.pop(); },
    (v) => { v.acceptance.meetsMinimum = false; },
    (v) => { v.acceptance.executedLayers[0].revertedDenials = 4; },
    (v) => { v.acceptance.originalPermitted = false; },
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


test('the displayed offline bar rejects malformed minima and either layer missing its original permit', () => {
  for (const required of [undefined, 0, 4, 6, '5']) {
    const value = report(); value.acceptance.requiredRevertedDenials = required;
    const gate = verificationGate(value, bindings);
    assert.equal(gate.offlineAcceptanceReady, false);
    assert.equal(gate.acceptanceReady, false);
  }
  for (const index of [0, 1]) {
    const value = report(); value.acceptance.executedLayers[index].originalPermitted = false;
    const gate = verificationGate(value, bindings);
    assert.equal(gate.offlineAcceptanceReady, false);
    assert.equal(gate.acceptanceReady, false);
  }
});
