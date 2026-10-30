import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { dryRunAcceptance, predictedRefusal } from '../shared/dry-run.mjs';
const vectors = JSON.parse(readFileSync(new URL('../../docs/examples/native-refusal-vectors.json', import.meta.url)));
test('wallet refusal attribution matches the shared Rust coordinator vectors', () => {
  for (const mutation of vectors.classes) for (const enforcer of vectors.enforcers) for (const code of vectors.codes) {
    const tuple = [mutation, enforcer, code];
    assert.equal(predictedRefusal(...tuple), vectors.allowed.some((allowed) => JSON.stringify(allowed) === JSON.stringify(tuple)), JSON.stringify(tuple));
  }
  for (const code of [-1, 0.5, '6', null, NaN, 4294967296]) assert.equal(predictedRefusal('arg_equality', 'policy', code), false);
});
const passing = () => [ { layer: 'reference', status: 'passed' },
  { layer: 'account_wasm', status: 'passed', evidence: { caseResults: [
    { class: 'original', expectedPermit: true, permitted: true, agree: true },
    ...Array.from({ length: 5 }, () => ({ class: 'arg_equality', expectedPermit: false, permitted: false, agree: true,
      refusedBy: 'policy', refusalCode: 6, stateUnchanged: true })),
  ] } }, { layer: 'captured_target', status: 'unavailable' }, { layer: 'live_enforcement', status: 'unavailable' } ];
test('original plus five denials in one executed layer meets the offline bar while live remains unavailable', () => {
  const result = dryRunAcceptance(passing());
  assert.equal(result.meetsMinimum, true); assert.equal(result.executedLayers[0].revertedDenials, 5);
  assert.equal(result.requiredRevertedDenials, 5);
});
for (const [name, change] of [
  ['missing original', (l) => { l[1].evidence.caseResults.shift(); }],
  ['a permitted mutation in place of the original', (l) => { l[1].evidence.caseResults[0].class = 'arg_equality'; }],
  ['four denials', (l) => { l[1].evidence.caseResults.pop(); }],
  ['wrong refusal code', (l) => { l[1].evidence.caseResults[1].refusalCode = 7; }],
  ['wrong refusal enforcer', (l) => { l[1].evidence.caseResults[1].refusedBy = 'account'; }],
  ['changed denied state', (l) => { l[1].evidence.caseResults[1].stateUnchanged = false; }],
  ['failed account', (l) => { l[1].status = 'failed'; }],
  ['failed reference', (l) => { l[0].status = 'failed'; }],
  ['failed second executed layer', (l) => { l[2].status = 'failed'; }],
  ['empty evidence', (l) => { delete l[1].evidence.caseResults; }],
]) test(`acceptance refuses ${name}`, () => {
  const layers = passing(); change(layers); assert.equal(dryRunAcceptance(layers).meetsMinimum, false);
});
test('denials from different layers do not add up to the per-layer minimum', () => {
  const layers = passing();
  layers[1].evidence.caseResults.pop();
  layers[2] = { ...structuredClone(layers[1]), layer: 'captured_target' };
  assert.equal(dryRunAcceptance(layers).meetsMinimum, false);
});
