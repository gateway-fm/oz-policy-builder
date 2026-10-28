const LAYERS = ['reference', 'account_wasm', 'captured_target', 'live_enforcement'];
const HASH = /^[0-9a-f]{64}$/;
const closed = () => ({ localReady: false, acceptanceReady: false });

/** Installation preflight is never counted as behavioral live-enforcement evidence. */
export function verificationGate(report, expected) {
  if (!report || !expected || !/^[0-9a-f]{32,128}$/.test(report.runId ?? '')
    || !Array.isArray(report.layers) || report.layers.length !== LAYERS.length) return closed();
  for (const name of ['specHash', 'wasmHash', 'bindingSetHash']) {
    if (!HASH.test(expected[name] ?? '') || report[name] !== expected[name]) return closed();
  }
  const byName = new Map(report.layers.map((item) => [item?.layer, item?.status]));
  if (byName.size !== LAYERS.length || LAYERS.some((name) =>
    !['passed', 'failed', 'unavailable', 'unsupported'].includes(byName.get(name)))) return closed();
  const acceptance = report.acceptance;
  const executed = acceptance?.executedLayers;
  const expectedExecuted = ['account_wasm', 'captured_target'].filter((name) => ['passed', 'failed'].includes(byName.get(name)));
  const minimum = acceptance?.meetsMinimum === true && acceptance.originalPermitted === true
    && acceptance.requiredRevertedDenials === 5 && Array.isArray(executed)
    && executed.length === expectedExecuted.length && executed.length > 0
    && executed.every((l, index) => l && typeof l === 'object' && l.layer === expectedExecuted[index]
      && l.status === byName.get(l.layer) && l.status === 'passed' && l.originalPermitted === true
      && Number.isSafeInteger(l.revertedDenials) && l.revertedDenials >= 0)
    && executed.some((l) => l.revertedDenials >= 5);
  const localReady = LAYERS.slice(0, 3).every((name) => byName.get(name) === 'passed');
  return { localReady, acceptanceReady: minimum && localReady && byName.get('live_enforcement') === 'passed' && report.complete === true };
}
