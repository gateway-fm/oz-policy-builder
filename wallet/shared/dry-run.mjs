// The coordinator's own refusal attribution, kept independent of the native worker's verdict.
// Shared conformance vectors also exercise the Rust coordinator's copy of this contract.
export function predictedRefusal(mutation, enforcer, code) {
  if (!Number.isSafeInteger(code) || code < 0 || code > 0xffffffff) return false;
  if (enforcer === 'account') {
    if (['different_contract', 'time_boundary'].includes(mutation)) return code === 3002;
    return ['wrong_signer', 'signer_boundary', 'strict_set_mutation'].includes(mutation) && code === 3016;
  }
  if (enforcer !== 'policy') return false;
  if (['wrong_signer', 'signer_boundary'].includes(mutation)) return code >= 1 && code <= 3;
  const expected = { zero_signers: 1, strict_set_mutation: 3, different_function: 5,
    arg_equality: 6, numeric_boundary: 6, different_address_arg: 6, arg_arity: 6, type_confusion: 6,
    tuple_cross_product: 6, call_count_boundary: 7, missing_state: 8, time_boundary: 9 };
  return Object.hasOwn(expected, mutation) && code === expected[mutation];
}

/** Same offline permit/deny bar as the CLI; full wallet installation remains a separate gate. */
export function dryRunAcceptance(layers) {
  const executedLayers = layers.filter((l) => ['account_wasm', 'captured_target'].includes(l.layer)
    && (l.status === 'failed' || l.evidence?.caseResults !== undefined)).map((layer) => {
    const passed = layer.status === 'passed', cases = layer.evidence?.caseResults ?? [];
    return { layer: layer.layer, status: layer.status,
      originalPermitted: passed && cases.some((c) => c.class === 'original' && c.expectedPermit === true
        && c.permitted === true && c.agree === true),
      revertedDenials: passed ? cases.filter((c) => c.expectedPermit === false && c.permitted === false
        && c.agree === true && c.stateUnchanged === true && predictedRefusal(c.class, c.refusedBy, c.refusalCode)).length : 0 };
  });
  const originalPermitted = executedLayers.length > 0 && executedLayers.every((l) => l.status === 'passed' && l.originalPermitted);
  return { requiredRevertedDenials: 5, originalPermitted, executedLayers,
    meetsMinimum: layers.find((l) => l.layer === 'reference')?.status === 'passed' && originalPermitted
      && executedLayers.some((l) => l.revertedDenials >= 5) };
}
