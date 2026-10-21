// The wallet's side of the pre-install authority check: what the harness, holding the owner key,
// decides from `check_policy_call_surface` / `prepare_install_intent` output. Pure: no network,
// no clock, no keys.
//
// The tool never says the install is safe; it lists who can change the account or the bound
// policy, refuses what it can rule out on its own, and leaves the rest to the wallet. The wallet
// accepts only when all of these hold (the check's output contract, "the wallet decision"):
//
//   1. nothing is refused;
//   2. nothing is unresolved;
//   3. every authority entry, always `all_of(S)`, has at least one trusted signer in S. Trusted
//      means the wallet's own keys plus identities the operator trusts, minus any identity the
//      tool marks as aliasing the restricted key (and minus the grant's own signers, which the
//      wallet removes itself as well);
//   4. a fresh re-run just before signing returns the identical `authority_commitment`, and is
//      itself accepted under (1)-(3).
//
// In this harness the operator's trust comes from a file or a flag, so it is labelled
// "operator-supplied test configuration": it is not evidence that a human approved anything, nor
// that an agent with the same shell could not have approved itself. A real wallet's protected
// approval UI is what that claim needs.
import { StrKey } from '@stellar/stellar-sdk';

import { RawJson } from './raw-json.mjs';

export const TRUST_OWN = 'own key';
export const TRUST_OPERATOR = 'operator-supplied test configuration';

const HEX = /^[0-9a-f]*$/;
const hexOf = (value, what) => {
  const h = String(value).toLowerCase();
  if (!HEX.test(h) || h.length % 2) throw new Error(`${what} is not hex`);
  return h;
};
const isHash = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);

function canonical(scheme, publicKey) {
  const h = hexOf(publicKey, `${scheme} key`);
  if (scheme === 'ed25519') {
    if (h.length !== 64) throw new Error('an ed25519 key must be a 32-byte key');
    return `ed25519:${h}`;
  }
  if (scheme === 'webauthn_p256') {
    if (h.length !== 130) throw new Error('a WebAuthn key must be the 65-byte P-256 point');
    if (!h.startsWith('04')) throw new Error('a WebAuthn key must be an uncompressed point (04 ‖ X ‖ Y)');
    return `webauthn_p256:${h}`;
  }
  throw new Error(`unknown key scheme ${scheme}`);
}

const classicKey = (address) => {
  if (!StrKey.isValidEd25519PublicKey(address ?? '')) throw new Error(`${address} is not a classic account`);
  return `ed25519:${Buffer.from(StrKey.decodeEd25519PublicKey(address)).toString('hex')}`;
};

/**
 * The identity a signer stands for: scheme and canonical key. The verifier address is not part
 * of it (the same key behind another copy of the verifier is the same signer), and an ed25519 key
 * behind a verifier is the same identity as the classic account with that key.
 */
export function identityKey(identity) {
  if (identity?.kind === 'classic_account') {
    const key = canonical('ed25519', identity.ed25519_public_key);
    if (key !== classicKey(identity.address)) throw new Error(`classic account ${identity.address} does not match its stated key`);
    return key;
  }
  if (identity?.kind === 'external') return canonical(identity.scheme, identity.public_key);
  throw new Error(`unknown identity kind ${identity?.kind}`);
}

/**
 * The key material of the grant's own signers, the restricted key. The check calls two keys the
 * same when their bytes are equal or share the first 32 bytes (an ed25519 key; a WebAuthn key with
 * another credential id), deliberately over-approximating; the wallet uses the same test, so it
 * never trusts what the check would call the agent.
 */
function restrictedMaterial(grant) {
  return grant.signers.map((s) => {
    if (s.kind === 'delegated') {
      return StrKey.isValidEd25519PublicKey(s.address) ? Buffer.from(StrKey.decodeEd25519PublicKey(s.address)) : `opaque:${s.address}`;
    }
    if (s.kind === 'external') return Buffer.from(hexOf(s.key_hex, 'grant signer key'), 'hex');
    throw new Error(`unknown grant signer kind ${s.kind}`);
  });
}

const materialOf = (key) => Buffer.from(key.split(':')[1], 'hex');
const aliases = (a, b) => (Buffer.isBuffer(a) && Buffer.isBuffer(b)
  ? a.equals(b) || (a.length >= 32 && b.length >= 32 && a.subarray(0, 32).equals(b.subarray(0, 32)))
  : a === b);

/**
 * The wallet's trusted keys, each with where the trust came from. `own`: keys the wallet holds.
 * `operator`: identities the operator trusts by configuration. Entries are
 * `{ scheme, public_key }` or `{ classic_account: 'G…' }`.
 */
export function walletTrust({ own = [], operator = [] } = {}) {
  const trust = new Map();
  const keyOf = (t) => (t.classic_account ? classicKey(t.classic_account) : canonical(t.scheme, t.public_key));
  for (const t of operator) trust.set(keyOf(t), TRUST_OPERATOR);
  for (const t of own) trust.set(keyOf(t), TRUST_OWN);
  return trust;
}

const describe = (identity) => (identity.kind === 'classic_account'
  ? `classic account ${identity.address}`
  : `${identity.scheme === 'webauthn_p256' ? 'passkey (WebAuthn P-256)' : 'ed25519 key'} ${String(identity.public_key).slice(0, 16)}… via verifier ${identity.verifier}`);

const reachText = (reach) => ({
  any_call: 'any call',
  account_calls: 'calls to the account itself',
  policy: `calls to policy ${reach.address}`,
}[reach?.kind] ?? `unknown reach ${reach?.kind}`);

/**
 * Decide on one check answer (`CheckPolicyCallSurfaceOutput`). `expect` is what the harness is
 * installing: `{ account, networkId, target, boundPolicies, ruleIndex, specHash,
 * registrySnapshotRoot }`; an answer about anything else is refused. (`binding_set_hash` is
 * computed by the tool and covered by the commitment; the wallet does not recompute it.) Returns `{ accept, reasons, entries, commitment }`; `entries` says, per authority
 * entry, which signers count and why, for the confirmation screen.
 */
export function decide(check, { trust, expect }) {
  const reasons = [];
  const entries = [];
  const v = check?.verdict;
  if (!v) return { accept: false, reasons: ['the answer has no verdict'], entries, commitment: null };

  // The answer must be about this install.
  const same = (got, want, what) => { if (got !== want) reasons.push(`the answer is about ${what} ${got}, not ${want}`); };
  same(v.account_address, expect.account, 'account');
  same(v.network_id, expect.networkId, 'network');
  same(v.grant?.target, expect.target, 'target');
  same(JSON.stringify(v.bound_policy_addresses), JSON.stringify(expect.boundPolicies), 'bound policies');
  if (expect.ruleIndex !== undefined) same(v.grant?.rule_index, expect.ruleIndex, 'spec rule');
  if (expect.specHash !== undefined) {
    same(check.spec_hash, expect.specHash, 'spec');
    same(v.spec_hash, expect.specHash, 'spec');
  }
  if (expect.registrySnapshotRoot !== undefined) same(check.registry_snapshot_root, expect.registrySnapshotRoot, 'registry root');
  // What the answer claims to cover must be exactly this install's target, account and policies.
  same(canonicalJson(v.scope), canonicalJson({ targets: [expect.target], account: expect.account, bound_policies: expect.boundPolicies }), 'scope');
  // The intent refuses these before it reads anything; a plain check only after. Refuse anyway.
  if (v.grant?.target === v.account_address) reasons.push('the grant targets the account itself: the agent could manage it');
  if ((v.bound_policy_addresses ?? []).includes(v.grant?.target)) reasons.push('the grant targets its own policy: the agent could reset it');
  // Expiry is outside the commitment, so it is judged at the ledger this answer was read.
  if (v.grant?.valid_until !== null && !(v.grant?.valid_until > v.observed_ledger)) {
    reasons.push(`the grant expires at ledger ${v.grant?.valid_until}, not after ledger ${v.observed_ledger} where this answer was read`);
  }
  if (!isHash(v.authority_commitment)) reasons.push('the answer has no well-formed authority_commitment');
  // The tool never says "safe"; output that does is not the tool's output.
  if (/\bsafe/i.test(check.summary ?? '')) reasons.push('the summary claims "safe", which the tool never does: malformed output');

  // 1, 2: refusals and unresolved items block, and no trust overrides them.
  for (const f of v.refusals ?? []) reasons.push(`refused: ${f.code} (${f.rule_id === null ? 'the new rule' : `rule ${f.rule_id}`}): ${f.reason}`);
  for (const f of v.unresolved ?? []) reasons.push(`unresolved: ${f.code} (${f.rule_id === null ? 'the new rule' : `rule ${f.rule_id}`}): ${f.reason}`);
  if (!Array.isArray(v.refusals) || !Array.isArray(v.unresolved)) reasons.push('the answer lacks refusals or unresolved');

  // 3: every rule that can change the account or the bound policy needs a trusted signer.
  let restricted;
  try {
    restricted = restrictedMaterial(v.grant);
  } catch (e) {
    reasons.push(`the grant's signers cannot be read: ${e.message}`);
    restricted = [];
  }
  const list = v.authority_list ?? [];
  // A key the check marks as the agent's anywhere is the agent's everywhere, under the same
  // aliasing test as the grant's own signers.
  const flagged = [];
  for (const entry of [...list, ...(v.notes?.target_rules ?? [])]) {
    for (const identity of entry.requirement?.signers ?? []) {
      if (identity?.aliases_restricted_key) {
        try { flagged.push(materialOf(identityKey(identity))); } catch { /* reported where it is evaluated */ }
      }
    }
  }
  // An empty list would satisfy "every entry" vacuously. No rule able to manage the account
  // means nobody could sign this install either, so refuse rather than accept on nothing.
  if (list.length === 0) reasons.push('no rule can manage the account or the bound policy; refusing rather than accepting on an empty list');
  for (const entry of list) {
    const row = { rule_id: entry.rule_id, reach: reachText(entry.reach), valid_until: entry.valid_until ?? null, signers: [] };
    entries.push(row);
    if (entry.requirement?.kind !== 'all_of') {
      reasons.push(`rule ${entry.rule_id}: requirement ${entry.requirement?.kind} cannot be evaluated by this wallet`);
      continue;
    }
    for (const identity of entry.requirement.signers ?? []) {
      const s = { label: null, trusted_by: null, excluded: null };
      row.signers.push(s);
      try {
        s.label = describe(identity);
        const key = identityKey(identity);
        const material = materialOf(key);
        if (identity.aliases_restricted_key || flagged.some((f) => aliases(material, f))) s.excluded = 'aliases the restricted key';
        else if (restricted.some((r) => aliases(material, r))) s.excluded = 'shares key material with the grant\'s own signer';
        else s.trusted_by = trust.get(key) ?? null;
      } catch (e) {
        s.label ??= `unreadable signer (${identity?.kind})`;
        s.excluded = `malformed: ${e.message}`;
        reasons.push(`rule ${entry.rule_id}: malformed signer: ${e.message}`);
      }
    }
    if (!row.signers.some((s) => s.trusted_by)) {
      reasons.push(`rule ${entry.rule_id} (${row.reach}) needs none of this wallet's trusted keys: whoever holds it could change the grant`);
    }
  }
  return {
    accept: reasons.length === 0,
    reasons,
    entries,
    commitment: isHash(v.authority_commitment) ? v.authority_commitment : null,
    observedLedger: v.observed_ledger,
  };
}

/** JSON with object keys sorted, so key order is no difference; a missing field stays missing. */
function canonicalJson(value) {
  if (value === undefined) return 'undefined';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/**
 * Every way the intent's `add_context_rule` arguments differ from the grant the check covered.
 * The commitment covers the grant, so only arguments equal to it are covered by the approval.
 */
export function intentMismatches(intent) {
  const out = [];
  const v = intent?.authority?.verdict;
  const g = v?.grant;
  if (!g) return ['the intent carries no checked grant'];
  const eq = (field, got, want) => { if (canonicalJson(got) !== canonicalJson(want)) out.push(`${field} ${JSON.stringify(got)} is not the checked ${JSON.stringify(want)}`); };
  eq('operation', intent.operation, 'add_context_rule');
  eq('account_contract', intent.account_contract, v.account_address);
  eq('context_contract', intent.context_contract, g.target);
  eq('rule_name', intent.rule_name, g.name);
  eq('valid_until_ledger', intent.valid_until_ledger, g.valid_until);
  eq('delegate_signers', intent.delegate_signers, g.signers);
  if (!Array.isArray(g.policies)) out.push('the checked grant has no policies');
  else eq('policies', intent.policies, g.policies.map((p, i) => ({ policy_index: i, address: p.address, install_params: p.install_params })));
  return out;
}

/**
 * The pre-sign re-check: the fresh answer must itself be accepted, and carry the commitment the
 * approval was given for. Ledger, evidence and summary may differ; they are outside it.
 */
export function recheck(approved, fresh, { trust, expect }) {
  if (!approved?.accept || !approved.commitment) return { accept: false, reasons: ['nothing was approved'] };
  const decision = decide(fresh, { trust, expect });
  const reasons = [...decision.reasons];
  if (decision.commitment !== approved.commitment) {
    reasons.push(`the authority state or the install changed since it was approved (commitment ${decision.commitment ?? 'none'}, approved ${approved.commitment}): ask again`);
  }
  // A fresh read is never older than the one approved.
  if (!(decision.observedLedger >= approved.observedLedger)) {
    reasons.push(`the re-check read ledger ${decision.observedLedger}, older than the approved ledger ${approved.observedLedger}`);
  }
  return { accept: reasons.length === 0, reasons };
}

const signerText = (s) => (s.kind === 'delegated' ? s.address : `external key ${String(s.key_hex).slice(0, 16)}… via ${s.verifier}`);
const findingText = (f) => `${f.code} (${f.rule_id === null ? 'the new rule' : `rule ${f.rule_id}`}): ${f.reason} Fix: ${f.remediation}`;

/** The screen the operator confirms. Plain words; it never says "safe". */
export function confirmationScreen({ check, decision }) {
  const v = check?.verdict ?? {};
  const g = v.grant ?? {};
  const list = (items, text) => (Array.isArray(items) && items.length ? items.map(text).join(', ') : '(missing)');
  const lines = [];
  lines.push('The authority check says (its own words):');
  for (const l of String(check?.summary ?? '').trim().split('\n')) lines.push(`  ${l}`);
  lines.push('');
  lines.push(`Install into account ${v.account_address}, read at ledger ${v.observed_ledger}:`);
  lines.push(`  rule "${g.name}" for ${list(g.signers, signerText)}: calls to ${g.target}, ` +
    `${g.valid_until === null ? 'no expiry' : `until ledger ${g.valid_until}`}, ` +
    `enforced by ${list(g.policies, (p) => `${p.address} (${p.install_params?.kind})`)}`);
  lines.push(`  The check covers only: the target ${list(v.scope?.targets, String)}, the account's own management, ` +
    `and the bound policies ${list(v.scope?.bound_policies, String)}. Rules for other contracts are not analysed.`);
  lines.push('');
  lines.push('Who can change the account or the bound policy:');
  for (const e of decision.entries) {
    lines.push(`  rule ${e.rule_id} (${e.reach}${e.valid_until === null ? '' : `, until ledger ${e.valid_until}`}) needs ALL of:`);
    for (const s of e.signers) {
      const mark = s.excluded ? `✗ excluded: ${s.excluded}` : s.trusted_by ? `✓ trusted: ${s.trusted_by}` : '⚠ not trusted by this wallet';
      lines.push(`    - ${s.label}  ${mark}`);
    }
  }
  if (decision.entries.length === 0) lines.push('  (no rule listed)');
  const listed = (title, items, text) => {
    if (!items?.length) return;
    lines.push('', title);
    for (const i of items) lines.push(`  ${text(i)}`);
  };
  listed('Refused by the check:', v.refusals, findingText);
  listed('Unresolved by the check:', v.unresolved, findingText);
  listed('Not analysed (outside the scope above, informational):', v.coverage_exclusions, (x) => `rule ${x.rule_id}`);
  listed('Rules for the restricted key (informational):', v.notes?.restricted_key_rules, (x) => `rule ${x.rule_id}${x.usable_alone ? ', usable by the agent alone' : ''}`);
  listed('Other rules for the target (informational):', v.notes?.target_rules, (x) => `rule ${x.rule_id} (${x.requirement?.kind})`);
  listed('Expired rules (an owner rule could revive them):', v.notes?.expired_rules, (x) => `rule ${x.rule_id}, expired at ledger ${x.valid_until}`);
  lines.push('');
  lines.push('Not checked: the RPC endpoint is trusted (no ledger proof); classic accounts must be master-key only;');
  lines.push('threshold and policy-guarded owner rules and nested accounts are refused, not analysed.');
  lines.push(`Trust in this harness is ${TRUST_OPERATOR}: not proof that a human approved this,`);
  lines.push('nor that an agent with the same access could not have approved it. A terminal prompt is only UX.');
  lines.push('');
  lines.push(decision.accept
    ? `ACCEPTED by this wallet under that trust, bound to commitment ${decision.commitment}; it is re-checked just before signing.`
    : 'REFUSED by this wallet:');
  if (!decision.accept) for (const r of decision.reasons) lines.push(`  - ${r}`);
  return lines.join('\n');
}

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
