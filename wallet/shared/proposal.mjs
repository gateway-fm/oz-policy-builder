import { Asset, Networks, StrKey } from '#wallet-stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, freezeCopy } from './approval.mjs';

export const MAX_PROPOSAL_BYTES = 16 * 1024;
const HASH = /^[0-9a-f]{64}$/;
const isHash = value => typeof value === 'string' && HASH.test(value);
const refuse = () => { throw new Error('proposal refused; review a supported grant for this wallet'); };
const integer = (n, low, high) => Number.isSafeInteger(n) && n >= low && n <= high;
const exact = (value, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k))) refuse();
};
const one = (value) => { if (!Array.isArray(value) || value.length !== 1) refuse(); return value[0]; };
const canonical = value => JSON.stringify(sort(value));
function sort(value) {
  return Array.isArray(value) ? value.map(sort) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(k => [k, sort(value[k])])) : value;
}

/** Bounded JSON with unique keys and exact integer literals in both browser and backend. */
function readJson(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_PROPOSAL_BYTES) refuse();
  let position = 0, nodes = 0;
  const space = () => { while (/[ \t\r\n]/.test(text[position] ?? '\0')) position++; };
  const string = () => {
    const match = /^"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(text.slice(position));
    if (!match) refuse();
    position += match[0].length;
    return JSON.parse(match[0]);
  };
  function value(depth) {
    if (++nodes > 2048 || depth > 16) refuse();
    space();
    if (text[position] === '"') return string();
    if (text[position] === '{' || text[position] === '[') {
      const object = text[position++] === '{', end = object ? '}' : ']';
      const result = object ? {} : [], keys = new Set();
      space();
      if (text[position] === end) { position++; return result; }
      while (true) {
        space();
        let key;
        if (object) {
          key = string(); space();
          if (keys.has(key) || ['__proto__', 'constructor', 'prototype'].includes(key) || text[position++] !== ':') refuse();
          keys.add(key);
        }
        const child = value(depth + 1);
        if (object) result[key] = child; else result.push(child);
        space();
        const separator = text[position++];
        if (separator === end) return result;
        if (separator !== ',') refuse();
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*))/.exec(text.slice(position));
    if (!match) refuse();
    position += match[0].length;
    const result = JSON.parse(match[0]);
    if (typeof result === 'number' && !Number.isSafeInteger(result)) refuse();
    return result;
  }
  const result = value(0); space();
  if (position !== text.length) refuse();
  return result;
}

/** The wallet's supported import is one exact native-asset transfer, capped and expiring. */
export function parseGrantProposal(text, accountAddress) {
  try {
    const p = readJson(text);
    exact(p, ['schema', 'network_id', 'transaction_hash', 'decisions', 'expected_grant', 'spec_hash']);
    if (p.schema !== 'ozpb-grant-proposal/v1' || p.network_id !== NETWORK_ID
      || !isHash(p.transaction_hash) || !isHash(p.spec_hash)
      || typeof accountAddress !== 'string' || !StrKey.isValidContract(accountAddress)) refuse();
    const d = p.decisions;
    exact(d, ['grant_name', 'delegate', 'valid_until_ledger', 'max_calls', 'unlimited_calls_acknowledged']);
    if (typeof d.grant_name !== 'string' || !/^[a-z][a-z0-9-]{0,19}$/.test(d.grant_name)
      || typeof d.delegate !== 'string' || !StrKey.isValidEd25519PublicKey(d.delegate) || !integer(d.valid_until_ledger, 1, 0xffffffff)
      || !integer(d.max_calls, 1, 10000) || d.unlimited_calls_acknowledged !== false) refuse();
    exact(p.expected_grant, ['account', 'rules']);
    if (p.expected_grant.account !== accountAddress) refuse();
    const r = one(p.expected_grant.rules);
    exact(r, ['context', 'calls', 'authorization', 'valid_until_ledger', 'max_calls', 'policy_kinds']);
    exact(r.context, ['type', 'contract', 'target_code_hash']);
    if (r.context.type !== 'CallContract' || r.context.contract !== Asset.native().contractId(Networks.TESTNET)
      || r.context.target_code_hash !== null || r.valid_until_ledger !== d.valid_until_ledger
      || r.max_calls !== d.max_calls || one(r.policy_kinds) !== 'gen:scope+count') refuse();
    const authorization = { kind: 'any_of', strict_signer_set: true, signers: [{ delegated: { address: d.delegate } }] };
    if (canonical(r.authorization) !== canonical(authorization)) refuse();
    const call = one(r.calls);
    exact(call, ['fn', 'args']);
    if (call.fn !== 'transfer' || !Array.isArray(call.args) || call.args.length !== 3) refuse();
    for (const [i, arg] of call.args.entries()) {
      exact(arg, ['i', 'c']); if (arg.i !== i) refuse();
      const kind = i === 2 ? 'eq_i128' : 'eq_address';
      exact(arg.c, [kind]); exact(arg.c[kind], ['value']);
      const v = arg.c[kind].value;
      if (i === 0 && v !== 'SELF' || i === 1 && (typeof v !== 'string' || !StrKey.isValidEd25519PublicKey(v))
        || i === 2 && (typeof v !== 'string' || !/^[1-9][0-9]{0,38}$/.test(v) || BigInt(v) >= 2n ** 127n)) refuse();
    }
    return freezeCopy(p);
  } catch { refuse(); }
}

/** Compare permissions, excluding acquisition provenance and observation-dependent spec hashes. */
export function checkProposalSpec(proposal, spec) {
  try {
    if (spec.name !== proposal.decisions.grant_name || spec.network_id !== proposal.network_id
      || spec.smart_account.observed_code_hash !== ACCOUNT_WASM) refuse();
    const grant = { account: spec.smart_account.address, rules: spec.rules.map(rule => ({
      context: { type: rule.context.type, contract: rule.context.contract, target_code_hash: rule.context.target_code_hash?.hash ?? null },
      calls: rule.allowed_calls.map(call => ({ fn: call.fn, args: call.args.map(arg => ({ i: arg.i, c: arg.c })) })),
      authorization: rule.authorization, valid_until_ledger: rule.valid_until?.ledger ?? null,
      max_calls: one(rule.state).call_count_per_installation.max_calls,
      policy_kinds: rule.policies.map(p => { exact(p, ['generated']); return p.generated.kind; }),
    })) };
    if (canonical(grant) !== canonical(proposal.expected_grant)) refuse();
  } catch { refuse(); }
}

export function checkProposalArtifact(proposal, artifact) {
  if (!isHash(artifact?.artifactId) || !isHash(artifact?.specHash) || !isHash(artifact?.wasmHash)
    || !artifact.files || typeof artifact.files !== 'object') refuse();
  checkProposalSpec(proposal, artifact.spec);
  return freezeCopy({ agentSpecHash: proposal.spec_hash, walletSpecHash: artifact.specHash,
    grantsMatch: true, hashesMatch: proposal.spec_hash === artifact.specHash });
}
