const ENDPOINTS = new Set(['status', 'readiness', 'prepare-account', 'confirm-account', 'prepare-sample', 'submit-sample', 'record', 'generate', 'import-proposal', 'pair-agent', 'agent-inbox', 'disconnect-agent', 'dismiss-agent-proposal', 'review-agent-proposal',
  'prepare-deploy', 'confirm-deploy', 'review', 'create-delegate', 'check-account', 'prepare-live', 'consent-live', 'run-live',
  'check-replay', 'assemble', 'submit', 'monitor-grant', 'prepare-replacement', 'confirm-replacement', 'prepare-revoke',
  'confirm-revoke', 'use-grant', 'try-grant-again', 'account-rules', 'prepare-earlier-revoke', 'confirm-earlier-revoke']);
const refused = () => new Error('wallet request refused; reconnect or try a fresh review');
/** The closed set of reasons a refusal may name (the backend's REFUSAL_REASONS); any other is dropped. */
export const REFUSAL_REASONS = new Set(['busy', 'rpc_too_slow', 'evidence_stale', 'signatures_still_valid', 'replay_journal_unavailable', 'account_changed',
  'review_expired', 'deployment_quote_stale', 'grant_already_used', 'network_mismatch', 'protocol_unsupported', 'fee_cap', 'spend_cap', 'payer_unfunded',
  'delegate_unfunded', 'pinned_code_missing', 'account_unfunded', 'registry_root_refused', 'no_diagnostic_events', 'delegate_key_unavailable']);
/** The operator setting a cap refusal may name, by reason (the backend's CAP_SETTINGS). */
export const CAP_SETTINGS = Object.freeze({ fee_cap: 'maxUploadFeeStroops', spend_cap: 'sessionSpendCapStroops' });
const stroops = (value) => typeof value === 'string' && /^(?:0|[1-9][0-9]{0,18})$/.test(value);
/** A cap refusal's detail, only in its closed shape: the setting, the simulated cost and the least value that lets it through. */
const capLimit = (reason, limit) => Object.hasOwn(CAP_SETTINGS, reason) && limit && typeof limit === 'object'
  && Object.keys(limit).length === 3 && limit.setting === CAP_SETTINGS[reason]
  && stroops(limit.simulatedFeeStroops) && stroops(limit.neededStroops)
  ? { limit: Object.freeze({ setting: limit.setting, simulatedFeeStroops: limit.simulatedFeeStroops, neededStroops: limit.neededStroops }) } : {};
/** A refusal's reason, and a cap refusal's detail, from at most 4 KiB of its JSON body; nothing else in it is kept. */
async function reasonOf(response) {
  const reader = response.body?.getReader();
  try {
    if (!reader || response.headers.get('content-type')?.split(';')[0] !== 'application/json') return {};
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 4096) return {};
      chunks.push(value);
    }
    const buffer = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
    const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
    const reason = body?.reason;
    return REFUSAL_REASONS.has(reason) ? { reason, ...capLimit(reason, body.limit) } : {};
  } catch { return {}; } finally { reader?.cancel().catch(() => {}); }
}

/**
 * Fragment credentials stay in memory and are removed before the first request. The launch URL also
 * names the session's network (`testnet` or `mainnet`), which the page then holds for its lifetime;
 * a URL without it is a testnet session.
 */
export function takeSession(location, history) {
  const url = new URL(location.href);
  const match = /^#session=([0-9a-f]{64})(?:&network=(testnet|mainnet))?$/.exec(url.hash);
  history.replaceState(null, '', url.pathname);
  if (!['http:', 'https:'].includes(url.protocol) || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    || url.username || url.password || url.search || !match) {
    throw new Error('wallet session unavailable; open the local launcher URL again');
  }
  return Object.freeze({ token: match[1], network: match[2] ?? 'testnet' });
}

export function takeSessionToken(location, history) { return takeSession(location, history).token; }

export function createClient(token, options = {}) {
  if (!/^[0-9a-f]{64}$/.test(token)) throw refused();
  const fetcher = options.fetch ?? globalThis.fetch;
  const maxBytes = options.maxBytes ?? 16 * 1024 * 1024;
  const timeoutMs = options.timeoutMs ?? 900_000;
  if (!Number.isInteger(maxBytes) || maxBytes < 1024 || maxBytes > 16 * 1024 * 1024
    || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 900_000) throw refused();
  return async (name, data) => {
    if (!ENDPOINTS.has(name)) throw refused();
    const body = JSON.stringify(data);
    if (typeof body !== 'string' || new TextEncoder().encode(body).byteLength > maxBytes) throw refused();
    const abort = new AbortController();
    let reader;
    let rejectDeadline;
    const deadline = new Promise((_, reject) => { rejectDeadline = reject; });
    const timer = setTimeout(() => {
      abort.abort();
      reader?.cancel().catch(() => {});
      rejectDeadline(refused());
    }, timeoutMs);
    try {
      const response = await Promise.race([fetcher(`/api/policy-builder/${name}`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body, signal: abort.signal, cache: 'no-store', credentials: 'omit', redirect: 'error',
      }), deadline]);
      if (!response.ok && !response.redirected) throw Object.assign(refused(), await Promise.race([reasonOf(response), deadline]));
      if (!response.ok || response.redirected || response.headers.get('content-type')?.split(';')[0] !== 'application/json'
        || !response.body) throw refused();
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      while (true) {
        const { done, value } = await Promise.race([reader.read(), deadline]);
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) throw refused();
        chunks.push(value);
      }
      const buffer = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
    } catch (error) {
      abort.abort();
      reader?.cancel().catch(() => {});
      throw REFUSAL_REASONS.has(error?.reason) ? error : refused();
    } finally {
      clearTimeout(timer);
    }
  };
}
