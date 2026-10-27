import { createServer } from 'node:http';

const BODY_BYTES = 64 * 1024;
const RESPONSE_BYTES = 8 * 1024 * 1024;
const PREFIX = '/api/policy-builder/';
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);

function parseBody(raw) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  let nodes = 0;
  function inspect(value, depth) {
    if (++nodes > 8192 || depth > 32) throw new Error();
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error();
    if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
      if (RESERVED.has(key)) throw new Error();
      inspect(child, depth + 1);
    }
  }
  const body = JSON.parse(text);
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
  inspect(body, 0);
  return body;
}

function bodyBytes(request) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let settled = false;
    const fail = () => { if (!settled) { settled = true; reject(new Error()); } };
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_BYTES) { chunks.length = 0; fail(); }
      else if (!settled) chunks.push(chunk);
    });
    request.on('end', () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks)); } });
    request.on('aborted', fail); request.on('error', fail);
  });
}

/** Authentication, admission and redaction surround every trusted local action. */
export function createWalletServer({ session, actions }) {
  const routes = Object.freeze({ ...actions });
  let busy = false;
  const server = createServer(async (request, response) => {
    function reply(status, body) {
      if (response.destroyed || response.writableEnded) return;
      let text = JSON.stringify(body);
      if (Buffer.byteLength(text) > RESPONSE_BYTES) { status = 422; text = '{"error":"wallet action unavailable"}'; }
      response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
        'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'" });
      response.end(text);
    }
    try {
      for (const name of ['host', 'origin', 'authorization', 'content-type']) {
        const count = request.rawHeaders.filter((_, index) => index % 2 === 0)
          .filter((header) => header.toLowerCase() === name).length;
        if (count !== 1) throw new Error();
      }
      session.authenticate(request.headers);
    } catch { request.resume(); reply(403, { error: 'wallet request unauthorized' }); return; }
    const path = request.url;
    const name = typeof path === 'string' && path.startsWith(PREFIX) ? path.slice(PREFIX.length) : '';
    if (request.method !== 'POST' || !/^[a-z]+(?:-[a-z]+)*$/.test(name) || !Object.hasOwn(routes, name)
      || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type'])) {
      request.resume(); reply(400, { error: 'invalid wallet request' }); return;
    }
    if (busy) { request.resume(); reply(409, { error: 'wallet session busy' }); return; }
    busy = true;
    try {
      let body;
      try { body = parseBody(await bodyBytes(request)); }
      catch { reply(400, { error: 'invalid wallet request' }); return; }
      try { reply(200, await routes[name](body)); }
      catch { reply(422, { error: 'wallet action unavailable; refresh and review again' }); }
    } finally { busy = false; }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 32;
  server.on('clientError', (_error, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
  return server;
}
