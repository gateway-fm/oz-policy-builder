import { Buffer } from 'buffer';

// The browser's buffer package implements standard base64, not Node's base64url alias.
export function encodeBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decodeBase64Url(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]{1,1366}$/.test(text) || text.length % 4 === 1) {
    throw new Error('invalid credential encoding');
  }
  const bytes = Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4), 'base64');
  if (bytes.length > 1024 || encodeBase64Url(bytes) !== text) throw new Error('invalid credential encoding');
  return bytes;
}
