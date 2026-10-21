// JSON the harness must pass on exactly. JavaScript numbers are doubles, so JSON.parse changes any
// integer beyond 2^53 and any long fraction, and JSON.stringify writes the changed value back.
// Found on testnet: the development registry snapshot carries i64::MAX, the harness re-serialized
// it as 9223372036854776000, and the check refused the snapshot (E_REGISTRY_SIGNATURE).
//
//   - `RawJson` holds JSON text that goes into a request byte for byte (the signed snapshot);
//   - `requestText` serializes a request with every `RawJson` spliced in unchanged;
//   - `parseJsonExact` reads the files the harness does re-serialize (spec, build manifest) and
//     refuses any number it could not write back exactly.
import { randomUUID } from 'node:crypto';

// While `requestText` runs, the splice it is building; outside it, null.
let splice = null;

export class RawJson {
  constructor(text) {
    const t = String(text);
    if (t.startsWith('\uFEFF')) throw new Error('raw JSON starts with a byte order mark, which the tool would refuse');
    let value;
    try {
      value = JSON.parse(t);
    } catch {
      throw new Error('raw JSON does not parse as JSON');
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('raw JSON must be an object');
    this.text = t.trim();
  }

  // Only `requestText` may serialize it; anywhere else this would silently emit `{"text": …}`.
  toJSON() {
    if (!splice) throw new Error('RawJson is serialized only by requestText');
    splice.raws.push(this.text);
    return `${splice.tag}${splice.raws.length - 1}`;
  }
}

/** The request as the tool reads it, with every `RawJson` spliced in unchanged. */
export function requestText(request) {
  const tag = `ozpb-raw-${randomUUID()}-`;
  splice = { tag, raws: [] };
  let json;
  let raws;
  try {
    json = JSON.stringify(request);
    raws = splice.raws;
  } finally {
    splice = null;
  }
  // Every occurrence of the tag must be one of ours, as a whole JSON string, or the splice could
  // land inside some other value.
  if (json.split(tag).length - 1 !== raws.length) throw new Error('the request contains the splice tag itself');
  let replaced = 0;
  const out = json.replace(new RegExp(`"${tag}(\\d+)"`, 'g'), (_m, i) => {
    replaced += 1;
    return raws[Number(i)];
  });
  // Each tag replaced exactly once, as a whole JSON string; anything else is not our splice.
  if (replaced !== raws.length) throw new Error('the request splice did not match its raw values');
  JSON.parse(out);
  return out;
}

/**
 * JSON.parse that refuses numbers it cannot represent exactly: an integer literal beyond the safe
 * range, or any other literal that does not read back as itself.
 */
export function parseJsonExact(text) {
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value !== 'number') return value;
    const source = context?.source;
    if (source === undefined) throw new Error('this node cannot check JSON numbers exactly (needs JSON.parse source text)');
    // An integer literal must be a safe integer; anything else must write back as itself, up to
    // trailing fractional zeros (an exponent form is refused: these files never use one).
    const exact = /^-?\d+$/.test(source)
      ? Number.isSafeInteger(value)
      : Number.isFinite(value) && JSON.stringify(value) === source.replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, '');
    if (!exact) throw new Error(`the number ${source} cannot be read exactly`);
    return value;
  });
}
