#!/usr/bin/env node
// Process-boundary fixture only; no network and no claim of an executed protocol call.
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const [command, ...args] = process.argv.slice(2);
const dir = process.env.OZPB_PROTOCOL_FIXTURE;
appendFileSync(join(dir, 'commands.jsonl'), JSON.stringify({ command, args }) + '\n');
const index = args.includes('--rule') ? args[args.indexOf('--rule') + 1] : null;
if (command === 'generate') {
  const out = args[args.indexOf('--out') + 1];
  mkdirSync(out);
  writeFileSync(join(out, 'policy.wasm'), `fixture wasm${index}`);
  writeFileSync(join(out, 'build-manifest.json'), readFileSync(join(dir, `manifest-${index}.json`)));
} else process.stdout.write(readFileSync(join(dir, index === null ? `${command}.json` : `${command}-${index}.json`)));
