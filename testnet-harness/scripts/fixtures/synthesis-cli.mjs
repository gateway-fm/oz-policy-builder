#!/usr/bin/env node
// A process-boundary fixture: outputs are supplied by the test, never synthesized here.
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [command, ...args] = process.argv.slice(2);
const dir = process.env.OZPB_FLOW_FIXTURE;
appendFileSync(join(dir, 'commands.jsonl'), JSON.stringify({ command, args }) + '\n');
if (process.env.OZPB_FLOW_FAIL === command) process.exit(7);
if (command === 'generate') {
  const out = args[args.indexOf('--out') + 1];
  mkdirSync(out);
  writeFileSync(join(out, 'policy.wasm'), Buffer.from('fixture wasm'));
  writeFileSync(join(out, 'build-manifest.json'), readFileSync(join(dir, 'manifest.json')));
} else {
  process.stdout.write(readFileSync(join(dir, command + '.json')));
}
