import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { loadBundleFiles, protocolChecker } from './bundle-command.mjs';
const capture = JSON.parse(readFileSync(new URL('./fixtures/protocol-swap-observation.json', import.meta.url)));
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ozpb-bundle-input-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const spec = structuredClone(capture.synthesis.spec);
  const run = { spec: join(dir, 'spec.json'), walkthrough: { artifacts: [] } };
  writeFileSync(run.spec, JSON.stringify(spec));
  for (let i = 0; i < spec.rules.length; i++) {
    const directory = join(dir, 'policies', `rule-${i}`);
    mkdirSync(directory, { recursive: true });
    const wasm = join(directory, 'policy.wasm'), manifest = join(directory, 'build-manifest.json');
    writeFileSync(wasm, `unit wasm${i}`);
    const hashes = { wasm_hash: createHash('sha256').update(`unit wasm${i}`).digest('hex'), normalized_input_hash: 'aa'.repeat(32) };
    writeFileSync(manifest, JSON.stringify({ rule_index: i, spec_hash: capture.synthesis.spec_hash,
      registry_snapshot: spec.registry_snapshot, ...hashes }));
    run.walkthrough.artifacts.push({ rule_index: i, directory, wasm, manifest, ...hashes });
  }
  const save = () => writeFileSync(join(dir, 'run.json'), JSON.stringify(run));
  save();
  return { dir, run, save };
}
for (const mode of ['matching', 'changed snapshot', 'wrong spec path', 'missing inventory', 'reordered inventory', 'alternate Wasm path', 'changed hash', 'extra Wasm']) {
  test(`bundle CLI input loading binds indexed files and cleanup snapshot: ${mode}`, (t) => {
    const f = fixture(t);
    const before = createHash('sha256').update(readFileSync(join(f.dir, 'run.json'))).digest('hex');
    if (mode === 'changed snapshot') { f.run.changed = true; f.save(); }
    if (mode === 'wrong spec path') f.run.spec = join(f.dir, 'elsewhere.json');
    if (mode === 'missing inventory') f.run.walkthrough.artifacts.pop();
    if (mode === 'reordered inventory') f.run.walkthrough.artifacts.reverse();
    if (mode === 'alternate Wasm path') f.run.walkthrough.artifacts[1].wasm = f.run.walkthrough.artifacts[0].wasm;
    if (mode === 'changed hash') f.run.walkthrough.artifacts[1].wasm_hash = 'bb'.repeat(32);
    if (mode === 'extra Wasm') writeFileSync(join(f.dir, 'policies/rule-1/extra.wasm'), 'unit');
    f.save();
    const act = () => loadBundleFiles(f.dir, mode === 'changed snapshot' || mode === 'matching' ? before : undefined);
    if (mode === 'matching') {
      const input = act();
      assert.equal(input.artifacts.length, 2);
      assert.deepEqual(input.artifacts.map((a) => a.manifest.rule_index), [0, 1]);
    } else assert.throws(act);
  });
}
test('protocol CLI requires explicit operator mode and complete trust configuration', () => {
  assert.throws(() => protocolChecker({}, {}, {}), /explicit --confirm operator/);
  assert.throws(() => protocolChecker({}, { confirm: 'operator' }, {}), /requires OZPB_BIN/);
});
