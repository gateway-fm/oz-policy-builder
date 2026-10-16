// Executes install.mjs through its artifact guard, then stops at the first RPC boundary.
// Hashes come from the real Rust CLI; none of the guard, validator or hash code is mocked.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import * as sdk from '@stellar/stellar-sdk';
import { cliSpecHash } from '../check-runner.mjs';

const mode = process.argv[2];
const sourceUrl = new URL('../install.mjs', import.meta.url);
const source = readFileSync(sourceUrl, 'utf8');
const dir = mkdtempSync(join(tmpdir(), 'ozpb-install-test-'));
try {
  let spec = JSON.parse(readFileSync(new URL('../../native-sac-policy-spec.json', import.meta.url), 'utf8'));
  // Nonzero so the optional authority path can be configured; no registry read is made here.
  spec.registry_snapshot = '1'.repeat(64);
  if (mode.endsWith('composed')) {
    const composed = JSON.parse(readFileSync(new URL('../../../docs/examples/subscription-spec.json', import.meta.url), 'utf8'));
    spec.rules[0].policies.unshift(composed.rules[0].policies.find((policy) => policy.reviewed));
  }
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const manifest = {
    wasm_hash: createHash('sha256').update(wasm).digest('hex'), rule_index: 0,
    registry_snapshot: spec.registry_snapshot, spec_hash: await cliSpecHash(spec),
  };
  const accepts = ['matching', 'canonical-order', 'authority-matching'].includes(mode);
  let expected = /build-manifest\.json/;
  if (mode.endsWith('composed')) expected = /exactly one generated scope\+count policy/;
  if (mode === 'missing') delete manifest.spec_hash;
  if (mode === 'malformed') manifest.spec_hash = 'not a hash';
  if (mode === 'unrelated') manifest.spec_hash = '0'.repeat(64);
  if (mode === 'amount' || mode === 'authority-amount') {
    spec.rules[0].allowed_calls[0].args[2].c.eq_i128.value = '9999999';
  }
  if (mode === 'call-cap') spec.rules[0].state[0].call_count_per_installation.max_calls = 2;
  if (mode === 'canonical-order') spec = Object.fromEntries(Object.entries(spec).reverse());
  if (mode === 'invalid-spec') {
    spec.schema = 'invalid-schema';
    expected = /E_SPEC_INVALID/;
  }
  if (mode === 'cli-failure') {
    process.env.OZPB_BIN = join(dir, 'nonexistent-ozpb');
    expected = /ENOENT/;
  }
  writeFileSync(join(dir, 'spec.json'), JSON.stringify(spec));
  writeFileSync(join(dir, 'policy.wasm'), wasm);
  writeFileSync(join(dir, 'build-manifest.json'), JSON.stringify(manifest));
  writeFileSync(join(dir, 'registry.json'), '{}');
  writeFileSync(join(dir, 'run.json'), JSON.stringify({
    account: spec.smart_account.address, spec: join(dir, 'spec.json'),
    owner: { kind: 'ed25519', address: spec.rules[0].authorization.signers[0].delegated.address },
  }));
  const opts = { 'run-dir': dir, wasm: join(dir, 'policy.wasm') };
  if (mode.startsWith('authority-')) Object.assign(opts, { 'authority-check': 'cli', confirm: 'operator' });
  let keyReads = 0;
  let reachedNetwork = false;
  const unexpected = () => assert.fail('unexpected network or signing operation');
  const rpc = {
    NETWORK_PASSPHRASE: sdk.Networks.TESTNET,
    args: () => opts,
    readJson: (path) => JSON.parse(readFileSync(path, 'utf8')),
    loadKey: () => { keyReads++; return {}; },
    log: () => {},
    assertTestnet: async () => { reachedNetwork = true; throw new Error('STOP_BEFORE_NETWORK'); },
    contractCodeHash: unexpected, contractIdOf: unexpected, latestLedger: unexpected,
    recordAuth: unexpected, submit: unexpected, viewCall: unexpected, writeJson: unexpected,
  };
  const context = vm.createContext({ Buffer, process: { env: {
    ...process.env,
    // Only the authority runner's configuration sees these values. It must never execute.
    OZPB_BIN: 'unused-authority-runner', OZPB_REGISTRY_ROOTS_FILE: 'unused-roots',
    OZPB_REGISTRY_MIN_VERSION: '1', OZPB_RPC_SOURCES_FILE: 'unused-sources',
    OZPB_SIGNED_REGISTRY_SNAPSHOT: join(dir, 'registry.json'),
  } } });
  const module = new vm.SourceTextModule(source, { context });
  await module.link(async (name) => {
    const exports = name === './rpc.mjs' ? rpc
      : name === './owner.mjs' ? { ownerSigner: async () => { keyReads++; return {}; } }
      : name === '@stellar/stellar-sdk' ? sdk
      : await import(name.startsWith('.') ? new URL(name, sourceUrl) : name);
    return new vm.SyntheticModule(Object.keys(exports), function () {
      for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    }, { context });
  });
  await assert.rejects(module.evaluate(), accepts ? /STOP_BEFORE_NETWORK/ : expected);
  assert.equal(reachedNetwork, accepts);
  assert.equal(keyReads, accepts ? 2 : 0);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
