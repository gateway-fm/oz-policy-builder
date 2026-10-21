import { createHash, randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { StrKey } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID, freezeCopy } from '../shared/approval.mjs';
import { RawJson, parseJsonExact, requestText } from './raw-json.mjs';
import { runTool } from './tool.mjs';

const NETWORK = 'Test SDF Network ; September 2015';
const HASH = /^[0-9a-f]{64}$/;
const FILES = ['Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'rustfmt.toml', 'src/contract.rs', 'src/lib.rs'];
const refuse = (code) => {
  throw Object.assign(new Error('wallet pipeline refused; refresh and review again'), code ? { code } : {});
};
// `capture-target` codes that name the call's own outcome rather than an endpoint fault.
const TARGET_CODES = Object.freeze(['E_TARGET_REFUSED', 'E_TARGET_ARCHIVED']);
const integer = (n, low, high) => Number.isSafeInteger(n) && n >= low && n <= high;
const hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const display = (value) => JSON.parse(JSON.stringify(value, (_key, part) => typeof part === 'bigint' ? part.toString() : part));
const save = (path, body) => writeFileSync(path, body, { mode: 0o600, flag: 'wx' });

/** Only this wallet-owned process chooses executable, trust roots, RPC and artifact paths. */
export class WalletToolchain {
  #config; #root; #runner; #records = new Map(); #artifacts = new Map(); #trustArgs;

  constructor({ executable, workRoot, rpcUrl, registrySnapshot, registryRoots, registryMinimumVersion, runner = runTool, buildEnvironment = {} }) {
    const url = new URL(rpcUrl);
    if (!isAbsolute(executable) || !isAbsolute(workRoot) || lstatSync(workRoot).isSymbolicLink()
      || !lstatSync(workRoot).isDirectory() || url.protocol !== 'https:' || url.username || url.password || url.hash || url.search
      || !integer(registryMinimumVersion, 1, Number.MAX_SAFE_INTEGER)
      || Buffer.byteLength(registrySnapshot) > 2 * 1024 * 1024 || Buffer.byteLength(registryRoots) > 256 * 1024) refuse();
    new RawJson(registrySnapshot); new RawJson(registryRoots);
    this.#root = mkdtempSync(join(workRoot, 'wallet-session-'));
    this.#config = { executable, rpcUrl, registrySnapshot, registryMinimumVersion, buildEnvironment };
    this.#runner = runner;
    save(join(this.#root, 'registry.signed.json'), registrySnapshot);
    save(join(this.#root, 'registry-roots.json'), registryRoots);
    save(join(this.#root, 'rpc-sources.json'), JSON.stringify({ testnet: { rpc_url: rpcUrl, network_passphrase: NETWORK } }));
    this.#trustArgs = ['--registry-roots', join(this.#root, 'registry-roots.json'), '--registry-min-version', String(registryMinimumVersion)];
  }

  #directory() { return mkdtempSync(join(this.#root, 'operation-')); }
  #get(map, id) { if (typeof id !== 'string' || !HASH.test(id) || !map.has(id)) refuse(); return map.get(id); }
  async #call(directory, command, args, parser = parseJsonExact, { signal, timeoutMs, codes = [] } = {}) {
    let raw;
    try {
      raw = await this.#runner(this.#config.executable, [command, ...args], { env: this.#config.buildEnvironment,
        ...(signal ? { signal } : {}), ...(timeoutMs ? { timeoutMs } : {}), ...(codes.length ? { codes } : {}) });
    } catch (error) {
      // Only a code this call allowlisted survives; the runner never returns the CLI's text.
      refuse(codes.includes(error?.code) ? error.code : undefined);
    }
    try {
      if (typeof raw !== 'string' || Buffer.byteLength(raw) > 16 * 1024 * 1024) refuse();
      save(join(directory, `${command}.json`), raw);
      return parser(raw);
    } catch { refuse(); }
  }

  recordFile(id) { return this.#get(this.#records, id).file; }
  artifact(id) { return this.#get(this.#artifacts, id); }
  get sessionRoot() { return this.#root; }

  async record({ transactionHash, accountAddress }) {
    try {
      if (!HASH.test(transactionHash) || !StrKey.isValidContract(accountAddress) || this.#records.size >= 8) refuse();
      const directory = this.#directory();
      const record = await this.#call(directory, 'record', ['--tx-hash', transactionHash, '--rpc-url', this.#config.rpcUrl, '--network', NETWORK],
        (text) => JSON.parse(text, (_key, value, context) => typeof value === 'number' && !Number.isSafeInteger(value)
          && /^-?\d+$/.test(context?.source ?? '') ? BigInt(context.source) : value));
      const bundle = record.bundle;
      const observation = bundle?.contract_executables?.[accountAddress];
      const authorizations = bundle?.authorizations?.filter((auth) => auth.authorizer === accountAddress);
      if (record.trust !== 'rpc_reported' || !HASH.test(record.recording_hash) || bundle.network_id !== NETWORK_ID
        || bundle.execution !== 'executed_success' || !integer(bundle.ledger, 1, 0xffffffff)
        || observation?.executable?.wasm?.code_hash !== ACCOUNT_WASM
        || !integer(observation.observed_ledger, bundle.ledger, 0xffffffff) || authorizations?.length !== 1) refuse();
      const recordId = randomBytes(32).toString('hex');
      const response = freezeCopy({ recordId, transactionHash, accountAddress, recordingHash: record.recording_hash,
        observedLedger: bundle.ledger, authorizations: display(authorizations), trust: 'rpc_reported' });
      this.#records.set(recordId, { file: join(directory, 'record.json'), response });
      return response;
    } catch { refuse(); }
  }

  async generate({ recordId, delegateAddress, validUntilLedger, maxCalls, grantName, currentLedger }) {
    try {
      const record = this.#get(this.#records, recordId);
      if (this.#artifacts.size >= 8 || !StrKey.isValidEd25519PublicKey(delegateAddress)
        || !integer(currentLedger, record.response.observedLedger, 0xffffffff - 17280)
        || !integer(validUntilLedger, currentLedger + 1, currentLedger + 17280) || !integer(maxCalls, 1, 10000)
        || typeof grantName !== 'string' || !/^[a-z][a-z0-9-]{0,19}$/.test(grantName)) refuse();
      const directory = this.#directory();
      const decisions = { grant_name: grantName, delegate_signers: [{ delegated: { address: delegateAddress } }],
        predicate: 'any_of', valid_until_ledger: validUntilLedger, no_expiry_acknowledged: false,
        max_calls: maxCalls, widenings: [], spending_limit: null };
      const account = { address: record.response.accountAddress, observed_code_hash: ACCOUNT_WASM,
        registry_resolution: 'resolved from the wallet operator signed registry' };
      save(join(directory, 'account.json'), JSON.stringify(account));
      save(join(directory, 'decisions.json'), JSON.stringify(decisions));
      const synthesis = await this.#call(directory, 'synthesize', ['--bundle', record.file, '--selected-authorizer', account.address,
        '--account', join(directory, 'account.json'), '--signed-registry', join(this.#root, 'registry.signed.json'), ...this.#trustArgs,
        '--decisions', join(directory, 'decisions.json'), '--template-family', 'policy-templates/scope@1']);
      const spec = synthesis.spec;
      const rule = spec?.rules?.[0];
      if (!HASH.test(synthesis.spec_hash) || spec?.network_id !== NETWORK_ID || spec.smart_account?.address !== account.address
        || spec.smart_account?.observed_code_hash !== ACCOUNT_WASM || spec.rules?.length !== 1 || (synthesis.questions?.length ?? 0) !== 0
        || rule.valid_until?.ledger !== validUntilLedger || JSON.stringify(rule.authorization?.signers) !== JSON.stringify(decisions.delegate_signers)
        || rule.policies?.length !== 1 || rule.policies[0].generated?.kind !== 'gen:scope+count'
        || JSON.stringify(rule.state) !== JSON.stringify([{ call_count_per_installation: { max_calls: maxCalls } }])) refuse();
      save(join(directory, 'spec.json'), JSON.stringify(spec));
      const reference = await this.#call(directory, 'reference-suite', ['--spec', join(directory, 'spec.json')]);
      if (reference.report?.spec_hash !== synthesis.spec_hash || reference.all_agree !== true || reference.disagreements !== 0
        || !integer(reference.total, 1, 100000) || JSON.stringify(reference.missing_classes) !== '[]'
        || JSON.stringify(reference.unmodeled_reviewed_policies) !== '[]') refuse();
      const generated = await this.#call(directory, 'generate', ['--spec', join(directory, 'spec.json'), '--rule', '0']);
      const manifest = generated.build_manifest;
      const fileNames = Object.keys(generated.files ?? {}).sort();
      if (JSON.stringify(fileNames) !== JSON.stringify(FILES) || fileNames.some((name) => typeof generated.files[name] !== 'string')
        || fileNames.reduce((size, name) => size + Buffer.byteLength(generated.files[name]), 0) > 2 * 1024 * 1024
        || typeof generated.wasm_base64 !== 'string' || generated.wasm_base64.length > 3 * 1024 * 1024
        || !/^[A-Za-z0-9+/]+={0,2}$/.test(generated.wasm_base64)) refuse();
      const wasm = Buffer.from(generated.wasm_base64, 'base64');
      if (wasm.toString('base64') !== generated.wasm_base64 || !wasm.subarray(0, 8).equals(Buffer.from([0,97,115,109,1,0,0,0]))
        || hex(wasm) !== generated.wasm_hash || manifest?.wasm_hash !== generated.wasm_hash
        || manifest.spec_hash !== synthesis.spec_hash || manifest.registry_snapshot !== spec.registry_snapshot || manifest.rule_index !== 0) refuse();
      const generatedDirectory = join(directory, 'generated');
      mkdirSync(join(generatedDirectory, 'src'), { recursive: true, mode: 0o700 });
      for (const name of FILES) save(join(generatedDirectory, name), generated.files[name]);
      save(join(directory, 'policy.wasm'), wasm);
      save(join(directory, 'build-manifest.json'), JSON.stringify(manifest));
      const verified = await this.#call(directory, 'verify', ['--spec', join(directory, 'spec.json'), '--rule', '0',
        '--generated-dir', generatedDirectory, '--wasm', join(directory, 'policy.wasm'), '--manifest', join(directory, 'build-manifest.json')]);
      if (verified.matches !== true || verified.models_all_policies !== true || JSON.stringify(verified.unmodeled_reviewed_policies) !== '[]'
        || verified.spec_conformance !== 'conforms (validated PolicySpec v1)'
        || verified.source_reproduction !== 'reproduced: generated non-lock files are byte-identical'
        || verified.wasm_reproduction !== 'reproduced: Wasm and BuildManifest are identical'
        || verified.normalized_input_hash !== manifest.normalized_input_hash
        || !/^pass: [1-9][0-9]* constraint-derived cases all agree$/.test(verified.offline_behavioral_conformance)) refuse();
      const artifactId = randomBytes(32).toString('hex');
      const response = freezeCopy({ artifactId, spec, specHash: synthesis.spec_hash, files: generated.files,
        buildManifest: manifest, wasmHash: generated.wasm_hash, reference, verification: verified,
        limitations: ['Artifact reproduction and reference evaluation do not constitute a complete four-layer dry run.'] });
      this.#artifacts.set(artifactId, { response, directory, wasmBase64: generated.wasm_base64 });
      return response;
    } catch { refuse(); }
  }

  /** Request objects come only from the trusted wallet controller's retained artifacts. */
  async authority(command, request) {
    if (!['check-policy-call-surface', 'prepare-install-intent', 'assemble-install-transaction'].includes(command)) refuse();
    const directory = this.#directory();
    save(join(directory, 'request.json'), requestText(request));
    return this.#call(directory, command, ['--request', join(directory, 'request.json'), ...this.#trustArgs,
      '--rpc-sources', join(this.#root, 'rpc-sources.json')]);
  }

  /**
   * CLI preparation for one retained artifact and its binding request. The fresh nonce and
   * artifact claims come only from this process; the returned request is the native job's input.
   */
  async prepareDryRun({ artifactId, candidate, candidateContextRuleId, signal }) {
    const held = this.artifact(artifactId);
    if (!integer(candidateContextRuleId, 0, 0xffffffff) || candidate?.spec !== held.response.spec || candidate.rule_index !== 0) refuse();
    const files = Object.fromEntries(FILES.filter((name) => name !== 'Cargo.lock').map((name) => [name, held.response.files[name]]));
    const request = Object.freeze({ candidate, artifact: { spec: held.response.spec, rule_index: 0, claimed_generated_files: files,
      claimed_wasm_base64: held.wasmBase64, claimed_build_manifest: held.response.buildManifest },
    candidate_context_rule_id: candidateContextRuleId, run_nonce: randomBytes(32).toString('hex') });
    const directory = this.#directory();
    save(join(directory, 'request.json'), requestText(request));
    const output = await this.#call(directory, 'prepare-dry-run', ['--request', join(directory, 'request.json'), ...this.#trustArgs,
      '--rpc-sources', join(this.#root, 'rpc-sources.json')], parseJsonExact, { signal });
    return { request, output };
  }

  /**
   * `capture-target` through the operator's `testnet` source for one unsigned envelope the
   * backend built itself. The envelope is confidential input: it reaches the CLI only in a
   * private request file. Neither it nor the capture is kept once the CLI exits, and no refusal
   * repeats either; the worker evidence binds the capture by its hash.
   */
  async captureTarget(envelope, { signal } = {}) {
    if (typeof envelope !== 'string' || envelope.length > 64 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope)) refuse();
    const directory = this.#directory();
    const request = join(directory, 'request.json');
    try {
      save(request, JSON.stringify({ network_id: NETWORK_ID, rpc_source: 'testnet', envelope_xdr_base64: envelope }));
      // A read, not a build: bounded well below the build deadline so the whole check stays bounded.
      return await this.#call(directory, 'capture-target', ['--request', request, '--rpc-sources', join(this.#root, 'rpc-sources.json')],
        parseJsonExact, { signal, timeoutMs: 120_000, codes: TARGET_CODES });
    } finally {
      // The capture repeats the call (account, recipient, amount), so it is as confidential as the envelope.
      rmSync(request, { force: true }); rmSync(join(directory, 'capture-target.json'), { force: true });
    }
  }

  bindingRequest(artifactId, policyAddress, resolutionReference) {
    const { response: artifact } = this.artifact(artifactId);
    if (!StrKey.isValidContract(policyAddress) || policyAddress === artifact.spec.smart_account.address
      || typeof resolutionReference !== 'string' || resolutionReference.length < 1 || resolutionReference.length > 256) refuse();
    return { spec: artifact.spec, rule_index: 0, binding_set: {
      schema: 'policy-binding-set/v1', spec_hash: artifact.specHash, network_id: NETWORK_ID, bindings: [{
        rule_index: 0, policy_index: 0, contract_address: policyAddress, observed_wasm_hash: artifact.wasmHash,
        recognition: { kind: 'verified_generated_manifest', build_manifest: artifact.buildManifest }, resolution_reference: resolutionReference,
      }],
    }, signed_registry_snapshot: new RawJson(this.#config.registrySnapshot), account_address: artifact.spec.smart_account.address,
    network_id: NETWORK_ID, rpc_source: 'testnet' };
  }
}
