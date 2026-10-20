import { verificationGate } from './verification.mjs';

const HASH = /^[0-9a-f]{64}$/;
const refused = () => new Error('wallet action refused; refresh and review the exact grant');
const copy = (value) => {
  const result = JSON.parse(JSON.stringify(value));
  const freeze = (part) => {
    if (part && typeof part === 'object') { Object.values(part).forEach(freeze); Object.freeze(part); }
    return part;
  };
  return freeze(result);
};
const sameWallet = (a, b) => ['contractId', 'credentialId', 'publicKey', 'verifier'].every((key) => a?.[key] === b?.[key]);

/** The route supplies the real validators; only serialized XDR crosses SDK versions. */
export class WalletController {
  #request; #validators; #sign; #origin; #pins; #notify; #busy = false;
  #state = copy({ status: null, wallet: null, record: null, artifact: null, deployment: null,
    review: null, accountPreview: null, deployPreview: null, installation: null, receipt: null, busy: false });
  constructor({ request, validators, sign, origin, pins, onChange = () => {} }) {
    this.#request = request; this.#validators = validators; this.#sign = sign;
    this.#origin = origin; this.#pins = copy(pins); this.#notify = onChange;
  }
  get state() { return this.#state; }
  #set(values) { this.#state = copy({ ...this.#state, ...values }); this.#notify(this.#state); }
  #clear() { this.#set({ record: null, artifact: null, deployment: null, review: null,
    accountPreview: null, deployPreview: null, installation: null, receipt: null }); }
  async #act(operation) {
    if (this.#busy) throw refused();
    this.#busy = true; this.#set({ busy: true });
    try { return await operation(); }
    catch { throw refused(); }
    finally { this.#busy = false; this.#set({ busy: false }); }
  }
  #capability(name) {
    if (this.#state.status?.capabilities?.[name] !== true) throw refused();
  }
  #bindings() {
    return { specHash: this.#state.artifact?.specHash, wasmHash: this.#state.artifact?.wasmHash,
      bindingSetHash: this.#state.deployment?.bindingSetHash };
  }
  async connect() {
    return this.#act(async () => {
      const status = await this.#request('status', {});
      if (status.network !== 'testnet' || Object.keys(this.#pins).some((key) => status[key] !== this.#pins[key])) throw refused();
      this.#set({ status });
    });
  }
  attachWallet(wallet) {
    if (this.#busy || !wallet || ['contractId', 'credentialId', 'publicKey', 'verifier']
      .some((key) => typeof wallet[key] !== 'string' || !wallet[key].length || wallet[key].length > 2048)) throw refused();
    this.#clear(); this.#set({ wallet });
  }
  async prepareAccount(credential) {
    return this.#act(async () => {
      this.#clear();
      const result = await this.#request('prepare-account', credential);
      if (!result.action?.id || result.summary?.accountWasm !== this.#pins.accountWasm
        || result.summary?.verifierWasm !== this.#pins.verifierWasm
        || result.summary?.credentialId !== credential.credentialId || result.summary?.publicKey !== credential.publicKey) throw refused();
      this.#set({ accountPreview: result });
    });
  }
  async confirmAccount() {
    return this.#act(async () => {
      const preview = this.#state.accountPreview;
      this.#set({ accountPreview: null });
      if (!preview) throw refused();
      const result = await this.#request('confirm-account', { id: preview.action.id });
      if (result.wallet?.credentialId !== preview.summary.credentialId
        || result.wallet?.publicKey !== preview.summary.publicKey || !result.wallet?.contractId || !result.wallet?.verifier) throw refused();
      this.#set({ wallet: result.wallet, receipt: result.receipts });
    });
  }
  async record(transactionHash) {
    return this.#act(async () => {
      this.#capability('record');
      const wallet = this.#state.wallet;
      this.#clear();
      if (!wallet || !HASH.test(transactionHash)) throw refused();
      const record = await this.#request('record', { transactionHash, wallet });
      if (!record.recordId || record.transactionHash !== transactionHash || record.accountAddress !== wallet.contractId) throw refused();
      this.#set({ record });
    });
  }
  async generate(parameters) {
    return this.#act(async () => {
      this.#capability('generate');
      const record = this.#state.record;
      this.#set({ artifact: null, deployment: null, review: null, deployPreview: null, installation: null, receipt: null });
      if (!record) throw refused();
      const selected = copy(parameters);
      const artifact = await this.#request('generate', { ...selected, recordId: record.recordId });
      if (!artifact.artifactId || !HASH.test(artifact.specHash) || !HASH.test(artifact.wasmHash)
        || !artifact.spec || !artifact.files) throw refused();
      const spec = artifact.spec;
      const rule = spec.rules?.[0];
      if (spec.name !== selected.grantName || spec.network_id !== this.#pins.networkId
        || spec.smart_account?.address !== this.#state.wallet.contractId || spec.rules?.length !== 1
        || rule.valid_until?.ledger !== selected.validUntilLedger
        || JSON.stringify(rule.authorization?.signers) !== JSON.stringify([{ delegated: { address: selected.delegateAddress } }])
        || JSON.stringify(rule.state) !== JSON.stringify([{ call_count_per_installation: { max_calls: selected.maxCalls } }])
        || !Array.isArray(rule.allowed_calls) || !rule.allowed_calls.length) throw refused();
      this.#set({ artifact });
    });
  }
  async prepareDeploy() {
    return this.#act(async () => {
      this.#capability('deploy');
      const artifact = this.#state.artifact;
      if (!artifact || this.#state.deployment) throw refused();
      const result = await this.#request('prepare-deploy', { artifactId: artifact.artifactId });
      if (!result.action?.id || result.summary?.specHash !== artifact.specHash || result.summary?.wasmHash !== artifact.wasmHash) throw refused();
      this.#set({ deployPreview: result });
    });
  }
  async confirmDeploy() {
    return this.#act(async () => {
      const preview = this.#state.deployPreview;
      this.#set({ deployPreview: null });
      if (!preview) throw refused();
      const deployment = await this.#request('confirm-deploy', { id: preview.action.id });
      if (!deployment.deploymentId || !deployment.policyAddress || !HASH.test(deployment.bindingSetHash)
        || deployment.wasmHash !== this.#state.artifact.wasmHash) throw refused();
      this.#set({ deployment, review: null, receipt: deployment.receipts ?? null });
    });
  }
  async review() {
    return this.#act(async () => {
      this.#set({ review: null });
      const { deployment, artifact, wallet } = this.#state;
      if (!deployment || !artifact || !wallet) throw refused();
      const result = await this.#request('review', { deploymentId: deployment.deploymentId, wallet });
      if (!result.reviewId || !sameWallet(result.wallet, wallet) || result.expected?.specHash !== artifact.specHash
        || result.expected?.bindingSetHash !== deployment.bindingSetHash || result.intent?.policies?.length !== 1
        || result.intent.policies[0].address !== deployment.policyAddress) throw refused();
      const approval = this.#validators.reviewIntent(result);
      this.#set({ review: { ...result, approval } });
    });
  }
  async install() {
    return this.#act(async () => {
      const review = this.#state.review;
      this.#set({ review: null });
      this.#capability('install');
      if (!review || !verificationGate(review.verification, this.#bindings()).acceptanceReady) throw refused();
      const result = await this.#request('assemble', { reviewId: review.reviewId });
      if (!result.pendingId || !verificationGate(result.verification, this.#bindings()).acceptanceReady
        || result.verification.runId !== review.verification.runId) throw refused();
      const checked = this.#validators.validateAssembly({ approval: review.approval,
        assembly: result.assembly, ownerRuleXdr: result.ownerRuleXdr, limits: result.limits });
      const signedAuthEntriesXdr = await this.#sign({ approval: review.approval, checked });
      const signed = await this.#validators.validateSignedAuthorization({ approval: review.approval,
        checked, signedAuthEntriesXdr, origin: this.#origin });
      const submitted = await this.#request('submit', { pendingId: result.pendingId,
        signedAuthEntriesXdr: signed.signedAuthEntriesXdr });
      if (!submitted.receipt || !submitted.installation) throw refused();
      this.#set({ receipt: submitted.receipt, installation: submitted.installation });
    });
  }
}
