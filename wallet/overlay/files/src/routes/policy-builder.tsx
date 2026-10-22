import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Buffer } from "buffer";
import { Networks, xdr } from "@stellar/stellar-sdk";
import { createPasskey, signWalletAuthEntries } from "../lib/passkey";
import { createClient, takeSessionToken } from "../policy-builder/client/client.mjs";
import { WalletController } from "../policy-builder/client/controller.mjs";
import type { WalletState } from "../policy-builder/client/controller.mjs";
import { verificationGate } from "../policy-builder/client/verification.mjs";
import { ACCOUNT_WASM, NETWORK_ID, WEBAUTHN_WASM, reviewIntent } from "../policy-builder/shared/approval.mjs";
import { validateAssembly } from "../policy-builder/shared/assembly.mjs";
import { validateLiveOwnerSignature, validateSignedAuthorization } from "../policy-builder/shared/signature.mjs";
import { checkLiveOwnerEntry, consentDisplay, liveCases, statementHash } from "../policy-builder/shared/live-consent.mjs";
import { reviewSample, validateSampleAssembly } from "../policy-builder/shared/sample.mjs";
import { installConsent } from "../policy-builder/shared/install.mjs";
import { reviewRemoval, revokeConsent, validateRemovalAssembly } from "../policy-builder/shared/revoke.mjs";

export const Route = createFileRoute("/policy-builder")({ component: PolicyBuilder });
const button = "rounded-lg bg-cyan-600 px-4 py-2 font-medium text-white disabled:cursor-not-allowed disabled:opacity-40";
const input = "w-full rounded-lg border border-slate-600 bg-slate-900 p-3 text-sm text-white";
const panel = "space-y-4 rounded-xl border border-slate-700 bg-slate-800/50 p-5";

function Evidence({ title, value, open = false }: { title: string; value: unknown; open?: boolean }) {
  if (value === null || value === undefined) return null;
  return <details open={open} className="rounded-lg border border-slate-700 p-3">
    <summary className="cursor-pointer font-medium">{title}</summary>
    <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs text-slate-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  </details>;
}

const object = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const items = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const label = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : "Unavailable";
const xlm = (value: unknown) => {
  const amount = typeof value === "string" && /^(0|[1-9][0-9]{0,15})$/.test(value) ? Number(value) : value;
  return typeof amount === "number" && Number.isSafeInteger(amount) && amount >= 0
    ? `${amount / 10_000_000} testnet XLM` : "Unavailable";
};

function GrantSummary({ spec }: { spec: unknown }) {
  if (!spec) return null;
  const grant = object(spec);
  return <div className="space-y-4 rounded-lg border border-cyan-700 bg-cyan-950/20 p-4">
    <h3 className="font-semibold">Grant: {label(grant.name)}</h3>
    <p className="break-all text-sm"><span className="text-slate-400">Account: </span>{label(object(grant.smart_account).address)}</p>
    {items(grant.rules).map((raw, index) => {
      const rule = object(raw);
      const authorization = object(rule.authorization);
      return <div key={index} className="space-y-3 text-sm">
        <dl className="grid gap-2 sm:grid-cols-2">
          <div><dt className="text-slate-400">Expires at ledger</dt><dd>{label(object(rule.valid_until).ledger)}</dd></div>
          <div><dt className="text-slate-400">Maximum calls per installation</dt><dd>{label(object(object(items(rule.state)[0]).call_count_per_installation).max_calls)}</dd></div>
          <div className="sm:col-span-2"><dt className="text-slate-400">Delegate</dt>
            <dd className="break-all">{items(authorization.signers).map((signer) => label(object(object(signer).delegated).address)).join(", ")}</dd></div>
          <div className="sm:col-span-2"><dt className="text-slate-400">Target contract</dt>
            <dd className="break-all">{label(object(rule.context).contract)}</dd></div>
        </dl>
        {items(rule.allowed_calls).map((rawCall, callIndex) => {
          const call = object(rawCall);
          return <div key={callIndex} className="rounded border border-slate-700 p-3">
            <p className="font-medium">Allowed function: {label(call.fn)}</p>
            <ul className="mt-2 space-y-1">
              {items(call.args).map((rawArg, argIndex) => {
                const arg = object(rawArg);
                const constraint = object(arg.c);
                const address = object(constraint.eq_address).value;
                const amount = object(constraint.eq_i128).value;
                const description = address !== undefined
                  ? `Address equals ${address === "SELF" ? "this account" : label(address)}`
                  : amount !== undefined ? `Integer equals ${label(amount)} (base units)`
                    : JSON.stringify(arg.c);
                return <li key={argIndex} className="break-all text-slate-300">Argument {label(arg.i)}: {description}</li>;
              })}
            </ul>
          </div>;
        })}
      </div>;
    })}
    <p className="text-xs text-slate-400">Review the exact specification and source below for all constraints and evidence.</p>
  </div>;
}

const LAYER_NAMES: Record<string, string> = { reference: "Reference evaluation", account_wasm: "Account Wasm execution",
  captured_target: "Captured target execution", live_enforcement: "Live enforcement" };

function VerificationLayers({ verification }: { verification: unknown }) {
  const layers = items(object(verification).layers);
  if (!layers.length) return null;
  return <ul className="space-y-2 text-sm">
    {layers.map((raw, index) => {
      const layer = object(raw);
      return <li key={index} className="rounded border border-slate-700 p-3">
        <span className="font-medium">{LAYER_NAMES[label(layer.layer)] ?? label(layer.layer)}: {label(layer.status)}</span>
        <p className="mt-1 text-slate-400">{label(layer.detail)}</p>
      </li>;
    })}
  </ul>;
}

/** The consent statement, exactly as this browser derived it from the reviewed grant. */
function LiveConsent({ display }: { display: unknown }) {
  const d = object(display);
  const owner = object(d.owner_signs);
  return <div className="space-y-3 rounded-lg border border-amber-500 bg-amber-950/30 p-4 text-sm">
    <h3 className="font-semibold">Consent to the live check</h3>
    <p className="font-medium text-amber-200">{label(d.warning)}</p>
    <p>Signatures expire at ledger <strong>{label(d.signature_expiration_ledger)}</strong> (ledger {label(d.current_ledger)} when prepared).
      {" "}Labels: {items(d.labels).map(label).join(", ")}.</p>
    <div className="rounded border border-slate-700 p-3">
      <p className="font-medium">Your owner passkey signs: {label(owner.contract)}.{label(owner.function)}</p>
      <p className="break-all text-slate-300">context {label(owner.context)}, name {label(owner.name)}, valid until {label(owner.valid_until)},
        signers {items(owner.signers).map(label).join(", ")}, policies {items(owner.policies).map(label).join(", ")},
        checked under owner rule {items(owner.context_rule_ids).map(label).join(", ")}</p>
    </div>
    {items(d.cases).map((raw, index) => {
      const c = object(raw);
      const call = object(c.simulated_call);
      const transfer = object(c.delegate_signs);
      return <div key={index} className="rounded border border-slate-700 p-3">
        <p className="font-medium">{label(c.case)}: expected {label(c.expected)}</p>
        <p className="break-all text-slate-300">Simulated call: {label(call.contract)}.{label(call.function)}({JSON.stringify(call.candidate)})</p>
        <p className="break-all text-slate-300">The delegate signs: {label(transfer.contract)}.{label(transfer.function)}(from {label(transfer.from)},
          to {label(transfer.to)}, {label(transfer.amount_stroops)} stroops) under rule {items(transfer.context_rule_ids).map(label).join(", ")}</p>
      </div>;
    })}
    <p className="text-slate-400">Delegate {label(object(d.delegate).address)}: {label(object(d.delegate).key)}.</p>
  </div>;
}

/** What the owner's installation signature does, exactly as this browser derived it from the review. */
function InstallConsent({ display }: { display: unknown }) {
  const d = object(display);
  const owner = object(d.owner_signs);
  const grant = object(d.grant);
  const tx = object(d.transaction);
  const fee = object(d.fee);
  return <div className="space-y-3 rounded-lg border border-amber-500 bg-amber-950/30 p-4 text-sm">
    <h3 className="font-semibold">Consent to install this grant</h3>
    <p className="font-medium text-amber-200">{label(d.warning)}</p>
    <div className="rounded border border-slate-700 p-3">
      <p className="font-medium">Your owner passkey signs: {label(owner.contract)}.{label(owner.function)}</p>
      <p className="break-all text-slate-300">context {label(owner.context)}, name {label(owner.name)}, valid until {label(owner.valid_until)},
        signers {items(owner.signers).map(label).join(", ")}, policies {items(owner.policies).map(label).join(", ")},
        checked under owner rule {items(owner.context_rule_ids).map(label).join(", ")}</p>
    </div>
    <div className="rounded border border-slate-700 p-3">
      <p className="font-medium">What installing grants (rule ID {label(grant.rule_id)})</p>
      <p className="break-all text-slate-300">Delegate {label(grant.delegate)} may call {label(grant.target)} at most {label(grant.max_calls)} time(s),
        until ledger {label(grant.valid_until_ledger)}, only as follows:</p>
      <ul className="mt-2 space-y-1">
        {items(grant.allowed_calls).map((raw, index) => {
          const call = object(raw);
          return <li key={index} className="break-all text-slate-300">{label(call.function)}({items(call.args).map((arg) =>
            `${label(object(arg).index)}: ${JSON.stringify(object(arg).constraint)}`).join(", ")})</li>;
        })}
      </ul>
    </div>
    <p>Transaction valid for ledgers {label(tx.min_ledger)}–{label(tx.max_ledger)}; your signature expires at ledger
      {" "}<strong>{label(tx.signature_expiration_ledger)}</strong>. Prepared fee {xlm(fee.prepared_fee_stroops)}, at most
      {" "}{xlm(fee.max_fee_stroops)}, paid by {label(fee.paid_by)}.</p>
  </div>;
}

/** What the owner's removal signature does. */
function RevokeConsent({ display }: { display: unknown }) {
  const d = object(display);
  const owner = object(d.owner_signs);
  const tx = object(d.transaction);
  const fee = object(d.fee);
  return <div className="space-y-3 rounded-lg border border-amber-500 bg-amber-950/30 p-4 text-sm">
    <h3 className="font-semibold">Consent to revoke this grant</h3>
    <p className="font-medium text-amber-200">{label(d.warning)}</p>
    <p className="break-all">Your owner passkey signs: {label(owner.contract)}.{label(owner.function)}({items(owner.args).map(label).join(", ")}),
      checked under owner rule {items(owner.context_rule_ids).map(label).join(", ")}.</p>
    <p>Your signature expires at ledger <strong>{label(tx.signature_expiration_ledger)}</strong>. Prepared fee {xlm(fee.prepared_fee_stroops)},
      at most {xlm(fee.max_fee_stroops)}, paid by {label(fee.paid_by)}.</p>
  </div>;
}

function PolicyBuilder() {
  const controller = useRef<WalletController | null>(null);
  const creatingRef = useRef(false);
  const [state, setState] = useState<WalletState | null>(null);
  const [message, setMessage] = useState("Open this page using the local wallet launcher's session URL.");
  const [creating, setCreating] = useState(false);
  const [walletJson, setWalletJson] = useState("");
  const [transactionHash, setTransactionHash] = useState("");
  const [delegateAddress, setDelegateAddress] = useState("");
  const [validUntilLedger, setValidUntilLedger] = useState("");
  const [maxCalls, setMaxCalls] = useState("1");
  const [grantName, setGrantName] = useState("delegated-action");
  useEffect(() => {
    if (controller.current) return;
    try {
      const token = takeSessionToken(window.location, window.history);
      const instance = new WalletController({
        request: createClient(token), validators: { reviewIntent, validateAssembly, validateSignedAuthorization,
          reviewSample, validateSampleAssembly, liveCases, consentDisplay, statementHash, checkLiveOwnerEntry, validateLiveOwnerSignature,
          installConsent, reviewRemoval, validateRemovalAssembly, revokeConsent },
        pins: { networkId: NETWORK_ID, accountWasm: ACCOUNT_WASM, verifierWasm: WEBAUTHN_WASM },
        origin: window.location.origin, onChange: setState,
        sign: async ({ approval, checked }) => {
          // Upstream SDK16 owns WebAuthn. The nested SDK17 validators receive serialized XDR.
          const entries = checked.authEntriesXdr.map((raw) => xdr.SorobanAuthorizationEntry.fromXDR(raw, "base64"));
          const signed = await signWalletAuthEntries({ authEntries: entries, wallet: approval.wallet,
            contextRuleIds: [checked.ownerRuleId], expiration: checked.expirationLedger,
            verifier: approval.wallet.verifier, networkPassphrase: Networks.TESTNET });
          return signed.map((entry) => entry.toXDR("base64"));
        },
      });
      controller.current = instance;
      setState(instance.state);
      void instance.connect().then(() => setMessage("Connected to the local testnet wallet backend."))
        .catch(() => setMessage("Connection refused. Open a fresh local launcher session."));
    } catch {
      setMessage("Session unavailable. Open a fresh local launcher session.");
    }
  }, []);
  useEffect(() => {
    setTransactionHash(state?.sampleTransactionHash ?? "");
  }, [state?.sampleTransactionHash, state?.wallet?.contractId]);
  useEffect(() => {
    if (state?.delegate?.address) setDelegateAddress(state.delegate.address);
  }, [state?.delegate?.address]);
  const busy = creating || state?.busy || !state?.status;
  const run = async (action: (value: WalletController) => Promise<void> | void) => {
    if (!controller.current || busy) return;
    setMessage("Working…");
    try { await action(controller.current); setMessage("Completed. Review the displayed result before continuing."); }
    catch { setMessage("Action refused. Refresh the evidence and review again."); }
  };
  const create = async () => {
    if (busy || creatingRef.current || !controller.current) return;
    creatingRef.current = true;
    setCreating(true);
    setMessage("Create the owner passkey. Account deployment requires a separate confirmation.");
    try {
      const credential = await createPasskey("Pollywallet Policy Builder", "Policy Builder owner");
      await controller.current.prepareAccount({ credentialId: credential.credentialId,
        publicKey: Buffer.from(credential.publicKey).toString("hex") });
      setMessage("Passkey created. Review the exact account deployment below.");
    } catch { setMessage("Passkey creation or account preparation was refused."); }
    finally { creatingRef.current = false; setCreating(false); }
  };
  const attach = () => run((value) => {
    const parsed: unknown = JSON.parse(walletJson);
    if (!parsed || typeof parsed !== "object") throw new Error("invalid wallet");
    const { contractId, credentialId, publicKey, verifier } = parsed as Record<string, unknown>;
    if (typeof contractId !== "string" || typeof credentialId !== "string"
      || typeof publicKey !== "string" || typeof verifier !== "string") {
      throw new Error("invalid wallet");
    }
    value.attachWallet({ contractId, credentialId, publicKey, verifier });
  });
  const bindings = { specHash: state?.artifact?.specHash, wasmHash: state?.artifact?.wasmHash,
    bindingSetHash: state?.deployment?.bindingSetHash };
  const gate = verificationGate(state?.review?.verification, bindings);
  return <main className="min-h-screen bg-slate-900 px-4 py-8 text-slate-100">
    <div className="mx-auto max-w-4xl space-y-6">
      <header>
        <p className="text-sm text-cyan-400">Pollywallet · Stellar testnet · local operator backend</p>
        <h1 className="mt-2 text-3xl font-semibold">Policy Builder</h1>
        <p className="mt-3 text-slate-300">Record an authorized transaction, inspect its generated grant, and review the exact
          policy before deployment or owner authorization. The owner passkey stays in your authenticator.</p>
      </header>
      <p role="status" aria-live="polite" className="rounded-lg border border-cyan-800 bg-cyan-950/30 p-4">{message}</p>
      <section className={panel} aria-labelledby="wallet-heading">
        <h2 id="wallet-heading" className="text-xl font-semibold">1. Choose the recognized account</h2>
        <p className="text-sm text-slate-300">This integration requires the reviewed account and verifier code shown below.
          Existing wallets with different code are refused.</p>
        <button className={button} disabled={busy} onClick={() => void create()}>Create owner passkey and preview account</button>
        {state?.accountPreview && <p className="rounded-lg border border-cyan-700 p-3 text-sm">
          The new account receives {xlm(object(state.accountPreview.summary).sampleFundingStroops)} for the sample transaction.
          {" "}Maximum total deployment and funding fees: {xlm(object(state.accountPreview.summary).maxTotalFeeStroops)}.
          {" "}These funds come from the local testnet fee payer.
        </p>}
        <Evidence title="Account deployment preview" value={state?.accountPreview} open />
        {state?.accountPreview && <button className={button} disabled={busy}
          onClick={() => void run((value) => value.confirmAccount())}>Confirm testnet account deployment</button>}
        <details><summary className="cursor-pointer">Attach an existing recognized wallet</summary>
          <label className="mt-3 block text-sm" htmlFor="wallet-locator">Public wallet locator JSON: contractId, credentialId, publicKey, verifier</label>
          <textarea id="wallet-locator" className={input} rows={4} value={walletJson}
            onChange={(event) => setWalletJson(event.target.value)} />
          <button className={button} disabled={busy || !walletJson} onClick={() => void attach()}>Use this wallet locator</button>
        </details>
        <Evidence title="Current public wallet locator — retain it to reconnect" value={state?.wallet} open />
      </section>
      <section className={panel} aria-labelledby="record-heading">
        <h2 id="record-heading" className="text-xl font-semibold">2. Record and generate</h2>
        {state?.sample && <div className="space-y-3 rounded-lg border border-cyan-700 bg-cyan-950/20 p-4">
          <h3 className="font-semibold">Create a sample transaction with this new account</h3>
          <p className="text-sm">Transfer exactly 0.1 testnet XLM from the account to the local testnet fee payer.
            The fee payer pays the transaction fee, up to 1 testnet XLM. Your owner passkey approves only this transfer.</p>
          <dl className="space-y-2 break-all text-sm">
            <div><dt className="text-slate-400">From</dt><dd>{state.wallet?.contractId}</dd></div>
            <div><dt className="text-slate-400">Recipient and fee payer</dt><dd>{state.sample.recipient}</dd></div>
          </dl>
          <button className={button} disabled={busy || state.sampleAttempted || !state.status?.capabilities.sampleTransfer}
            onClick={() => void run((value) => value.prepareSample())}>Prepare 0.1 XLM sample transfer</button>
          {state.samplePreview && <>
            <p className="text-sm">Prepared fee: {xlm(object(state.samplePreview.assembly).fee_stroops)}.
              {" "}Review expires within 120 seconds and may expire sooner as ledgers advance.</p>
            <div className="flex flex-wrap gap-3">
              <button className={button} disabled={busy}
                onClick={() => void run((value) => value.approveSample())}>Approve 0.1 XLM transfer with owner passkey</button>
              <button className={button} disabled={busy}
                onClick={() => void run((value) => value.cancelSample())}>Cancel sample review</button>
            </div>
            <Evidence title="Exact unsigned sample transaction and owner evidence" value={state.samplePreview} />
          </>}
          {state.sampleAttempted && !state.sampleTransactionHash && <p className="text-sm text-amber-200">
            A submission was attempted. Further sample attempts are disabled. Check the backend journal if confirmation is missing.
          </p>}
          {state.sampleTransactionHash && <p className="text-sm text-cyan-300">
            Sample transfer confirmed. Record its hash below to generate the grant.
          </p>}
        </div>}
        <label htmlFor="record-hash" className="block text-sm">Confirmed testnet transaction hash authorized by this account</label>
        <input id="record-hash" className={input} value={transactionHash} onChange={(event) => setTransactionHash(event.target.value)} />
        <button className={button} disabled={busy || !state?.wallet || !state?.status?.capabilities.record}
          onClick={() => void run((value) => value.record(transactionHash.trim()))}>Record transaction</button>
        <Evidence title="Recorded authorization and evidence" value={state?.record} />
        <label htmlFor="delegate" className="block text-sm">Restricted delegate address</label>
        <input id="delegate" className={input} value={delegateAddress} onChange={(event) => setDelegateAddress(event.target.value)} />
        {(state?.status?.capabilities.accountCheck || state?.status?.capabilities.liveCheck) && <div className="space-y-2 text-sm">
          <button className={button} disabled={busy || !!state.delegate}
            onClick={() => void run((value) => value.createDelegate())}>Create local automation delegate</button>
          <p className="text-slate-400">The backend creates an Ed25519 delegate key held only in its memory and discarded when it stops,
            and creates its testnet account through Friendbot so that a grant can name it.
            It signs offline candidate-execution checks and, only after you consent, the live check's two testnet transfers, which
            the backend simulates and never submits. It is automation, not your owner passkey, and no key leaves the backend.</p>
        </div>}
        <div className="grid gap-4 sm:grid-cols-3">
          <label className="text-sm">Grant name<input className={input} maxLength={20} value={grantName} onChange={(event) => setGrantName(event.target.value)} /></label>
          <label className="text-sm">Expires at ledger<input className={input} type="number" min="1" max="4294967295"
            value={validUntilLedger} onChange={(event) => setValidUntilLedger(event.target.value)} /></label>
          <label className="text-sm">Maximum calls<input className={input} type="number" min="1" max="10000"
            value={maxCalls} onChange={(event) => setMaxCalls(event.target.value)} /></label>
        </div>
        <button className={button} disabled={busy || !state?.record || !state?.status?.capabilities.generate}
          onClick={() => void run((value) => value.generate({ delegateAddress: delegateAddress.trim(), grantName,
            validUntilLedger: Number(validUntilLedger), maxCalls: Number(maxCalls) }))}>Generate and verify policy</button>
        <GrantSummary spec={state?.artifact?.spec} />
        <Evidence title="Immutable generated artifact, exact specification, source and verification" value={state?.artifact} />
      </section>
      <section className={panel} aria-labelledby="deploy-heading">
        <h2 id="deploy-heading" className="text-xl font-semibold">3. Deploy the exact artifact</h2>
        <p className="text-sm text-slate-300">Deployment spends the local testnet fee payer's funds. It does not grant authority over your account.</p>
        <button className={button} disabled={busy || !state?.artifact || !!state.deployment || !state?.status?.capabilities.deploy}
          onClick={() => void run((value) => value.prepareDeploy())}>Preview deployment</button>
        <Evidence title="Deployment consent" value={state?.deployPreview} open />
        {state?.deployPreview && <button className={button} disabled={busy}
          onClick={() => void run((value) => value.confirmDeploy())}>Confirm exact policy deployment</button>}
        <Evidence title="Deployed policy and binding set" value={state?.deployment} />
      </section>
      <section className={panel} aria-labelledby="review-heading">
        <h2 id="review-heading" className="text-xl font-semibold">4. Review owner authorization</h2>
        <button className={button} disabled={busy || !state?.deployment}
          onClick={() => void run((value) => value.review())}>Refresh authority and review exact grant</button>
        {state?.review && <GrantSummary spec={state?.artifact?.spec} />}
        <Evidence title="Exact grant, owner authority and evidence" value={state?.review} />
        <VerificationLayers verification={state?.review?.verification} />
        {state?.status?.capabilities.accountCheck && <button className={button}
          disabled={busy || !state?.review || !state?.delegate}
          onClick={() => void run((value) => value.checkAccount())}>Run local execution checks with the local delegate</button>}
        <p className="text-sm text-slate-300">Local verification: {gate.localReady ? "three required layers passed" : "incomplete"}.
          {" "}Full acceptance: {gate.acceptanceReady ? "all four required layers passed" : "incomplete; installation is disabled"}.</p>
        <p className="text-sm text-slate-400">The live-enforcement layer comes only from the consented live check below. A virtual
          authenticator does not establish human approval. The local checks run with an offline signing domain: account-Wasm in fresh
          synthetic state, then the exact transfer against target state the operator RPC reports now. Neither is live-enforcement or
          installation evidence.</p>
      </section>
      <section className={panel} aria-labelledby="live-heading">
        <h2 id="live-heading" className="text-xl font-semibold">5. Live enforcement check</h2>
        <p className="text-sm text-slate-300">Simulates the reviewed grant on testnet through the atomic live helper: the exact transfer,
          which the policy must permit, and one stroop more, which it must refuse. Nothing is submitted, but the signatures it needs are
          real until they expire, so the check runs only after you consent to the statement below.</p>
        {state?.status?.capabilities.liveCheck && <button className={button}
          disabled={busy || !state?.review || !state?.delegate || !!state?.livePreview}
          onClick={() => void run((value) => value.prepareLive())}>Prepare the live check</button>}
        {state?.livePreview && <LiveConsent display={state.livePreview.display} />}
        {state?.livePreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.consentLive())}>I consent: sign the installation with my owner passkey and simulate both cases</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelLive())}>Cancel live check</button>
        </div>}
        {state?.status?.capabilities.liveCheck && <button className={button} disabled={busy || !state?.review}
          onClick={() => void run((value) => value.checkReplay())}>Check that the live-check signatures were not used</button>}
        {state?.replay && state.replay.status === "closed" && <p className="rounded-lg border border-slate-700 p-3 text-sm">
          Replay check: closed. Every released signature expired unused or was used by this session's installation
          {" "}{items(state.replay.closedBy).map(label).join(", ")}.
        </p>}
        {state?.replay && state.replay.status !== "closed" && <p className={`rounded-lg border p-3 text-sm ${state.replay.status === "changed" ? "border-red-500 text-red-200" : "border-slate-700"}`}>
          Replay check: {label(state.replay.status)} at ledger {label(state.replay.latestLedger)}; signatures valid until ledger {label(state.replay.signaturesValidUntil)}.
          {" "}{label(state.replay.alert ?? (state.replay.status === "waiting" ? "Installation must wait until that ledger has passed." : "The account did not change."))}
        </p>}
      </section>
      <section className={panel} aria-labelledby="install-heading">
        <h2 id="install-heading" className="text-xl font-semibold">6. Install the reviewed grant</h2>
        <p className="text-sm text-slate-300">Available only when all four layers passed for this review, their captured and live evidence
          is recent, and the replay check shows the live-check signatures expired unused. The backend asks the CLI for a fresh unsigned
          transaction, which this browser checks against the review before showing what your passkey would sign.
          Installation is {state?.status?.capabilities.install ? "available" : "not available"} in this backend.
          {typeof state?.status?.installOpensAfterLedger === "number" && <> An earlier released signature stays valid until ledger
            {" "}{label(state.status.installOpensAfterLedger)}; no installation entry is released before that ledger has passed.</>}</p>
        <button className={button}
          disabled={busy || !state?.review || !gate.acceptanceReady || !state?.status?.capabilities.install || state?.installAttempted || !!state?.installPreview}
          onClick={() => void run((value) => value.prepareInstall())}>Prepare installation</button>
        {state?.installPreview && <InstallConsent display={state.installPreview.display} />}
        {state?.installPreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.install())}>I consent: sign the installation with my owner passkey</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelInstall())}>Cancel installation</button>
        </div>}
        {state?.installAttempted && !state?.installation && <p className="text-sm text-amber-200">
          An installation was attempted. Further attempts are disabled; the backend lists what it confirmed below and in its journal.
        </p>}
        <Evidence title="Installation record" value={state?.installation} open />
      </section>
      <section className={panel} aria-labelledby="revoke-heading">
        <h2 id="revoke-heading" className="text-xl font-semibold">7. Revoke</h2>
        <p className="text-sm text-slate-300">Removes the installed rule with a transaction your owner passkey signs. It succeeds only when the
          account reports the removal and the rule then reads back absent; whether the policy dropped its own state is reported separately.</p>
        <button className={button}
          disabled={busy || !state?.installation || !state?.status?.capabilities.lifecycle || state?.revokeAttempted || !!state?.revokePreview}
          onClick={() => void run((value) => value.prepareRevoke())}>Prepare revocation</button>
        {state?.revokePreview && <RevokeConsent display={state.revokePreview.display} />}
        {state?.revokePreview && <div className="flex flex-wrap gap-3">
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.revoke())}>I consent: sign the removal with my owner passkey</button>
          <button className={button} disabled={busy}
            onClick={() => void run((value) => value.cancelRevoke())}>Cancel revocation</button>
        </div>}
        <Evidence title="Removal result" value={state?.removal} open />
      </section>
      <Evidence title="Transaction receipts" value={state?.receipt} open />
      <Evidence title="Backend capabilities, installations, recognized code and verification limitations" value={state?.status} />
      <p className="text-sm text-slate-400">Monitoring and replacement controls appear only when their backend checks are implemented.
        Keep this session on the local operator machine.</p>
    </div>
  </main>;
}
