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
import { validateSignedAuthorization } from "../policy-builder/shared/signature.mjs";

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
        request: createClient(token), validators: { reviewIntent, validateAssembly, validateSignedAuthorization },
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
        <label htmlFor="record-hash" className="block text-sm">Confirmed testnet transaction hash authorized by this account</label>
        <input id="record-hash" className={input} value={transactionHash} onChange={(event) => setTransactionHash(event.target.value)} />
        <button className={button} disabled={busy || !state?.wallet || !state?.status?.capabilities.record}
          onClick={() => void run((value) => value.record(transactionHash.trim()))}>Record transaction</button>
        <Evidence title="Recorded authorization and evidence" value={state?.record} />
        <label htmlFor="delegate" className="block text-sm">Restricted delegate address</label>
        <input id="delegate" className={input} value={delegateAddress} onChange={(event) => setDelegateAddress(event.target.value)} />
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
        <p className="text-sm text-slate-300">Local verification: {gate.localReady ? "three required layers passed" : "incomplete"}.
          {" "}Full acceptance: {gate.acceptanceReady ? "all four required layers passed" : "incomplete; signing is disabled"}.</p>
        <button className={button} disabled={busy || !state?.review || !gate.acceptanceReady || !state?.status?.capabilities.install}
          onClick={() => void run((value) => value.install())}>Approve exact grant with owner passkey and install</button>
        <p className="text-sm text-slate-400">A refreshed unsigned envelope is checked against this review before the authenticator prompt.
          Missing live-enforcement evidence remains unavailable. A virtual authenticator does not establish human approval.</p>
      </section>
      <Evidence title="Transaction receipts and installation result" value={{ receipt: state?.receipt, installation: state?.installation }} open />
      <Evidence title="Backend capabilities, recognized code and verification limitations" value={state?.status} />
      <p className="text-sm text-slate-400">Monitoring, revocation and replacement controls appear only when their backend checks are implemented.
        Keep this session on the local operator machine.</p>
    </div>
  </main>;
}
