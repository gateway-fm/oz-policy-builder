// Make the smart account call the native SAC's `transfer(from = account, to, amount)`, authorized
// by one of its signers through one context rule, and report what the account decided.
//
//   OZPB_HARNESS_SECRETS=<file> node invoke.mjs --run-dir <dir> --amount <stroops> --to <G…>
//       [--signer delegate|owner] [--rule <id>] [--expect permit|deny:<code>] [--bundle <out.json>]
//       [--wrong-challenge yes]
//
// `--signer delegate` (the default) goes through the rule the generated policy guards, so the
// account's `__check_auth` calls the policy's `enforce`; `--signer owner --rule 0` goes through
// the Default rule, which has no policy. The run uses the second once, to make the recorded
// transaction the spec is justified by. The owner is whatever setup.mjs created: an ed25519 key,
// or a passkey that signs in a headless browser (`owner.mjs`).
//
// A denial is observed in the enforcing simulation, before the transaction is signed or
// submitted: the simulation runs `__check_auth` and every installed policy exactly as the network
// would. With
// `--expect deny:<code>` the code must have been raised by the installed policy contract itself,
// not merely appear somewhere in the error, so an unrelated failure cannot pass as a denial.
//
// `--signer owner --wrong-challenge yes` is the passkey's negative control: the passkey signs
// random bytes instead of the account's digest, and the code must come from the WebAuthn
// verifier contract instead of the policy (`ChallengeInvalid`, #3114). It shows that the
// verifier is consulted, and that a well-formed passkey signature over some other challenge
// does not authorize this call.
import { join } from 'node:path';
import { Address, Operation } from '@stellar/stellar-sdk';

import { contractCall, entryAddress, i128, policyDenial, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import {
  NETWORK_PASSPHRASE, RPC_URL, SimulationError, args, assertTestnet, latestLedger, loadKey, log, readJson,
  enforceSimulation, recordAuth, submit, writeJson,
} from './rpc.mjs';

const opts = args();
const run = readJson(join(opts['run-dir'], 'run.json'));
const signerName = opts.signer ?? 'delegate';
if (!['delegate', 'owner'].includes(signerName)) throw new Error('--signer is delegate or owner');
const ruleId = Number(opts.rule ?? (signerName === 'owner' ? 0 : run.rule_id));
if (!Number.isInteger(ruleId)) throw new Error('no rule id: pass --rule, or run install.mjs first');
const amount = BigInt(opts.amount);
const to = opts.to;
const wrongChallenge = opts['wrong-challenge'] === 'yes';
const expect = opts.expect ?? (wrongChallenge ? 'deny:3114' : undefined);
if (wrongChallenge && expect !== 'deny:3114') throw new Error('--wrong-challenge requires an expected verifier denial');
const postRevocation = expect === 'deny-account:3000';
const negativeControl = postRevocation || /^deny:[0-9]+$/.test(expect ?? '');
if (expect !== undefined && expect !== 'permit' && !negativeControl) throw new Error('invalid --expect');
if (negativeControl && opts.bundle) throw new Error('negative controls cannot export an executed transaction bundle');
if (postRevocation && (signerName !== 'delegate' || !run.lifecycle?.removals?.some((r) =>
  r.rule_id === ruleId && r.event === 'verified' && r.rule_readback === 'absent'))) {
  throw new Error('account-denial control requires the delegate and a confirmed removal of this rule');
}

const payer = loadKey('payer');
if (opts['wrong-challenge'] !== undefined && (!wrongChallenge || signerName !== 'owner')) {
  throw new Error('--wrong-challenge yes applies only to --signer owner');
}
const signer = signerName === 'owner' ? await ownerSigner(run, { wrongChallenge }) : loadKey(signerName);
// The contract whose own error code counts as the refusal: the verifier for the control, else the policy.
const enforcer = wrongChallenge ? run.owner.verifier : postRevocation ? run.account : run.policy;

const transferArgs = [new Address(run.account).toScVal(), new Address(to).toScVal(), i128(amount)];
const transfer = (auth) => Operation.invokeContractFunction({
  contract: run.sac, function: 'transfer', args: transferArgs, ...(auth ? { auth } : {}),
});

await assertTestnet();

const label = `transfer ${amount} → ${to.slice(0, 6)}… as ${signerName}${wrongChallenge ? ' (wrong challenge)' : ''} via rule ${ruleId}`;
const entries = await recordAuth(payer, transfer(), label);
const own = entries.filter((e) => entryAddress(e) === run.account);
if (own.length !== 1 || entries.length !== 1) {
  throw new Error(`expected exactly the account's own auth entry, recorded ${entries.length}`);
}

const validUntil = (await latestLedger()) + 100;
const { accountEntry, delegateEntry } = await signForSmartAccount({
  entry: own[0], expect: contractCall(run.sac, 'transfer', transferArgs), signer, ruleIds: [ruleId],
  validUntilLedger: validUntil, networkPassphrase: NETWORK_PASSPHRASE,
});
// A Delegated signer's proof is a second entry; an External signer's is inside the account's.
const op = transfer([accountEntry, delegateEntry].filter(Boolean));

let outcome; let simulationLedger;
try {
  if (negativeControl) {
    const observed = await enforceSimulation(payer, op);
    simulationLedger = observed.ledger;
    if (observed.result === 'deny') throw new SimulationError(label, observed.error);
    if (observed.result !== 'permit') throw new Error('unexpected enforcing simulation result');
    outcome = { result: 'permit', observation: 'enforcing_simulation', ledger: simulationLedger };
    log(`UNEXPECTED SIMULATION PERMIT  ${label}; no fee transaction submitted`);
  } else {
    const sent = await submit(payer, op, { stage: label });
    outcome = { result: 'permit', hash: sent.hash, ...(sent.receipt?.ledger ? { ledger: sent.receipt.ledger } : {}) };
    log(`PERMITTED  ${label}  tx ${sent.hash}`);
    if (opts.bundle) await writeImportBundle(sent.hash, opts.bundle);
  }
} catch (e) {
  if (!(e instanceof SimulationError)) throw e;
  const code = enforcer ? policyDenial(e.error, run.account, enforcer) : null;
  const who = wrongChallenge ? 'verifier' : postRevocation ? 'account' : 'policy';
  outcome = { result: 'deny', enforcer: enforcer ?? null, code, host: e.error.split('\n')[0],
    ...(simulationLedger === undefined ? {} : { ledger: simulationLedger }) };
  log(`DENIED     ${label}  ${who} error ${code === null ? `(none: not raised by the ${who})` : `#${code}`}`);
  log(`           ${outcome.host}`);
}

// Kept in the run directory, so the evidence of each attempt outlives the terminal.
const record = { label, signer: signerName, rule: ruleId, amount: amount.toString(), to,
  ...(postRevocation ? { control: 'post_revocation' } : {}), ...outcome };
run.invocations = [...(run.invocations ?? []), record];
writeJson(join(opts['run-dir'], 'run.json'), run);

if (expect) {
  const ok = expect === 'permit'
    ? outcome.result === 'permit'
    : outcome.result === 'deny' && `${postRevocation ? 'deny-account' : 'deny'}:${outcome.code}` === expect;
  if (!ok) {
    console.error(`UNEXPECTED: wanted ${expect}, got ${outcome.result}${outcome.code ? `:${outcome.code}` : ''}`);
    process.exit(1);
  }
}

/**
 * Save an executed transaction in the shape `ozpb import` reads (docs/examples/import-bundle.json):
 * the raw XDR exactly as RPC returned it, nothing decoded or re-encoded on the way.
 */
async function writeImportBundle(hash, path) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getTransaction', params: { hash } }),
  });
  const { result } = await res.json();
  if (result?.status !== 'SUCCESS') throw new Error(`getTransaction ${hash}: ${result?.status}`);
  writeJson(path, {
    created_at_unix: Number(result.createdAt),
    envelope_xdr_base64: result.envelopeXdr,
    ledger: result.ledger,
    network_passphrase: NETWORK_PASSPHRASE,
    result_meta_xdr_base64: result.resultMetaXdr,
    result_xdr_base64: result.resultXdr,
    successful: true,
  });
  log(`           import bundle → ${path}`);
}
