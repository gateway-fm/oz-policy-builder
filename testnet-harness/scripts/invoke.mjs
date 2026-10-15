// Make the smart account call the native SAC's `transfer(from = account, to, amount)`, authorized
// by one of its Delegated signers through one context rule, and report what the account decided.
//
//   OZPB_HARNESS_SECRETS=<file> node invoke.mjs --run-dir <dir> --amount <stroops> --to <G…>
//       [--signer delegate|owner] [--rule <id>] [--expect permit|deny:<code>] [--bundle <out.json>]
//
// `--signer delegate` (the default) goes through the rule the generated policy guards, so the
// account's `__check_auth` calls the policy's `enforce`; `--signer owner --rule 0` goes through
// the Default rule, which has no policy. The run uses the second once, to make the recorded
// transaction the spec is justified by.
//
// A denial is observed in the enforcing simulation, before the transaction is signed or
// submitted: the simulation runs `__check_auth` and every installed policy exactly as the network
// would. With
// `--expect deny:<code>` the code must have been raised by the installed policy contract itself,
// not merely appear somewhere in the error, so an unrelated failure cannot pass as a denial.
import { join } from 'node:path';
import { Address, Operation } from '@stellar/stellar-sdk';

import { contractCall, entryAddress, i128, policyDenial, signForSmartAccount } from './lib.mjs';
import {
  NETWORK_PASSPHRASE, RPC_URL, SimulationError, args, assertTestnet, latestLedger, loadKey, log, readJson,
  recordAuth, submit, writeJson,
} from './rpc.mjs';

const opts = args();
const run = readJson(join(opts['run-dir'], 'run.json'));
const signerName = opts.signer ?? 'delegate';
if (!['delegate', 'owner'].includes(signerName)) throw new Error('--signer is delegate or owner');
const ruleId = Number(opts.rule ?? (signerName === 'owner' ? 0 : run.rule_id));
if (!Number.isInteger(ruleId)) throw new Error('no rule id: pass --rule, or run install.mjs first');
const amount = BigInt(opts.amount);
const to = opts.to;
const expect = opts.expect;

const payer = loadKey('payer');
const signer = loadKey(signerName);

const transferArgs = [new Address(run.account).toScVal(), new Address(to).toScVal(), i128(amount)];
const transfer = (auth) => Operation.invokeContractFunction({
  contract: run.sac, function: 'transfer', args: transferArgs, ...(auth ? { auth } : {}),
});

await assertTestnet();

const label = `transfer ${amount} → ${to.slice(0, 6)}… as ${signerName} via rule ${ruleId}`;
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
const op = transfer([accountEntry, delegateEntry]);

let outcome;
try {
  const sent = await submit(payer, op, { stage: label });
  outcome = { result: 'permit', hash: sent.hash };
  log(`PERMITTED  ${label}  tx ${sent.hash}`);
  if (opts.bundle) await writeImportBundle(sent.hash, opts.bundle);
} catch (e) {
  if (!(e instanceof SimulationError)) throw e;
  const code = run.policy ? policyDenial(e.error, run.account, run.policy) : null;
  outcome = { result: 'deny', policy_code: code, host: e.error.split('\n')[0] };
  log(`DENIED     ${label}  policy error ${code === null ? '(none: not raised by the policy)' : `#${code}`}`);
  log(`           ${outcome.host}`);
}

// Kept in the run directory, so the evidence of each attempt outlives the terminal.
const record = { label, signer: signerName, rule: ruleId, amount: amount.toString(), to, ...outcome };
run.invocations = [...(run.invocations ?? []), record];
writeJson(join(opts['run-dir'], 'run.json'), run);

if (expect) {
  const ok = expect === 'permit'
    ? outcome.result === 'permit'
    : outcome.result === 'deny' && `deny:${outcome.policy_code}` === expect;
  if (!ok) {
    console.error(`UNEXPECTED: wanted ${expect}, got ${outcome.result}${outcome.policy_code ? `:${outcome.policy_code}` : ''}`);
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
