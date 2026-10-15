// Deploy a generated policy and install it into the run's smart account with `add_context_rule`,
// authorized by the account's administrator — the step a wallet performs when its user approves.
//
//   OZPB_HARNESS_SECRETS=<file> node install.mjs --run-dir <dir> --wasm <generated .wasm>
//
// The rule is built from the spec the policy was generated from, not from arguments: its target,
// expiry and signer set are the ones compiled into the policy, which refuses (`SignerSetDiverged`)
// if the live rule's signers ever differ from them. The owner signs through rule 0, the Default
// rule the constructor created; the account's `add_context_rule` then calls the policy's
// `install`, so a policy that refuses installation fails this transaction.
//
// What this does NOT do: `prepare_install_intent` and the authority-surface check
// (`docs/SCOPE.md` §1) are not exported for wallet use on this tree, so nothing here establishes
// that installing is safe on an account someone else controls. The harness installs only into the
// account setup.mjs deployed a moment earlier, whose administrator it knows by construction.
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  Address, Operation, TransactionBuilder, nativeToScVal, rpc, scValToNative, xdr,
} from '@stellar/stellar-sdk';

import { callContractRule, contractCall, delegatedSigner, entryAddress, optionU32, signForSmartAccount } from './lib.mjs';
import {
  NETWORK_PASSPHRASE, args, assertTestnet, contractCodeHash, contractIdOf, latestLedger, loadKey, log,
  readJson, recordAuth, server, submit, writeJson,
} from './rpc.mjs';

const ADMIN_RULE = 0;

const opts = args();
const runPath = join(opts['run-dir'], 'run.json');
const run = readJson(runPath);
const spec = readJson(run.spec);
const wasm = readFileSync(opts.wasm);
const payer = loadKey('payer');
const owner = loadKey('owner');

if (spec.rules.length !== 1) throw new Error('the harness installs single-rule specs');
const rule = spec.rules[0];
if (spec.smart_account.address !== run.account) throw new Error('spec is for another account');
const signers = rule.authorization.signers.map((s) => {
  if (!s.delegated) throw new Error('only Delegated signers are installable here');
  return s.delegated.address;
});

// The wasm must be the one generated from this spec's rule 0. `ozpb generate` writes a
// BuildManifest beside it; its spec hash is canonical and not recomputed here, but the wasm hash,
// rule index and registry snapshot are checked so a stray --wasm cannot be installed silently.
const wasmHash = createHash('sha256').update(wasm).digest('hex');
const manifest = readJson(join(dirname(opts.wasm), 'build-manifest.json'));
if (manifest.wasm_hash !== wasmHash || manifest.rule_index !== 0 || manifest.registry_snapshot !== spec.registry_snapshot) {
  throw new Error('the wasm is not the one build-manifest.json beside it records for rule 0 of this spec');
}
await assertTestnet();

// --- deploy the generated artifact ---------------------------------------------------------------
const upload = await submit(payer, Operation.uploadContractWasm({ wasm }), { stage: 'upload policy wasm' });
const uploaded = Buffer.from(scValToNative(upload.returnValue)).toString('hex');
if (uploaded !== wasmHash) throw new Error(`network stored ${uploaded}, local wasm is ${wasmHash}`);
log(`uploaded  policy wasm ${wasmHash}  (tx ${upload.hash})`);

const create = await submit(payer, Operation.createCustomContract({
  address: new Address(payer.publicKey()),
  wasmHash: Buffer.from(wasmHash, 'hex'),
  salt: randomBytes(32),
}), { stage: 'create policy' });
const policy = contractIdOf(create.returnValue);
if ((await contractCodeHash(policy)) !== wasmHash) throw new Error('deployed policy runs other code');
log(`policy    ${policy}  (tx ${create.hash})`);

// --- add_context_rule(context_type, name, valid_until, signers, policies) ------------------------
// `policies: Map<Address, Val>` maps each policy to its install parameters; the generated policy's
// `AccountParams` is `u32`, and it ignores the value.
const ruleArgs = [
  callContractRule(rule.context.contract),
  nativeToScVal(spec.name, { type: 'string' }),
  optionU32(rule.valid_until?.ledger),
  xdr.ScVal.scvVec(signers.map(delegatedSigner)),
  xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: new Address(policy).toScVal(), val: xdr.ScVal.scvU32(0) })]),
];
const addRule = (auth) => Operation.invokeContractFunction({
  contract: run.account, function: 'add_context_rule', args: ruleArgs, ...(auth ? { auth } : {}),
});

const recorded = await recordAuth(payer, addRule(), 'add_context_rule');
const own = recorded.filter((e) => entryAddress(e) === run.account);
if (own.length !== 1 || recorded.length !== 1) {
  throw new Error(`expected exactly the account's own auth entry, recorded ${recorded.length}`);
}
const { accountEntry, delegateEntry } = await signForSmartAccount({
  entry: own[0], expect: contractCall(run.account, 'add_context_rule', ruleArgs), signer: owner, ruleIds: [ADMIN_RULE],
  validUntilLedger: (await latestLedger()) + 100, networkPassphrase: NETWORK_PASSPHRASE,
});
const installed = await submit(payer, addRule([accountEntry, delegateEntry]), { stage: 'add_context_rule' });
const contextRule = scValToNative(installed.returnValue);
const ruleId = Number(contextRule.id);
log(`installed rule ${ruleId} "${contextRule.name}" → policy ${policy}  (tx ${installed.hash})`);

// --- read it back --------------------------------------------------------------------------------
// From the policy's side, not just the account's: `is_installed` is true only if the policy's own
// `install` ran for this (account, rule).
async function view(contract, fn, fnArgs) {
  const source = await server.getAccount(payer.publicKey());
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(Operation.invokeContractFunction({ contract, function: fn, args: fnArgs }))
    .setTimeout(60).build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(`${fn}: ${sim.error.split('\n')[0]}`);
  return scValToNative(sim.result.retval);
}
const isInstalled = await view(policy, 'is_installed', [xdr.ScVal.scvU32(ruleId), new Address(run.account).toScVal()]);
const remaining = await view(policy, 'remaining_calls', [xdr.ScVal.scvU32(ruleId), new Address(run.account).toScVal()]);
if (isInstalled !== true) throw new Error('policy does not report itself installed');
log(`          policy reports is_installed = ${isInstalled}, remaining_calls = ${remaining}`);

Object.assign(run, {
  policy,
  policy_wasm_hash: wasmHash,
  rule_id: ruleId,
});
run.tx = { ...run.tx, upload_policy: upload.hash, create_policy: create.hash, add_context_rule: installed.hash };
writeJson(runPath, run);
