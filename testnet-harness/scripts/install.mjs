// Deploy a generated policy and install it into the run's smart account with `add_context_rule`,
// authorized by the account's administrator — the step a wallet performs when its user approves.
//
//   OZPB_HARNESS_SECRETS=<file> node install.mjs --run-dir <dir> --wasm <generated .wasm>
//       [--authority-check cli --confirm tty|operator [--trust <file>]]
//
// The rule is built from the spec the policy was generated from, not from arguments: its target,
// expiry and signer set are the ones compiled into the policy, which refuses (`SignerSetDiverged`)
// if the live rule's signers ever differ from them. The owner signs through rule 0, the Default
// rule the constructor created: an ed25519 key, or a passkey signing in a headless browser
// (`owner.mjs`). The account's `add_context_rule` then calls the policy's `install`, so a policy
// that refuses installation fails this transaction.
//
// Without `--authority-check`, nothing here asks who else can change the account: the harness
// installs only into the account setup.mjs deployed a moment earlier, whose administrator it knows
// by construction. That is not evidence about anyone else's account.
//
// With `--authority-check cli` the harness acts as the wallet that holds the owner key
// (`approve-install.mjs`): it asks `ozpb prepare-install-intent` for the arguments, decides on the
// authority check's answer with its own trust, shows the confirmation screen, re-runs the check
// just before signing and requires the same `authority_commitment` (and an unexpired grant at the
// fresh ledger). It then signs exactly the intent's arguments, which must also equal the ones
// built here from the spec. The spec must name the signed registry root (`write-spec.mjs
// --registry-root`), and the check is run with the same stellar-cli and build cache as
// `ozpb generate` (`OZPB_STELLAR_BINARY`, `OZPB_BUILD_CACHE_DIR`), because it rebuilds the policy
// to recognize it. The trust is operator-supplied test configuration (the owner key this run
// created, plus `--trust`); `--confirm tty` is a terminal prompt and `--confirm operator` is no
// prompt at all: neither shows that a human approved. It needs an `ozpb` built from the branch
// that has the check commands (`OZPB_BIN`); README records the testnet runs it has had.
import { randomBytes } from 'node:crypto';
import { closeSync, openSync, readFileSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { ReadStream } from 'node:tty';
import { Address, Operation, scValToNative, xdr } from '@stellar/stellar-sdk';

import { approveInstall, signedRuleArgs } from './approve-install.mjs';
import { checkArtifact } from './artifact.mjs';
import { cliCheckRunner } from './check-runner.mjs';
import { RawJson, parseJsonExact } from './raw-json.mjs';
import { addContextRuleArgs, contractCall, entryAddress, signForSmartAccount } from './lib.mjs';
import { ownerSigner } from './owner.mjs';
import { TRUST_OPERATOR, checkRequest, walletTrust } from './wallet-decision.mjs';
import {
  NETWORK_PASSPHRASE, args, assertTestnet, contractCodeHash, contractIdOf, latestLedger, loadKey, log,
  readJson, recordAuth, submit, viewCall, writeJson,
} from './rpc.mjs';

const ADMIN_RULE = 0;

const opts = args();
const runPath = join(opts['run-dir'], 'run.json');
const run = readJson(runPath);
// Read exactly: with --authority-check the spec and manifest are passed on to the check.
const spec = parseJsonExact(readFileSync(run.spec, 'utf8'));
const wasm = readFileSync(opts.wasm);

// The authority check, if asked for, is configured before anything is deployed, so a missing
// setting fails here rather than after the policy is on chain.
const authorityCheck = opts['authority-check'];
if (authorityCheck !== undefined && authorityCheck !== 'cli') throw new Error('--authority-check takes cli');
if (!authorityCheck && (opts.trust !== undefined || opts.confirm !== undefined)) {
  throw new Error('--trust and --confirm apply only with --authority-check');
}
let checker;
if (authorityCheck) {
  const env = (name) => {
    if (!process.env[name]) throw new Error(`--authority-check needs ${name}`);
    return process.env[name];
  };
  if (!['tty', 'operator'].includes(opts.confirm)) throw new Error('--authority-check needs --confirm tty|operator');
  if (opts.confirm === 'tty') {
    // Fail now, not after the policy is deployed, if there is no terminal to ask on.
    try { closeSync(openSync('/dev/tty', 'r')); } catch { throw new Error('--confirm tty needs a controlling terminal'); }
  }
  if (/^0+$/.test(spec.registry_snapshot)) {
    throw new Error('--authority-check needs a spec that names the signed registry root: write it with write-spec.mjs --registry-root');
  }
  const operator = opts.trust ? readJson(opts.trust).operator ?? [] : [];
  const own = run.owner.kind === 'passkey'
    ? [{ scheme: 'webauthn_p256', public_key: run.owner.public_key }]
    : [{ classic_account: run.owner.address }];
  checker = {
    runner: cliCheckRunner({
      // A built `ozpb` that has the check commands; this tree's own CLI does not. It must be the
      // one `ozpb generate` ran with, or the check's rebuild of the policy will not match.
      command: [env('OZPB_BIN')],
      registryRoots: env('OZPB_REGISTRY_ROOTS_FILE'),
      registryMinVersion: env('OZPB_REGISTRY_MIN_VERSION'),
      rpcSources: env('OZPB_RPC_SOURCES_FILE'),
      // The check rebuilds the policy offline and compares it with the manifest: the same
      // stellar-cli and the warm cache `ozpb generate` used, or the rebuild cannot match.
      build: {
        stellarBinary: process.env.OZPB_STELLAR_BINARY,
        cacheDir: process.env.OZPB_BUILD_CACHE_DIR,
        jobs: process.env.OZPB_BUILD_JOBS,
        timeoutSecs: process.env.OZPB_BUILD_TIMEOUT_SECS,
      },
    }),
    // Raw: the signed snapshot carries integers JavaScript numbers cannot hold exactly.
    signedRegistrySnapshot: new RawJson(readFileSync(env('OZPB_SIGNED_REGISTRY_SNAPSHOT'), 'utf8')),
    rpcSource: process.env.OZPB_RPC_SOURCE ?? 'testnet',
    trust: walletTrust({ own, operator }),
    operator,
    confirm: opts.confirm === 'tty' ? ttyConfirm : async () => {
      log(`          no prompt: --confirm operator approves ahead of time (${TRUST_OPERATOR})`);
      return true;
    },
  };
}

/**
 * Ask on the terminal itself, not stdin. UX only: whoever has this terminal can answer. A TTY
 * stream, destroyed afterwards, so no pending read keeps the process alive.
 */
async function ttyConfirm() {
  const fd = openSync('/dev/tty', 'r+');
  const input = new ReadStream(fd);
  const rl = createInterface({ input, terminal: false });
  try {
    writeSync(fd, 'Type "install" to sign this install: ');
    const answer = await new Promise((resolve, reject) => {
      rl.once('line', resolve);
      rl.once('close', () => resolve(''));
      input.once('error', reject);
    });
    return answer.trim() === 'install';
  } finally {
    rl.close();
    input.destroy();
  }
}

if (spec.rules.length !== 1) throw new Error('the harness installs single-rule specs');
const rule = spec.rules[0];
if (spec.smart_account.address !== run.account) throw new Error('spec is for another account');
const signers = rule.authorization.signers.map((s) => {
  if (!s.delegated) throw new Error('only Delegated signers are installable here');
  return s.delegated.address;
});

// The wasm must be the one generated from this spec's rule 0. `ozpb generate` writes a
// BuildManifest beside it. The CLI validates and canonically hashes the same spec we read above,
// on both install paths, before loading keys or deploying anything. This trusts the local
// generator's manifest; independent Wasm reproduction is a separate `ozpb verify` operation.
const manifest = parseJsonExact(readFileSync(join(dirname(opts.wasm), 'build-manifest.json'), 'utf8'));
const wasmHash = await checkArtifact(spec, wasm, manifest);
const payer = loadKey('payer');
const owner = await ownerSigner(run);
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
const fromSpec = {
  context: rule.context.contract,
  name: spec.name,
  validUntil: rule.valid_until?.ledger ?? null,
  signers: signers.map((address) => ({ kind: 'delegated', address })),
  policies: [{ address: policy, install_params: { kind: 'generated' } }],
};
let ruleArgs = addContextRuleArgs(fromSpec);

if (checker) {
  // The spec hash comes from the manifest `ozpb generate` wrote; the registry root from the spec.
  const request = checkRequest({
    spec, ruleIndex: 0, manifest, policyAddress: policy, resolutionReference: `testnet deploy tx ${create.hash}`,
    signedRegistrySnapshot: checker.signedRegistrySnapshot, rpcSource: checker.rpcSource,
  });
  const approval = await approveInstall({
    runner: checker.runner, request, trust: checker.trust, confirm: checker.confirm, log,
    expect: {
      account: run.account, networkId: request.network_id, target: fromSpec.context, boundPolicies: [policy], ruleIndex: 0,
      specHash: manifest.spec_hash, registrySnapshotRoot: spec.registry_snapshot,
    },
  });
  // Sign exactly the approved intent, and only if it is also what this spec asks for.
  let refused = approval.approved ? null : approval.reasons;
  if (!refused) {
    try {
      ruleArgs = signedRuleArgs({ approved: approval.args, fromSpec, account: run.account });
    } catch (e) {
      refused = [e.message];
    }
  }
  run.authority_check = {
    trust_configuration: TRUST_OPERATOR,
    confirm: opts.confirm === 'tty' ? 'tty prompt (UX only)' : 'none: --confirm operator',
    operator_trust: checker.operator,
    ...(refused ? { refused } : approval.evidence),
  };
  writeJson(runPath, run);
  if (refused) {
    for (const r of refused) log(`          ${r}`);
    throw new Error('the harness wallet did not approve this install; nothing was signed');
  }
  log(`          approved: authority_commitment ${approval.commitment}, re-checked at ledger ${approval.evidence.rechecked_at_ledger}`);
}
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
const installed = await submit(payer, addRule([accountEntry, delegateEntry].filter(Boolean)), { stage: 'add_context_rule' });
const contextRule = scValToNative(installed.returnValue);
const ruleId = Number(contextRule.id);
log(`installed rule ${ruleId} "${contextRule.name}" → policy ${policy}  (tx ${installed.hash})`);

// --- read it back --------------------------------------------------------------------------------
// From the policy's side, not just the account's: `is_installed` is true only if the policy's own
// `install` ran for this (account, rule).
const view = async (contract, fn, fnArgs) => scValToNative(await viewCall(payer, contract, fn, fnArgs));
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
