// Write this run's PolicySpec: the committed template, filled from the recording `ozpb import`
// made of the run's executed transfer.
//
//   node write-spec.mjs --run-dir <dir> [--registry-root <hex>]
//                                            (reads run.json and recording.json, writes spec.json)
//
// Historical manual workflow, retained for inspecting the October 15 runs. The default wrapper
// now records through RPC and runs synthesis-flow.mjs. This helper does not run synthesis:
// raw-XDR imports have no recorder-observed account executable, which synthesis requires.
// Its manual spec therefore remains limited by these explicit checks:
//
//   * the template must have exactly the expected shape — one rule, one allowed call with three
//     exact arguments, one signer, one generated policy — so nothing outside what is filled in
//     below can widen the grant;
//   * the call constraints (contract, function, from, to, amount) and the network are checked
//     against the recording, so the rule allows exactly the call the recording shows the account
//     authorizing;
//   * its evidence entry is the import's own `recording_hash` and trust label, not a placeholder.
//
// The rest is decided, not observed, and comes from the run: the signer is the delegate (the
// grant is for someone other than the recorded owner), the expiry is a day after the recorded
// ledger, the call cap is the template's, and the account's code hash is the one setup.mjs read
// from the network and checked against the pin. What synthesis would have resolved from the
// signed registry is left visibly unresolved (`registry_snapshot` all zeroes,
// `registry_resolution` saying so).
//
// `--registry-root` is for the authority check (`install.mjs --authority-check`), which refuses a
// spec whose `registry_snapshot` is not the root of the signed snapshot it is given. The root is
// written in before `ozpb generate`, because the spec hash and the build manifest cover it. That
// names the registry the check will use; it resolves nothing in the spec against it, and
// `registry_resolution` says so.
import { join } from 'node:path';

import { args, log, readJson, writeJson } from './rpc.mjs';

const TEMPLATE = new URL('../native-sac-policy-spec.json', import.meta.url);
// About one day of ledgers at ~5 s: long enough for a run, short enough that a grant on a
// throwaway account lapses on its own.
const VALID_FOR_LEDGERS = 17_280;

const opts = args();
const runDir = opts['run-dir'];
const registryRoot = opts['registry-root'];
if (registryRoot !== undefined && (!/^[0-9a-f]{64}$/.test(registryRoot) || /^0+$/.test(registryRoot))) {
  throw new Error('--registry-root must be a signed registry root: 64 lowercase hex digits, not zero');
}
const run = readJson(join(runDir, 'run.json'));
const recording = readJson(join(runDir, 'recording.json'));
const bundle = recording.bundle;

// --- the recording must show exactly the call the grant will allow -----------------------------
const at = bundle.authorizations.findIndex((a) => a.authorizer === run.account);
if (at < 0) throw new Error('the recording has no authorization by the run\'s account');
const root = bundle.authorizations[at].root;
const call = root.call?.contract;
const same = (a, b, what) => {
  if (a !== b) throw new Error(`recorded ${what} is ${a}, expected ${b}`);
};
same(bundle.execution, 'executed_success', 'execution');
same(call?.contract, run.sac, 'contract');
same(call?.fn_name, 'transfer', 'function');
same(call.args.length, 3, 'argument count');
same(call.args[0].address, run.account, 'from');
same(call.args[1].address, run.recipient, 'to');
same(BigInt(String(call.args[2].i128)).toString(), run.amount, 'amount');
same(root.sub_invocations.length, 0, 'sub-invocation count');

// --- the template must have exactly the shape this script fills ------------------------------------
const spec = readJson(TEMPLATE);
same(spec.network_id, bundle.network_id, 'network');
same(spec.rules.length, 1, 'template rule count');
const rule = spec.rules[0];
same(rule.context.type, 'CallContract', 'template context');
same(rule.authorization.signers.length, 1, 'template signer count');
same(rule.allowed_calls.length, 1, 'template allowed-call count');
const allowed = rule.allowed_calls[0];
same(allowed.args.length, 3, 'template argument count');
allowed.args.forEach((a, i) => {
  same(a.i, i, `template argument ${i} index`);
  same(a.prov, 'observed_exact', `template argument ${i} provenance`);
});
same(JSON.stringify(rule.policies.map((p) => Object.keys(p))), '[["generated"]]', 'template policies');
same(rule.state.length, 1, 'template state count');
same(rule.state[0].call_count_per_installation.max_calls, 1, 'template call cap');
same(spec.evidence.recordings.length, 1, 'template evidence count');

// --- fill it, refusing any field that no longer holds its placeholder -------------------------------
function fill(label, holder, key, placeholder, value) {
  if (holder[key] !== placeholder) {
    throw new Error(`template ${label} is ${JSON.stringify(holder[key])}, expected its placeholder`);
  }
  holder[key] = value;
}
const ZERO = '0'.repeat(64);
fill('smart_account.address', spec.smart_account, 'address',
  'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526', run.account);
fill('smart_account.observed_code_hash', spec.smart_account, 'observed_code_hash',
  'a12747ff6c139dc14fc2fd30d200d6bbb5da7b5d59812c047ce1f9cad226b289', run.account_code_hash);
fill('context.contract', rule.context, 'contract',
  'CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ', call.contract);
fill('valid_until.ledger', rule.valid_until, 'ledger', 4223456, bundle.ledger + VALID_FOR_LEDGERS);
fill('signer', rule.authorization.signers[0].delegated, 'address',
  'GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI', run.delegate);
same(allowed.fn, call.fn_name, 'template function');
same(allowed.args[0].c.eq_address.value, 'SELF', 'template from');
fill('args[1] recipient', allowed.args[1].c.eq_address, 'value',
  'GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC', call.args[1].address);
fill('args[2] amount', allowed.args[2].c.eq_i128, 'value', '10000000', run.amount);
same(allowed.justified_by.length, 1, 'template justification count');
fill('justified_by', allowed.justified_by, 0, 'recordings[0]/auth[0]/root', `recordings[0]/auth[${at}]/root`);
fill('evidence hash', spec.evidence.recordings[0], 'hash', ZERO, recording.recording_hash);
fill('evidence trust', spec.evidence.recordings[0], 'trust', 'incomplete', recording.trust);
same(spec.registry_snapshot, ZERO, 'template registry_snapshot');
if (registryRoot !== undefined) {
  fill('registry_snapshot', spec, 'registry_snapshot', ZERO, registryRoot);
  fill('smart_account.registry_resolution', spec.smart_account, 'registry_resolution',
    'not resolved: hand-written testnet-harness template, not a synthesis output',
    'not resolved: hand-written testnet-harness template, not a synthesis output; registry_snapshot '
      + 'names the signed registry the authority check is given, and nothing here was resolved against it');
}

writeJson(join(runDir, 'spec.json'), spec);
run.valid_until_ledger = rule.valid_until.ledger;
run.spec = join(runDir, 'spec.json');
if (registryRoot !== undefined) run.registry_root = registryRoot;
writeJson(join(runDir, 'run.json'), run);
log(`spec      ${run.spec}`);
log(`          justified by recording ${recording.recording_hash} (${recording.trust}), auth[${at}]`);
log(`          valid until ledger ${rule.valid_until.ledger}, at most ${rule.state[0].call_count_per_installation.max_calls} call`);
