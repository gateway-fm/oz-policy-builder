// Offline tests for deploy-live-helper.mjs: every RPC answer below is a mock, nothing is signed
// for or sent to a network.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Address, Keypair, Networks, StrKey, nativeToScVal, scValToNative, xdr } from '@stellar/stellar-sdk';

import {
  EXPECTED_HELPER_HASH, HELPER_ERROR_CODES, buildCaseAuthorizations, candidateScVal, contractIdFor, deployReviewedWasm,
  evaluateDenial, evaluatePermit, expectedHelperHash, requireTestnet,
} from './deploy-live-helper.mjs';
import { authDigest, i128 } from './lib.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const G = (n) => StrKey.encodeEd25519PublicKey(Buffer.alloc(32, n));
const ACCOUNT = C(1);
const POLICY = C(2);
const HELPER = C(3);
const SAC = C(4);
const RECIPIENT = G(5);
const DELEGATE = G(6);
const AMOUNT = 1_000_000n;

test('the expected helper hash is the reviewed constant the real-Wasm host tests assert', () => {
  const rust = readFileSync(new URL('../../execution-runtime/tests/atomic_helper.rs', import.meta.url), 'utf8');
  assert.match(EXPECTED_HELPER_HASH, /^[0-9a-f]{64}$/);
  assert.ok(rust.includes(`"${EXPECTED_HELPER_HASH}"`));
  assert.throws(() => expectedHelperHash('const OTHER: &str = "00";'), /EXPECTED_HELPER_HASH/);
  assert.throws(() => expectedHelperHash(`${rust}\nconst EXPECTED_HELPER_HASH: &str = "${'a'.repeat(64)}";`), /exactly one/);
});

// --- network pin and deployment -----------------------------------------------------------------

function deployment({ passphrase = Networks.TESTNET, stored, observed, created } = {}) {
  const wasm = Buffer.from('reviewed helper bytes');
  const hash = sha256(wasm);
  const calls = [];
  const d = { wasm, hash, calls, payer: Keypair.random(), contract: null };
  const deps = {
    getNetwork: async () => ({ passphrase, protocolVersion: 29 }),
    submit: async (_payer, operation, { stage }) => {
      calls.push(stage);
      const fn = operation.body.invokeHostFunctionOp.hostFunction;
      if (fn.type === 'hostFunctionTypeUploadContractWasm') {
        return { hash: 'aa'.repeat(32), returnValue: xdr.ScVal.scvBytes(Buffer.from(stored ?? hash, 'hex')) };
      }
      const preimage = fn.createContractV2.contractIdPreimage.fromAddress;
      d.contract = created ?? contractIdFor(Address.fromScAddress(preimage.address).toString(), preimage.salt.value);
      return { hash: 'bb'.repeat(32), returnValue: new Address(d.contract).toScVal() };
    },
    contractCodeObservation: async (id) => {
      calls.push(`readback ${id}`);
      return { value: observed ?? hash, ledger: 1234 };
    },
  };
  return Object.assign(d, { deps });
}

test('a contract ID is derived locally from the deployer, salt and testnet network ID', () => {
  // Independent derivation: sha256(XDR HashIdPreimage::ContractId { network_id, FromAddress }).
  const deployer = G(7);
  const salt = Buffer.alloc(32, 9);
  const preimage = Buffer.concat([
    Buffer.from([0, 0, 0, 8]), createHash('sha256').update(Networks.TESTNET).digest(),
    Buffer.from([0, 0, 0, 0]), Buffer.from(new Address(deployer).toScAddress().toXDR()), salt,
  ]);
  assert.equal(contractIdFor(deployer, salt), StrKey.encodeContract(createHash('sha256').update(preimage).digest()));
  assert.notEqual(contractIdFor(deployer, Buffer.alloc(32, 8)), contractIdFor(deployer, salt));
});

test('refuses a created contract ID that is not the one derived from the deployer and salt', async () => {
  const d = deployment({ created: HELPER });
  await assert.rejects(deployReviewedWasm({ ...d, expectedHash: d.hash, label: 'helper' }),
    new RegExp(`RPC reported ${HELPER}, not`));
  assert.deepEqual(d.calls, ['upload helper Wasm', 'create helper']);
});

test('refuses any network but testnet before anything is uploaded', async () => {
  for (const passphrase of [Networks.PUBLIC, Networks.FUTURENET, 'Standalone Network ; February 2017']) {
    const d = deployment({ passphrase });
    await assert.rejects(requireTestnet(d.deps.getNetwork), /not testnet/);
    await assert.rejects(deployReviewedWasm({ ...d, expectedHash: d.hash, label: 'helper' }), /not testnet/);
    assert.deepEqual(d.calls, []);
  }
  const d = deployment();
  assert.equal((await requireTestnet(d.deps.getNetwork)).protocolVersion, 29);
});

test('refuses a built Wasm whose hash differs from the reviewed one, before any submission', async () => {
  const d = deployment();
  await assert.rejects(deployReviewedWasm({ ...d, expectedHash: 'cc'.repeat(32), label: 'helper' }),
    /helper Wasm .* is not the reviewed/);
  assert.deepEqual(d.calls, []);
});

test('refuses when the network stores other bytes than the ones uploaded', async () => {
  const d = deployment({ stored: 'dd'.repeat(32) });
  await assert.rejects(deployReviewedWasm({ ...d, expectedHash: d.hash, label: 'helper' }), /network stored/);
  assert.deepEqual(d.calls, ['upload helper Wasm']);
});

test('refuses a deployed instance whose code hash differs on readback', async () => {
  const d = deployment({ observed: 'ee'.repeat(32) });
  await assert.rejects(deployReviewedWasm({ ...d, expectedHash: d.hash, label: 'helper' }), / runs e{64}, not the reviewed/);
  assert.deepEqual(d.calls, ['upload helper Wasm', 'create helper', `readback ${d.contract}`]);
});

test('a reviewed deployment reports the readback, not the local claim', async () => {
  const d = deployment();
  const deployed = await deployReviewedWasm({ ...d, expectedHash: d.hash, label: 'helper' });
  assert.match(deployed.contract, /^C/);
  assert.deepEqual(deployed, {
    contract: d.contract, code_hash: d.hash, readback_ledger: 1234, upload_tx: 'aa'.repeat(32), create_tx: 'bb'.repeat(32),
  });
});

// --- the helper call and its authorizations -------------------------------------------------------

const CANDIDATE = {
  account: ACCOUNT, policy: POLICY, policyHash: 'ab'.repeat(32), delegate: DELEGATE, expectedRuleId: 1,
  name: 'native-sub', validUntil: 5000, recipient: RECIPIENT, amount: AMOUNT,
};

test('the candidate is the helper struct: field-name map in symbol order, exact types', () => {
  const map = candidateScVal(CANDIDATE).map;
  // The fields and Rust types as the helper declares them, read from its source.
  const rust = readFileSync(new URL('../../contracts/atomic-live-helper/src/lib.rs', import.meta.url), 'utf8');
  const body = /pub struct Candidate \{([^}]*)\}/.exec(rust)[1];
  const declared = [...body.matchAll(/pub (\w+): ([\w<>0-9]+),/g)].map((m) => [m[1], m[2]]);
  assert.equal(declared.length, 9);
  const scType = { Address: 'scvAddress', i128: 'scvI128', u32: 'scvU32', String: 'scvString', 'BytesN<32>': 'scvBytes' };
  assert.deepEqual(map.map((e) => [e.key.sym.toString(), e.val.type]),
    declared.map(([name, type]) => [name, scType[type]]).sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
  assert.deepEqual(map.map((e) => e.key.sym.toString()),
    ['account', 'amount', 'delegate', 'expected_rule_id', 'name', 'policy', 'policy_hash', 'recipient', 'valid_until']);
  const field = (name) => map.find((e) => e.key.sym.toString() === name).val;
  assert.equal(field('amount').toXDR('hex'), i128(AMOUNT).toXDR('hex'));
  assert.equal(field('expected_rule_id').type, 'scvU32');
  assert.equal(field('valid_until').type, 'scvU32');
  assert.equal(Buffer.from(scValToNative(field('policy_hash'))).toString('hex'), 'ab'.repeat(32));
  assert.equal(field('name').type, 'scvString');
  assert.throws(() => candidateScVal({ ...CANDIDATE, amount: 1_000_002n }), /1\.\.=1000001/);
});

test('case authorizations: owner installs under rule 0, delegate transfers under the candidate rule, no helper root', async () => {
  const owner = Keypair.random();
  const delegate = Keypair.random();
  const entries = await buildCaseAuthorizations({
    candidate: { ...CANDIDATE, delegate: delegate.publicKey() }, sac: SAC, owner, delegate,
    validUntilLedger: 777, networkPassphrase: Networks.TESTNET,
  });
  assert.equal(entries.length, 4);
  const [install, ownerProof, transfer, delegateProof] = entries;
  const root = (e) => e.rootInvocation.function.contractFn;
  const address = (e) => Address.fromScAddress((e.credentials.addressV2 ?? e.credentials.address).address).toString();
  assert.equal(root(install).functionName.toString(), 'add_context_rule');
  assert.equal(Address.fromScAddress(root(install).contractAddress).toString(), ACCOUNT);
  assert.equal(root(transfer).functionName.toString(), 'transfer');
  assert.equal(Address.fromScAddress(root(transfer).contractAddress).toString(), SAC);
  // The exact calls the helper makes, built here by hand rather than through lib.mjs.
  const sym = (v) => xdr.ScVal.scvSymbol(v);
  const addr = (v) => new Address(v).toScVal();
  const hex = (args) => args.map((a) => a.toXDR('hex'));
  assert.deepEqual(hex(root(install).args), hex([
    xdr.ScVal.scvVec([sym('CallContract'), addr(SAC)]), xdr.ScVal.scvString('native-sub'), xdr.ScVal.scvU32(5000),
    xdr.ScVal.scvVec([xdr.ScVal.scvVec([sym('Delegated'), addr(delegate.publicKey())])]),
    xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: addr(POLICY), val: xdr.ScVal.scvU32(0) })]),
  ]));
  assert.deepEqual(hex(root(transfer).args), hex([addr(ACCOUNT), addr(RECIPIENT),
    xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: AMOUNT }))]));
  assert.deepEqual(transfer.rootInvocation.subInvocations, []);
  assert.deepEqual(install.rootInvocation.subInvocations, []);
  assert.deepEqual(entries.map(address), [ACCOUNT, owner.publicKey(), ACCOUNT, delegate.publicKey()]);
  for (const e of entries) assert.notEqual(Address.fromScAddress(e.rootInvocation.function.contractFn.contractAddress).toString(), HELPER);
  const payload = (e) => e.credentials.addressV2.signature.map;
  const ruleIds = (e) => payload(e).find((m) => m.key.sym.toString() === 'context_rule_ids').val.vec.map((v) => v.u32);
  const signer = (e) => Address.fromScVal(payload(e).find((m) => m.key.sym.toString() === 'signers').val.map[0].key.vec[1]).toString();
  assert.deepEqual(ruleIds(install), [0]);
  assert.deepEqual(ruleIds(transfer), [1]);
  assert.equal(signer(install), owner.publicKey());
  assert.equal(signer(transfer), delegate.publicKey());
  // The two account entries need distinct nonces, and every entry expires at the given ledger.
  assert.notEqual(install.credentials.addressV2.nonce, transfer.credentials.addressV2.nonce);
  for (const e of entries) assert.equal((e.credentials.addressV2 ?? e.credentials.address).signatureExpirationLedger, 777);
  // Each signer's own entry authorizes exactly the account's digest of its account entry: the
  // address-bound preimage hash, bound to that entry's rule IDs.
  const digestOf = (e) => Buffer.from(scValToNative(e.rootInvocation.function.contractFn.args[0]));
  const payloadOf = (e) => createHash('sha256').update(
    xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(new xdr.HashIdPreimageSorobanAuthorizationWithAddress({
      networkId: createHash('sha256').update(Networks.TESTNET).digest(), nonce: e.credentials.addressV2.nonce,
      signatureExpirationLedger: 777, invocation: e.rootInvocation, address: e.credentials.addressV2.address,
    })).toXDR()).digest();
  assert.deepEqual(digestOf(ownerProof), authDigest(payloadOf(install), [0]));
  assert.deepEqual(digestOf(delegateProof), authDigest(payloadOf(transfer), [1]));
  for (const [proof, account] of [[ownerProof, install], [delegateProof, transfer]]) {
    assert.equal(Address.fromScAddress(proof.rootInvocation.function.contractFn.contractAddress).toString(), ACCOUNT);
    assert.equal(proof.rootInvocation.function.contractFn.functionName.toString(), '__check_auth');
    assert.notEqual(account, proof);
  }
  // A transfer amount the candidate does not name cannot be signed through this path.
  await assert.rejects(buildCaseAuthorizations({ candidate: { ...CANDIDATE, amount: 0n }, sac: SAC, owner, delegate,
    validUntilLedger: 777, networkPassphrase: Networks.TESTNET }), /1\.\.=1000001/);
  await assert.rejects(buildCaseAuthorizations({ candidate: CANDIDATE, sac: SAC, owner, delegate,
    validUntilLedger: 777, networkPassphrase: Networks.PUBLIC }), /testnet/);
});

// --- denial attribution ---------------------------------------------------------------------------

// Constructed in the format of the verbatim testnet denial in lib.test.mjs, with a helper frame
// above it: the asset's failed account authentication names the account and carries the policy's
// code, and the policy itself raised it. The live run in docs/evidence/ is what shows that this
// attribution survives the nesting.
const NESTED_DENIAL = [
  'HostError: Error(Auth, InvalidAction)',
  '',
  'Event log (newest first):',
  `   0: [Diagnostic Event] contract:${HELPER}, topics:[error, Error(Auth, InvalidAction)], data:"escalating error to VM trap from failed host function call: call"`,
  `   1: [Diagnostic Event] contract:${SAC}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${ACCOUNT}, Error(Contract, #6)]`,
  `   2: [Failed Diagnostic Event (not emitted)] contract:${ACCOUNT}, topics:[log], data:["VM call trapped with HostError", __check_auth, Error(Contract, #6)]`,
  `   3: [Failed Diagnostic Event (not emitted)] contract:${POLICY}, topics:[error, Error(Contract, #6)], data:["failing with contract error", 6]`,
].join('\n');
const DENIAL_CONTEXT = { account: ACCOUNT, policy: POLICY, helper: HELPER };

test('a denial counts only with the code raised by the policy contract inside the account authentication', () => {
  assert.deepEqual(evaluateDenial({ error: NESTED_DENIAL }, DENIAL_CONTEXT),
    { result: 'deny', enforcer: POLICY, code: 6, host: 'HostError: Error(Auth, InvalidAction)' });
  // The same number from another contract (the asset's #6 is AccountMissingError) is not the policy.
  assert.equal(evaluateDenial({ error: NESTED_DENIAL.replaceAll(`contract:${POLICY}`, `contract:${SAC}`) }, DENIAL_CONTEXT).result, 'failed');
  // A policy error with no failed account authentication of this account is not a decision on it.
  assert.equal(evaluateDenial({ error: NESTED_DENIAL.replace(`${ACCOUNT}, Error(Contract, #6)]`, `${C(9)}, Error(Contract, #6)]`) }, DENIAL_CONTEXT).result, 'failed');
  // Any other policy code is a policy decision, but not the adjacent-amount denial this case expects.
  const exhausted = NESTED_DENIAL.replaceAll('#6', '#7').replace('contract error", 6]', 'contract error", 7]');
  assert.deepEqual(evaluateDenial({ error: exhausted }, DENIAL_CONTEXT, { code: 6 }).result, 'failed');
  assert.equal(evaluateDenial({ error: exhausted }, DENIAL_CONTEXT).code, 7);
  // A simulation that succeeded is not a denial.
  assert.equal(evaluateDenial({ result: { retval: xdr.ScVal.scvVoid() } }, DENIAL_CONTEXT).result, 'failed');
});

test('a helper refusal 7001-7009 is a failed case, never a policy denial', () => {
  assert.deepEqual(HELPER_ERROR_CODES, [7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009]);
  for (const code of HELPER_ERROR_CODES) {
    const refusal = [`HostError: Error(Contract, #${code})`, '', 'Event log (newest first):',
      `   0: [Diagnostic Event] contract:${HELPER}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`].join('\n');
    assert.deepEqual(evaluateDenial({ error: refusal }, DENIAL_CONTEXT),
      { result: 'failed', reason: 'helper_refusal', code, host: `HostError: Error(Contract, #${code})` });
    // Even beside an otherwise complete policy denial, a helper refusal settles nothing about the policy.
    assert.equal(evaluateDenial({ error: `${NESTED_DENIAL}\n${refusal.split('\n')[3]}` }, DENIAL_CONTEXT).result, 'failed');
  }
});

test('an account error is not a policy denial', () => {
  for (const code of [3002, 3005, 3016]) {
    const text = [`HostError: Error(Auth, InvalidAction)`, '', 'Event log (newest first):',
      `   0: [Diagnostic Event] contract:${SAC}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${ACCOUNT}, Error(Contract, #${code})]`,
      `   1: [Failed Diagnostic Event (not emitted)] contract:${ACCOUNT}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`].join('\n');
    assert.deepEqual(evaluateDenial({ error: text }, DENIAL_CONTEXT),
      { result: 'failed', reason: 'not_a_policy_denial', host: 'HostError: Error(Auth, InvalidAction)' });
  }
});

// --- permit effects -------------------------------------------------------------------------------

const contractKey = (contract, key, durability = xdr.ContractDataDurability.persistent) =>
  xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contract).toScAddress(), key, durability }));
const contractEntry = (contract, key, val, durability = xdr.ContractDataDurability.persistent) => new xdr.LedgerEntry({
  lastModifiedLedgerSeq: 10,
  data: xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({
    ext: xdr.ExtensionPoint.v0(), contract: new Address(contract).toScAddress(), key, durability, val,
  })),
  ext: xdr.LedgerEntryExt.v0(),
});
const accountKey = (g) => xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(g).xdrAccountId() }));
const accountEntry = (g, balance) => new xdr.LedgerEntry({
  lastModifiedLedgerSeq: 10,
  data: xdr.LedgerEntryData.account(new xdr.AccountEntry({
    accountId: Keypair.fromPublicKey(g).xdrAccountId(), balance, seqNum: 1n, numSubEntries: 0, inflationDest: null,
    flags: 0, homeDomain: '', thresholds: Buffer.from([1, 0, 0, 0]), signers: [], ext: xdr.AccountEntryExt.v0(),
  })),
  ext: xdr.LedgerEntryExt.v0(),
});
const balanceKeyVal = (address) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Balance'), new Address(address).toScVal()]);
const sacBalance = (amount) => nativeToScVal({ amount, authorized: true, clawback: false },
  { type: { amount: ['symbol', 'i128'], authorized: ['symbol'], clawback: ['symbol'] } });
const policyKey = (name, rule = 1) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name), new Address(ACCOUNT).toScVal(), xdr.ScVal.scvU32(rule)]);
const ruleKey = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('ContextRuleData'), xdr.ScVal.scvU32(1)]);
const change = (key, before, after) => ({ type: before ? (after ? 'updated' : 'deleted') : 'created', key, before, after });

function permitSimulation({ sent = AMOUNT, received = AMOUNT, used = 1, extra = [], ruleId = 1, drop = [] } = {}) {
  const changes = {
    sender: change(contractKey(SAC, balanceKeyVal(ACCOUNT)),
      contractEntry(SAC, balanceKeyVal(ACCOUNT), sacBalance(4_000_000n)),
      contractEntry(SAC, balanceKeyVal(ACCOUNT), sacBalance(4_000_000n - sent))),
    recipient: change(accountKey(RECIPIENT), accountEntry(RECIPIENT, 100_000_000n), accountEntry(RECIPIENT, 100_000_000n + received)),
    rule: change(contractKey(ACCOUNT, ruleKey), null, contractEntry(ACCOUNT, ruleKey, xdr.ScVal.scvMap([]))),
    installed: change(contractKey(POLICY, policyKey('Installed')), null, contractEntry(POLICY, policyKey('Installed'), xdr.ScVal.scvBool(true))),
    counter: change(contractKey(POLICY, policyKey('CallCount')), null, contractEntry(POLICY, policyKey('CallCount'), xdr.ScVal.scvU32(used))),
    nonce: change(contractKey(ACCOUNT, xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: 5n })), xdr.ContractDataDurability.temporary), null,
      contractEntry(ACCOUNT, xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: 5n })), xdr.ScVal.scvVoid(), xdr.ContractDataDurability.temporary)),
  };
  for (const name of drop) delete changes[name];
  const rule = nativeToScVal({ id: ruleId }, { type: { id: ['symbol', 'u32'] } });
  return { result: { retval: rule }, stateChanges: [...Object.values(changes), ...extra] };
}
const PERMIT_CONTEXT = { sac: SAC, account: ACCOUNT, recipient: RECIPIENT, policy: POLICY, amount: AMOUNT, ruleId: 1, maxCalls: 1 };

test('a permit requires exactly the amount moved, the candidate rule returned and its counter used once', () => {
  assert.deepEqual(evaluatePermit(permitSimulation(), PERMIT_CONTEXT), {
    result: 'permit', returned_rule_id: 1,
    balance_changes: { account: (-AMOUNT).toString(), recipient: AMOUNT.toString() },
    candidate_counter: { rule_id: 1, used_before: 0, used_after: 1, remaining_after: 0, installed_in_simulation: true },
  });
});

for (const [name, sim, why] of [
  ['one stroop more leaving the account', permitSimulation({ sent: AMOUNT + 1n }), /account balance changed by -1000001/],
  ['one stroop less reaching the recipient', permitSimulation({ received: AMOUNT - 1n }), /recipient balance changed by 999999/],
  ['no balance change at all', permitSimulation({ drop: ['sender', 'recipient'] }), /account balance changed by 0/],
  ['another account balance changed', permitSimulation({ extra: [change(accountKey(DELEGATE), accountEntry(DELEGATE, 5n), accountEntry(DELEGATE, 4n))] }), /unexpected balance change/],
  ['another asset balance changed', permitSimulation({ extra: [change(contractKey(C(8), balanceKeyVal(ACCOUNT)), null, contractEntry(C(8), balanceKeyVal(ACCOUNT), sacBalance(1n)))] }), /unexpected balance change/],
  ['the counter untouched', permitSimulation({ drop: ['counter'] }), /candidate counter/],
  ['the counter used twice', permitSimulation({ used: 2 }), /candidate counter/],
  ['no fresh installation marker', permitSimulation({ drop: ['installed'] }), /installation marker/],
  ['no rule stored by the account', permitSimulation({ drop: ['rule'] }), /account did not store rule 1/],
  ['another rule returned', permitSimulation({ ruleId: 2 }), /returned rule 2/],
]) {
  test(`a permit is refused with ${name}`, () => {
    const outcome = evaluatePermit(sim, PERMIT_CONTEXT);
    assert.equal(outcome.result, 'failed');
    assert.match(outcome.reason, why);
  });
}

test('a failed simulation is never a permit', () => {
  assert.deepEqual(evaluatePermit({ error: NESTED_DENIAL }, PERMIT_CONTEXT),
    { result: 'failed', reason: 'simulation failed', host: 'HostError: Error(Auth, InvalidAction)' });
});
