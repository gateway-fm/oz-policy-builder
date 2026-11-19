import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Keypair, StrKey, hash, xdr } from '@stellar/stellar-sdk';
import { isGrantRule, reviewRemoval, revokeConsent, validateRemovalAssembly } from '../shared/revoke.mjs';
import { ruleReadbackResult } from '../server/install.mjs';
import { fixture } from './approval-fixture.mjs';
import { RULE_ID, removalFor } from './install-fixture.mjs';
import { WALLET_NETWORKS } from '../shared/networks.mjs';
const NETWORK_ID = WALLET_NETWORKS.testnet.networkId;

const PAYER = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 11)).publicKey();
const LEDGER = 200000;

function removal(mutate) {
  const f = fixture();
  const approval = reviewRemoval({ networkId: NETWORK_ID, wallet: f.wallet, ownerRuleId: 7, ownerRuleXdr: f.ownerRuleXdr,
    installation: { account: f.wallet.contractId, ruleId: RULE_ID, transactionHash: 'e'.repeat(64) } });
  const value = removalFor({ account: f.wallet.contractId, payer: PAYER, sequence: '100', ledger: LEDGER, mutate });
  return { approval, ownerRuleXdr: f.ownerRuleXdr, ...value, f };
}

test('removal validation returns only the exact unsigned owner entry for remove_context_rule(rule id)', () => {
  const value = removal();
  const checked = validateRemovalAssembly(value);
  assert.equal(checked.ownerRuleId, 7);
  assert.equal(checked.expirationLedger, LEDGER + 119);
  assert.equal(checked.authEntriesXdr.length, 1);
  assert.equal(checked.authorityCommitment, value.approval.commitment);
  assert.ok(Object.isFrozen(checked));
  const display = revokeConsent({ approval: value.approval, checked, maxFeeStroops: 10_000_000 });
  assert.deepEqual(display.owner_signs, { contract: value.f.wallet.contractId, function: 'remove_context_rule', args: [RULE_ID],
    context_rule_ids: [7] });
  assert.equal(display.fee.prepared_fee_stroops, 1100);
  assert.match(display.warning, /best effort/);
});

test('the removal approval is bound to the installation and the owner rule it was reviewed with', () => {
  const f = fixture();
  const base = { networkId: NETWORK_ID, wallet: f.wallet, ownerRuleId: 7, ownerRuleXdr: f.ownerRuleXdr,
    installation: { account: f.wallet.contractId, ruleId: RULE_ID, transactionHash: 'e'.repeat(64) } };
  const commitment = reviewRemoval(base).commitment;
  assert.notEqual(reviewRemoval({ ...base, installation: { ...base.installation, ruleId: 2 } }).commitment, commitment);
  assert.notEqual(reviewRemoval({ ...base, installation: { ...base.installation, transactionHash: 'd'.repeat(64) } }).commitment, commitment);
  assert.throws(() => reviewRemoval({ ...base, installation: { ...base.installation, account: StrKey.encodeContract(Buffer.alloc(32, 1)) } }),
    /refused/, 'the rule must be on the wallet\'s own account');
  assert.throws(() => reviewRemoval({ ...base, installation: { ...base.installation, ruleId: 7 } }), /refused/, 'never the owner rule');
  assert.throws(() => reviewRemoval({ ...base, ownerRuleXdr: f.ruleXdr({ signers: xdr.ScVal.scvVec([]) }) }), /refused/);
});

for (const name of ['function', 'rule id', 'account', 'extra auth', 'nested auth', 'signed auth', 'expiry', 'fee', 'payer',
  'sequence', 'memo', 'extra operation', 'digest', 'stale', 'restore']) {
  test(`removal validation refuses an altered ${name}`, () => {
    const value = removal((tx, envelope, entry) => {
      const op = tx.operations[0];
      const ih = op.body.invokeHostFunctionOp;
      switch (name) {
        case 'function': ih.hostFunction.invokeContract.functionName = 'add_context_rule'; break;
        case 'rule id': ih.hostFunction.invokeContract.args[0] = xdr.ScVal.scvU32(2); break;
        case 'account': ih.hostFunction.invokeContract.contractAddress = new Address(StrKey.encodeContract(Buffer.alloc(32, 1))).toScAddress(); break;
        case 'extra auth': ih.auth.push(entry); break;
        case 'nested auth': ih.auth[0].rootInvocation.subInvocations.push(xdr.SorobanAuthorizedInvocation.fromXDR(entry.rootInvocation.toXDR())); break;
        case 'signed auth': ih.auth[0].credentials.addressV2.signature = xdr.ScVal.scvU32(1); break;
        case 'expiry': ih.auth[0].credentials.addressV2.signatureExpirationLedger = LEDGER + 120; break;
        case 'fee': tx.fee = 10_000_001; break;
        case 'payer': tx.sourceAccount = xdr.MuxedAccount.keyTypeEd25519(Buffer.alloc(32, 5)); break;
        case 'sequence': tx.seqNum = 105n; break;
        case 'memo': tx.memo = xdr.Memo.memoText('hidden'); break;
        case 'extra operation': tx.operations.push(op); break;
        default: break;
      }
    });
    if (name === 'digest') value.assembly.envelope_xdr_sha256 = '0'.repeat(64);
    else if (name === 'stale') value.limits.currentLedger = LEDGER + 120;
    else if (name === 'restore') value.assembly.restoration = 'separate_transaction_reassemble_required';
    else {
      const envelope = xdr.TransactionEnvelope.fromXDR(value.assembly.envelope_xdr_base64, 'base64');
      value.assembly.envelope_xdr_sha256 = Buffer.from(hash(envelope.toXDR())).toString('hex');
    }
    assert.throws(() => validateRemovalAssembly(value), /refused/);
  });
}

// --- the absent readback: `get_context_rule` refused with the account's own #3000 --------------------

const ACCOUNT = StrKey.encodeContract(Buffer.alloc(32, 0x21));
const OTHER = StrKey.encodeContract(Buffer.alloc(32, 0x22));
function hostError(contract, code) {
  return new xdr.DiagnosticEvent({ inSuccessfulContractCall: false, event: new xdr.ContractEvent({ ext: xdr.ExtensionPoint.v0(),
    contractId: new xdr.ContractId(StrKey.decodeContract(contract)), type: xdr.ContractEventType.diagnostic,
    body: xdr.ContractEventBody.v0(new xdr.ContractEventV0({ topics: [xdr.ScVal.scvSymbol('error'),
      xdr.ScVal.scvError(xdr.ScError.sceContract(code))], data: xdr.ScVal.scvString('failing with contract error') })) }) }).toXDR('base64');
}

test('a rule reads back present only from a successful call returning it', () => {
  const rule = xdr.ScVal.scvMap([]).toXDR('base64');
  assert.deepEqual(ruleReadbackResult({ latestLedger: 10, results: [{ xdr: rule, auth: [] }], events: [] }, { account: ACCOUNT }),
    { status: 'present', xdr: rule, ledger: 10 });
});

test('a rule reads back absent only on the account\'s own contract error 3000', () => {
  assert.deepEqual(ruleReadbackResult({ latestLedger: 11, error: 'HostError: Error(Contract, #3000)', events: [hostError(ACCOUNT, 3000)] },
    { account: ACCOUNT }), { status: 'absent', ledger: 11 });
  for (const [name, simulation] of [
    ['another contract', { latestLedger: 11, error: 'x', events: [hostError(OTHER, 3000)] }],
    ['another code', { latestLedger: 11, error: 'x', events: [hostError(ACCOUNT, 3001)] }],
    ['no events', { latestLedger: 11, error: 'x' }],
    ['no ledger', { error: 'x', events: [hostError(ACCOUNT, 3000)] }],
    ['a result and an error', { latestLedger: 11, error: 'x', results: [{ xdr: xdr.ScVal.scvVoid().toXDR('base64') }],
      events: [hostError(ACCOUNT, 3000)] }],
    ['two results', { latestLedger: 11, results: [{ xdr: 'AAAAAQ==' }, { xdr: 'AAAAAQ==' }] }],
  ]) {
    assert.throws(() => ruleReadbackResult(simulation, { account: ACCOUNT }), /refused/, name);
  }
});

test('removal validation refuses an owner entry whose credentials name another address', () => {
  const value = removal((tx) => {
    tx.operations[0].body.invokeHostFunctionOp.auth[0].credentials.addressV2.address = new Address(StrKey.encodeContract(Buffer.alloc(32, 1))).toScAddress();
  });
  const envelope = xdr.TransactionEnvelope.fromXDR(value.assembly.envelope_xdr_base64, 'base64');
  value.assembly.envelope_xdr_sha256 = Buffer.from(hash(envelope.toXDR())).toString('hex');
  assert.throws(() => validateRemovalAssembly(value), /refused/);
});

test('changed-rule consent commits and displays exact saved and current configuration', async () => {
  const { installedRule } = await import('./install-fixture.mjs');
  const value = removal();
  const recordedRuleXdr = installedRule(value.f.intent).toXDR('base64');
  const changed = installedRule(value.f.intent, { signerIds: [9] });
  changed.map.find((entry) => entry.key.sym.toString() === 'name').val = xdr.ScVal.scvString('changed grant');
  const configurationChange = { recordedRuleXdr, observedRuleXdr: changed.toXDR('base64') };
  const approval = reviewRemoval({ ...value.approval, configurationChange });
  assert.notEqual(approval.commitment, value.approval.commitment);
  const checked = validateRemovalAssembly({ ...value, approval });
  const display = revokeConsent({ approval, checked, maxFeeStroops: 10000000 });
  assert.equal(display.configurationChange.observed.name, 'changed grant');
  assert.deepEqual(display.configurationChange.observed.signerIds, [9]);
  assert.match(display.warning, /current configuration/);
  assert.notEqual(display.configurationChange.recordedRuleHash, display.configurationChange.observedRuleHash);
  assert.throws(() => reviewRemoval({ ...value.approval,
    configurationChange: { ...configurationChange, observedRuleXdr: value.f.ownerRuleXdr } }), /refused/);
});

// --- a grant installed by an earlier session -------------------------------------------------------
//
// A restarted backend holds no record of an earlier session's installation. Removal is still always
// possible: the approval names the rule by its exact current bytes, read from the account, instead of
// an installation transaction, and the consent shows that configuration.

function earlier(change = {}) {
  const f = fixture();
  const ruleXdr = installedRuleXdr(f);
  const approval = reviewRemoval({ networkId: NETWORK_ID, wallet: f.wallet, ownerRuleId: 7, ownerRuleXdr: f.ownerRuleXdr,
    installation: { account: f.wallet.contractId, ruleId: RULE_ID, transactionHash: null, ruleXdr, ...change } });
  return { f, ruleXdr, approval };
}
function installedRuleXdr(f, { signers, context, policies } = {}) {
  const fields = {
    // A grant on another contract's calls, never on the account's own.
    context_type: context ?? xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'), new Address(StrKey.encodeContract(Buffer.alloc(32, 8))).toScVal()]),
    id: xdr.ScVal.scvU32(RULE_ID), name: xdr.ScVal.scvString('earlier grant'),
    policies: policies ?? xdr.ScVal.scvVec([new Address(StrKey.encodeContract(Buffer.alloc(32, 5))).toScVal()]),
    policy_ids: xdr.ScVal.scvVec([xdr.ScVal.scvU32(0)]), signer_ids: xdr.ScVal.scvVec([xdr.ScVal.scvU32(1)]),
    signers: signers ?? xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'),
      new Address(Keypair.fromRawEd25519Seed(Buffer.alloc(32, 6)).publicKey()).toScVal()])]),
    valid_until: xdr.ScVal.scvU32(300000),
  };
  return xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val: fields[key] })))
    .toXDR('base64');
}

test('an earlier session\'s grant is removed by its exact current bytes, shown in the consent', () => {
  const { f, ruleXdr, approval } = earlier();
  assert.equal(approval.installation.transactionHash, null);
  assert.equal(approval.installation.ruleXdr, ruleXdr);
  // The commitment binds the rule's bytes: the same rule ID with other bytes is another approval.
  const other = installedRuleXdr(f, { signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Delegated'),
    new Address(Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7)).publicKey()).toScVal()])]) });
  assert.notEqual(earlier({ ruleXdr: other }).approval.commitment, approval.commitment);
  const value = removalFor({ account: f.wallet.contractId, payer: PAYER, sequence: '100', ledger: LEDGER });
  const checked = validateRemovalAssembly({ ...value, approval, ownerRuleXdr: f.ownerRuleXdr });
  const display = revokeConsent({ approval, checked, maxFeeStroops: 10_000_000 });
  assert.equal(display.installation.transaction, null);
  assert.equal(display.installation.from_earlier_session, true);
  assert.equal(display.installation.rule.name, 'earlier grant');
  assert.deepEqual(display.installation.rule.signers, [['Delegated', Keypair.fromRawEd25519Seed(Buffer.alloc(32, 6)).publicKey()]]);
  assert.match(display.warning, /not installed by this wallet session/);
});

test('an earlier session\'s removal takes only a grant-shaped rule: a call-contract context with at least one policy', () => {
  const f = fixture();
  const none = xdr.ScVal.scvVec([]);
  const policy = xdr.ScVal.scvVec([new Address(StrKey.encodeContract(Buffer.alloc(32, 5))).toScVal()]);
  const defaultContext = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]);
  const grant = installedRuleXdr(f);
  assert.equal(isGrantRule(grant, RULE_ID), true);
  for (const [label, ruleXdr] of [
    // A recovery or admin rule: any call, no policy limiting it. Removing it could lock the owner out of a recovery path.
    ['a default-context rule with no policies', installedRuleXdr(f, { context: defaultContext, policies: none })],
    ['a default-context rule with a policy', installedRuleXdr(f, { context: defaultContext, policies: policy })],
    ['a call-contract rule with no policies', installedRuleXdr(f, { policies: none })],
  ]) {
    assert.equal(isGrantRule(ruleXdr, RULE_ID), false, label);
    assert.throws(() => earlier({ ruleXdr }), /refused/, label);
  }
  assert.equal(isGrantRule(grant, RULE_ID + 1), false, 'bytes for another rule ID');
  // A call-contract rule on the account itself (a guardian or recovery rule), or on its own policy.
  const ownCalls = installedRuleXdr(f, { context: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'), new Address(f.wallet.contractId).toScVal()]) });
  assert.equal(isGrantRule(ownCalls, RULE_ID, { account: f.wallet.contractId }), false, 'the account\'s own calls');
  assert.throws(() => earlier({ ruleXdr: ownCalls }), /refused/, 'the account\'s own calls');
  const onPolicy = installedRuleXdr(f, { context: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'),
    new Address(StrKey.encodeContract(Buffer.alloc(32, 5))).toScVal()]) });
  assert.equal(isGrantRule(onPolicy, RULE_ID), false, 'a rule on its own policy contract');
  // A target bound as a policy in another of the account's rules.
  const other = StrKey.encodeContract(Buffer.alloc(32, 9));
  const onOther = installedRuleXdr(f, { context: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('CallContract'), new Address(other).toScVal()]) });
  assert.equal(isGrantRule(onOther, RULE_ID, { account: f.wallet.contractId }), true);
  assert.equal(isGrantRule(onOther, RULE_ID, { account: f.wallet.contractId, boundPolicies: [other] }), false, 'a policy bound elsewhere');
});

test('an earlier session\'s removal never takes the owner\'s own rule or a rule the owner signs for', () => {
  const f = fixture();
  // The owner rule itself, by ID or by bytes.
  assert.throws(() => earlier({ ruleId: 7 }), /refused/);
  assert.throws(() => earlier({ ruleXdr: f.ownerRuleXdr }), /refused/);
  // Any rule naming the owner's passkey: removing it could take away the owner's own access.
  const ownerSigner = xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'), new Address(f.wallet.verifier).toScVal(),
    xdr.ScVal.scvBytes(Buffer.concat([Buffer.from(f.wallet.publicKey, 'hex'), Buffer.from([1])]))])]);
  assert.throws(() => earlier({ ruleXdr: installedRuleXdr(f, { signers: ownerSigner }) }), /refused/);
  // Bytes for another rule ID, or none at all with no installation transaction either.
  assert.throws(() => earlier({ ruleId: RULE_ID + 1 }), /refused/);
  assert.throws(() => earlier({ ruleXdr: undefined }), /refused/);
  // A recorded installation does not also carry bytes.
  assert.throws(() => earlier({ transactionHash: 'e'.repeat(64) }), /refused/);
});
