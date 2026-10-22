import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Keypair, StrKey, hash, xdr } from '@stellar/stellar-sdk';
import { reviewRemoval, revokeConsent, validateRemovalAssembly } from '../shared/revoke.mjs';
import { ruleReadbackResult } from '../server/install.mjs';
import { fixture } from './approval-fixture.mjs';
import { RULE_ID, removalFor } from './install-fixture.mjs';

const PAYER = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 11)).publicKey();
const LEDGER = 200000;

function removal(mutate) {
  const f = fixture();
  const approval = reviewRemoval({ wallet: f.wallet, ownerRuleId: 7, ownerRuleXdr: f.ownerRuleXdr,
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
  const base = { wallet: f.wallet, ownerRuleId: 7, ownerRuleXdr: f.ownerRuleXdr,
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
