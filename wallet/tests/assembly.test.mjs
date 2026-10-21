import assert from 'node:assert/strict';
import test from 'node:test';
import { Account, Address, Keypair, Networks, Operation, SorobanDataBuilder, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { sample } from './assembly-fixture.mjs';
import { fixture } from './approval-fixture.mjs';
import { reviewIntent } from '../shared/approval.mjs';
import { installCall, validateAssembly } from '../shared/assembly.mjs';


test('independent wallet validation returns only the exact unsigned owner authorization', () => {
  const value = validateAssembly(sample());
  assert.equal(value.ownerRuleId, 7);
  assert.equal(value.expirationLedger, 123479);
  assert.equal(value.authEntriesXdr.length, 1);
  assert.ok(Object.isFrozen(value));
});

test('wallet requires an open inclusion ledger below the exclusive maximum', () => {
  for (const [validity, current, accepted] of [[1, 123456, false], [2, 123457, false], [2, 123456, true]]) {
    const maximum = 123456 + validity;
    const value = sample((tx) => {
      tx.cond.v2.ledgerBounds.maxLedger = maximum;
      tx.operations[0].body.invokeHostFunctionOp.auth[0].credentials.address.signatureExpirationLedger = maximum - 1;
    });
    value.assembly.max_ledger = maximum;
    value.assembly.simulation_ledger = current;
    value.limits.currentLedger = current;
    value.limits.validityLedgers = validity;
    if (accepted) assert.doesNotThrow(() => validateAssembly(value));
    else assert.throws(() => validateAssembly(value), /refused/);
  }
});

for (const name of ['payer', 'sequence', 'fee', 'memo', 'signature', 'operation source', 'extra operation', 'function', 'arguments', 'extra auth',
  'nested auth', 'foreign auth', 'signed auth', 'expiry', 'unbounded ledger', 'time bound', 'extra signer', 'footprint duplicate']) {
  test(`independent XDR review rejects altered ${name} even with matching envelope digest`, () => {
    const value = sample((tx, envelope, entry) => {
      const op = tx.operations[0];
      const ih = op.body.invokeHostFunctionOp;
      switch (name) {
        case 'payer': tx.sourceAccount = xdr.MuxedAccount.keyTypeEd25519(Buffer.alloc(32, 5)); break;
        case 'sequence': tx.seqNum = 102n; break;
        case 'fee': tx.fee = 100001; break;
        case 'memo': tx.memo = xdr.Memo.memoText('hidden'); break;
        case 'signature': envelope.v1.signatures.push(new xdr.DecoratedSignature({ hint: Buffer.alloc(4), signature: Buffer.alloc(64) })); break;
        case 'operation source': op.sourceAccount = tx.sourceAccount; break;
        case 'extra operation': tx.operations.push(op); break;
        case 'function': ih.hostFunction.invokeContract.functionName = 'remove_context_rule'; break;
        case 'arguments': ih.hostFunction.invokeContract.args[1] = xdr.ScVal.scvString('different'); break;
        case 'extra auth': ih.auth.push(entry); break;
        case 'nested auth': ih.auth[0].rootInvocation.subInvocations.push(xdr.SorobanAuthorizedInvocation.fromXDR(entry.rootInvocation.toXDR())); break;
        case 'foreign auth': ih.auth[0].credentials.address.address = new Address(Keypair.random().publicKey()).toScAddress(); break;
        case 'signed auth': ih.auth[0].credentials.address.signature = xdr.ScVal.scvU32(1); break;
        case 'expiry': ih.auth[0].credentials.address.signatureExpirationLedger = 123480; break;
        case 'unbounded ledger': tx.cond.v2.ledgerBounds.maxLedger = 0; break;
        case 'time bound': tx.cond.v2.timeBounds.minTime = 1n; break;
        case 'extra signer': tx.cond.v2.extraSigners.push(xdr.SignerKey.signerKeyTypeEd25519(Buffer.alloc(32))); break;
        case 'footprint duplicate': {
          const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.alloc(32) }));
          tx.ext.sorobanData.resources.footprint.readOnly.push(key, key); break;
        }
      }
    });
    assert.throws(() => validateAssembly(value), /refused/);
  });
}

for (const name of ['digest', 'network', 'commitment', 'stale', 'backwards', 'restore', 'auth mode', 'committed', 'fee metadata', 'sequence metadata', 'new credential']) {
  test(`wallet refuses incoherent or stale ${name}`, () => {
    const value = sample();
    switch (name) {
      case 'digest': value.assembly.envelope_xdr_sha256 = '0'.repeat(64); break;
      case 'network': value.assembly.network_id = '0'.repeat(64); break;
      case 'commitment': value.assembly.intent.authority.verdict.authority_commitment = '0'.repeat(64); break;
      case 'stale': value.limits.currentLedger = 123480; break;
      case 'backwards': value.assembly.simulation_ledger = 123455; break;
      case 'restore': value.assembly.restoration = 'separate_transaction_reassemble_required'; break;
      case 'auth mode': value.assembly.simulation_auth_mode = 'enforce'; break;
      case 'committed': value.assembly.writes_committed = true; break;
      case 'fee metadata': value.assembly.fee_stroops = 1; break;
      case 'sequence metadata': value.assembly.source_sequence = '101'; break;
      case 'new credential': value.ownerRuleXdr = fixture().ruleXdr({ signers: xdr.ScVal.scvVec([]) }); break;
    }
    assert.throws(() => validateAssembly(value), /refused/);
  });
}
