import { Account, Address, Asset, Keypair, Networks, Operation, SorobanDataBuilder, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { fixture } from './approval-fixture.mjs';
import { NETWORK_ID } from '../shared/approval.mjs';
export function sampleTransfer(mutate = () => {}, version = 'legacy') {
  const f = fixture();
  const recipient = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 11)).publicKey();
  const ownerRuleXdr = f.ruleXdr({ id: xdr.ScVal.scvU32(0) });
  const descriptor = { recipient, amountStroops: '1000000', ownerRuleXdr };
  const call = new xdr.InvokeContractArgs({ contractAddress: new Address(Asset.native().contractId(Networks.TESTNET)).toScAddress(),
    functionName: 'transfer', args: [new Address(f.wallet.contractId).toScVal(), new Address(recipient).toScVal(),
      xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 1_000_000n }))] });
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials[version === 'v2' ? 'sorobanCredentialsAddressV2' : 'sorobanCredentialsAddress'](new xdr.SorobanAddressCredentials({
      address: new Address(f.wallet.contractId).toScAddress(), nonce: 123n,
      signatureExpirationLedger: 219, signature: xdr.ScVal.scvVoid(),
    })), rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [],
    }),
  });
  const envelope = new TransactionBuilder(new Account(recipient, '100'), { fee: '1000', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] }))
    .setLedgerbounds(100, 220).setTimeout(0).setSorobanData(new SorobanDataBuilder().setResourceFee('100').build()).build().toEnvelope();
  mutate(envelope.v1.tx, envelope);
  return { wallet: f.wallet, descriptor, ownerRuleXdr,
    assembly: { envelope_xdr_base64: envelope.toXDR('base64'), envelope_xdr_sha256: Buffer.from(hash(envelope.toXDR())).toString('hex'),
      network_id: NETWORK_ID, fee_payer: recipient, source_sequence: '100', fee_stroops: 1100,
      sequence_read_ledger: 100, simulation_ledger: 101, min_ledger: 100, max_ledger: 220,
      restoration: 'none', simulation_auth_mode: 'record', evidence_trust: 'rpc_reported', state_dependent: true, writes_committed: false },
    limits: { feePayer: recipient, sourceSequence: '100', maxFeeStroops: 10_000_000, currentLedger: 101, validityLedgers: 120, ownerReadLedger: 100 } };
}
