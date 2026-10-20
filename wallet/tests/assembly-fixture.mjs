import { Account, Address, Keypair, Networks, Operation, SorobanDataBuilder, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { fixture } from './approval-fixture.mjs';
import { reviewIntent } from '../shared/approval.mjs';
import { installCall } from '../shared/assembly.mjs';
export function sample(mutate = () => {}) {
  const input = fixture();
  const approval = reviewIntent(input);
  const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 11));
  const call = installCall(approval.intent);
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(approval.wallet.contractId).toScAddress(), nonce: xdr.Int64.fromString('123'),
      signatureExpirationLedger: 123479, signature: xdr.ScVal.scvVoid(),
    })), rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call), subInvocations: [],
    }),
  });
  const envelope = new TransactionBuilder(new Account(payer.publicKey(), '100'), { fee: '1000', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] }))
    .setLedgerbounds(123456, 123480).setTimeout(0).setSorobanData(new SorobanDataBuilder().setResourceFee('100').build()).build().toEnvelope();
  mutate(envelope.v1.tx, envelope, entry);
  const data = {
    intent: input.intent, envelope_xdr_base64: envelope.toXDR('base64'),
    envelope_xdr_sha256: Buffer.from(hash(envelope.toXDR())).toString('hex'), network_id: input.expected.networkId,
    fee_payer: payer.publicKey(), source_sequence: '100', fee_stroops: 1100,
    sequence_read_ledger: 123456, simulation_ledger: 123457, min_ledger: 123456, max_ledger: 123480,
    restoration: 'none', simulation_auth_mode: 'record', evidence_trust: 'rpc_reported', state_dependent: true, writes_committed: false,
  };
  return { approval, assembly: data, ownerRuleXdr: input.ownerRuleXdr,
    limits: { feePayer: payer.publicKey(), sourceSequence: '100', maxFeeStroops: 100000, currentLedger: 123457, validityLedgers: 24 } };
}
