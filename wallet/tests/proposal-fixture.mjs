import { Asset, Networks, StrKey } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, NETWORK_ID } from '../shared/approval.mjs';
import { fixture } from './approval-fixture.mjs';

export function proposalFixture() {
  const wallet = fixture().wallet;
  const delegate = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 21));
  const recipient = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 22));
  const context = { type: 'CallContract', contract: Asset.native().contractId(Networks.TESTNET), target_code_hash: null };
  const calls = [{ fn: 'transfer', args: [
    { i: 0, c: { eq_address: { value: 'SELF' } } },
    { i: 1, c: { eq_address: { value: recipient } } },
    { i: 2, c: { eq_i128: { value: '1000000' } } },
  ] }];
  const authorization = { kind: 'any_of', strict_signer_set: true, signers: [{ delegated: { address: delegate } }] };
  const proposal = { schema: 'ozpb-grant-proposal/v1', network_id: NETWORK_ID, transaction_hash: '2'.repeat(64),
    decisions: { grant_name: 'wallet-grant', delegate, valid_until_ledger: 200, max_calls: 2, unlimited_calls_acknowledged: false },
    expected_grant: { account: wallet.contractId, rules: [{ context, calls, authorization,
      valid_until_ledger: 200, max_calls: 2, policy_kinds: ['gen:scope+count'] }] }, spec_hash: '3'.repeat(64) };
  const spec = { name: 'wallet-grant', network_id: NETWORK_ID,
    smart_account: { address: wallet.contractId, observed_code_hash: ACCOUNT_WASM },
    rules: [{ context: structuredClone(context), authorization: structuredClone(authorization),
      allowed_calls: calls.map((call) => ({ ...structuredClone(call), justified_by: ['recordings[0]/auth[0]/root'],
        args: call.args.map((arg) => ({ ...structuredClone(arg), prov: 'observed_exact' })) })),
      valid_until: { ledger: 200 }, state: [{ call_count_per_installation: { max_calls: 2 } }],
      policies: [{ generated: { kind: 'gen:scope+count' } }] }] };
  const artifact = { artifactId: '4'.repeat(64), specHash: '5'.repeat(64), wasmHash: '6'.repeat(64), spec, files: {} };
  const record = { recordId: '7'.repeat(64), transactionHash: proposal.transaction_hash, accountAddress: wallet.contractId };
  return { wallet, proposal, spec, artifact, record };
}
