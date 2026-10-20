import { readFileSync } from 'node:fs';
import { Address, xdr } from '@stellar/stellar-sdk';
export function fixture() {
  const intent = JSON.parse(readFileSync(new URL('../../testnet-harness/scripts/fixtures/authority/intent-passkey-owner.json', import.meta.url)));
  const v = intent.authority.verdict;
  const signer = v.authority_list[0].requirement.signers[0];
  // Deliberately not rule0: selection comes from the recognized authority list.
  v.authority_list[0].rule_id = 7;
  const wallet = { contractId: v.account_address, publicKey: signer.public_key, credentialId: 'AQ', verifier: signer.verifier };
  const ruleXdr = (changes = {}) => {
    const fields = {
      id: xdr.ScVal.scvU32(7), context_type: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Default')]),
      valid_until: xdr.ScVal.scvVoid(), name: xdr.ScVal.scvString('owner'), policies: xdr.ScVal.scvVec([]),
      signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('External'), new Address(wallet.verifier).toScVal(),
        xdr.ScVal.scvBytes(Buffer.concat([Buffer.from(wallet.publicKey, 'hex'), Buffer.from([1])]))])]), ...changes,
    };
    return xdr.ScVal.scvMap(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)).map(([key, val]) =>
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val }))).toXDR('base64');
  };
  return { intent, wallet, ownerRuleXdr: ruleXdr(), ruleXdr, expected: {
    account: v.account_address, target: v.grant.target, networkId: v.network_id,
    specHash: intent.authority.spec_hash, bindingSetHash: intent.authority.binding_set_hash,
    registrySnapshotRoot: intent.authority.registry_snapshot_root, boundPolicies: v.bound_policy_addresses, ruleIndex: 0,
  } };
}
