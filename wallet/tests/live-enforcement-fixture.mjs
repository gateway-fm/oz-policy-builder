// Live-case fixtures built from the public record of the 21 October 2026 testnet probe of the atomic
// live helper: its addresses, amounts, rule, ledgers and denial code. The probe kept no signed entries
// and no raw simulation, so the authorization entries, ledger changes and error text below are
// constructed in the shapes the helper, the pinned account and the RPC produce. Everything is
// encoded here by hand, independently of the module under test.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Account, Address, Keypair, Networks, Operation, SorobanDataBuilder, StrKey, TransactionBuilder, nativeToScVal, xdr } from '@stellar/stellar-sdk';

const evidence = JSON.parse(readFileSync(new URL('../../docs/evidence/atomic-live-helper-testnet-2026-10-21.json', import.meta.url), 'utf8'));
const permitCase = evidence.cases.find((c) => c.case === 'target:original:0');
const denialCase = evidence.cases.find((c) => c.case === 'target:argument-denial:0');

export const PROBE = Object.freeze({
  networkId: evidence.network_id,
  helper: evidence.helper.contract,
  account: evidence.account.contract,
  accountCodeHash: evidence.account.code_hash,
  asset: evidence.asset,
  policy: evidence.candidate_policy.contract,
  policyCodeHash: evidence.candidate_policy.code_hash,
  ruleName: evidence.candidate_policy.name,
  validUntil: evidence.candidate_policy.valid_until_ledger,
  owner: evidence.owner,
  delegate: evidence.delegate,
  recipient: evidence.recipient,
  ruleId: permitCase.expected_rule_id,
  expiry: permitCase.signature_expiration_ledger,
  simulationLedger: permitCase.simulation_ledger,
  permitAmount: BigInt(permitCase.amount),
  denialAmount: BigInt(denialCase.amount),
  denialCode: denialCase.code,
  accountBalance: BigInt(evidence.post_expiry_readback.account_balance_before_cases.amount),
});

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const sym = (s) => xdr.ScVal.scvSymbol(s);
const u32 = (n) => xdr.ScVal.scvU32(n);
const addr = (a) => new Address(a).toScVal();
const vec = (items) => xdr.ScVal.scvVec(items);
const i128 = (v) => xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: BigInt(v) >> 64n, lo: BigInt(v) & ((1n << 64n) - 1n) }));
/** A contracttype struct: a map keyed by field-name symbols in ascending order. */
export const struct = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort()
  .map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));

export const delegated = (address) => vec([sym('Delegated'), addr(address)]);
export const PASSKEY = Object.freeze({
  verifier: StrKey.encodeContract(Buffer.alloc(32, 0x5a)),
  keyHex: `04${'11'.repeat(64)}${'22'.repeat(16)}`,
});
export const external = (verifier, keyHex) => vec([sym('External'), addr(verifier), xdr.ScVal.scvBytes(Buffer.from(keyHex, 'hex'))]);

export function intent(overrides = {}) {
  return {
    network_id: PROBE.networkId, helper: PROBE.helper, account: PROBE.account, policy: PROBE.policy,
    policy_code_hash: PROBE.policyCodeHash, delegate: PROBE.delegate, recipient: PROBE.recipient,
    amount: PROBE.permitAmount.toString(), expected_rule_id: PROBE.ruleId, owner_rule_id: 0,
    owner_signer: { kind: 'delegated', address: PROBE.owner }, rule_name: PROBE.ruleName,
    valid_until_ledger: PROBE.validUntil, signature_expiration_ledger: PROBE.expiry,
    ...overrides,
  };
}

const call = (contract, fn, args, subInvocations = []) => new xdr.SorobanAuthorizedInvocation({
  function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
    contractAddress: new Address(contract).toScAddress(), functionName: fn, args,
  })),
  subInvocations,
});

export const installRoot = (signer = delegated(PROBE.delegate), name = PROBE.ruleName) => call(PROBE.account, 'add_context_rule', [
  vec([sym('CallContract'), addr(PROBE.asset)]), xdr.ScVal.scvString(name), u32(PROBE.validUntil),
  vec([signer]), xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: addr(PROBE.policy), val: u32(0) })]),
]);
export const transferRoot = (amount = PROBE.permitAmount, subInvocations = [], recipient = PROBE.recipient, fn = 'transfer') =>
  call(PROBE.asset, fn, [addr(PROBE.account), addr(recipient), i128(amount)], subInvocations);

/** `AuthPayload { context_rule_ids, signers }`: each signer maps to its proof bytes. */
export function authPayload(ruleIds, signers) {
  return struct({
    context_rule_ids: vec(ruleIds.map(u32)),
    signers: xdr.ScVal.scvMap(signers.map(([key, proof]) => new xdr.ScMapEntry({ key, val: xdr.ScVal.scvBytes(proof) }))),
  });
}

let nonce = 1000n;
/**
 * The account's own entry, with address-bound (V2) credentials as the probe signed it, or classic
 * ones with `v1`.
 */
export function accountEntry(root, ruleIds, signers, { expiry = PROBE.expiry, v1 = false } = {}) {
  const credentials = new xdr.SorobanAddressCredentials({
    address: new Address(PROBE.account).toScAddress(), nonce: nonce++, signatureExpirationLedger: expiry,
    signature: authPayload(ruleIds, signers),
  });
  return new xdr.SorobanAuthorizationEntry({
    credentials: v1 ? xdr.SorobanCredentials.sorobanCredentialsAddress(credentials)
      : xdr.SorobanCredentials.sorobanCredentialsAddressV2(credentials),
    rootInvocation: root,
  });
}

/** `sha256(sha256(preimage) || xdr(rule ids))`, the preimage derived by hand for either credential. */
export function authDigest(entry, ruleIds) {
  const networkId = sha256(Buffer.from(Networks.TESTNET));
  const c = entry.credentials.addressV2 ?? entry.credentials.address;
  const preimage = entry.credentials.addressV2
    ? xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(new xdr.HashIdPreimageSorobanAuthorizationWithAddress({
      networkId, nonce: c.nonce, signatureExpirationLedger: c.signatureExpirationLedger, invocation: entry.rootInvocation, address: c.address,
    }))
    : xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
      networkId, nonce: c.nonce, signatureExpirationLedger: c.signatureExpirationLedger, invocation: entry.rootInvocation,
    }));
  return sha256(Buffer.concat([sha256(preimage.toXDR()), vec(ruleIds.map(u32)).toXDR()]));
}

/**
 * A delegated signer's own entry for `account.__check_auth(digest)`, with classic credentials as the
 * probe used. The signature is a well-formed placeholder: the host verified the real ones, and the
 * validator binds the entry by its digest, not by re-verifying the Ed25519 signature.
 */
export function signerEntry(signer, digest, { expiry = PROBE.expiry } = {}) {
  const raw = StrKey.decodeEd25519PublicKey(signer);
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(signer).toScAddress(), nonce: nonce++, signatureExpirationLedger: expiry,
      signature: vec([struct({ public_key: xdr.ScVal.scvBytes(raw), signature: xdr.ScVal.scvBytes(Buffer.alloc(64, 7)) })]),
    })),
    rootInvocation: call(PROBE.account, '__check_auth', [xdr.ScVal.scvBytes(digest)]),
  });
}

/** The four entries of one case, as the probe built them: owner installs under 0, delegate transfers under 1. */
export function caseEntries({ amount = PROBE.permitAmount, v1 = false, recipient = PROBE.recipient } = {}) {
  const install = accountEntry(installRoot(), [0], [[delegated(PROBE.owner), Buffer.alloc(0)]], { v1 });
  const transfer = accountEntry(transferRoot(amount, [], recipient), [PROBE.ruleId], [[delegated(PROBE.delegate), Buffer.alloc(0)]], { v1 });
  return [install, signerEntry(PROBE.owner, authDigest(install, [0])), transfer,
    signerEntry(PROBE.delegate, authDigest(transfer, [PROBE.ruleId]))];
}

/** The same case with a passkey owner: its proof sits in the account entry, so there is no owner entry. */
export function passkeyEntries({ ownerRule = 4 } = {}) {
  const install = accountEntry(installRoot(), [ownerRule], [[external(PASSKEY.verifier, PASSKEY.keyHex), Buffer.alloc(96, 3)]]);
  const transfer = accountEntry(transferRoot(), [PROBE.ruleId], [[delegated(PROBE.delegate), Buffer.alloc(0)]]);
  return [install, transfer, signerEntry(PROBE.delegate, authDigest(transfer, [PROBE.ruleId]))];
}

export function candidate(amount = PROBE.permitAmount, recipient = PROBE.recipient) {
  return struct({
    account: addr(PROBE.account), amount: i128(amount), delegate: addr(PROBE.delegate), expected_rule_id: u32(PROBE.ruleId),
    name: xdr.ScVal.scvString(PROBE.ruleName), policy: addr(PROBE.policy),
    policy_hash: xdr.ScVal.scvBytes(Buffer.from(PROBE.policyCodeHash, 'hex')), recipient: addr(recipient),
    valid_until: u32(PROBE.validUntil),
  });
}

const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 41));
/** The unsigned transaction an enforce-mode simulation of `install_and_transfer` receives. */
export function envelopeXdr(entries, { amount = PROBE.permitAmount, contract = PROBE.helper, fn = 'install_and_transfer', recipient } = {}) {
  return new TransactionBuilder(new Account(payer.publicKey(), '100'), { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeContractFunction({ contract, function: fn, args: [candidate(amount, recipient)], auth: entries }))
    .setTimeout(0).build().toEnvelope().toXDR('base64');
}

// --- ledger changes ---------------------------------------------------------------------------------

const persistent = xdr.ContractDataDurability.persistent;
export const dataKey = (contract, key, durability = persistent) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
  contract: new Address(contract).toScAddress(), key, durability,
}));
export const dataEntry = (contract, key, val, durability = persistent) => new xdr.LedgerEntry({
  lastModifiedLedgerSeq: PROBE.simulationLedger,
  data: xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({
    ext: xdr.ExtensionPoint.v0(), contract: new Address(contract).toScAddress(), key, durability, val,
  })),
  ext: xdr.LedgerEntryExt.v0(),
});
const accountId = (g) => Keypair.fromPublicKey(g).xdrAccountId();
export const accountKey = (g) => xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: accountId(g) }));
export const accountEntryOf = (g, balance, seqNum = 21474836480n) => new xdr.LedgerEntry({
  lastModifiedLedgerSeq: PROBE.simulationLedger,
  data: xdr.LedgerEntryData.account(new xdr.AccountEntry({
    accountId: accountId(g), balance, seqNum, numSubEntries: 0, inflationDest: null, flags: 0, homeDomain: '',
    thresholds: Buffer.from([1, 0, 0, 0]), signers: [],
    ext: xdr.AccountEntryExt.v1(new xdr.AccountEntryExtensionV1({
      liabilities: new xdr.Liabilities({ buying: 0n, selling: 0n }), ext: xdr.AccountEntryExtensionV1Ext.v0(),
    })),
  })),
  ext: xdr.LedgerEntryExt.v0(),
});
export const change = (key, before, after) => ({ type: before ? (after ? 'updated' : 'deleted') : 'created', key, before, after });
export const keyed = (name, ...rest) => vec([sym(name), ...rest]);
export const sacBalance = (amount) => nativeToScVal({ amount, authorized: true, clawback: false },
  { type: { amount: ['symbol', 'i128'], authorized: ['symbol'], clawback: ['symbol'] } });
const instanceKey = xdr.ScVal.scvLedgerKeyContractInstance();
export const instance = (storage) => xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({
  executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.from(PROBE.accountCodeHash, 'hex')),
  storage: Object.entries(storage).map(([name, value]) => new xdr.ScMapEntry({ key: keyed(name), val: u32(value) })),
}));
const RECIPIENT_BALANCE = 100_000_000_000n;
const nonceKey = (n) => xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce: n }));
const temporary = xdr.ContractDataDurability.temporary;

/**
 * Every entry a permit writes on a fresh pinned account, by name, so a test can drop or replace one.
 * A contract `recipient` holds its balance in the asset contract, created unless `recipientBefore`.
 */
export function permitChanges(entries, {
  amount = PROBE.permitAmount, received = amount, used = 1, ruleId = PROBE.ruleId, recipient = PROBE.recipient, recipientBefore = null,
} = {}) {
  const policyKey = (name) => keyed(name, addr(PROBE.account), u32(ruleId));
  const rule = struct({
    context_type: vec([sym('CallContract'), addr(PROBE.asset)]), name: xdr.ScVal.scvString(PROBE.ruleName),
    policy_ids: vec([u32(0)]), signer_ids: vec([u32(1)]), valid_until: u32(PROBE.validUntil),
  });
  const changes = {
    sender: change(dataKey(PROBE.asset, keyed('Balance', addr(PROBE.account))),
      dataEntry(PROBE.asset, keyed('Balance', addr(PROBE.account)), sacBalance(PROBE.accountBalance)),
      dataEntry(PROBE.asset, keyed('Balance', addr(PROBE.account)), sacBalance(PROBE.accountBalance - amount))),
    recipient: StrKey.isValidContract(recipient)
      ? change(dataKey(PROBE.asset, keyed('Balance', addr(recipient))),
        recipientBefore === null ? null : dataEntry(PROBE.asset, keyed('Balance', addr(recipient)), sacBalance(recipientBefore)),
        dataEntry(PROBE.asset, keyed('Balance', addr(recipient)), sacBalance((recipientBefore ?? 0n) + received)))
      : change(accountKey(recipient), accountEntryOf(recipient, RECIPIENT_BALANCE), accountEntryOf(recipient, RECIPIENT_BALANCE + received)),
    instance: change(dataKey(PROBE.account, instanceKey),
      dataEntry(PROBE.account, instanceKey, instance({ Count: 1, NextId: 1, NextSignerId: 1 })),
      dataEntry(PROBE.account, instanceKey, instance({ Count: 2, NextId: 2, NextPolicyId: 1, NextSignerId: 2 }))),
    rule: change(dataKey(PROBE.account, keyed('ContextRuleData', u32(ruleId))), null,
      dataEntry(PROBE.account, keyed('ContextRuleData', u32(ruleId)), rule)),
    signer: change(dataKey(PROBE.account, keyed('SignerData', u32(1))), null,
      dataEntry(PROBE.account, keyed('SignerData', u32(1)), struct({ count: u32(1), signer: delegated(PROBE.delegate) }))),
    signerLookup: change(dataKey(PROBE.account, keyed('SignerLookup', xdr.ScVal.scvBytes(sha256(delegated(PROBE.delegate).toXDR())))), null,
      dataEntry(PROBE.account, keyed('SignerLookup', xdr.ScVal.scvBytes(sha256(delegated(PROBE.delegate).toXDR()))), u32(1))),
    policyData: change(dataKey(PROBE.account, keyed('PolicyData', u32(0))), null,
      dataEntry(PROBE.account, keyed('PolicyData', u32(0)), struct({ count: u32(1), policy: addr(PROBE.policy) }))),
    policyLookup: change(dataKey(PROBE.account, keyed('PolicyLookup', addr(PROBE.policy))), null,
      dataEntry(PROBE.account, keyed('PolicyLookup', addr(PROBE.policy)), u32(0))),
    installed: change(dataKey(PROBE.policy, policyKey('Installed')), null,
      dataEntry(PROBE.policy, policyKey('Installed'), xdr.ScVal.scvBool(true))),
    counter: change(dataKey(PROBE.policy, policyKey('CallCount')), null,
      dataEntry(PROBE.policy, policyKey('CallCount'), u32(used))),
  };
  // Each address-credential entry consumes its nonce: a temporary entry under the signing address.
  entries.forEach((entry, i) => {
    const c = entry.credentials.addressV2 ?? entry.credentials.address;
    if (!c) return;
    const owner = Address.fromScAddress(c.address).toString();
    changes[`nonce${i}`] = change(dataKey(owner, nonceKey(c.nonce), temporary), null,
      dataEntry(owner, nonceKey(c.nonce), xdr.ScVal.scvVoid(), temporary));
  });
  return changes;
}

export function returnedRule({ id = PROBE.ruleId, name = PROBE.ruleName } = {}) {
  return struct({
    context_type: vec([sym('CallContract'), addr(PROBE.asset)]), id: u32(id), name: xdr.ScVal.scvString(name),
    policies: vec([addr(PROBE.policy)]), policy_ids: vec([u32(0)]), signer_ids: vec([u32(1)]),
    signers: vec([delegated(PROBE.delegate)]), valid_until: u32(PROBE.validUntil),
  });
}

/**
 * A change as the RPC reports it, base64. The host writes an updated entry with
 * `last_modified_ledger_seq` 0, while the entry before keeps the ledger it was last written at.
 */
export function rawChange({ key, before, after }) {
  const at = (entry, ledger) => {
    if (!entry) return null;
    const copy = xdr.LedgerEntry.fromXDR(entry.toXDR());
    copy.lastModifiedLedgerSeq = ledger;
    return copy.toXDR('base64');
  };
  return { type: before ? (after ? 2 : 3) : 1, key: key.toXDR('base64'), before: at(before, PROBE.simulationLedger - 1000), after: at(after, 0) };
}

/** The RPC's raw result of a successful enforce-mode simulation. */
export function permitSimulation(changes, { retval = returnedRule(), latestLedger = PROBE.simulationLedger, archived = [] } = {}) {
  const data = new SorobanDataBuilder().setResourceFee('100').build();
  if (archived.length) data.ext = xdr.SorobanTransactionDataExt.resourceExt(new xdr.SorobanResourcesExtV0({ archivedSorobanEntries: archived }));
  return {
    id: '1', latestLedger, events: [], minResourceFee: '100', transactionData: data.toXDR('base64'),
    results: [{ auth: [], xdr: retval.toXDR('base64') }], stateChanges: Object.values(changes).map(rawChange),
  };
}

/**
 * A failed enforce-mode simulation of the adjacent amount, in the format of the RPC's host error:
 * the helper frame on top, the asset's failed authentication of the account carrying the policy's
 * code, and the policy raising it.
 */
export function denialText({ code = PROBE.denialCode, raisedBy = PROBE.policy, account = PROBE.account } = {}) {
  return [
    'HostError: Error(Auth, InvalidAction)',
    '',
    'Event log (newest first):',
    `   0: [Diagnostic Event] contract:${PROBE.helper}, topics:[error, Error(Auth, InvalidAction)], data:"escalating error to VM trap from failed host function call: call"`,
    `   1: [Diagnostic Event] contract:${PROBE.asset}, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", ${account}, Error(Contract, #${code})]`,
    `   2: [Failed Diagnostic Event (not emitted)] contract:${PROBE.account}, topics:[log], data:["VM call trapped with HostError", __check_auth, Error(Contract, #${code})]`,
    `   3: [Failed Diagnostic Event (not emitted)] contract:${raisedBy}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`,
  ].join('\n');
}

export function helperRefusalText(code) {
  return [`HostError: Error(Contract, #${code})`, '', 'Event log (newest first):',
    `   0: [Diagnostic Event] contract:${PROBE.helper}, topics:[error, Error(Contract, #${code})], data:["failing with contract error", ${code}]`].join('\n');
}

export const failedSimulation = (error, extra = {}) => ({ id: '1', latestLedger: PROBE.simulationLedger, events: [], error, ...extra });

/** The probe's permit case end to end: the approved intent, the simulated envelope and its result. */
export function permitSample() {
  const entries = caseEntries();
  return { intent: intent(), envelopeXdr: envelopeXdr(entries), simulation: permitSimulation(permitChanges(entries)) };
}

/** The probe's denial case end to end. */
export function denialSample() {
  const entries = caseEntries({ amount: PROBE.denialAmount });
  return {
    intent: intent({ amount: PROBE.denialAmount.toString() }),
    envelopeXdr: envelopeXdr(entries, { amount: PROBE.denialAmount }),
    simulation: failedSimulation(denialText()),
  };
}
