import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import * as sdk from '@stellar/stellar-sdk';

const mode = process.argv[2];
const payer = sdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 9));
let expectedHash; let polls = 0;
const simulationModes = [];
class Server {
  async getAccount() { return new sdk.Account(payer.publicKey(), '1'); }
  async simulateTransaction(_tx, _resources, authMode) {
    simulationModes.push(authMode);
    return { latestLedger: mode === 'missing read ledger' ? undefined : 31, result: { retval: sdk.xdr.ScVal.scvU32(42), auth: [] } };
  }
  async getLedgerEntries(key) {
    const wanted = key.contractData;
    const entry = { key, lastModifiedLedgerSeq: 27, liveUntilLedgerSeq: 39,
      val: sdk.xdr.LedgerEntryData.contractData(new sdk.xdr.ContractDataEntry({
        ext: sdk.xdr.ExtensionPoint.v0(), contract: wanted.contract, key: wanted.key, durability: wanted.durability,
        val: sdk.xdr.ScVal.scvContractInstance(new sdk.xdr.ScContractInstance({
          executable: sdk.xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32, 5)), storage: null,
        })),
      })),
    };
    if (mode === 'other entry key') entry.key = sdk.xdr.LedgerKey.contractData(new sdk.xdr.LedgerKeyContractData({
      ...wanted, contract: new sdk.Address(sdk.StrKey.encodeContract(Buffer.alloc(32, 2))).toScAddress(),
    }));
    if (mode === 'other data contract') entry.val.contractData.contract = new sdk.Address(sdk.StrKey.encodeContract(Buffer.alloc(32, 2))).toScAddress();
    if (mode === 'other data key') entry.val.contractData.key = sdk.xdr.ScVal.scvU32(5);
    if (mode === 'other durability') entry.val.contractData.durability = sdk.xdr.ContractDataDurability.temporary;
    if (mode === 'expired instance') entry.liveUntilLedgerSeq = 28;
    if (mode === 'future modified') entry.lastModifiedLedgerSeq = 30;
    if (mode === 'missing modified') delete entry.lastModifiedLedgerSeq;
    if (mode === 'missing TTL') delete entry.liveUntilLedgerSeq;
    return { latestLedger: mode === 'missing read ledger' ? undefined : 29, entries: [entry] };
  }
  async sendTransaction(tx) {
    // Model the RPC wire identity independently of the SDK's Uint8Array digest API.
    expectedHash = createHash('sha256').update(tx.signatureBase()).digest('hex');
    assert.match(expectedHash, /^[0-9a-f]{64}$/);
    return { status: 'PENDING', hash: mode === 'submitted hash differs' ? 'ab'.repeat(32) : expectedHash };
  }
  async pollTransaction() {
    polls++;
    return { status: mode === 'failed result' ? 'FAILED' : 'SUCCESS',
      txHash: mode === 'confirmed hash differs' ? 'cd'.repeat(32) : expectedHash,
      returnValue: sdk.xdr.ScVal.scvVoid() };
  }
}
const replaced = { ...sdk, rpc: { ...sdk.rpc, Server, assembleTransaction: (tx) => ({ build: () => tx }) } };
const context = vm.createContext({ process: { env: {} }, URL, Buffer, console });
const source = new vm.SourceTextModule(readFileSync(new URL('../rpc.mjs', import.meta.url), 'utf8'), { context });
await source.link(async (name) => {
  const exports = name === '@stellar/stellar-sdk' ? replaced : await import(name);
  return new vm.SyntheticModule(Object.keys(exports), function () {
    for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
  }, { context });
});
await source.evaluate();
const operation = sdk.Operation.invokeContractFunction({ contract: sdk.StrKey.encodeContract(Buffer.alloc(32, 1)),
  function: 'get', args: [] });
if (mode === 'explicit auth modes') {
  await source.namespace.recordAuth(payer, operation, 'test');
  const simulated = await source.namespace.enforceSimulation(payer, operation);
  assert.deepEqual(simulationModes, ['record', 'enforce']);
  assert.equal(simulated.ledger, 31);
  assert.equal(simulated.result, 'permit');
  assert.equal(expectedHash, undefined, 'no transaction sent');
} else if (mode === 'read ledgers') {
  const code = await source.namespace.contractCodeObservation(sdk.StrKey.encodeContract(Buffer.alloc(32, 1)));
  assert.equal(code.value, '05'.repeat(32));
  assert.equal(code.ledger, 29);
  const call = await source.namespace.viewCallObservation(payer, sdk.StrKey.encodeContract(Buffer.alloc(32, 1)), 'get');
  assert.equal(sdk.scValToNative(call.value), 42);
  assert.equal(call.ledger, 31);
} else if (mode === 'missing read ledger') {
  await assert.rejects(source.namespace.contractCodeObservation(sdk.StrKey.encodeContract(Buffer.alloc(32, 1))), /valid ledger/);
  await assert.rejects(source.namespace.viewCallObservation(payer, sdk.StrKey.encodeContract(Buffer.alloc(32, 1)), 'get'), /valid ledger/);
} else if (['other entry key', 'other data contract', 'other data key', 'other durability',
  'expired instance', 'future modified', 'missing modified', 'missing TTL'].includes(mode)) {
  await assert.rejects(source.namespace.contractCodeObservation(sdk.StrKey.encodeContract(Buffer.alloc(32, 1))), /instance|ledger/);
} else if (mode === 'matching') {
  const sent = await source.namespace.submit(payer, operation);
  assert.equal(sent.hash, expectedHash);
  assert.equal(sent.receipt.txHash, expectedHash);
} else {
  await assert.rejects(source.namespace.submit(payer, operation), mode === 'failed result' ? /ended FAILED/ : /identity/);
  if (mode === 'submitted hash differs') assert.equal(polls, 0);
}
