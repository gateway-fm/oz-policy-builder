import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import * as sdk from '@stellar/stellar-sdk';

const mode = process.argv[2];
const payer = sdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 9));
let expectedHash; let checkpointHash; let polls = 0; let signatures = 0;
const signDecorated = payer.signDecorated.bind(payer);
payer.signDecorated = (...args) => { signatures++; return signDecorated(...args); };
const simulationModes = [];
class Server {
  async getAccount() { return new sdk.Account(mode === 'wrong fetched source'
    ? sdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7)).publicKey() : payer.publicKey(), '1'); }
  async simulateTransaction(_tx, _resources, authMode) {
    simulationModes.push(authMode);
    if (mode === 'source auth' || mode === 'create source auth') {
      const entries = _tx.operations[0].auth;
      assert.equal(entries.length, 1);
      assert.equal(entries[0].credentials.type, 'sorobanCredentialsSourceAccount');
      assert.equal(entries[0].rootInvocation.subInvocations.length, 0);
      const isCreate = mode === 'create source auth';
      assert.equal(entries[0].rootInvocation.function.type, isCreate
        ? 'sorobanAuthorizedFunctionTypeCreateContractV2HostFn' : 'sorobanAuthorizedFunctionTypeContractFn');
      assert.deepEqual(Buffer.from(entries[0].rootInvocation.function.value.toXDR()),
        Buffer.from(_tx.operations[0].func.value.toXDR()));
    }
    if (mode === 'upload no auth') assert.equal(_tx.operations[0].auth.length, 0);
    if (mode === 'existing auth') assert.deepEqual(Buffer.from(_tx.operations[0].auth[0].toXDR()), savedExistingAuth);
    if (mode === 'readback error ledger') return { latestLedger: 31, error: 'HostError: Error(Contract, #3000)' };
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
    if (mode === 'submission checkpoint') assert.equal(checkpointHash, expectedHash);
    return { status: mode === 'send backpressure' ? 'TRY_AGAIN_LATER' : mode === 'unknown send status' ? 'unexpected' : 'PENDING', hash: mode === 'submitted hash differs' ? 'ab'.repeat(32) : expectedHash };
  }
  async getTransaction() {
    polls++;
    if (mode === 'poll transient error' && polls === 1) throw new Error('fetch failed');
    return { status: mode === 'failed result' ? 'FAILED' : 'SUCCESS',
      txHash: mode === 'confirmed hash differs' ? 'cd'.repeat(32) : expectedHash,
      returnValue: sdk.xdr.ScVal.scvVoid() };
  }
}
function assemble(tx) {
  const envelope = tx.toEnvelope();
  const wire = envelope.v1.tx;
  if (mode === 'fee ceiling') wire.fee = 10_000_000;
  if (mode === 'fee zero') wire.fee = 0;
  if (mode === 'fee above ceiling') wire.fee = 10_000_001;
  if (mode === 'upload fee ceiling') wire.fee = 100_000_000;
  if (mode === 'named fee ceiling') wire.fee = 30_000_000;
  if (mode === 'named fee above ceiling') wire.fee = 30_000_001;
  if (mode === 'upload fee above ceiling') wire.fee = 100_000_001;
  // 22 October 2026: the W3 router rule's 21,814-byte Wasm assembled at 101,220,139 stroops.
  if (mode === 'upload named fee 10.12 XLM' || mode === 'upload default fee 10.12 XLM') wire.fee = 101_220_139;
  if (mode === 'upload named fee at ceiling') wire.fee = 150_000_000;
  if (mode === 'upload named fee above ceiling') wire.fee = 150_000_001;
  if (mode === 'named call fee above ten') wire.fee = 100_000_001;
  if (mode === 'upload bytes replaced') wire.operations[0] = sdk.Operation.uploadContractWasm({ wasm: Buffer.from([0, 97, 115, 109, 1]) });
  if (mode === 'replacement upload bypass') {
    wire.operations[0] = sdk.Operation.uploadContractWasm({ wasm: Buffer.from([0, 97, 115, 109]) });
    wire.fee = 100_000_000;
  }
  if (mode === 'negative resource fee' || mode === 'resource fee exceeds total' || mode === 'resource fee') {
    wire.ext = sdk.xdr.TransactionExt.sorobanData(new sdk.xdr.SorobanTransactionData({
      ext: sdk.xdr.SorobanTransactionDataExt.v0(),
      resources: new sdk.xdr.SorobanResources({
        footprint: new sdk.xdr.LedgerFootprint({ readOnly: [], readWrite: [] }),
        instructions: 0, diskReadBytes: 0, writeBytes: 0,
      }),
      resourceFee: mode === 'negative resource fee' ? -1n : mode === 'resource fee' ? 200n : 1_000_001n,
    }));
  }
  if (mode === 'replacement operation') wire.operations[0] = sdk.Operation.invokeContractFunction({
    contract: sdk.StrKey.encodeContract(Buffer.alloc(32, 2)), function: 'steal', args: [],
  });
  if (mode === 'replacement source') wire.sourceAccount = sdk.xdr.MuxedAccount.keyTypeEd25519(Buffer.alloc(32, 7));
  if (mode === 'replacement sequence') wire.seqNum += 1n;
  if (mode === 'replacement timeout') wire.cond.timeBounds.maxTime = 0n;
  if (mode === 'replacement memo') wire.memo = sdk.xdr.Memo.memoText('different');
  if (mode === 'extra operation') wire.operations.push(wire.operations[0]);
  if (mode === 'extra auth') wire.operations[0].body.invokeHostFunctionOp.auth.push(new sdk.xdr.SorobanAuthorizationEntry({
    credentials: sdk.xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new sdk.xdr.SorobanAuthorizedInvocation({
      function: sdk.xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new sdk.xdr.InvokeContractArgs({
        contractAddress: new sdk.Address(sdk.StrKey.encodeContract(Buffer.alloc(32, 1))).toScAddress(),
        functionName: 'other', args: [],
      })), subInvocations: [],
    }),
  }));
  const built = new sdk.Transaction(envelope, mode === 'replacement network' ? sdk.Networks.PUBLIC : sdk.Networks.TESTNET);
  if (mode === 'replacement signatures') built.sign(sdk.Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8)));
  return { build: () => built };
}
const replaced = { ...sdk, rpc: { ...sdk.rpc, Server, assembleTransaction: assemble } };
const context = vm.createContext({ process: { env: {} }, URL, Buffer, console, setTimeout });
const source = new vm.SourceTextModule(readFileSync(new URL('../rpc.mjs', import.meta.url), 'utf8'), { context });
await source.link(async (name) => {
  const exports = name === '@stellar/stellar-sdk' ? replaced : await import(name);
  return new vm.SyntheticModule(Object.keys(exports), function () {
    for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
  }, { context });
});
await source.evaluate();
let operation = sdk.Operation.invokeContractFunction({ contract: sdk.StrKey.encodeContract(Buffer.alloc(32, 1)),
  function: 'get', args: [] });
if (mode === 'create source auth' || mode === 'wrong create source') operation = sdk.Operation.createCustomContract({
  address: new sdk.Address(mode === 'wrong create source' ? sdk.StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 4)) : payer.publicKey()),
  wasmHash: Buffer.alloc(32, 1), salt: Buffer.alloc(32, 3), constructorArgs: [sdk.xdr.ScVal.scvU32(17)],
});
if (mode.startsWith('upload ')) operation = sdk.Operation.uploadContractWasm({ wasm: Buffer.from([0, 97, 115, 109]) });
let savedExistingAuth;
if (mode === 'existing auth') {
  const entry = new sdk.xdr.SorobanAuthorizationEntry({
    credentials: sdk.xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new sdk.xdr.SorobanAuthorizedInvocation({
      function: sdk.xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(operation.body.invokeHostFunctionOp.hostFunction.invokeContract),
      subInvocations: [],
    }),
  });
  savedExistingAuth = Buffer.from(entry.toXDR());
  operation.body.invokeHostFunctionOp.auth.push(entry);
}
if (mode === 'send backpressure' || mode === 'unknown send status') {
  await assert.rejects(source.namespace.submit(payer, operation), /not accepted/);
  assert.equal(polls, 0, 'an unaccepted send is not confirmation');
} else if (mode === 'submission checkpoint' || mode === 'checkpoint failure') {
  const pending = source.namespace.submit(payer, operation, { onSubmitting: async (hash) => {
    assert.equal(expectedHash, undefined, 'checkpoint precedes send');
    assert.equal(signatures, 1);
    assert.match(hash, /^[0-9a-f]{64}$/);
    checkpointHash = hash;
    if (mode === 'checkpoint failure') throw new Error('journal unavailable');
  } });
  if (mode === 'checkpoint failure') {
    await assert.rejects(pending, /journal unavailable/);
    assert.equal(expectedHash, undefined);
    assert.equal(polls, 0);
  } else {
    const sent = await pending;
    assert.equal(sent.hash, checkpointHash);
  }
} else if (mode === 'explicit auth modes') {
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
} else if (['matching', 'fee ceiling', 'resource fee', 'submit enforce mode', 'source auth', 'create source auth',
  'upload no auth', 'upload fee ceiling', 'existing auth', 'named fee ceiling',
  'upload named fee 10.12 XLM', 'upload named fee at ceiling'].includes(mode)) {
  const sent = await source.namespace.submit(payer, operation, mode === 'named fee ceiling' ? { maxFee: 30_000_000n }
    : mode.startsWith('upload named') ? { maxFee: source.namespace.POLICY_WASM_UPLOAD_FEE } : {});
  assert.equal(sent.hash, expectedHash);
  assert.equal(sent.receipt.txHash, expectedHash);
  if (mode === 'submit enforce mode') assert.deepEqual(simulationModes, ['enforce']);
} else if (['fee zero', 'fee above ceiling', 'negative resource fee', 'resource fee exceeds total', 'replacement operation',
  'replacement source', 'replacement sequence', 'replacement network', 'replacement timeout', 'replacement memo',
  'replacement signatures', 'extra operation', 'extra auth', 'wrong fetched source', 'wrong create source',
  'upload fee above ceiling', 'upload bytes replaced', 'replacement upload bypass', 'named fee above ceiling',
  'upload named fee above ceiling', 'upload default fee 10.12 XLM', 'named call fee above ten'].includes(mode)) {
  await assert.rejects(source.namespace.submit(payer, operation, mode === 'named fee above ceiling' ? { maxFee: 30_000_000n }
    : mode === 'upload named fee above ceiling' ? { maxFee: source.namespace.POLICY_WASM_UPLOAD_FEE }
    : mode === 'named call fee above ten' ? { maxFee: 100_000_000n } : {}),
    /submission refused/);
  assert.equal(signatures, 0, 'nothing signed');
  assert.equal(expectedHash, undefined, 'nothing submitted');
  assert.equal(polls, 0);
} else if (mode === 'poll transient error') {
  const sent = await source.namespace.submit(payer, operation);
  assert.equal(sent.hash, expectedHash);
  assert.equal(polls, 2, 'a transport error while polling is retried, not treated as an outcome');
} else if (mode === 'submission max time') {
  let seen;
  await source.namespace.submit(payer, operation, { onSubmitting: (hash, prepared) => { seen = { hash, ...prepared }; } });
  assert.equal(seen.hash, expectedHash);
  assert.ok(Number.isSafeInteger(seen.max_time) && seen.max_time > Math.floor(Date.now() / 1000), 'validity window end is journaled');
  assert.equal(seen.min_ledger, 31, 'the simulation ledger before which it cannot land is journaled');
} else if (mode === 'readback error ledger') {
  await assert.rejects(source.namespace.viewCallObservation(payer, sdk.StrKey.encodeContract(Buffer.alloc(32, 1)), 'missing'),
    (error) => error instanceof source.namespace.SimulationError && error.ledger === 31);
} else if (mode === 'named ceiling out of range' || mode === 'upload named ceiling out of range') {
  // A call may name at most 10 XLM; only a Wasm upload may name more, and at most 20 XLM.
  // submit's own pre-check refuses these before anything is simulated. checkAssembly re-derives
  // the bound from the intended envelope, deliberately redundant with this pre-check (both classify
  // the same operation), so through submit only the pre-check can be observed refusing.
  const outOfRange = mode === 'named ceiling out of range'
    ? [9_999_999n, 100_000_001n, 150_000_000n, 200_000_000n, 30_000_000]
    : [9_999_999n, 200_000_001n, 150_000_000];
  for (const maxFee of outOfRange) {
    await assert.rejects(source.namespace.submit(payer, operation, { maxFee }), /invalid fee ceiling/);
  }
  assert.deepEqual(simulationModes, [], 'refused before simulation');
  assert.equal(signatures, 0, 'nothing signed');
  assert.equal(expectedHash, undefined, 'nothing submitted');
} else {
  await assert.rejects(source.namespace.submit(payer, operation), mode === 'failed result' ? /ended FAILED/ : /identity/);
  if (mode === 'submitted hash differs') assert.equal(polls, 0);
}
