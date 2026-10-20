import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Account, Address, Asset, Keypair, Networks, Operation, SorobanDataBuilder, TransactionBuilder, hash, xdr } from '@stellar/stellar-sdk';
import { boundedRpcServer, checkPreparedEnvelope, WalletNetwork } from '../server/network.mjs';
import { NETWORK_ID } from '../shared/approval.mjs';

const contract = Asset.native().contractId(Networks.TESTNET);
function invocation(payer) {
  return Operation.invokeContractFunction({ contract, function: 'transfer', args: [
    new Address(payer).toScVal(), new Address(contract).toScVal(), xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: 1n })),
  ] });
}
function transaction() {
  const payer = Keypair.random();
  return new TransactionBuilder(new Account(payer.publicKey(), '7'), { fee: '1000', networkPassphrase: Networks.TESTNET })
    .addOperation(invocation(payer.publicKey())).setTimeout(60).build();
}
function prepared(original) {
  const envelope = xdr.TransactionEnvelope.fromXDR(original.toEnvelope().toXDR());
  envelope.v1.tx.fee = 2000;
  envelope.v1.tx.ext = xdr.TransactionExt.sorobanData(new SorobanDataBuilder().setResourceFee(1000).build());
  return TransactionBuilder.fromXDR(envelope.toXDR('base64'), Networks.TESTNET);
}

test('enforcing assembly can change only bounded resources and fee', () => {
  const original = transaction();
  const assembled = prepared(original);
  assert.doesNotThrow(() => checkPreparedEnvelope(assembled, original.toEnvelope().toXDR()));
});
for (const mutation of ['network', 'source', 'sequence', 'call', 'auth', 'signature', 'timeout', 'fee', 'resource fee']) {
  test(`enforcing assembly refuses substituted ${mutation}`, () => {
    const original = transaction();
    const envelope = prepared(original).toEnvelope();
    const tx = envelope.v1.tx;
    if (mutation === 'source') tx.sourceAccount = xdr.MuxedAccount.keyTypeEd25519(Keypair.random().rawPublicKey());
    if (mutation === 'sequence') tx.seqNum += 1n;
    if (mutation === 'call') tx.operations[0].body.invokeHostFunctionOp.hostFunction.invokeContract.functionName = 'burn';
    if (mutation === 'auth') tx.operations[0].body.invokeHostFunctionOp.auth = [new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(tx.operations[0].body.invokeHostFunctionOp.hostFunction.invokeContract),
        subInvocations: [],
      }),
    })];
    if (mutation === 'signature') envelope.v1.signatures.push(new xdr.DecoratedSignature({ hint: Buffer.alloc(4), signature: Buffer.alloc(64) }));
    if (mutation === 'timeout') tx.cond.timeBounds.maxTime += 1n;
    if (mutation === 'fee') tx.fee = 10_000_001;
    if (mutation === 'resource fee') tx.ext.sorobanData.resourceFee = 2001n;
    const changed = TransactionBuilder.fromXDR(envelope.toXDR('base64'), mutation === 'network' ? Networks.PUBLIC : Networks.TESTNET);
    assert.throws(() => checkPreparedEnvelope(changed, original.toEnvelope().toXDR()), /refused/);
  });
}

test('RPC transport uses only fixed endpoint and rejects oversized responses and redirects', async () => {
  const calls = [];
  let oversized = false;
  const server = boundedRpcServer('https://rpc.example/testnet', async (url, options) => {
    calls.push({ url, options });
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { passphrase: Networks.TESTNET } }),
      { headers: { 'content-length': oversized ? String(32 * 1024 * 1024) : '100' } });
  });
  assert.equal((await server.getNetwork()).passphrase, Networks.TESTNET);
  assert.equal(calls[0].url, 'https://rpc.example/testnet');
  assert.equal(calls[0].options.redirect, 'error');
  assert.equal(calls[0].options.credentials, 'omit');
  oversized = true;
  await assert.rejects(() => server.getNetwork(), /refused/);
});

function networkFixture(t, change = () => {}) {
  const root = mkdtempSync(join(tmpdir(), 'wallet-network-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const calls = [];
  let sent;
  const server = {
    getNetwork: async () => ({ passphrase: Networks.TESTNET, protocolVersion: 29 }),
    getAccount: async (address) => new Account(address, '7'),
    simulateTransaction: async (tx, _resources, mode) => {
      calls.push({ mode, tx });
      return { latestLedger: 100, result: { auth: [], retval: xdr.ScVal.scvVoid() } };
    },
    sendTransaction: async (tx) => {
      calls.push({ sent: tx });
      sent = tx;
      assert.ok(readdirSync(root).some((name) => name.endsWith('.intended.json')), 'journal must exist before send');
      return { status: 'PENDING', hash: Buffer.from(tx.hash()).toString('hex') };
    },
    getTransaction: async () => ({
      status: 'SUCCESS', ledger: 101, latestLedger: 101, envelopeXdr: sent.toEnvelope(),
      resultXdr: new xdr.TransactionResult({ feeCharged: 2000n, ext: xdr.TransactionResultExt.v0(),
        result: xdr.TransactionResultResult.txSuccess([xdr.OperationResult.opInner(xdr.OperationResultTr.invokeHostFunction(
          xdr.InvokeHostFunctionResult.invokeHostFunctionSuccess(Buffer.from(hash(
            new xdr.InvokeHostFunctionSuccessPreImage({ returnValue: xdr.ScVal.scvVoid(), events: [] }).toXDR())),
          ),
        ))]),
      }),
      resultMetaXdr: xdr.TransactionMeta.v3(new xdr.TransactionMetaV3({ ext: xdr.ExtensionPoint.v0(),
        txChangesBefore: [], operations: [new xdr.OperationMeta({ changes: [] })], txChangesAfter: [],
        sorobanMeta: new xdr.SorobanTransactionMeta({ ext: xdr.SorobanTransactionMetaExt.v0(),
          events: [], returnValue: xdr.ScVal.scvVoid(), diagnosticEvents: [] }),
      })),
    }),
  };
  change(server);
  const network = new WalletNetwork({ rpcUrl: 'https://rpc.example/testnet', journalRoot: root, server,
    fetchImpl: async (url) => { calls.push({ funded: url }); return new Response('{}'); },
    assemble: (tx) => ({ build: () => prepared(tx) }), pause: async () => {} });
  return { network, server, root, calls };
}

test('startup and reads never fund; wrong network prevents Friendbot and transaction submission', async (t) => {
  const { network, calls } = networkFixture(t, (server) => { server.getNetwork = async () => ({ passphrase: Networks.PUBLIC }); });
  assert.deepEqual(calls, []);
  await assert.rejects(() => network.fundPayer(), /refused/);
  assert.deepEqual(calls, []);
});

test('wallet constructs source authorization, enforces it and journals before sending', async (t) => {
  const { network, calls, root } = networkFixture(t);
  await network.fundPayer();
  const result = await network.submitOperation(invocation(network.payerAddress), 'sample-funding');
  assert.match(result.hash, /^[a-f0-9]{64}$/);
  assert.equal(result.ledger, 101);
  assert.equal(calls.find((call) => call.mode).mode, 'enforce');
  const simulated = calls.find((call) => call.mode).tx.toEnvelope().v1.tx.operations[0].body.invokeHostFunctionOp;
  assert.equal(simulated.auth.length, 1);
  assert.equal(simulated.auth[0].credentials.type, 'sorobanCredentialsSourceAccount');
  assert.equal(simulated.auth[0].rootInvocation.subInvocations.length, 0);
  const receipts = readdirSync(root).filter((name) => name.endsWith('.confirmed.json'));
  assert.equal(receipts.length, 1);
  assert.equal(JSON.parse(readFileSync(join(root, receipts[0]))).hash, result.hash);
  assert.match(calls.find((call) => call.funded).funded, /^https:\/\/friendbot\.stellar\.org\/\?addr=G/);
});

test('ambiguous submission blocks later writes and retains the intended hash', async (t) => {
  let sends = 0;
  const { network, root } = networkFixture(t, (server) => { server.sendTransaction = async () => { sends++; throw new Error('lost response'); }; });
  await network.fundPayer();
  await assert.rejects(() => network.submitOperation(invocation(network.payerAddress), 'sample-funding'), /refused/);
  await assert.rejects(() => network.submitOperation(invocation(network.payerAddress), 'sample-funding'), /refused/);
  assert.equal(sends, 1);
  const intention = readdirSync(root).find((name) => name.endsWith('.intended.json'));
  assert.match(JSON.parse(readFileSync(join(root, intention))).hash, /^[a-f0-9]{64}$/);
});

for (const mismatch of ['envelope', 'result', 'events']) {
  test(`confirmed ${mismatch} mismatch cannot become a success receipt`, async (t) => {
    const { network, root } = networkFixture(t, (server) => {
      const original = server.getTransaction;
      server.getTransaction = async () => {
        const receipt = await original();
        if (mismatch === 'envelope') receipt.envelopeXdr.v1.tx.seqNum += 1n;
        if (mismatch === 'result') receipt.resultXdr.result = xdr.TransactionResultResult.txFailed([]);
        if (mismatch === 'events') receipt.resultMetaXdr.v3.sorobanMeta.returnValue = xdr.ScVal.scvU32(1);
        return receipt;
      };
    });
    await network.fundPayer();
    await assert.rejects(() => network.submitOperation(invocation(network.payerAddress), 'sample-funding'), /refused/);
    assert.equal(readdirSync(root).filter((name) => name.endsWith('.confirmed.json')).length, 0);
  });
}

function entryServer(mode = 'valid') {
  const code = Buffer.from([0,97,115,109,1,0,0,0]);
  const wasmHash = Buffer.from(hash(code)).toString('hex');
  const instance = new Address(contract).toScAddress();
  const server = { getLedgerEntries: async (requested) => {
    const isCode = requested.type === 'contractCode';
    const key = xdr.LedgerKey.fromXDR(requested.toXDR());
    let val = isCode
      ? xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({
        ext: xdr.ContractCodeEntryExt.v0(), hash: Buffer.from(wasmHash, 'hex'), code,
      }))
      : xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({
        ext: xdr.ExtensionPoint.v0(), contract: instance, key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent,
        val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.from(wasmHash, 'hex')), storage: [],
        })),
      }));
    if (mode === 'wrong key') {
      if (isCode) key.contractCode.hash = new xdr.Hash(Buffer.alloc(32));
      else key.contractData.key = xdr.ScVal.scvU32(1);
    }
    if (mode === 'wrong value key' && !isCode) val.contractData.key = xdr.ScVal.scvU32(1);
    if (mode === 'wrong code hash' && isCode) val.contractCode.hash = new xdr.Hash(Buffer.alloc(32));
    if (mode === 'wrong code bytes' && isCode) val.contractCode.code = Buffer.from('wrong');
    if (mode === 'wrong instance hash' && !isCode) val.contractData.val.instance.executable = xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32));
    if (mode === 'wrong type') val = xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.v0(), hash: Buffer.alloc(32), code: Buffer.alloc(0),
    }));
    if (mode === 'wrong durability' && !isCode) val.contractData.durability = xdr.ContractDataDurability.temporary;
    if (mode === 'native executable' && !isCode) val.contractData.val.instance.executable = xdr.ContractExecutable.contractExecutableStellarAsset();
    const latestLedger = isCode && mode === 'drift' ? 113 : isCode && mode === 'backwards' ? 99 : 100;
    return { latestLedger, entries: [{
      // Real wire round trip makes the fixture exercise SDK17 field shapes.
      key: xdr.LedgerKey.fromXDR(key.toXDR()), val: xdr.LedgerEntryData.fromXDR(val.toXDR()),
      lastModifiedLedgerSeq: mode === 'future modification' ? 101 : 90,
      liveUntilLedgerSeq: mode === 'expired' ? 99 : 200,
    }] };
  } };
  return { server, wasmHash };
}
test('instance recognition checks exact live keys, retained code bytes and separate observation ledgers', async (t) => {
  const { server, wasmHash } = entryServer();
  const { network } = networkFixture(t, (stub) => { stub.getLedgerEntries = server.getLedgerEntries; });
  assert.deepEqual(await network.requireInstance(contract, wasmHash), { contractId: contract, wasmHash, ledger: 100, nonAtomic: true });
});
for (const mode of ['wrong key', 'wrong value key', 'wrong code hash', 'wrong code bytes', 'wrong instance hash',
  'wrong type', 'wrong durability', 'native executable', 'future modification', 'expired', 'drift', 'backwards']) {
  test(`recognition refuses inconsistent ledger evidence: ${mode}`, async (t) => {
    const { server, wasmHash } = entryServer(mode);
    const { network } = networkFixture(t, (stub) => { stub.getLedgerEntries = server.getLedgerEntries; });
    await assert.rejects(() => network.requireInstance(contract, wasmHash), /refused/);
  });
}
for (const mismatch of [false, true]) {
  test(`creation independently binds its predicted address before accepting readback: mismatch=${mismatch}`, async (t) => {
    const { network } = networkFixture(t);
    let readbacks = 0;
    network.requireCode = async () => {};
    network.requireInstance = async () => { readbacks++; };
    const wasmHash = 'aa'.repeat(32);
    network.submitOperation = async (operation) => {
      const create = operation.body.invokeHostFunctionOp.hostFunction.createContractV2;
      assert.equal(Buffer.from(create.executable.wasmHash.value).toString('hex'), wasmHash);
      assert.equal(Address.fromScAddress(create.contractIdPreimage.fromAddress.address).toString(), network.payerAddress);
      const raw = xdr.HashIdPreimage.envelopeTypeContractId(new xdr.HashIdPreimageContractId({
        networkId: Buffer.from(NETWORK_ID, 'hex'), contractIdPreimage: create.contractIdPreimage,
      })).toXDR();
      const expected = new Address(mismatch ? contract : Address.contract(hash(raw)).toString());
      return { hash: 'bb'.repeat(32), returnValue: expected.toScVal() };
    };
    const result = network.create(wasmHash, [xdr.ScVal.scvVec([])], 'deploy-account');
    if (mismatch) { await assert.rejects(result, /refused/); assert.equal(readbacks, 0); }
    else { assert.match((await result).contractId, /^C/); assert.equal(readbacks, 1); }
  });
}
