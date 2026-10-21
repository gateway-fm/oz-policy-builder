import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Operation, StrKey, xdr } from '@stellar/stellar-sdk';
import { protocolInvocation, protocolOperation, assertProtocolEntry } from './protocol-calls.mjs';

const account = StrKey.encodeContract(Buffer.alloc(32, 8));
const other = StrKey.encodeContract(Buffer.alloc(32, 9));
const A = (a) => new Address(a).toScVal();
const I = (n) => xdr.ScVal.scvI128(new xdr.Int128Parts({ hi: 0n, lo: BigInt(n) }));
const pool = 'CAPBMXIQTICKWFPWFDJWMAKBXBPJZUKLNONQH3MLPLLBKQ643CYN5PRW';
const router = 'CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD';
const native = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
const usdc = 'CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F';
const pair = 'CDVAIOYHCD4RUSLQNVFI7RIZBFT2JZMJWM4RTOLQZQXL4QAVXU5RFKDB';
const claim = { kind: 'blend_claim', account };
const swap = { kind: 'soroswap_swap', account, amount_in: '1000000', minimum_out: '100000', deadline: 1_800_000_000 };
function expected(contract, fn, args, children = []) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
      contractAddress: new Address(contract).toScAddress(), functionName: fn, args,
    })), subInvocations: children,
  });
}
function entry(plan, root = protocolInvocation(plan)) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(account).toScAddress(), nonce: 4n, signatureExpirationLedger: 500,
      signature: xdr.ScVal.scvVoid(),
    })), rootInvocation: root,
  });
}
for (const plan of [claim, swap]) {
  test(`${plan.kind} preserves the exact public protocol invocation through wire encoding`, () => {
    const wanted = plan === claim ? expected(pool, 'claim', [A(account), xdr.ScVal.scvVec([xdr.ScVal.scvU32(3)]), A(account)])
      : expected(router, 'swap_exact_tokens_for_tokens', [I(1000000), I(100000), xdr.ScVal.scvVec([A(native), A(usdc)]),
        A(account), xdr.ScVal.scvU64(1_800_000_000n)], [expected(native, 'transfer', [A(account), A(pair), I(1000000)])]);
    assert.deepEqual(Buffer.from(protocolInvocation(plan).toXDR()), Buffer.from(wanted.toXDR()));
    const op = xdr.Operation.fromXDR(protocolOperation(plan).toXDR());
    assert.deepEqual(Buffer.from(op.body.invokeHostFunctionOp.hostFunction.invokeContract.toXDR()), Buffer.from(wanted.function.contractFn.toXDR()));
    assertProtocolEntry(xdr.SorobanAuthorizationEntry.fromXDR(entry(plan).toXDR()), plan);
  });
}
for (const mutation of ['missing child', 'extra child', 'child amount', 'child recipient', 'root recipient', 'root path', 'authorizer']) {
  test(`swap authorization refuses ${mutation}`, () => {
    const auth = entry(swap);
    const root = auth.rootInvocation;
    if (mutation === 'missing child') root.subInvocations = [];
    if (mutation === 'extra child') root.subInvocations.push(root.subInvocations[0]);
    if (mutation === 'child amount') root.subInvocations[0].function.contractFn.args[2] = I(1000001);
    if (mutation === 'child recipient') root.subInvocations[0].function.contractFn.args[1] = A(other);
    if (mutation === 'root recipient') root.function.contractFn.args[3] = A(other);
    if (mutation === 'root path') root.function.contractFn.args[2] = xdr.ScVal.scvVec([A(usdc), A(native)]);
    if (mutation === 'authorizer') auth.credentials.address.address = new Address(other).toScAddress();
    assert.throws(() => assertProtocolEntry(xdr.SorobanAuthorizationEntry.fromXDR(auth.toXDR()), swap), /protocol authorization/);
  });
}
for (const plan of [{ ...swap, amount_in: '10000001' }, { ...swap, minimum_out: '0' }, { ...swap, deadline: 0 },
  { ...claim, account: StrKey.encodeEd25519PublicKey(Buffer.alloc(32)) }, { ...claim, kind: 'arbitrary' }]) {
  test(`protocol plan refuses an invalid bound: ${JSON.stringify(plan)}`, () => assert.throws(() => protocolOperation(plan), /protocol plan/));
}
