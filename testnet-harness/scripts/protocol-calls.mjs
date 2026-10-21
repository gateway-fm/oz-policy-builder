// Closed testnet walkthrough calls. Every selected-account authorization includes the entire
// protocol invocation tree, including the independently installable token capability in W3.
import { Address, Operation, StrKey, xdr } from '@stellar/stellar-sdk';
import { contractCall, entryAddress, i128 } from './lib.mjs';

export const PROTOCOL_TARGETS = Object.freeze({
  blend_pool: 'CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF',
  blend_code: 'a41fc53d6753b6c04eb15b021c55052366a4c8e0e21bc72700f461264ec1350e',
  router: 'CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD',
  router_code: '4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c',
  native: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC',
  swap_output: 'CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F',
  pair: 'CDVAIOYHCD4RUSLQNVFI7RIZBFT2JZMJWM4RTOLQZQXL4QAVXU5RFKDB',
});
const A = (address) => new Address(address).toScVal();
const requireThat = (condition) => { if (!condition) throw new Error('invalid protocol plan'); };
const positive = (n) => typeof n === 'string' && /^[1-9][0-9]{0,38}$/.test(n) && BigInt(n) <= (1n << 127n) - 1n;

export function protocolInvocation(plan) {
  requireThat(plan && StrKey.isValidContract(plan.account));
  const p = PROTOCOL_TARGETS;
  if (plan.kind === 'blend_claim') {
    return contractCall(p.blend_pool, 'claim', [A(plan.account), xdr.ScVal.scvVec([xdr.ScVal.scvU32(6)]), A(plan.account)]);
  }
  requireThat(plan.kind === 'soroswap_swap' && positive(plan.amount_in) && BigInt(plan.amount_in) <= 10_000_000n
    && positive(plan.minimum_out) && Number.isSafeInteger(plan.deadline) && plan.deadline > 0);
  const root = contractCall(p.router, 'swap_exact_tokens_for_tokens', [i128(plan.amount_in), i128(plan.minimum_out),
    xdr.ScVal.scvVec([A(p.native), A(p.swap_output)]), A(plan.account), xdr.ScVal.scvU64(BigInt(plan.deadline))]);
  root.subInvocations = [contractCall(p.native, 'transfer', [A(plan.account), A(p.pair), i128(plan.amount_in)])];
  return root;
}

export function protocolOperation(plan, auth = []) {
  const call = protocolInvocation(plan).function.contractFn;
  return Operation.invokeContractFunction({ contract: Address.fromScAddress(call.contractAddress).toString(),
    function: call.functionName.toString(), args: call.args, auth });
}

export function assertProtocolEntry(entry, plan) {
  if (entryAddress(entry) !== plan.account || !Buffer.from(entry.rootInvocation.toXDR()).equals(Buffer.from(protocolInvocation(plan).toXDR()))) {
    throw new Error('protocol authorization differs from the exact intended invocation tree');
  }
}
