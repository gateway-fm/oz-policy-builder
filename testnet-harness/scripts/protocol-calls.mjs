// Closed testnet walkthrough calls. Every selected-account authorization includes the entire
// protocol invocation tree, including the independently installable token capability in W3.
import { Address, Operation, StrKey, xdr } from '@stellar/stellar-sdk';
import { contractCall, entryAddress, i128 } from './lib.mjs';

export const PROTOCOL_TARGETS = Object.freeze({
  // W1: Blend v2 pool whose reserve 1 is Circle's testnet USDC; the claim names that reserve's
  // bToken (supply) id, 1 * 2 + 1. Its pool BLND token and backstop are read back by blend-preflight.
  blend_pool: 'CAPBMXIQTICKWFPWFDJWMAKBXBPJZUKLNONQH3MLPLLBKQ643CYN5PRW',
  blend_code: 'a41fc53d6753b6c04eb15b021c55052366a4c8e0e21bc72700f461264ec1350e',
  blend_claim_id: 3,
  blend_asset: 'CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA',
  blnd: 'CB22KRA3YZVCNCQI64JQ5WE7UY2VAV7WFLK6A2JN3HEX56T2EDAFO7QF',
  blend_backstop: 'CBDVWXT433PRVTUNM56C3JREF3HIZHRBA64NB2C3B2UNCKIS65ZYCLZA',
  router: 'CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD',
  router_code: '4b95bbf9caec2c6e00c786f53c5f392c2fcdb8435ac0a862ab5e0645eb65824c',
  native: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC',
  swap_output: 'CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F',
  pair: 'CDVAIOYHCD4RUSLQNVFI7RIZBFT2JZMJWM4RTOLQZQXL4QAVXU5RFKDB',
});
/**
 * The reviewed adapter the development registry binds to `router_code`
 * (docs/TARGET-ADAPTERS.md). Synthesis derives the router's input bound and leaves its deadline
 * unconstrained through it; the harness never writes either as its own decision.
 */
export const ROUTER_ADAPTER = 'soroswap-router@1';
/** The one argument the adapter leaves unconstrained, disclosed as high blast radius. */
export const ROUTER_DEADLINE_ARG = 4;
const A = (address) => new Address(address).toScVal();
const requireThat = (condition) => { if (!condition) throw new Error('invalid protocol plan'); };
const positive = (n) => typeof n === 'string' && /^[1-9][0-9]{0,38}$/.test(n) && BigInt(n) <= (1n << 127n) - 1n;

export const SOROSWAP_DECISIONS_SCHEMA = 'ozpb-soroswap-operator-decisions/v1';
/** The operator's explicit acceptance of the adapter's unconstrained deadline. */
export const ADAPTER_DEADLINE_ACCEPTED = 'accept_any_value_high_blast_radius';
const MAX_SWAP_INPUT = 10_000_000n;
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const intent = (text) => typeof text === 'string' && text.length >= 1 && text.length <= 200 && !/[\u0000-\u001f\u007f]/.test(text);

/**
 * The W3 decisions an operator makes, read from a file, never from the harness's own code: the
 * absolute output floor (the router's `amount_out_min`), the cap on the independently usable
 * native transfer to the pair, and the acceptance of the adapter's any-value deadline. The
 * journaled copy (`journal: true`) also names the SHA-256 of the file it was read from.
 */
export function soroswapDecisions(value, { journal = false } = {}) {
  const fail = (what) => { throw new Error(`invalid Soroswap operator decisions: ${what}`); };
  const keys = ['schema', 'output_floor', 'transfer_cap', 'adapter_deadline', ...(journal ? ['source_sha256'] : [])];
  if (!exactKeys(value, keys)) fail(`expected exactly ${keys.join(', ')}`);
  if (value.schema !== SOROSWAP_DECISIONS_SCHEMA) fail(`schema must be ${SOROSWAP_DECISIONS_SCHEMA}`);
  const floor = value.output_floor, cap = value.transfer_cap;
  if (!exactKeys(floor, ['min', 'intent']) || !positive(floor.min) || BigInt(floor.min) < 2n || !intent(floor.intent)) {
    fail('output_floor needs a decimal min of at least 2 (its control lowers it by one) and a 1-200 character intent');
  }
  if (!exactKeys(cap, ['max', 'intent']) || !positive(cap.max) || BigInt(cap.max) > MAX_SWAP_INPUT || !intent(cap.intent)) {
    fail(`transfer_cap needs a decimal max of at most ${MAX_SWAP_INPUT} and a 1-200 character intent`);
  }
  if (value.adapter_deadline !== ADAPTER_DEADLINE_ACCEPTED) {
    fail(`adapter_deadline must be "${ADAPTER_DEADLINE_ACCEPTED}": the adapter leaves the deadline unconstrained`);
  }
  if (journal && !/^[0-9a-f]{64}$/.test(value.source_sha256 ?? '')) fail('missing source file hash');
  return value;
}

export function protocolInvocation(plan) {
  requireThat(plan && StrKey.isValidContract(plan.account));
  const p = PROTOCOL_TARGETS;
  if (plan.kind === 'blend_claim') {
    return contractCall(p.blend_pool, 'claim', [A(plan.account), xdr.ScVal.scvVec([xdr.ScVal.scvU32(p.blend_claim_id)]), A(plan.account)]);
  }
  requireThat(plan.kind === 'soroswap_swap' && positive(plan.amount_in) && BigInt(plan.amount_in) <= MAX_SWAP_INPUT
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
