import assert from 'node:assert/strict';
import test from 'node:test';
import { Address, Keypair, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk';
import { closePosition, fundingSwapInvocation, openPosition, refreshEmission, supplyInvocation, withdrawInvocation }
  from './blend-position.mjs';
import { BLEND_FUNDING, BLEND_POSITION, EMISSION_MARGIN_SECONDS } from './blend-preflight.mjs';
import { PROTOCOL_TARGETS } from './protocol-calls.mjs';
import { i128 } from './lib.mjs';
import { NETWORK_PASSPHRASE, PINNED_ACCOUNT_WASM, SimulationError } from './rpc.mjs';
const p = PROTOCOL_TARGETS;
const C = (n) => StrKey.encodeContract(Buffer.alloc(32, n));
const A = (v) => new Address(v).toScVal();
const sym = (s) => xdr.ScVal.scvSymbol(s);
const u64 = (n) => xdr.ScVal.scvU64(xdr.Uint64.fromString(String(n)));
const map = (fields) => xdr.ScVal.scvMap(Object.keys(fields).sort().map((key) => new xdr.ScMapEntry({ key: sym(key), val: fields[key] })));
const idMap = (entries) => xdr.ScVal.scvMap(entries.map(([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvU32(k), val: i128(v) })));
const CLOSE = 1_792_600_000;
const AMOUNT = BLEND_POSITION.amount;

function plan(account) {
  return { kind: 'blend_claim', account, grant_duration_ledgers: 300, owner_wait_ledgers: 12, accrual_ledgers: 12,
    position: { pool: p.blend_pool, asset: p.blend_asset, reserve_index: 1, request_type: 0, amount: AMOUNT.toString(), claim_ids: [3] },
    funding: { amount_in: BLEND_FUNDING.amount_in.toString(), minimum_out: AMOUNT.toString(), route: [p.native, p.blend_asset],
      pair: BLEND_FUNDING.pair, deadline: CLOSE + 3600 }, emission_refresh: null, prerequisites: {} };
}

function fixture({ withPlan = true } = {}) {
  const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1));
  const account = C(3);
  const run = { network: NETWORK_PASSPHRASE, account, account_code_hash: PINNED_ACCOUNT_WASM, payer: payer.publicKey(),
    owner: { kind: 'passkey' }, ...(withPlan ? { walkthrough: plan(account) } : {}) };
  const control = {}, state = { usdc: 0n, supply: 0n, ledger: 1000, expiration: CLOSE + 4 * 86400, eps: 3_620_045_854_265n };
  const sends = [], signatures = [], saved = [];
  let txn = 0;
  const positions = () => map({ collateral: idMap([]), liabilities: idMap([]), supply: idMap(state.supply ? [[1, state.supply]] : []) });
  const deps = {
    assertTestnet: async () => {},
    latestLedger: async () => (state.ledger += 3),
    latestLedgerClose: async () => ({ ledger: state.ledger, close_time: CLOSE }),
    delay: async () => {},
    now: () => 0,
    contractCodeHash: async (id) => id === account ? PINNED_ACCOUNT_WASM : id === p.blend_pool ? (control.poolCode ?? p.blend_code)
      : id === p.router ? p.router_code : 'aa'.repeat(32),
    loadKey: (name) => { assert.equal(name, 'payer'); return payer; },
    ownerSigner: async () => ({ verifier: C(6), keyData: Buffer.alloc(66, 1), sign: async (digest) => {
      signatures.push(digest); return Buffer.alloc(64, 2);
    } }),
    viewCall: async (_payer, contract, fn, args) => {
      if (contract === p.blend_asset && fn === 'balance') { assert.equal(scValToNative(args[0]), account); return i128(state.usdc); }
      if (contract === p.blend_pool && fn === 'get_positions') {
        if (control.unreadable) throw new Error('rpc down');
        return control.collateral ? map({ collateral: idMap([[1, 7n]]), liabilities: idMap([]), supply: idMap([[1, state.supply]]) }) : positions();
      }
      if (contract === p.blend_pool && fn === 'get_reserve_emissions') {
        return control.emission === null ? xdr.ScVal.scvVoid() : map({ eps: u64(state.eps), expiration: u64(state.expiration),
          index: i128(1), last_time: u64(CLOSE - 10) });
      }
      throw new Error(`unexpected view ${contract}.${fn}`);
    },
    recordAuth: async (_payer, op) => {
      const host = op.body.invokeHostFunctionOp.hostFunction.invokeContract;
      const fn = host.functionName.toString();
      const w = run.walkthrough;
      const type = fn === 'submit' ? scValToNative(host.args[3])[0].request_type : null;
      const root = fn === 'swap_exact_tokens_for_tokens' ? fundingSwapInvocation(w) : type === 0 ? supplyInvocation(w) : withdrawInvocation(w);
      if (control.missingChild) root.subInvocations = [];
      return [new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
          address: new Address(account).toScAddress(), nonce: 1n, signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid(),
        })), rootInvocation: root,
      })];
    },
    submit: async (_payer, op, options) => {
      const host = op.body.invokeHostFunctionOp.hostFunction.invokeContract;
      const fn = host.functionName.toString();
      if (fn === 'gulp_emissions' && control.gulpRefused) throw new SimulationError('gulp', 'Error(Contract, #1200)');
      const hash = (++txn).toString(16).padStart(64, '0');
      await options.onSubmitting(hash);
      sends.push(fn === 'submit' ? `submit:${scValToNative(host.args[3])[0].request_type}` : fn);
      if (control.ambiguous === sends.at(-1)) throw new Error('send unconfirmed');
      if (control.failedOnce === sends.at(-1)) { delete control.failedOnce; throw new Error(`blend withdrawal: transaction ${hash} ended FAILED`); }
      state.ledger += 2;
      let returnValue = xdr.ScVal.scvVoid();
      if (fn === 'gulp_emissions') { state.expiration = control.gulpTooShort ? CLOSE + 60 : CLOSE + 7 * 86400; returnValue = i128(50_000_000); }
      if (fn === 'swap_exact_tokens_for_tokens') {
        state.usdc += 213_000_000n; returnValue = xdr.ScVal.scvVec([i128(BLEND_FUNDING.amount_in), i128(213_000_000n)]);
      }
      if (sends.at(-1) === 'submit:0') { state.usdc -= AMOUNT; state.supply = AMOUNT - 100n; returnValue = positions(); }
      if (sends.at(-1) === 'submit:1') {
        if (!control.stillOpen) { state.usdc += AMOUNT + 5n; state.supply = 0n; }
        returnValue = positions();
      }
      return { hash, returnValue, receipt: { ledger: state.ledger } };
    },
  };
  const save = () => saved.push(structuredClone(run));
  return { run, control, state, deps, sends, signatures, saved, save };
}

test('Blend position calls are the exact owner trees: swap with its input transfer, supply with its deposit, bare withdrawal', () => {
  const w = plan(C(3));
  const swap = fundingSwapInvocation(w), supply = supplyInvocation(w), withdraw = withdrawInvocation(w);
  assert.equal(swap.function.contractFn.functionName.toString(), 'swap_exact_tokens_for_tokens');
  assert.deepEqual(scValToNative(swap.function.contractFn.args[2]), [p.native, p.blend_asset]);
  assert.deepEqual(swap.subInvocations.map((n) => scValToNative(xdr.ScVal.scvVec(n.function.contractFn.args))),
    [[C(3), BLEND_FUNDING.pair, BLEND_FUNDING.amount_in]]);
  const [request] = scValToNative(supply.function.contractFn.args[3]);
  assert.deepEqual(request, { request_type: 0, address: p.blend_asset, amount: AMOUNT });
  assert.deepEqual(scValToNative(xdr.ScVal.scvVec(supply.subInvocations[0].function.contractFn.args)), [C(3), p.blend_pool, AMOUNT]);
  assert.equal(Address.fromScAddress(supply.subInvocations[0].function.contractFn.contractAddress).toString(), p.blend_asset);
  const [out] = scValToNative(withdraw.function.contractFn.args[3]);
  assert.equal(out.request_type, 1);
  assert.ok(out.amount > AMOUNT, 'withdrawal asks for more than was supplied so the pool returns the whole balance');
  assert.equal(withdraw.subInvocations.length, 0);
});

test('a plan that widens the position or the funding swap is refused before any call', async () => {
  for (const widen of [(w) => { w.position.amount = '100000001'; }, (w) => { w.funding.amount_in = '2000000001'; },
    (w) => { w.position.request_type = 2; }, (w) => { w.funding.pair = C(9); }]) {
    const f = fixture();
    widen(f.run.walkthrough);
    await assert.rejects(openPosition({ run: f.run, save: f.save }, f.deps), /Blend position plan/);
    assert.deepEqual(f.sends, []);
  }
});

test('opening funds the account, swaps and supplies as the owner, then waits before the owner claim', async () => {
  const f = fixture();
  const journal = await openPosition({ run: f.run, save: f.save }, f.deps);
  assert.deepEqual(f.sends, ['transfer', 'swap_exact_tokens_for_tokens', 'submit:0']);
  assert.equal(journal.status, 'open');
  assert.equal(journal.funding_swap.returned_amount, '213000000');
  assert.equal(journal.supply.status, 'confirmed');
  assert.equal(journal.supply.b_tokens, (AMOUNT - 100n).toString());
  assert.equal(journal.supply.usdc_spent, AMOUNT.toString());
  assert.ok(journal.owner_wait.ledger >= journal.supply.ledger + 12);
  assert.equal(f.signatures.length, 2, 'the owner signs the swap and the supply; the payer funds the XLM');
  // Every prepared transaction is journaled before it is sent.
  assert.ok(f.saved.some((s) => s.walkthrough.position_journal?.supply?.status === 'pending'));
});

test('a recorded tree without the deposit is refused before the owner signs anything for it', async () => {
  const f = fixture(); f.control.missingChild = true;
  await assert.rejects(openPosition({ run: f.run, save: f.save }, f.deps), /exact intended Blend/);
  assert.deepEqual(f.sends, ['transfer']);
  assert.equal(f.signatures.length, 0);
  assert.equal(f.run.walkthrough.position_journal.status, 'incomplete');
});

test('cleanup withdraws an open position and reads the account back empty', async () => {
  const f = fixture();
  await openPosition({ run: f.run, save: f.save }, f.deps);
  const result = await closePosition({ run: f.run, save: f.save }, f.deps);
  assert.equal(result.status, 'withdrawn');
  assert.equal(f.sends.at(-1), 'submit:1');
  const w = f.run.walkthrough.position_journal.withdrawal;
  assert.equal(w.status, 'confirmed');
  assert.equal(w.readback, 'empty');
  assert.equal(w.usdc_returned, (AMOUNT + 5n).toString());
  // Idempotent: a second close sends nothing.
  assert.equal((await closePosition({ run: f.run, save: f.save }, f.deps)).status, 'withdrawn');
  assert.equal(f.sends.filter((s) => s === 'submit:1').length, 1);
});

test('cleanup reports a position that is still open after the withdrawal as incomplete', async () => {
  const f = fixture();
  await openPosition({ run: f.run, save: f.save }, f.deps);
  f.control.stillOpen = true;
  const result = await closePosition({ run: f.run, save: f.save }, f.deps);
  assert.deepEqual(result, { status: 'incomplete', reason: 'position_still_open' });
  assert.equal(f.run.walkthrough.position_journal.status, 'incomplete');
  assert.equal(f.run.walkthrough.position_journal.withdrawal.readback, 'still_open');
});

test('an unconfirmed withdrawal is never resubmitted and an open position stays reported', async () => {
  const f = fixture();
  await openPosition({ run: f.run, save: f.save }, f.deps);
  f.control.ambiguous = 'submit:1';
  assert.deepEqual(await closePosition({ run: f.run, save: f.save }, f.deps), { status: 'incomplete', reason: 'withdrawal_failed' });
  assert.equal(f.run.walkthrough.position_journal.withdrawal.status, 'pending');
  assert.deepEqual(await closePosition({ run: f.run, save: f.save }, f.deps), { status: 'incomplete', reason: 'withdrawal_unconfirmed' });
  assert.equal(f.sends.filter((s) => s === 'submit:1').length, 1);
});

test('cleanup does not infer that an unconfirmed supply opened nothing', async () => {
  const f = fixture(); f.control.ambiguous = 'submit:0';
  await assert.rejects(openPosition({ run: f.run, save: f.save }, f.deps), /unconfirmed/);
  f.state.supply = 0n;
  assert.deepEqual(await closePosition({ run: f.run, save: f.save }, f.deps), { status: 'incomplete', reason: 'supply_unconfirmed' });
  assert.equal(f.sends.includes('submit:1'), false);
});

test('cleanup withdraws a live position even when the supply confirmation was lost', async () => {
  const f = fixture(); f.control.ambiguous = 'submit:0';
  await assert.rejects(openPosition({ run: f.run, save: f.save }, f.deps), /unconfirmed/);
  f.state.supply = AMOUNT - 100n; // the supply landed after all
  assert.equal((await closePosition({ run: f.run, save: f.save }, f.deps)).status, 'withdrawn');
});

test('cleanup signs nothing when the pool code changed, and reports the position as incomplete', async () => {
  const f = fixture();
  await openPosition({ run: f.run, save: f.save }, f.deps);
  f.control.poolCode = 'bb'.repeat(32);
  const signed = f.signatures.length;
  assert.deepEqual(await closePosition({ run: f.run, save: f.save }, f.deps), { status: 'incomplete', reason: 'identity_check_failed' });
  assert.equal(f.signatures.length, signed);
  assert.equal(f.sends.includes('submit:1'), false);
});

test('cleanup has nothing to do before a position step began', async () => {
  const f = fixture();
  assert.deepEqual(await closePosition({ run: f.run, save: f.save }, f.deps), { status: 'not_applicable' });
  const g = fixture({ withPlan: false });
  assert.deepEqual(await closePosition({ run: g.run, save: g.save }, g.deps), { status: 'not_applicable' });
  assert.deepEqual(f.sends, []);
});

test('the emission refresh sends nothing while the claimed id still emits', async () => {
  const f = fixture({ withPlan: false });
  const record = await refreshEmission({ run: f.run, save: f.save }, f.deps);
  assert.equal(record.status, 'not_needed');
  assert.deepEqual(f.sends, []);
});

for (const when of ['expired', 'expiring']) {
  test(`an ${when} emission is refreshed once by the permissionless gulp, and the run records it`, async () => {
    const f = fixture({ withPlan: false });
    f.state.expiration = when === 'expired' ? CLOSE - 1 : CLOSE + EMISSION_MARGIN_SECONDS - 1;
    const record = await refreshEmission({ run: f.run, save: f.save }, f.deps);
    assert.deepEqual(f.sends, ['gulp_emissions']);
    assert.equal(record.status, 'gulped');
    assert.match(record.transaction, /^[0-9a-f]{64}$/);
    assert.equal(record.gulped, '50000000');
    assert.equal(record.expiration_after, CLOSE + 7 * 86400);
    assert.deepEqual(f.run.blend_emission_refresh, record);
    await assert.rejects(refreshEmission({ run: f.run, save: f.save }, f.deps), /already recorded/);
  });
}

test('an expired emission the pool cannot gulp is refused with its reason', async () => {
  const f = fixture({ withPlan: false });
  f.state.expiration = CLOSE - 1; f.control.gulpRefused = true;
  await assert.rejects(refreshEmission({ run: f.run, save: f.save }, f.deps), /expired.*gulp_emissions was refused/);
  assert.equal(f.run.blend_emission_refresh.status, 'refused');
  assert.deepEqual(f.sends, []);
});

for (const [name, change] of [['zero', (f) => { f.state.eps = 0n; }], ['missing', (f) => { f.control.emission = null; }]]) {
  test(`a ${name} emission is refused without a gulp`, async () => {
    const f = fixture({ withPlan: false });
    change(f);
    await assert.rejects(refreshEmission({ run: f.run, save: f.save }, f.deps), new RegExp(`is ${name}; refusing`));
    assert.deepEqual(f.sends, []);
  });
}

test('a withdrawal the network definitively did not apply is rebuilt once, never more', async () => {
  const f = fixture();
  await openPosition({ run: f.run, save: f.save }, f.deps);
  f.control.failedOnce = 'submit:1';
  const result = await closePosition({ run: f.run, save: f.save }, f.deps);
  assert.equal(result.status, 'withdrawn');
  assert.equal(f.sends.filter((s) => s === 'submit:1').length, 2);
  const j = f.run.walkthrough.position_journal;
  assert.equal(j.failed_withdrawals.length, 1);
  assert.equal(j.failed_withdrawals[0].status, 'not_applied');
  assert.notEqual(j.failed_withdrawals[0].transaction, j.withdrawal.transaction);
});

test('a confirmed withdrawal that left the position open is not called unconfirmed on a later close', async () => {
  const f = fixture();
  await openPosition({ run: f.run, save: f.save }, f.deps);
  f.control.stillOpen = true;
  await closePosition({ run: f.run, save: f.save }, f.deps);
  assert.deepEqual(await closePosition({ run: f.run, save: f.save }, f.deps), { status: 'incomplete', reason: 'position_still_open' });
  assert.equal(f.sends.filter((s) => s === 'submit:1').length, 1);
});

for (const [name, change, reason] of [
  ['an unexpected collateral position', (f) => { f.control.collateral = true; }, 'unexpected_position'],
  ['unreadable positions', (f) => { f.control.unreadable = true; }, 'position_unreadable'],
  ['a confirmed supply that is no longer there', (f) => { f.state.supply = 0n; }, 'position_missing'],
]) {
  test(`cleanup reports ${name} as incomplete and sends nothing`, async () => {
    const f = fixture();
    await openPosition({ run: f.run, save: f.save }, f.deps);
    change(f);
    assert.deepEqual(await closePosition({ run: f.run, save: f.save }, f.deps), { status: 'incomplete', reason });
    assert.equal(f.sends.includes('submit:1'), false);
  });
}

test('a gulp that leaves the emission short of the run window stops the run and says so', async () => {
  const f = fixture({ withPlan: false });
  f.state.expiration = CLOSE - 1; f.control.gulpTooShort = true;
  await assert.rejects(refreshEmission({ run: f.run, save: f.save }, f.deps), /still expiring after gulp_emissions/);
  assert.equal(f.run.blend_emission_refresh.status, 'gulped_still_not_live');
  assert.match(f.run.blend_emission_refresh.transaction, /^[0-9a-f]{64}$/);
});
