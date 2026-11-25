// The wallet's mainnet network checks against responses mainnet really gave (fixtures/
// mainnet-rpc-2026-11-25.json, recorded read-only through the wallet's own WalletNetwork; its
// provenance names the endpoint, date and ledgers). The recording is replayed through the real
// JSON-RPC client the backend uses (`boundedRpcServer` over a fetch), so the SDK's parsing and the
// wallet's checks both run on mainnet's actual shapes: the passphrase and protocol, the ledger header
// hashing to its ID, the pinned account and verifier Wasm hashing to their pins, an account the
// operator has not funded, and an endpoint that returns diagnostic events. A request the recording
// does not hold fails the test, so it also pins which reads the checks make.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Keypair, Networks, xdr } from '@stellar/stellar-sdk';
import { ACCOUNT_WASM, WEBAUTHN_WASM } from '../shared/approval.mjs';
import { WALLET_NETWORKS } from '../shared/networks.mjs';
import { MAINNET_FEE_DEFAULTS } from '../server/config.mjs';
import { FeePayer } from '../server/fee-payer.mjs';
import { WalletNetwork, TESTNET_FEES } from '../server/network.mjs';

const RECORDED = JSON.parse(readFileSync(new URL('./fixtures/mainnet-rpc-2026-11-25.json', import.meta.url), 'utf8'));
// The recording's fee payer: a throwaway key anyone can derive, so that its requests replay byte for byte.
const PAYER = Keypair.fromRawEd25519Seed(createHash('sha256').update('ozpb-wallet-mainnet-rpc-fixture').digest());
const requestKey = ({ method, params }) => `${method} ${JSON.stringify(params ?? null)}`;

/**
 * A WalletNetwork whose endpoint answers only the recorded requests, each with its recorded response
 * (after `change`). A request the recording does not hold is answered with an error and kept in
 * `missed`, so that a refusal can be told from a gap in the recording (`refusedByCheck`).
 */
function replayed({ profile = WALLET_NETWORKS.mainnet, change = () => {} } = {}) {
  const answers = new Map(RECORDED.exchanges.map(({ request, response }) => [requestKey(request), structuredClone(response)]));
  change(answers);
  const asked = [], missed = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    const key = requestKey({ method: body.method, params: body.params });
    asked.push(body.method);
    if (url !== 'https://mainnet.sorobanrpc.com/' || !answers.has(key)) {
      missed.push(`${url} ${key.slice(0, 200)}`);
      throw new Error('not in the recording');
    }
    return new Response(JSON.stringify({ ...answers.get(key), id: body.id }), { headers: { 'content-type': 'application/json' } });
  };
  const mainnet = profile === WALLET_NETWORKS.mainnet;
  const network = new WalletNetwork({ network: profile, rpcUrl: 'https://mainnet.sorobanrpc.com', fetchImpl,
    feePayer: new FeePayer(PAYER, mainnet), fees: mainnet ? MAINNET_FEE_DEFAULTS : TESTNET_FEES });
  return { network, asked, answers, missed };
}
/** `call` is refused by the wallet's own check on recorded answers, not by a request the recording lacks. */
async function refusedByCheck(replay, call, predicate = () => true) {
  await assert.rejects(call, predicate);
  assert.deepEqual(replay.missed, [], 'every request was in the recording');
}
const answer = (answers, method, match = () => true) => [...answers.entries()].find(([key]) => key.startsWith(`${method} `) && match(key))[1];
const codeKey = (hash) => xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(hash, 'hex') })).toXDR('base64');

test('the recording is mainnet\'s, from the endpoint and date its provenance names', () => {
  assert.match(RECORDED.provenance.source, /^Stellar mainnet through https:\/\/mainnet\.sorobanrpc\.com, 25 November 2026/);
  assert.equal(RECORDED.provenance.fee_payer.split(',')[0], PAYER.publicKey());
  assert.deepEqual(RECORDED.exchanges.map(({ request }) => request.method).sort(),
    ['getLatestLedger', 'getLedgerEntries', 'getLedgerEntries', 'getLedgerEntries', 'getNetwork', 'simulateTransaction']);
});

test('recorded mainnet: the endpoint serves mainnet at protocol 30, and its ledger header hashes to the reported ID', async () => {
  const { network } = replayed();
  assert.deepEqual(await network.assertNetwork(), { passphrase: Networks.PUBLIC, protocolVersion: 30 });
  const clock = await network.ledgerClock();
  assert.equal(clock.sequence, 65662739);
  assert.ok(clock.closeTime > Date.UTC(2026, 10, 24) / 1000 && clock.closeTime < Date.UTC(2026, 10, 26) / 1000, String(clock.closeTime));
  assert.equal(await network.latestLedger(), 65662739);
});

test('recorded mainnet: the pinned account and WebAuthn verifier Wasm are stored, and their bytes hash to the pins', async () => {
  const { network, asked } = replayed();
  assert.deepEqual(await network.requireCode(ACCOUNT_WASM), { hash: ACCOUNT_WASM, ledger: 65662739 });
  assert.deepEqual(await network.requireCode(WEBAUTHN_WASM), { hash: WEBAUTHN_WASM, ledger: 65662740 });
  assert.deepEqual(await network.codePresent(ACCOUNT_WASM), { present: true, ledger: 65662739 });
  assert.deepEqual(await network.codePresent(WEBAUTHN_WASM), { present: true, ledger: 65662740 });
  assert.ok(asked.every((method) => ['getNetwork', 'getLedgerEntries'].includes(method)), asked.join());
});

test('recorded mainnet: an operator account that does not exist is unfunded, with mainnet\'s two 0.5 XLM base reserves as its minimum', async () => {
  const { network } = replayed();
  assert.deepEqual(await network.payerAccount(), { exists: false, minimumStroops: '10000000', ledger: 65662740 });
  await assert.rejects(() => network.fundPayer(), (error) => error.reason === 'payer_unfunded');
  assert.equal(network.canSubmit, false);
});

test('recorded mainnet: the endpoint returns diagnostic events with a simulation, which the live check and removal read', async () => {
  const { network } = replayed();
  assert.deepEqual(await network.diagnosticEvents(), { returned: true, ledger: 65662740 });
});

test('the same mainnet answers refuse a testnet session, and the checks refuse them altered', async () => {
  const testnet = replayed({ profile: WALLET_NETWORKS.testnet });
  await refusedByCheck(testnet, () => testnet.network.assertNetwork(), (error) => error.reason === 'network_mismatch');
  await refusedByCheck(testnet, () => testnet.network.codePresent(ACCOUNT_WASM), (error) => error.reason === 'network_mismatch');

  const earlier = replayed({ change: (answers) => { answer(answers, 'getNetwork').result.protocolVersion = 29; } });
  await refusedByCheck(earlier, () => earlier.network.assertNetwork(), (error) => error.reason === 'protocol_unsupported' && error.protocolVersion === 29);

  // A header that does not hash to the ID the endpoint reports.
  const header = replayed({ change: (answers) => { answer(answers, 'getLatestLedger').result.id = 'ab'.repeat(32); } });
  await refusedByCheck(header, () => header.network.ledgerClock());

  // One byte of the stored account Wasm changed: its bytes no longer hash to the pin.
  const code = replayed({ change: (answers) => {
    const entry = answer(answers, 'getLedgerEntries', (key) => key.includes(codeKey(ACCOUNT_WASM))).result.entries[0];
    const data = xdr.LedgerEntryData.fromXDR(entry.xdr, 'base64');
    const wasm = Buffer.from(data.contractCode.code);
    wasm[wasm.length - 1] ^= 1;
    data.contractCode.code = wasm;
    entry.xdr = data.toXDR('base64');
    assert.notEqual(entry.xdr, RECORDED.exchanges.find(({ request }) => request.params?.keys?.[0] === codeKey(ACCOUNT_WASM)).response.result.entries[0].xdr);
  } });
  await refusedByCheck(code, () => code.network.requireCode(ACCOUNT_WASM));
  await refusedByCheck(code, () => code.network.codePresent(ACCOUNT_WASM));
  assert.deepEqual(await code.network.requireCode(WEBAUTHN_WASM), { hash: WEBAUTHN_WASM, ledger: 65662740 });

  // A gap in the recording is told apart from a refusal.
  const gap = replayed({ change: (answers) => { answers.delete([...answers.keys()].find((key) => key.includes(codeKey(ACCOUNT_WASM)))); } });
  await assert.rejects(() => refusedByCheck(gap, () => gap.network.requireCode(ACCOUNT_WASM)), /every request was in the recording/);
});
