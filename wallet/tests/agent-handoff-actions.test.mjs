import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { createWalletActions } from '../server/actions.mjs';
import { AgentHandoff } from '../server/agent-handoff.mjs';
import { proposalFixture } from './proposal-fixture.mjs';
import { WALLET_NETWORKS } from '../shared/networks.mjs';
import { TESTNET_FEES } from '../server/network.mjs';

test('pairing checks the backend delegate and staging does not invoke import, builds or RPC', async () => {
  const f = proposalFixture(); const handoff = new AgentHandoff({ network: WALLET_NETWORKS.testnet }); const calls = [];
  const delegate = { address: f.proposal.decisions.delegate, capabilityId: 'a'.repeat(64) };
  const actions = createWalletActions({ handoff, session: {}, native: {},
    delegates: { check: (cap, address) => { assert.equal(cap, delegate.capabilityId); assert.equal(address, delegate.address); calls.push('delegate'); } },
    network: new Proxy({}, { get: (_, key) => key === 'profile' ? WALLET_NETWORKS.testnet : key === 'fees' ? TESTNET_FEES : () => { throw new Error('unexpected network call'); } }),
    toolchain: new Proxy({}, { get: () => () => { throw new Error('unexpected build'); } }) });
  const paired = await actions['pair-agent']({ wallet: f.wallet, delegate });
  assert.deepEqual(calls, ['delegate']);
  await assert.rejects(() => actions['pair-agent']({ wallet: f.wallet, delegate: { ...delegate, capabilityId: 'b'.repeat(64) } }));
  const connected = handoff.connect(paired.pairingCode);
  const proposal = JSON.stringify(f.proposal); const deliveryId = createHash('sha256').update(proposal).digest('hex');
  handoff.deliver(connected.capability, { deliveryId, proposal });
  assert.equal((await actions['agent-inbox']({})).pending.proposal, proposal);
  await assert.rejects(() => actions['create-delegate']({}));
  await actions['dismiss-agent-proposal']({ deliveryId });
  assert.equal((await actions['agent-inbox']({})).pending, null);
  await actions['disconnect-agent']({});
  assert.equal((await actions['agent-inbox']({})).connection, null);
});

// The agent's `connect_wallet` accepts a testnet connection only, so a session on any other network
// does not offer the direct hand-off: the agent's proposal comes in through manual import there.
test('the direct hand-off is offered on testnet only: a mainnet session neither offers nor pairs it', async () => {
  const f = proposalFixture(); const delegate = { address: f.proposal.decisions.delegate, capabilityId: 'a'.repeat(64) };
  const { MAINNET_FEE_DEFAULTS } = await import('../server/config.mjs');
  const actionsOn = (profile, fees) => {
    const calls = []; const handoff = new AgentHandoff({ network: profile });
    const actions = createWalletActions({ handoff, session: {}, native: {}, delegates: { available: true, check: () => calls.push('delegate') },
      network: { profile, fees, spentStroops: '0', payerAddress: 'G'.repeat(56) },
      toolchain: new Proxy({}, { get: () => () => { throw new Error('unexpected build'); } }) });
    return { actions, calls, handoff };
  };
  const testnet = actionsOn(WALLET_NETWORKS.testnet, TESTNET_FEES);
  assert.equal((await testnet.actions.status({})).capabilities.agentHandoff, true);
  assert.match((await testnet.actions['pair-agent']({ wallet: f.wallet, delegate })).pairingCode, /^ozpb-pair-[0-9a-f]{64}$/);
  const mainnet = actionsOn(WALLET_NETWORKS.mainnet, MAINNET_FEE_DEFAULTS);
  assert.equal((await mainnet.actions.status({})).capabilities.agentHandoff, false);
  assert.equal((await mainnet.actions.status({})).capabilities.importProposal, true, 'manual import stays');
  await assert.rejects(() => mainnet.actions['pair-agent']({ wallet: f.wallet, delegate }), /refused/);
  assert.deepEqual(mainnet.calls, [], 'refused before the delegate is checked');
  assert.equal(mainnet.handoff.view().pairingPending, false, 'no pairing code exists for the agent to use');
});
