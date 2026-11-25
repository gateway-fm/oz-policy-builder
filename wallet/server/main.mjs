import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadWalletConfig } from './config.mjs';
import { createWalletServer } from './http.mjs';
import { WalletNetwork, journaledSpend } from './network.mjs';
import { AgentHandoff } from './agent-handoff.mjs';
import { DelegateCapabilities } from './native-execution.mjs';
import { WalletSession } from './session.mjs';
import { WalletToolchain } from './toolchain.mjs';

// WebAuthn requires a domain RP ID: Chrome refuses registration on 127.0.0.1.
// Listeners still bind only the IPv4 loopback interface.
const ORIGIN = 'http://localhost:3000';
const BACKEND_HOST = '127.0.0.1';
/**
 * The backend's loopback port per network. The Vite development server proxies only to the testnet
 * port; only `vite preview`, serving a production build, proxies to the mainnet one, so a mainnet
 * session cannot be reached from the development server.
 */
export const BACKEND_PORTS = Object.freeze({ testnet: 4317, mainnet: 4318 });

/**
 * The operator-facing reason the RPC endpoint cannot serve this session, or null: it must serve the
 * configured network at protocol 30. One read-only `getNetwork`; nothing is signed or sent.
 */
export async function networkPreflight(network) {
  try { await network.assertNetwork(); return null; } catch (error) {
    if (error?.reason === 'protocol_unsupported') {
      return `The RPC endpoint reports protocol ${error.protocolVersion ?? 'unknown'} for ${network.profile.name}; this wallet runs on `
        + `protocol 30 only.`;
    }
    if (error?.reason === 'network_mismatch') {
      return `The RPC endpoint does not serve ${network.profile.name}, the network this session was configured for (operator \`network\`).`;
    }
    return `The RPC endpoint did not answer getNetwork; check the operator \`rpcUrl\`.`;
  }
}

/**
 * Assemble trusted local components without invoking any network method or executable. The network
 * is chosen once, by the operator configuration, and recorded first in the session journal.
 */
export async function createWalletRuntime(configPath, { actionsFactory } = {}) {
  const config = loadWalletConfig(configPath);
  const secret = randomBytes(32).toString('hex');
  const session = new WalletSession({ origin: ORIGIN, host: 'localhost:3000', secret });
  const toolchain = new WalletToolchain(config);
  const journalRoot = join(toolchain.sessionRoot, 'journal');
  mkdirSync(journalRoot, { mode: 0o700 });
  // On mainnet the spend cap counts what earlier sessions in this (network-bound) work root sent.
  const spentStroops = config.network.friendbot ? '0' : journaledSpend(config.workRoot, config.network, config.fees);
  const network = new WalletNetwork({ rpcUrl: config.rpcUrl, journalRoot, network: config.network, feePayer: config.feePayer, fees: config.fees,
    spentStroops });
  const createActions = actionsFactory ?? (await import('./actions.mjs')).createWalletActions;
  const native = config.nativeExecutable ? Object.freeze({ executable: config.nativeExecutable }) : null;
  const live = config.liveHelper ? Object.freeze({ helper: config.liveHelper }) : null;
  const handoff = new AgentHandoff({ network: config.network });
  // Disposable automation keys on testnet; on mainnet only the operator's delegate key, if any.
  const delegates = new DelegateCapabilities(config.network, { random: Boolean(config.network.friendbot),
    key: config.delegateKey ? config.delegateKey.keypair() : null });
  const actions = createActions({ session, toolchain, network, native, live, handoff, delegates, pinnedWasmDir: config.pinnedWasmDir });
  const server = createWalletServer({ session, actions, handoff });
  return { server, network: config.network, preflight: () => networkPreflight(network),
    launchUrl: `${ORIGIN}/policy-builder#session=${secret}&network=${config.network.name}` };
}

export async function startWallet(configPath) {
  const runtime = await createWalletRuntime(configPath);
  const refused = await runtime.preflight();
  if (refused) throw Object.assign(new Error('wallet startup refused'), { startup: refused });
  await new Promise((resolve, reject) => {
    runtime.server.once('error', reject);
    runtime.server.listen(BACKEND_PORTS[runtime.network.name], BACKEND_HOST, () => {
      runtime.server.off('error', reject);
      resolve();
    });
  });
  return runtime;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new Error();
    const { server, launchUrl } = await startWallet(process.argv[3]);
    process.stdout.write(`${launchUrl}\n`);
    const stop = () => server.close();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    server.on('close', () => {
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
    });
    server.on('error', () => {
      process.stderr.write('Wallet listener failed; inspect retained local state before restarting.\n');
      server.close();
      process.exitCode = 1;
    });
  } catch (error) {
    process.stderr.write(`${typeof error?.startup === 'string' ? error.startup
      : 'Wallet startup refused. Check the operator configuration and local ports.'}\n`);
    process.exitCode = 1;
  }
}
