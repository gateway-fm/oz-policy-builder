// The Stellar networks this wallet runs against: a closed, frozen set, chosen once per backend
// session by the operator configuration and once per page by its launch URL. Everything that
// depends on the network (passphrase, network ID, the native asset's contract, the unit shown to
// the owner) is derived here from the passphrase, never written down a second time. Shared by the
// backend and the browser: no I/O.
import { Buffer } from 'buffer';
import { Asset, Networks, hash } from '#wallet-stellar-sdk';

/** The only protocol this wallet supports, on every network. */
export const PROTOCOL_VERSION = 30;

const refuse = () => { throw new Error('wallet network refused: this wallet runs on testnet or mainnet only'); };

function profile(name, passphrase, { unit, explorer, friendbot }) {
  return Object.freeze({
    name, passphrase, networkId: Buffer.from(hash(Buffer.from(passphrase))).toString('hex'),
    nativeAsset: Asset.native().contractId(passphrase), unit, explorer, friendbot,
  });
}

export const WALLET_NETWORKS = Object.freeze({
  testnet: profile('testnet', Networks.TESTNET, {
    unit: 'testnet XLM', explorer: 'https://stellar.expert/explorer/testnet', friendbot: 'https://friendbot.stellar.org',
  }),
  // No Friendbot: every account on mainnet is funded by someone who owns real XLM.
  mainnet: profile('mainnet', Networks.PUBLIC, {
    unit: 'XLM', explorer: 'https://stellar.expert/explorer/public', friendbot: null,
  }),
});

/** The profile for `name` (`testnet` or `mainnet`); anything else refuses. */
export function walletNetwork(name) {
  if (name !== 'testnet' && name !== 'mainnet') refuse();
  return WALLET_NETWORKS[name];
}

/** The profile whose network ID (hex SHA-256 of its passphrase) is `networkId`; anything else refuses. */
export function networkById(networkId) {
  const found = typeof networkId === 'string' ? Object.values(WALLET_NETWORKS).find((n) => n.networkId === networkId) : undefined;
  if (!found) refuse();
  return found;
}

/** An amount in stroops as the owner reads it on this network, e.g. `10000000 stroops (1 XLM)`. */
export function stroopsText(stroops, network) {
  return `${stroops} stroops (${Number(stroops) / 10_000_000} ${network.unit})`;
}
