// Which build of the applied app may run which session. The upstream app is a testnet prototype
// (its README says so): its own routes sign with a public deployer seed, relay through unauthenticated
// server functions, keep delegate secret keys in localStorage and pin testnet constants. A mainnet
// session therefore runs only from a production build made for mainnet (`VITE_OZPB_NETWORK=mainnet`,
// `vite build`, served by `vite preview`), which serves the Policy Builder alone: every upstream route
// shows a refusal and every upstream server function with an effect refuses. The Vite development
// server never runs a mainnet session. Pure: it reads only the build's `import.meta.env`.

/** The network a build was made for: `mainnet` only when built with `VITE_OZPB_NETWORK=mainnet`. */
export function buildNetwork(env) {
  return env?.VITE_OZPB_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
}

/**
 * Whether this build may run a session on `network`: mainnet only in a production build made for
 * mainnet, never under the development server; a mainnet build runs no testnet session.
 */
export function sessionAllowed(network, env) {
  if (network === 'mainnet') return buildNetwork(env) === 'mainnet' && env?.DEV === false && env?.PROD === true;
  return network === 'testnet' && buildNetwork(env) === 'testnet';
}

/** Why a session is refused, for the page. */
export function sessionRefusal(network, env) {
  if (sessionAllowed(network, env)) return null;
  if (network === 'mainnet') {
    return 'A mainnet session runs only from a production build made for mainnet: build with VITE_OZPB_NETWORK=mainnet, '
      + 'serve it with vite preview and open the launch URL again. This page is the development server or a testnet build.';
  }
  return 'This build was made for mainnet and runs no testnet session; use the development server for testnet.';
}

/** Whether the upstream prototype's own routes and server functions are available in this build. */
export function upstreamAllowed(env) {
  return buildNetwork(env) !== 'mainnet';
}

export const UPSTREAM_DISABLED = 'This upstream testnet prototype feature is disabled in a mainnet build of the wallet.';

/** For upstream server functions with an effect: refuses in a mainnet build, before anything else runs. */
export function assertUpstreamEnabled(env) {
  if (!upstreamAllowed(env)) throw new Error(UPSTREAM_DISABLED);
}
