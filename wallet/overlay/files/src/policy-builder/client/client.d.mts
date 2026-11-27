export const REFUSAL_REASONS: ReadonlySet<string>;
export const CAP_SETTINGS: Readonly<{ fee_cap: 'maxUploadFeeStroops'; spend_cap: 'sessionSpendCapStroops' }>;
export function takeSession(location: Pick<Location, 'href'>, history: Pick<History, 'replaceState'>): Readonly<{ token: string; network: 'testnet' | 'mainnet' }>;
export function takeSessionToken(location: Pick<Location, 'href'>, history: Pick<History, 'replaceState'>): string;
export function createClient(token: string, options?: {
  fetch?: typeof fetch; maxBytes?: number; timeoutMs?: number;
}): (name: string, data: unknown) => Promise<unknown>;
