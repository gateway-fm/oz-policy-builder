/** Direct credentials only. Preserve the arm: it selects the signed preimage. */
export function directAddressCredentials(credentials) {
  if (credentials?.type === 'sorobanCredentialsAddress') return credentials.address;
  if (credentials?.type === 'sorobanCredentialsAddressV2') return credentials.addressV2;
  throw new Error('unsupported wallet authorization credentials');
}
