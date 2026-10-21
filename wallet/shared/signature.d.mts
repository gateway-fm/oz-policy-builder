export interface SignedAuthorization {
  readonly envelopeXdr: string;
  readonly signedAuthEntriesXdr: readonly string[];
  readonly authentication: 'webauthn_user_verified';
  readonly human_approval_attested: false;
}
export function validateSignedAuthorization(input: unknown): Promise<SignedAuthorization>;
