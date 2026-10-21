export interface VerificationBindings { specHash: string; wasmHash: string; bindingSetHash: string }
export function verificationGate(report: unknown, expected: Partial<VerificationBindings>): {
  localReady: boolean; acceptanceReady: boolean;
};
