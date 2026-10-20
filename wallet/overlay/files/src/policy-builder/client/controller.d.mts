import type { Approval, WalletIdentity } from '../shared/approval.mjs';
import type { CheckedAssembly } from '../shared/assembly.mjs';
import type { SignedAuthorization } from '../shared/signature.mjs';
import type { SampleApproval, SampleDescriptor } from '../shared/sample.mjs';
type Details = Readonly<Record<string, unknown>>;
export interface WalletState {
  readonly busy: boolean;
  readonly status: (Details & { capabilities: Readonly<Record<string, boolean>>; verification?: unknown }) | null;
  readonly wallet: WalletIdentity | null;
  readonly record: Details | null;
  readonly artifact: (Details & { artifactId: string; specHash: string; wasmHash: string }) | null;
  readonly deployment: (Details & { deploymentId: string; bindingSetHash: string; policyAddress: string }) | null;
  readonly review: (Details & { approval: Approval; verification: unknown }) | null;
  readonly accountPreview: Details | null;
  readonly deployPreview: Details | null;
  readonly installation: Details | null;
  readonly receipt: unknown;
  readonly sample: SampleDescriptor | null;
  readonly samplePreview: Details | null;
  readonly sampleTransactionHash: string | null;
  readonly sampleAttempted: boolean;
}
export class WalletController {
  constructor(options: {
    request(name: string, data: unknown): Promise<unknown>;
    validators: {
      reviewIntent(input: unknown): Approval;
      validateAssembly(input: unknown): CheckedAssembly;
      reviewSample(input: unknown): SampleApproval;
      validateSampleAssembly(input: unknown): CheckedAssembly;
      validateSignedAuthorization(input: unknown): Promise<SignedAuthorization>;
    };
    sign(input: { approval: Pick<Approval, 'wallet' | 'ownerRuleId' | 'commitment'>; checked: CheckedAssembly }): Promise<string[]>;
    origin: string;
    pins: { networkId: string; accountWasm: string; verifierWasm: string };
    onChange?(state: WalletState): void;
  });
  readonly state: WalletState;
  connect(): Promise<void>;
  attachWallet(wallet: WalletIdentity): void;
  prepareAccount(credential: { credentialId: string; publicKey: string }): Promise<void>;
  confirmAccount(): Promise<void>;
  prepareSample(): Promise<void>;
  cancelSample(): void;
  approveSample(): Promise<void>;
  record(transactionHash: string): Promise<void>;
  generate(parameters: { delegateAddress: string; validUntilLedger: number; maxCalls: number; grantName: string }): Promise<void>;
  prepareDeploy(): Promise<void>;
  confirmDeploy(): Promise<void>;
  review(): Promise<void>;
  install(): Promise<void>;
}
