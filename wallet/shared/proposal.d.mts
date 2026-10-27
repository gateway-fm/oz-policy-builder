export const MAX_PROPOSAL_BYTES: number;
export interface GrantProposal {
  readonly schema: 'ozpb-grant-proposal/v1';
  readonly network_id: string;
  readonly transaction_hash: string;
  readonly spec_hash: string;
  readonly decisions: Readonly<{ grant_name: string; delegate: string; valid_until_ledger: number;
    max_calls: number; unlimited_calls_acknowledged: false }>;
  readonly expected_grant: Readonly<Record<string, unknown>>;
}
export interface ProposalReview {
  readonly agentSpecHash: string;
  readonly walletSpecHash: string;
  readonly grantsMatch: true;
  readonly hashesMatch: boolean;
}
export function parseGrantProposal(text: string, accountAddress: string): GrantProposal;
export function checkProposalSpec(proposal: GrantProposal, spec: unknown): void;
export function checkProposalArtifact(proposal: GrantProposal, artifact: unknown): ProposalReview;
