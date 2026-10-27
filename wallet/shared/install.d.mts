import type { Approval } from './approval.mjs';
import type { CheckedAssembly } from './assembly.mjs';
export const INSTALL_VALIDITY_LEDGERS: 60;
export function installConsent(input: { approval: Approval; checked: CheckedAssembly; spec: unknown; maxFeeStroops: number;
  ruleId: number }): Readonly<Record<string, unknown>>;
