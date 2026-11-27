# Audit remediation log

What happened to each finding of the external security audit of the authorization-to-install
path ([AUDIT-SCOPE.md](AUDIT-SCOPE.md)): the finding as the report states it, the commit that
fixes it, the regression test that fails without that commit, and its status. Together with the
published audit report, this log is the "published audit report + remediation" of the third
milestone ([TRANCHE-3-VERIFICATION.md](TRANCHE-3-VERIFICATION.md)).

**No audit report has been received.** This file records remediation when it arrives. Until then
there is no audited revision, no report to link and no finding below.

## How a finding is recorded

- **Finding**: the report's identifier, severity and title, as the report gives them.
- **Fix**: the commit in this repository that changes the behaviour. As for any reported defect
  ([SECURITY.md](../SECURITY.md#after-a-report), [architecture §8](architecture.md#8-testing-strategy)),
  the regression test comes first and fails before the fix.
- **Regression test**: the test's full name and the file that defines it, named as
  [MAINNET-GATES.md](MAINNET-GATES.md#how-the-evidence-blocks-are-read) names tests.
- **Status**: `fixed`; `accepted risk`, with the reason and who accepted it; `disputed`, with the
  reason; or `open`.

A finding that changes a documented claim also changes the document in the fixing commit
([CONTRIBUTING.md](../CONTRIBUTING.md#documentation)).

## Report

| Audited revision | Auditor | Report | Published |
| --- | --- | --- | --- |

## Findings

| Finding | Severity | Fix commit | Regression test | Status |
| --- | --- | --- | --- | --- |
