#!/usr/bin/env python3
"""Fail unless synthesis refused, and refused for the reason under test.

An assertion about a *refusal*, which is why it is stricter than it looks. Step 8 of the demo
runs the synthesis of step 4 again with one field of one input flipped — `install_safe` from true
to false — and expects it to be turned down. That expectation is only evidence if the refusal is
the one being demonstrated: a mistyped flag, an unreadable file or a missing registry would also
make the command exit non-zero, and would "prove" fail-closed behaviour that was never
exercised. Any non-zero exit is not the claim; this specific refusal is.

So two things must hold in the captured stderr, and the second is the load-bearing one:

  * the error code is `E_INCOMPATIBLE_ACCOUNT`, and
  * its message is the install-safety one.

The code alone is ambiguous by design — the synthesizer raises it for an address that does not
match the selected authorizer, an observed code hash that disagrees with the account record, an
authorizer that turns out to be a Stellar Asset contract, and an account the recorder observed
no executable for. Every one of those would also be a refusal, and none of them is the one this
step changed the input to trigger. Matching the message text couples this check to
`SynthError::IncompatibleAccount`'s wording on purpose: if that wording changes, this fails and
someone re-reads what the demo is claiming, which is the correct outcome.

Usage: assert_refused_for_install_safety.py <captured-stderr-file>
"""

import sys

ERROR_CODE = "E_INCOMPATIBLE_ACCOUNT"
# From `SynthError::IncompatibleAccount` in crates/synthesizer/src/lib.rs, raised when the
# account compatibility record's `install_safe` verdict is false.
REASON = "installation authority surface is unsafe"


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as handle:
        stderr = handle.read()

    coded = [line.strip() for line in stderr.splitlines() if ERROR_CODE in line]
    reasons = [line for line in coded if REASON in line]

    if not coded:
        print(f"  ASSERTION FAILED: synthesis did not refuse with {ERROR_CODE}")
        print("  It failed, but not in the way this step demonstrates, so the run proves nothing")
        print("  about fail-closed behaviour. What it printed:")
        print("\n".join(f"    {line}" for line in stderr.splitlines()) or "    (nothing)")
        return 1

    if not reasons:
        print(f"  ASSERTION FAILED: {ERROR_CODE} was raised for a different reason")
        print(f"  This step flips `install_safe`, so the message should name the {REASON!r}")
        print("  condition. Refusing over something else means the demonstration missed:")
        print("\n".join(f"    {line}" for line in coded))
        return 1

    print(f"  refused, as required : {ERROR_CODE}")
    for line in reasons:
        print(f"    {line}")
    print("  ^ the refusal is the result here, not a fault: a toolkit that writes a policy for")
    print("    an account whose installation surface it cannot vouch for has no fail-closed")
    print("    property left to demonstrate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
