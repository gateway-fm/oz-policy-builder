#!/usr/bin/env python3
"""Print the four facts a reader needs from a recording.

`ozpb simulate` writes a RecordOutput: the RecordingBundle, its canonical hash, the trust
level, and any notes. Most of that document is base64 XDR — unreadable on a terminal and
beside the point — so the demo shows the fields that carry the claim instead of the file.

  * **evidence trust** — how the evidence was acquired. `rpc_reported` means a live RPC
    endpoint returned it, and is as trustworthy as that endpoint. The level is derived by
    code from the acquisition path and cannot be asked for: `ozpb_domain::TrustLevel` hides
    its discriminant and mints levels only through constructors, and `ledger_verified` has
    no constructor at all in Phase 1. That is why it is worth printing — it is the one field
    a caller could otherwise have talked up.
  * **authorizer** — the address whose authorization this invocation would require. It is the
    smart account, and it is what the synthesized policy gets scoped to.
  * **recorded call** — the target contract, the function, and how many arguments it took.
    The policy will allow exactly this shape and nothing wider, so this is the shape to
    recognize again in the generated source two steps later.
  * **token movements** — transfers the recorder attributed from execution meta. Always 0 for
    a simulated recording: `simulateTransaction` returns the required authorizations and no
    meta, so there is nothing to attribute. Printed because "nothing moved" is part of the
    claim that recording needs no custody of the account.

Usage: summarize_recording.py <record-output.json>
"""

import json
import sys


def what_was_missing(problem: BaseException) -> str:
    """Name the absent thing, in the reader's terms rather than Python's."""
    if isinstance(problem, KeyError):
        return f"the recording has no {problem.args[0]!r} field"
    if isinstance(problem, IndexError):
        return "the recording lists no authorizations at all"
    return f"a field is not the type this summary expects ({problem})"


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as handle:
        output = json.load(handle)

    # Read every field first, so a shape that is not the one described above is reported as one
    # legible sentence instead of a Python traceback halfway through the summary. This is the
    # script that shows a grant's evidence: a reader has to be able to tell "the tool broke" from
    # "the evidence did not hold", and a KeyError in a stack trace tells them neither.
    try:
        bundle = output["bundle"]
        trust = output["trust"]
        # The first authorization is the one the demo built the envelope for. A transaction can
        # carry several (an ordinary G-account authorizer alongside the smart account, say),
        # which is why synthesis takes `--selected-authorizer` rather than guessing; here there
        # is one.
        authorization = bundle["authorizations"][0]
        authorizer = authorization["authorizer"]
        call = authorization["root"]["call"]["contract"]
        fn_name, contract, args = call["fn_name"], call["contract"], call["args"]
        movements = len(bundle.get("token_movements", []))
    except (KeyError, IndexError, TypeError) as problem:
        print(f"  CANNOT SUMMARIZE the recording: {what_was_missing(problem)}.")
        print(f"    file: {sys.argv[1]}")
        print("  That is not the RecordOutput shape this summary expects, so it prints nothing")
        print("  rather than half a summary. Either `ozpb simulate` returned something other")
        print("  than a recording, or the bundle schema moved and this script did not.")
        return 1

    print("  evidence trust :", trust, "(code-derived, never caller-selected)")
    print("  authorizer     :", authorizer)
    print("  recorded call  :", fn_name, "on", contract[:12] + "…", "with", len(args), "args")
    print("  token movements:", movements)
    return 0


if __name__ == "__main__":
    sys.exit(main())
