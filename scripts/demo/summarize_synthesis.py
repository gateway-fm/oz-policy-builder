#!/usr/bin/env python3
"""Print what the synthesized PolicySpec actually permits.

`ozpb synthesize` writes a SynthesizeOutput: the PolicySpec, its canonical hash, and the
rationale lines. This prints the parts that show the permission is minimal, because "a spec
was produced" is not the claim — "the spec permits this and nothing else" is.

  * **spec hash** — the canonical hash of the spec. Computed over a canonical ScVal preimage
    of the value, never over the JSON bytes, so it survives reformatting and is what the
    BuildManifest of the generated crate refers back to. This is the identity that ties the
    summary below to the crate compiled in the next steps.
  * **scoped to** — the one contract and the one function this rule covers. The rule's context
    is `CallContract(<that contract>)`; a `Default` rule, which would cover everything the
    account does, is never synthesized at all — minimum permission is structural here, not a
    setting.
  * **argument shape** — the comparator per argument, in order. `allowed_calls` is a
    disjunction of *complete* tuples: one constraint for every argument, never a per-index
    allowlist that would let unrelated combinations through. Three `eq_*` entries mean all
    three arguments of the recorded `transfer` are pinned to the values that were recorded.
  * **composed** — the policies this rule installs alongside, and where each comes from.
    `reviewed` is a pre-existing upstream contract resolved through the registry by exact wasm
    hash (never by a claimed name); `generated` is the crate this toolkit is about to write,
    named pre-build by its audited template family because its wasm hash does not exist yet.
  * **rationale** — the synthesizer's own account of each non-obvious decision, in its words.
    Worth reading out loud: it is where the spec says what it could *not* constrain, e.g. that
    upstream's spending limit caps the amount over a window but does not bind the recipient.

Usage: summarize_synthesis.py <synthesize-output.json>
"""

import json
import sys


def sole_key(union, what: str) -> str:
    """The one key of an externally tagged union — or a refusal to guess.

    Both things this script reads out of the spec, an argument comparator and a policy
    reference, are serde's externally tagged enums: exactly one key, whose name *is* the
    variant. Taking "the first key" of a dict that turned out to hold two would print one
    comparator out of several as if it were the shape, or one provenance as if it were the
    only one — an answer that looks right and is not. In a demo whose entire subject is
    minimum permission, that is the worst available failure, so this refuses instead.
    """
    if not isinstance(union, dict) or len(union) != 1:
        sys.exit(
            f"  CANNOT SUMMARIZE: expected {what} to be a one-key object, got {union!r}.\n"
            "  Naming one key of it would describe the spec as narrower than it is."
        )
    return next(iter(union))


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as handle:
        output = json.load(handle)

    # Rule 0 is the only rule a single recording produces, and it is the rule the demo
    # generates code for (`ozpb generate --rule 0`).
    rule = output["spec"]["rules"][0]
    call = rule["allowed_calls"][0]

    print("  spec hash      :", output["spec_hash"])
    print("  scoped to      :", rule["context"]["contract"], "->", call["fn"])
    # Each constraint is {"i": index, "c": {<comparator>: <value>}}; the comparator name is
    # what shows the shape without printing the values, which are already visible above and
    # in the generated source.
    shape = [sole_key(arg["c"], "an argument comparator") for arg in call["args"]]
    print("  argument shape :", shape)
    # A PolicyRef is an externally tagged union too, so its single key is its provenance.
    print(
        "  composed       :",
        [sole_key(policy, "a composed policy reference") for policy in rule["policies"]],
        "(reviewed = OpenZeppelin's spending limit, by hash; generated = ours)",
    )
    for line in output["rationale"]:
        print("  rationale      :", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
