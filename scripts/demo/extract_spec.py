#!/usr/bin/env python3
"""Lift the PolicySpec out of the synthesis output so codegen can take it.

Plumbing between two CLI subcommands, and nothing else. `ozpb synthesize` prints a
SynthesizeOutput — the spec plus its hash plus the rationale — while `ozpb generate --spec`
takes a PolicySpec. Handing the whole envelope over would not work even as a shortcut: every
schema type in this tree is `deny_unknown_fields`, so the extra keys are a parse error rather
than something quietly ignored.

The value is copied, not transformed. It is re-indented on the way out, which is safe
precisely because the spec hash is computed over a canonical ScVal preimage of the value and
never over these bytes — that is what lets the hash printed by summarize_synthesis.py stand
for the crate built from this file.

Usage: extract_spec.py <synthesize-output.json> <spec-out.json>
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    synthesis_path, spec_path = sys.argv[1], sys.argv[2]

    with open(synthesis_path, encoding="utf-8") as handle:
        spec = json.load(handle)["spec"]
    with open(spec_path, "w", encoding="utf-8") as handle:
        json.dump(spec, handle, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
