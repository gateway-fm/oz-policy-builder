#!/usr/bin/env python3
"""Write the account compatibility record that `ozpb synthesize --account` reads.

This file writes an input, it checks nothing. Synthesis needs to know *which* smart account
the grant is for and *what code* that account runs, and neither is something a recording can
supply on its own: they are decisions and resolutions about the account, not observations of a
transaction. So they arrive as their own document (architecture §4.1, "account compatibility
record"), and the synthesizer cross-checks it against the recording — address against
`--selected-authorizer`, code hash against what the recorder observed on chain — rather than
trusting it.

`docs/examples/account.json` is the committed illustration of the same shape and a reader can
diff the two. The demo cannot reuse it: it deploys a fresh account every run, so the address is
different every time. Two fields differ: the address, and `registry_resolution` — the committed
example fills in a release-shaped string, this one a sentence, and neither survives synthesis
(see below).

The fields:

  * `address`, `observed_code_hash` — the account just deployed and the code hash the network
    reported for it. Already asserted equal to the pinned OpenZeppelin example one step
    earlier, so this is not where that claim is made.
  * `registry_resolution` — deliberately a sentence and not an identity. The toolkit
    *overwrites* it with the entry it actually resolved out of the signed snapshot
    ("stellar-accounts@… (registry entry …)"), so nothing invented here can reach the spec.
    Written as prose to make that visible rather than as a plausible-looking release string.
Installation authority is deliberately not a caller-supplied boolean. Phase 1 resolves account
compatibility from observed code plus the signed registry; later installation checks live in the
installation flow.

Usage: write_account_record.py <out.json> <account-address> <code-hash-hex>
"""

import json
import sys


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) != 3:
        sys.exit(__doc__)
    out_path, address, observed_code_hash = arguments

    record = {
        "address": address,
        "observed_code_hash": observed_code_hash,
        "registry_resolution": "resolved by the toolkit from the signed snapshot",
    }
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
