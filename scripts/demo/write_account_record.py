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
  * `install_rule` — the context-rule slot (`id`) and role the grant is destined to occupy on
    the account. Recorded in the spec as a decision; nothing in this milestone enforces it,
    and the generated contract does not hard-code it either — its call counter is keyed by
    whatever `(account, context rule id)` it is installed under. Honouring this is the install
    flow's job, which is the next milestone.
  * `install_safe` — the verdict that a safe install can be prepared for that slot. The
    synthesizer refuses outright when it is false, so it is a precondition and not a hint.
    True here by construction: the account was deployed seconds ago with `--policies '{}'`,
    so no rule can be displaced. Establishing it for an account a user already owns is part
    of the install flow, not of this demo.

`--install-unsafe` writes the identical record with that last verdict false, which the demo's
last step feeds to the same synthesis command in order to watch it refuse. It is a flag on this
script rather than a second script because *one boolean* being the only difference between a
policy and a refusal is the whole content of that step; two files would hide it.

Usage: write_account_record.py [--install-unsafe] <out.json> <account-address> <code-hash-hex>
"""

import json
import sys


def main() -> int:
    arguments = sys.argv[1:]
    install_safe = True
    if arguments[:1] == ["--install-unsafe"]:
        install_safe = False
        arguments = arguments[1:]
    if len(arguments) != 3:
        sys.exit(__doc__)
    out_path, address, observed_code_hash = arguments

    record = {
        "address": address,
        "observed_code_hash": observed_code_hash,
        "registry_resolution": "resolved by the toolkit from the signed snapshot",
        "install_rule": {"id": 0, "role": "admin"},
        "install_safe": install_safe,
    }
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
