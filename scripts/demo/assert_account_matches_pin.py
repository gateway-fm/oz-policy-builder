#!/usr/bin/env python3
"""Fail unless the deployed account is the OpenZeppelin example this tree pins.

An assertion, not a report. The capability registry recognizes a smart account by matching
the code hash observed on chain against `ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM`;
anything else fails closed. So if the contract the demo just deployed were something else,
the synthesis that succeeds two steps later would be evidence about a different contract, and
the demo would look exactly the same. Hence a check here, before anything is built on it.

Where the observed value comes from: while recording, the toolkit asks RPC for the ledger
entry of every contract the invocation references (`getLedgerEntries`) and stores the answer
under `bundle.contract_executables`. This therefore compares *what the network says* against
*the constant this repository ships* — which makes it a live check of the pin as much as a
check of the deployment. The pin is otherwise verifiable only by rebuilding upstream at the
pinned tag with the pinned toolchain, which `scripts/verify-pinned-upstream.sh` does and no
demo can afford to do.

A mismatch exits non-zero and, under the caller's `set -e`, stops the demo. That is the
intended behaviour: a demo that printed MISMATCH and carried on would be worse than one that
never looked, because it would still end in a green "done".

Usage: assert_account_matches_pin.py <record-output.json> <account-address> <expected-hex>
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    recording, account, expected = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(recording, encoding="utf-8") as handle:
        bundle = json.load(handle)["bundle"]
    observed = bundle.get("contract_executables", {}).get(account)
    if observed is None:
        print("  ASSERTION FAILED: the recording carries no observed executable for")
        print(f"    {account}")
        print("  Nothing can be said about the account's code, so the pin is unchecked.")
        print("  Expect this if the acquisition layer stopped resolving referenced contracts.")
        return 1

    # `executable` is a tagged union: `{"wasm": {"code_hash": …}}` for a deployed Wasm
    # contract, the bare string `"stellar_asset"` for a built-in SAC. A smart account is
    # always the former; the other arm would mean this address is not an account at all.
    executable = observed["executable"]
    if not isinstance(executable, dict) or "wasm" not in executable:
        print("  ASSERTION FAILED: the authorizer is not a Wasm contract")
        print(f"    network reports: {executable!r}")
        return 1

    code_hash = executable["wasm"]["code_hash"]
    print("  account wasm   :", code_hash)
    if code_hash != expected:
        print("  ASSERTION FAILED: the deployed account is not the pinned OpenZeppelin example")
        print("    network reports:", code_hash)
        print("    this tree pins :", expected)
        print("  Synthesis would fail closed on this account; the pin or the deploy is wrong.")
        return 1
    print("  ^ matches the pinned OpenZeppelin account hash, so the registry recognizes it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
