#!/usr/bin/env python3
"""Assert that synthesis rejected the deliberately unregistered account Wasm hash."""

import sys

ERROR_CODE = "E_INCOMPATIBLE_ACCOUNT"
REASON_FRAGMENTS = ("no recognized account entry", "wasm hash")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: assert_refused_for_account_hash.py CAPTURED_STDERR")
    stderr = open(sys.argv[1], encoding="utf-8").read()
    matching = [
        line.strip()
        for line in stderr.splitlines()
        if ERROR_CODE in line and all(fragment in line for fragment in REASON_FRAGMENTS)
    ]
    if not matching:
        print(f"  ASSERTION FAILED: expected the account-hash {ERROR_CODE} refusal")
        print("  A different non-zero exit does not demonstrate the check under test:")
        print("\n".join(f"    {line}" for line in stderr.splitlines()) or "    (nothing)")
        return 1
    print(f"  refused, as required : {ERROR_CODE}")
    for line in matching:
        print(f"    {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
