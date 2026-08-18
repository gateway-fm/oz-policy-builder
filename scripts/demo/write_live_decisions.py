#!/usr/bin/env python3
"""Copy the reviewed demo decisions and set expiry from an authenticated run's live ledger.

The template remains deterministic documentation. A live demo must not reuse its fixed ledger:
that turns a previously valid demo into an expired one without any source change.
"""

import json
import sys
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit("usage: write_live_decisions.py LATEST_RPC_JSON TEMPLATE OUTPUT")

latest = json.loads(Path(sys.argv[1]).read_text())
if latest.get("error") is not None:
    raise SystemExit(f"getLatestLedger failed: {latest['error']}")
sequence = latest.get("result", {}).get("sequence")
if not isinstance(sequence, int) or sequence < 0 or sequence > 0xFFFFFFFF:
    raise SystemExit("getLatestLedger response has no valid u32 result.sequence")

# 120,960 ledgers is about seven days at Stellar's normal five-second close time. It is long
# enough to present the demo while remaining a bounded, reviewable grant. Synthesis separately
# rejects an expiry that is not after the evidence ledger.
horizon = 120_960
if sequence > 0xFFFFFFFF - horizon:
    raise SystemExit("latest ledger is too close to u32::MAX for the demo horizon")

decisions = json.loads(Path(sys.argv[2]).read_text())
decisions["valid_until_ledger"] = sequence + horizon
Path(sys.argv[3]).write_text(json.dumps(decisions, indent=2) + "\n")
print(f"  latest ledger: {sequence}; policy expires at {sequence + horizon} (+{horizon})")
