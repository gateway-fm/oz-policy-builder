#!/usr/bin/env python3
"""Specifications for the captured-target tests; these are not trust receipts.

`fixture WORK` binds the synthetic native-execution rule to the source network's native asset
contract. `testnet WORK CALL_JSON` binds the same rule shape to the account, recipient, amount
and ledger of a recorded testnet capture (see target_capture_conformance.rs).
"""
import base64
import binascii
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
mode, work_arg, *rest = sys.argv[1:]
work = Path(work_arg)
subprocess.run([sys.executable, str(root / "scripts/native-execution-fixture.py"), "spec", str(work)], check=True)
spec = json.loads((work / "spec.json").read_text())
# ContractId preimage: envelope=8, network hash, from-asset=1, native asset=0.
preimage = struct.pack(">I", 8) + bytes.fromhex(spec["network_id"]) + struct.pack(">II", 1, 0)
payload = bytes([16]) + hashlib.sha256(preimage).digest()
contract = base64.b32encode(payload + struct.pack("<H", binascii.crc_hqx(payload, 0))).decode().rstrip("=")
rule = spec["rules"][0]
rule["context"]["contract"] = contract
rule["context"].pop("target_code_hash", None)
args = rule["allowed_calls"][0]["args"]
if mode == "fixture":
    args[2]["c"]["eq_i128"]["value"] = "1000000"
elif mode == "testnet":
    call = json.loads(Path(rest[0]).read_text())
    spec["smart_account"]["address"] = call["account"]
    args[1]["c"]["eq_address"]["value"] = call["recipient"]
    args[2]["c"]["eq_i128"]["value"] = call["amount"]
    # The capture ledger must fall inside the grant's validity window.
    rule["valid_until"] = {"ledger": call["observed_ledger"] + 100_000, "approx_time": None}
else:
    raise SystemExit("expected fixture or testnet")
(work / "spec.json").write_text(json.dumps(spec, separators=(",", ":")))
