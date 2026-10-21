#!/usr/bin/env python3
"""Prepare the exact bounded native-SAC helper fixture. No network operation."""
import base64
import binascii
import hashlib
import json
from pathlib import Path
import struct
import sys

root = Path(__file__).resolve().parent.parent
work = Path(sys.argv[1])
network = bytes([77]) * 32
# HashIDPreimage(ENVELOPE_TYPE_CONTRACT_ID, network, FromAsset(Asset::Native)).
preimage = struct.pack(">i", 8) + network + struct.pack(">ii", 1, 0)
contract_hash = hashlib.sha256(preimage).digest()
body = bytes([2 << 3]) + contract_hash
target = base64.b32encode(
    body + struct.pack("<H", binascii.crc_hqx(body, 0))
).decode()
spec = json.loads((root / "docs/examples/subscription-spec.json").read_text())
spec["network_id"] = network.hex()
spec["smart_account"]["observed_code_hash"] = hashlib.sha256(
    (work / "pinned-account.wasm").read_bytes()
).hexdigest()
rule = spec["rules"][0]
rule["context"]["contract"] = target
rule["context"].pop("target_code_hash", None)  # Native SAC has no Wasm code hash.
rule["valid_until"]["ledger"] = 2000
rule["authorization"]["signers"] = [{
    "delegated": {"address": "GAMX62ZD4FWIKMWGVPEDR6WNL2TYTPQMO2ZJEAZUAON7VCZ5G2GWDF7W"}
}]
rule["allowed_calls"][0]["args"][2]["c"]["eq_i128"]["value"] = "1000000"
rule["policies"] = [p for p in rule["policies"] if "generated" in p]
assert len(rule["policies"]) == 1
(work / "spec.json").write_text(json.dumps(spec, separators=(",", ":")) + "\n")
# The same grant without a call cap: its policy exports no counter the helper could read.
rule["state"] = []
(work / "spec-uncapped.json").write_text(json.dumps(spec, separators=(",", ":")) + "\n")
