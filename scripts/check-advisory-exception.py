#!/usr/bin/env python3
"""Bound the RUSTSEC-2026-0387 acceptance by date and dependency inventory."""
import datetime
import hashlib
import json
from pathlib import Path
import sys
import tomllib

ADVISORY = "RUSTSEC-2026-0387"
LOCKS = {"Cargo.lock", "contracts/Cargo.lock", "execution-runtime/Cargo.lock"}
SENSITIVE = {
    "crypto-bigint", "elliptic-curve", "ecdsa", "k256", "p256", "primeorder",
    "soroban-env-host",
}


def fingerprint(lock):
    """Include affected packages and every direct caller, with versions and checksums."""
    inventory = []
    for package in lock["package"]:
        dependencies = package.get("dependencies", [])
        if package["name"] in SENSITIVE or any(
            dependency.split()[0] in SENSITIVE for dependency in dependencies
        ):
            entry = dict(package)
            if "dependencies" in entry:
                entry["dependencies"] = sorted(dependencies)
            inventory.append(entry)
    inventory.sort(key=lambda entry: (entry["name"], entry["version"], entry.get("source", "")))
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def check(root, today):
    config = tomllib.loads((root / "deny.toml").read_text())
    ignores = config.get("advisories", {}).get("ignore", [])
    if not any((entry if isinstance(entry, str) else entry.get("id")) == ADVISORY
               for entry in ignores):
        return
    policy = json.loads((root / "scripts/advisory-exception.json").read_text())
    if policy["advisory"] != ADVISORY or not policy["owner"].strip():
        raise ValueError("the advisory exception needs its reviewed ID and responsible owner")
    expires = datetime.date.fromisoformat(policy["expires_utc"])
    if today >= expires:
        raise ValueError(f"{ADVISORY} exception expired at {expires} 00:00 UTC; reassess or remove it")
    if set(policy["lock_inventories"]) != LOCKS:
        raise ValueError("the advisory exception must cover all three workspace inventories")
    for name in sorted(LOCKS):
        lock = tomllib.loads((root / name).read_text())
        if fingerprint(lock) != policy["lock_inventories"][name]:
            raise ValueError(f"{name}: the reviewed crypto dependency inventory changed; reassess the exception")


if __name__ == "__main__":
    try:
        check(Path(__file__).resolve().parent.parent,
              datetime.datetime.now(datetime.timezone.utc).date())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"advisory exception refused: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("advisory exception expiry and dependency inventories OK")
