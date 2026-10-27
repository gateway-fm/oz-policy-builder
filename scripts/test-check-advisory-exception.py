#!/usr/bin/env python3
"""Exercise the exception boundary without fetching crates or compiling Rust."""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("guard", Path(__file__).with_name("check-advisory-exception.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
TODAY = datetime.date(2026, 10, 27)


class ExceptionTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        (self.root / "scripts").mkdir()
        (self.root / "deny.toml").write_text('[advisories]\nignore = [{id = "' + guard.ADVISORY + '"}]\n')
        self.packages = [
            {"name": "crypto-bigint", "version": "0.5.5", "checksum": "reviewed", "dependencies": []},
            {"name": "elliptic-curve", "version": "0.13.8", "dependencies": ["crypto-bigint"]},
        ]
        self.policy = {"advisory": guard.ADVISORY, "owner": "reviewing maintainer",
                       "expires_utc": "2026-11-10", "lock_inventories": {}}
        for name in guard.LOCKS:
            packages = [] if name == "Cargo.lock" else self.packages
            self.write_lock(name, packages)
            self.policy["lock_inventories"][name] = guard.fingerprint({"package": packages})
        self.write_policy()

    def write_lock(self, name, packages):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('version = 4\n' + ('package = []\n' if not packages else '') + ''.join(
            '\n[[package]]\n' + ''.join(f'{key} = {json.dumps(value)}\n' for key, value in package.items())
            for package in packages))

    def write_policy(self):
        (self.root / "scripts/advisory-exception.json").write_text(json.dumps(self.policy))

    def test_reviewed_inventory_before_expiry_passes(self):
        guard.check(self.root, TODAY)

    def test_expiry_day_and_later_fail(self):
        for day in (datetime.date(2026, 11, 10), datetime.date(2026, 11, 11)):
            with self.subTest(day=day), self.assertRaisesRegex(ValueError, "expired"):
                guard.check(self.root, day)

    def test_omitted_workspace_fails(self):
        del self.policy["lock_inventories"]["Cargo.lock"]
        self.write_policy()
        with self.assertRaisesRegex(ValueError, "all three"):
            guard.check(self.root, TODAY)

    def test_new_root_dependency_fails(self):
        self.write_lock("Cargo.lock", self.packages)
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            guard.check(self.root, TODAY)

    def test_changed_version_checksum_or_caller_fails(self):
        for mutation in ("version", "checksum", "caller"):
            packages = json.loads(json.dumps(self.packages))
            if mutation == "caller":
                packages.append({"name": "new-signer", "version": "1.0.0", "dependencies": ["crypto-bigint"]})
            else:
                packages[0][mutation] = "different"
            self.write_lock("contracts/Cargo.lock", packages)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "inventory changed"):
                guard.check(self.root, TODAY)

    def test_missing_policy_fails(self):
        (self.root / "scripts/advisory-exception.json").unlink()
        with self.assertRaises(OSError):
            guard.check(self.root, TODAY)

    def test_wrong_id_or_missing_owner_fails(self):
        for key in ("advisory", "owner"):
            original = self.policy[key]
            self.policy[key] = ""
            self.write_policy()
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.check(self.root, TODAY)
            self.policy[key] = original

    def test_removing_exception_restores_normal_audit_without_guard(self):
        (self.root / "deny.toml").write_text('[advisories]\nignore = []\n')
        (self.root / "scripts/advisory-exception.json").unlink()
        guard.check(self.root, datetime.date(2030, 1, 1))

    def run_gate(self):
        source = Path(__file__).parent
        for name in ("check-licenses.sh", "check-advisory-exception.py"):
            shutil.copyfile(source / name, self.root / "scripts" / name)
        binaries = self.root / "bin"
        binaries.mkdir()
        cargo = binaries / "cargo"
        cargo.write_text('''#!/bin/sh
if [ "$*" = "deny --version" ]; then
    echo 'cargo-deny 0.20.2'
    exit 0
fi
found=0
for arg do
    if [ "$arg" = "--locked" ]; then found=1; fi
done
if [ "$found" != 1 ]; then
    echo 'missing --locked: metadata could change the reviewed graph' >&2
    exit 91
fi
printf '%s\\n' "$*" >> "$OZPB_TEST_CARGO_LOG"
''')
        cargo.chmod(0o755)
        (binaries / "cargo-deny").symlink_to(cargo)
        return subprocess.run(["/bin/bash", str(self.root / "scripts/check-licenses.sh")],
                              env={**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                                   "OZPB_TEST_CARGO_LOG": str(self.root / "cargo.log")},
                              capture_output=True, text=True)

    def test_gate_refuses_expiry_before_running_cargo(self):
        self.policy["expires_utc"] = "2000-01-01"
        self.write_policy()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exception expired", result.stderr)
        self.assertFalse((self.root / "cargo.log").exists())

    def test_all_six_audits_forbid_lockfile_updates(self):
        self.policy["expires_utc"] = str(datetime.datetime.now(datetime.timezone.utc).date()
                                         + datetime.timedelta(days=1))
        self.write_policy()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len((self.root / "cargo.log").read_text().splitlines()), 6)


if __name__ == "__main__":
    unittest.main()
