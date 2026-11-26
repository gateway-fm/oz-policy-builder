#!/usr/bin/env python3
"""Focused checks for the retention checker's envelope, path selection and search."""

import base64
import importlib.util
import io
import json
import tarfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check_hosted_retention", HERE / "check-hosted-retention.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

UNSIGNED = json.loads((HERE.parent / "docs/examples/import-bundle.json").read_text())["envelope_xdr_base64"]


class SignedEnvelopeTest(unittest.TestCase):
    def test_one_decorated_signature_replaces_the_empty_array(self):
        hint, signature = b"\x01\x02\x03\x04", bytes(range(64))
        signed = base64.b64decode(CHECKER.signed_envelope(UNSIGNED, hint, signature))
        unsigned = base64.b64decode(UNSIGNED)
        self.assertEqual(signed[:-76], unsigned[:-4])
        self.assertEqual(signed[-76:], (1).to_bytes(4, "big") + hint + (64).to_bytes(4, "big") + signature)

    def test_a_signed_or_other_envelope_is_refused(self):
        signed = CHECKER.signed_envelope(UNSIGNED, b"hint", bytes(range(64)))
        with self.assertRaises(ValueError):
            CHECKER.signed_envelope(signed, bytes(4), bytes(64))
        other_type = base64.b64encode((5).to_bytes(4, "big") + base64.b64decode(UNSIGNED)[4:]).decode()
        with self.assertRaises(ValueError):
            CHECKER.signed_envelope(other_type, bytes(4), bytes(64))


class PathsToReadTest(unittest.TestCase):
    MOUNTS = ["/run/ozpb/bearer-token", "/tmp/ozpb", "/var/cache/ozpb"]

    def test_mounts_their_contents_and_the_directories_holding_them_are_not_read(self):
        diff = "\n".join(["C /run", "C /run/ozpb", "A /run/ozpb/bearer-token", "A /tmp/ozpb",
                          "A /tmp/ozpb/x", "C /var", "C /var/cache"])
        self.assertEqual(CHECKER.paths_to_read(diff, self.MOUNTS), [])

    def test_any_other_added_or_changed_path_is_read_and_a_deleted_one_is_not(self):
        diff = "\n".join(["A /tmp/request.json", "C /etc/passwd", "D /opt/ozpb/gone", "A /run/ozpb-other",
                          "C /var/log"])
        self.assertEqual(CHECKER.paths_to_read(diff, self.MOUNTS),
                         ["/tmp/request.json", "/etc/passwd", "/run/ozpb-other", "/var/log"])

    def test_a_directory_is_read_through_its_listed_entries_not_whole(self):
        diff = "\n".join(["C /usr", "C /usr/sbin", "A /usr/sbin/docker-init", "C /opt", "D /opt/gone",
                          "A /srv/empty"])
        self.assertEqual(CHECKER.paths_to_read(diff, self.MOUNTS), ["/usr/sbin/docker-init", "/srv/empty"])


class OutputTest(unittest.TestCase):
    STARTUP = CHECKER.STARTUP_LINE + b"http://127.0.0.1:8080/v1/mcp\n"

    def test_the_startup_line_alone_and_a_silent_proxy_pass(self):
        self.assertIsNone(CHECKER.output_problem("api", b"", self.STARTUP))
        self.assertIsNone(CHECKER.output_problem("proxy", b"", b""))

    def test_any_other_output_fails_even_without_a_canary(self):
        self.assertIsNotNone(CHECKER.output_problem("api", b"", b""))
        self.assertIsNotNone(CHECKER.output_problem("api", b"", self.STARTUP + b"tools/call generate_code\n"))
        self.assertIsNotNone(CHECKER.output_problem("api", b"", self.STARTUP.rstrip(b"\n") + b" session 7"))
        self.assertIsNotNone(CHECKER.output_problem("api", b"request\n", self.STARTUP))
        self.assertIsNotNone(CHECKER.output_problem("proxy", b"", b"POST /v1/mcp 401\n"))
        self.assertIsNotNone(CHECKER.output_problem("proxy", b"banner\n", b""))


class SearchTest(unittest.TestCase):
    NEEDLES = {"token": b"secret-token", "signature": b"\x00\xffraw"}

    def archive(self, files):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            for name, content in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        data.seek(0)
        return data

    def test_contents_and_names_are_searched_and_printed_paths_are_redacted(self):
        findings = []
        count = CHECKER.scan_tar(self.archive({
            "tmp/clean": b"nothing here",
            "tmp/log": b"prefix secret-token suffix",
            "tmp/raw": b"\x10\x00\xffraw\x10",
            "tmp/secret-token.txt": b"",
        }), self.NEEDLES, "api tmpfs", findings)
        self.assertEqual(count, 4)
        self.assertIn(("token", "api tmpfs: /tmp/log"), findings)
        self.assertIn(("signature", "api tmpfs: /tmp/raw"), findings)
        self.assertIn(("token", "api tmpfs: a file name"), findings)
        self.assertNotIn("secret-token", "".join(where for _, where in findings))

    def test_a_clean_archive_has_no_finding(self):
        findings = []
        CHECKER.scan_tar(self.archive({"tmp/a": b"a", "tmp/b": b"b"}), self.NEEDLES, "proxy tmpfs", findings)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
