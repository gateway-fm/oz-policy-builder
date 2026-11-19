#!/usr/bin/env python3
"""Drive the log-redaction check through mutated copies of the shipped self-hosting files.

Each case changes one setting that would make the package retain request data, a credential or
debug output, and requires the check to name it. The unmodified copies must pass, so a check that
refuses everything fails here too.
"""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
spec = importlib.util.spec_from_file_location("redaction", HERE / "check-log-redaction.py")
redaction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redaction)


class LogRedactionTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        for name in redaction.FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, target)

    def edit(self, name, old, new, count=1):
        path = self.root / name
        text = path.read_text()
        self.assertEqual(text.count(old), count, f"{name}: fixture text {old!r} moved")
        path.write_text(text.replace(old, new))

    def append(self, name, text):
        with (self.root / name).open("a") as target:
            target.write(text)

    def refused(self, pattern):
        problems = redaction.check(self.root)
        self.assertTrue(any(pattern in problem for problem in problems),
                        f"expected a problem naming {pattern!r}, got {problems}")

    def test_shipped_files_pass(self):
        self.assertEqual(redaction.check(self.root), [])

    def test_the_real_tree_passes_through_the_command_line(self):
        result = subprocess.run([sys.executable, str(HERE / "check-log-redaction.py")],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_refusal_exits_non_zero_through_the_command_line(self):
        self.edit(redaction.CADDYFILE, "output discard", "output stderr")
        result = subprocess.run([sys.executable, str(HERE / "check-log-redaction.py"),
                                 "--root", str(self.root)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("discard", result.stderr)

    # The proxy.

    def test_proxy_default_logger_writing_anywhere_is_refused(self):
        for output in ("output stderr", "output stdout", "output file /tmp/caddy/access.log"):
            with self.subTest(output=output):
                self.setUp()
                self.edit(redaction.CADDYFILE, "output discard", output)
                self.refused("discard")

    def test_proxy_without_a_discarding_default_logger_is_refused(self):
        self.edit(redaction.CADDYFILE, "\tlog default {\n\t\toutput discard\n\t}\n", "")
        self.refused("default logger")

    def test_proxy_named_logger_is_refused_unless_it_discards(self):
        self.edit(redaction.CADDYFILE, "\tauto_https off\n",
                  "\tauto_https off\n\tlog access {\n\t\toutput stdout\n\t\tlevel DEBUG\n\t}\n")
        self.refused("log access")

    def test_proxy_access_log_is_refused(self):
        for site_line in ("\tlog\n", "\tlog {\n\t\toutput stderr\n\t}\n"):
            with self.subTest(site_line=site_line):
                self.setUp()
                self.edit(redaction.CADDYFILE, "\ttls /run/tls/", site_line + "\ttls /run/tls/")
                self.refused("access log")

    def test_proxy_access_log_nested_in_a_route_is_refused(self):
        self.edit(redaction.CADDYFILE, "\t\trespond @browser 403\n", "\t\trespond @browser 403\n\t\tlog\n")
        self.refused("access log")

    def test_proxy_debug_mode_is_refused(self):
        self.edit(redaction.CADDYFILE, "\tadmin off\n", "\tadmin off\n\tdebug\n")
        self.refused("debug")

    def test_proxy_logging_credentials_is_refused(self):
        self.edit(redaction.CADDYFILE, "\t\tstrict_sni_host on\n", "\t\tstrict_sni_host on\n\t\tlog_credentials\n")
        self.refused("log_credentials")

    def test_proxy_admin_endpoint_is_refused(self):
        self.edit(redaction.CADDYFILE, "\tadmin off\n", "")
        self.refused("admin off")

    def test_proxy_imported_configuration_is_refused(self):
        self.append(redaction.CADDYFILE, "import /etc/caddy/extra.caddy\n")
        self.refused("import")

    def test_proxy_unbalanced_braces_are_refused(self):
        self.append(redaction.CADDYFILE, "}\n")
        self.refused("braces")

    # The Compose package.

    def test_compose_container_log_retention_is_refused(self):
        for service in ("api", "tls"):
            with self.subTest(service=service):
                self.setUp()
                text = (self.root / redaction.COMPOSE).read_text()
                head, _, tail = text.partition(f"\n  {service}:\n")
                tail = tail.replace("      driver: none\n", "      driver: json-file\n", 1)
                (self.root / redaction.COMPOSE).write_text(head + f"\n  {service}:\n" + tail)
                self.refused(f"service {service}")

    def test_compose_service_without_a_logging_setting_is_refused(self):
        self.edit(redaction.COMPOSE, "    logging:\n      driver: none\n", "", count=2)
        self.refused("service api")
        self.refused("service tls")

    def test_compose_added_service_is_held_to_the_same_rule(self):
        self.edit(redaction.COMPOSE, "\n  tls:\n", "\n  sidecar:\n    image: example\n  tls:\n")
        self.refused("service sidecar")

    def test_compose_flow_style_logging_is_accepted(self):
        self.edit(redaction.COMPOSE, "    logging:\n      driver: none\n", "    logging: {driver: none}\n", count=2)
        self.assertEqual(redaction.check(self.root), [])

    def test_proxy_printing_its_environment_is_refused(self):
        self.edit(redaction.COMPOSE, "    network_mode: service:api\n",
                  "    network_mode: service:api\n    command: [caddy, run, --environ, --config, /etc/caddy/Caddyfile]\n")
        self.refused("--environ")
        self.setUp()
        self.edit(redaction.DOCKERFILE, "USER 10001:10001\n\n",
                  'USER 10001:10001\nCMD ["caddy", "run", "--environ"]\n\n')
        self.refused("--environ")

    # The worker-mode package.

    def test_unit_journal_retention_is_refused(self):
        for old, new in (("StandardOutput=null", "StandardOutput=journal"),
                         ("StandardError=null", "StandardError=inherit"),
                         ("StandardError=null\n", "")):
            with self.subTest(new=new):
                self.setUp()
                self.edit(redaction.UNIT, old, new)
                self.refused(old.split("=")[0])

    def test_unit_later_override_is_refused(self):
        self.edit(redaction.UNIT, "StandardError=null\n", "StandardError=null\nStandardError=journal\n")
        self.refused("StandardError")

    def test_worker_container_log_retention_is_refused(self):
        self.edit(redaction.LAUNCHER, '"--log-driver", "none"', '"--log-driver", "journald"')
        self.refused("--log-driver")
        self.setUp()
        self.edit(redaction.LAUNCHER, ' "--log-driver", "none",', "")
        self.refused("--log-driver")

    # The API's entrypoint, which reads the bearer token and the trust files.

    def test_entrypoint_shell_tracing_is_refused(self):
        for old, new in (("set -eu", "set -eux"), ("set -eu", "set -eu\nset -o xtrace"),
                         ("#!/bin/sh", "#!/bin/sh -x"), ("set -eu", "set -x -eu")):
            with self.subTest(new=new):
                self.setUp()
                self.edit(redaction.ENTRYPOINT, old, new)
                self.refused("trac")

    def test_entrypoint_printing_a_credential_or_trust_input_is_refused(self):
        for variable in ("OZPB_HTTP_BEARER_TOKEN", "{OZPB_RPC_SOURCES_JSON}", "OZPB_REGISTRY_ROOTS_JSON"):
            with self.subTest(variable=variable):
                self.setUp()
                self.edit(redaction.ENTRYPOINT, "export OZPB_HTTP_BEARER_TOKEN\n",
                          f'export OZPB_HTTP_BEARER_TOKEN\necho "token: ${variable}" >&2\n')
                self.refused(variable.strip("{}"))

    def test_entrypoint_dumping_its_environment_is_refused(self):
        self.edit(redaction.ENTRYPOINT, "export OZPB_HTTP_BEARER_TOKEN\n", "export OZPB_HTTP_BEARER_TOKEN\nprintenv >&2\n")
        self.refused("printenv")

    def test_entrypoint_printing_the_token_any_other_way_is_refused(self):
        # Each prints the bearer token or the whole environment without a bare `printenv`, and each
        # line is one the narrower first version of this check let through.
        for line, needle in (
            ("printenv OZPB_HTTP_BEARER_TOKEN >&2", "printenv"),
            ('cat "$token_file" >&2', "token file"),
            ("export -p", "export -p"),
            ("set", "set"),
            ('echo "a|b $OZPB_HTTP_BEARER_TOKEN" >&2', "OZPB_HTTP_BEARER_TOKEN"),
            ('x=$(cat "$token_file" >&2)', "substitution prints to stderr"),
        ):
            with self.subTest(line=line):
                self.setUp()
                self.edit(redaction.ENTRYPOINT, "export OZPB_HTTP_BEARER_TOKEN\n",
                          f"export OZPB_HTTP_BEARER_TOKEN\n{line}\n")
                self.refused(needle)

    # The binaries: a log subscriber is what would make the server's own events reach stderr.

    def test_linked_log_subscriber_is_refused(self):
        for crate in ("tracing-subscriber", "env_logger", "sentry"):
            with self.subTest(crate=crate):
                self.setUp()
                self.append(redaction.LOCK, f'\n[[package]]\nname = "{crate}"\nversion = "1.0.0"\n')
                self.refused(crate)


if __name__ == "__main__":
    unittest.main()
