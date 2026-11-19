#!/usr/bin/env python3
"""Refuse a self-hosting package that would retain request data, a credential or debug output.

The shipped package keeps confidential input out of logs by not retaining any: the proxy's
loggers discard, the containers and the systemd unit drop their output, and nothing prints the
bearer token or the trust inputs. This reads those settings in the files the package ships and
fails on any that would turn a log back on. It reads configuration only; it does not run the
endpoint, and it does not read the server's own Rust log statements, which are reviewed.
"""
import argparse
import ast
from pathlib import Path
import re
import sys
import tomllib

CADDYFILE = "deployment/Caddyfile"
COMPOSE = "deployment/compose.yaml"
UNIT = "deployment/ozpb-api.service"
ENTRYPOINT = "deployment/entrypoint.sh"
LAUNCHER = "deployment/worker-launcher.py"
DOCKERFILE = "deployment/Dockerfile"
LOCK = "Cargo.lock"
FILES = (CADDYFILE, COMPOSE, UNIT, ENTRYPOINT, LAUNCHER, DOCKERFILE, LOCK)

# What the entrypoint holds in its environment: the credential and the trust inputs, whose RPC
# URLs can carry a provider key in their query strings.
SECRET_VARIABLES = ("OZPB_HTTP_BEARER_TOKEN", "OZPB_REGISTRY_ROOTS_JSON",
                    "OZPB_REGISTRY_SNAPSHOT_JSON", "OZPB_RPC_SOURCES_JSON")

# Crates that install a log or trace subscriber, or upload crashes or telemetry. None is linked
# today, so the server's dependencies' log events go nowhere; adding one needs a review against
# what those events carry, and this list then needs the reviewed crate's exception.
LOG_SINK_CRATES = {
    "env_logger", "fern", "flexi_logger", "log4rs", "opentelemetry", "pretty_env_logger",
    "sentry", "simple_logger", "simplelog", "slog-async", "slog-term", "stderrlog", "syslog",
    "systemd-journal-logger", "tracing-appender", "tracing-journald", "tracing-subscriber",
}


def caddy_directives(text):
    """Yield (enclosing block headers, tokens) for each directive line of a Caddyfile."""
    stack, entries = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        tokens = []
        for token in raw.split():
            if token.startswith("#"):
                break
            tokens.append(token)
        if not tokens:
            continue
        if tokens == ["}"]:
            if not stack:
                raise ValueError(f"{CADDYFILE}:{number}: unbalanced braces")
            stack.pop()
            continue
        if "{" in tokens[:-1] or "}" in tokens:
            raise ValueError(f"{CADDYFILE}:{number}: braces this check cannot read")
        opens = tokens[-1] == "{"
        directive = tuple(tokens[:-1] if opens else tokens)
        entries.append((tuple(stack), directive))
        if opens:
            stack.append(directive)
    if stack:
        raise ValueError(f"{CADDYFILE}: unbalanced braces")
    return entries


def check_caddyfile(text):
    problems = []
    try:
        entries = caddy_directives(text)
    except ValueError as error:
        return [str(error)]
    if not entries or entries[0] != ((), ()):
        return [f"{CADDYFILE}: no global options block; the default logger writes to stderr"]
    global_options = [(stack, d) for stack, d in entries if stack[:1] == ((),)]
    sites = [(stack, d) for stack, d in entries if stack[:1] != ((),) and stack]
    for stack, directive in entries:
        if directive[:1] == ("import",):
            problems.append(f"{CADDYFILE}: import pulls in configuration this check does not read")
        if directive[:1] == ("log_credentials",):
            problems.append(f"{CADDYFILE}: log_credentials writes Authorization headers into logs")
    if ((), ("admin", "off")) not in [(s[1:], d) for s, d in global_options]:
        problems.append(f"{CADDYFILE}: no 'admin off'; the admin endpoint can load a config that logs")
    loggers = {}
    for stack, directive in global_options:
        if len(stack) == 1 and directive[:1] == ("debug",):
            problems.append(f"{CADDYFILE}: debug enables debug-level logging of every request")
        if len(stack) == 1 and directive[:1] == ("log",):
            name = directive[1] if len(directive) > 1 else "default"
            outputs = [d for s, d in global_options if s == ((), directive) and d[:1] == ("output",)]
            loggers[name] = bool(outputs) and all(d == ("output", "discard") for d in outputs)
    if "default" not in loggers:
        problems.append(f"{CADDYFILE}: no default logger set to discard; Caddy's writes to stderr")
    for name, discards in sorted(loggers.items()):
        if not discards:
            problems.append(f"{CADDYFILE}: global 'log {name}' must have exactly 'output discard'")
    for stack, directive in sites:
        if directive[:1] == ("log",):
            problems.append(f"{CADDYFILE}: 'log' in site '{' '.join(stack[0])}' enables an access log")
    return problems


def yaml_tree(text):
    """Nest a block-style YAML file by indentation: [(text, children)]. Enough for Compose keys."""
    root = []
    stack = [(-1, root)]
    for raw in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        while stack[-1][0] >= indent:
            stack.pop()
        node = (line.strip(), [])
        stack[-1][1].append(node)
        stack.append((indent, node[1]))
    return root


def check_compose(text):
    problems = []
    services = [children for key, children in yaml_tree(text) if key == "services:"]
    if len(services) != 1:
        return [f"{COMPOSE}: no services mapping"]
    for key, children in services[0]:
        name = key.rstrip(":")
        settings = [(k, c) for k, c in children if k.split(":", 1)[0] == "logging"]
        flow = len(settings) == 1 and re.fullmatch(r'logging:\s*\{\s*driver:\s*"?none"?\s*\}', settings[0][0])
        block = len(settings) == 1 and settings[0][0] == "logging:" and [
            k for k, _ in settings[0][1] if k.startswith("driver:")] in (
            ["driver: none"], ['driver: "none"'], ["driver: 'none'"])
        if not (flow or block):
            problems.append(f"{COMPOSE}: service {name} must set logging driver none; "
                            "any other driver retains its output")
    return problems


def check_environ(name, text):
    for line in text.splitlines():
        if not line.lstrip().startswith("#") and "--environ" in line:
            return [f"{name}: --environ prints the proxy's environment at startup"]
    return []


def check_unit(text):
    problems = []
    for key in ("StandardOutput", "StandardError"):
        values = re.findall(rf"^\s*{key}\s*=\s*(.*?)\s*$", text, re.MULTILINE)
        if not values or any(value != "null" for value in values):
            problems.append(f"{UNIT}: {key} must be null; the journal would retain the API's output")
    return problems


def check_launcher(text):
    drivers = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.List, ast.Tuple)):
            values = [e.value if isinstance(e, ast.Constant) else None for e in node.elts]
            for index, value in enumerate(values):
                if value == "--log-driver":
                    drivers.append(values[index + 1] if index + 1 < len(values) else None)
                elif isinstance(value, str) and value.startswith("--log-driver="):
                    drivers.append(value.split("=", 1)[1])
    if not drivers or any(driver != "none" for driver in drivers):
        return [f"{LAUNCHER}: the worker container must run with --log-driver none"]
    return []


def check_entrypoint(text):
    problems = []
    lines = text.splitlines()
    if lines and lines[0].startswith("#!") and re.search(r"\s-[A-Za-z]*x", lines[0]):
        problems.append(f"{ENTRYPOINT}: shell tracing in the interpreter line prints the bearer token")
    for line in lines[1:]:
        code = re.sub(r"(^|\s)#.*$", "", line)
        if re.search(r"\bset\b[^;&|]*?(\s-[A-Za-z]*x|\s-o\s+xtrace\b)", code):
            problems.append(f"{ENTRYPOINT}: shell tracing prints the bearer token as it is read")
        # A command substitution's output is captured, not printed: `$(cat "$token_file")` is how
        # the script reads the token. Everything else on the line reaches stdout or stderr.
        shown = re.sub(r"\$\([^()]*\)", "", code)
        # …unless the substitution sends its output to stderr, which is printed after all.
        inners = re.findall(r"\$\(([^()]*)\)", code)
        if any(re.search(r">&2|>\s*/dev/stderr", inner) for inner in inners):
            problems.append(f"{ENTRYPOINT}: a command substitution prints to stderr")
        start = r"(^|[;&|]\s*)\s*"
        if re.search(start + r"printenv\b", shown) or re.search(start + r"env\s*($|[;&|>])", shown):
            problems.append(f"{ENTRYPOINT}: printenv/env prints the bearer token and trust inputs")
        if re.search(r"\bexport\s+-p\b", shown) or re.search(start + r"set\s*($|[;&|>])", shown):
            problems.append(f"{ENTRYPOINT}: export -p / set prints the bearer token and trust inputs")
        if re.search(r"\bcat\b[^;&|]*(\$\{?token_file\b|bearer-token)", shown):
            problems.append(f"{ENTRYPOINT}: cat of the token file prints the bearer token")
        # To the end of the line: a `|` inside a quoted string must not end the printed text.
        for command in re.findall(r"\b(?:echo|printf)\b.*", shown):
            for variable in SECRET_VARIABLES:
                if re.search(rf"\$\{{?{variable}\b", command):
                    problems.append(f"{ENTRYPOINT}: prints {variable}")
    return problems


def check_lock(text):
    linked = {package["name"] for package in tomllib.loads(text).get("package", [])}
    return [f"{LOCK}: links {crate}, a log or telemetry sink; review what the server's events "
            "carry before linking one" for crate in sorted(linked & LOG_SINK_CRATES)]


def check(root):
    root = Path(root)
    read = {name: (root / name).read_text() for name in FILES}
    return (check_caddyfile(read[CADDYFILE]) + check_compose(read[COMPOSE])
            + check_environ(COMPOSE, read[COMPOSE]) + check_environ(DOCKERFILE, read[DOCKERFILE])
            + check_unit(read[UNIT]) + check_launcher(read[LAUNCHER])
            + check_entrypoint(read[ENTRYPOINT]) + check_lock(read[LOCK]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        problems = check(args.root)
    except (OSError, SyntaxError, tomllib.TOMLDecodeError) as error:
        problems = [f"cannot read the package: {error}"]
    for problem in problems:
        print(f"log redaction refused: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("log redaction: every shipped log sink discards; no credential or trust input is printed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
