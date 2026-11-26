#!/usr/bin/env python3
"""Read docs/MAINNET-GATES.md and print what scripts/check-mainnet-gates.sh must check.

The document is the list. Its summary table carries one row per gate in architecture §10, and
each `gate-evidence` block names the tests that establish a gate. This reader refuses the
document before anything runs when a row is missing, a status is unknown, a named test is not
in the file the row cites, a release test is not required by the release gate, a CI step is
not in its workflow, or CI does not run the checker for a part the document uses. Running the
named tests, and requiring each to pass exactly once, is the shell script's job.

Output, one tab-separated line per check:
    rust     <gates> <part> <full test name> <cargo selector arguments...>
    node     <gates> <part> <file under wallet/> <name pattern> <title>
    release  <gates> <path> <full test name>
    step     <gates> <workflow> <command>
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

STATUSES = {"closed", "narrowed", "open", "review"}
RELEASE_SCRIPT = "scripts/test-pinned-account-authorization.sh"
RELEASE_WORKFLOW = ".github/workflows/nightly-live.yml"
CI_WORKFLOW = ".github/workflows/ci.yml"
CHECKER = "bash scripts/check-mainnet-gates.sh --part"
SELF_TEST = "python3 scripts/test-check-mainnet-gates.py"
GATE_HEADING = "**Acceptance gates before any mainnet use**"
RUST_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*")
ROW = re.compile(r"^\|\s*G(\d+)\s*\|")
BLOCK = re.compile(r"^```gate-evidence\s+(\S+)\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")
ENTRY = re.compile(r"^(\S+)\s+(\S+)\s+(.+?)\s*$")


class PlanError(Exception):
    pass


def architecture_gate_count(root):
    """Count the bullets of architecture §10's mainnet gate list, so a new gate needs a row."""
    lines = (root / "docs/architecture.md").read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(GATE_HEADING)]
    if len(starts) != 1:
        raise PlanError(f"docs/architecture.md: expected one '{GATE_HEADING}' list")
    count = 0
    for line in lines[starts[0] + 1:]:
        if line.startswith("**"):
            break
        if line.startswith("- "):
            count += 1
    if count == 0:
        raise PlanError("docs/architecture.md: the mainnet gate list has no entries")
    return count


def read_document(doc):
    """Return ({gate: status}, [(gate, line number, run, path, name)])."""
    statuses, entries, gate, blocks = {}, [], None, {}
    for number, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
        # A fence this reader does not recognize would drop a gate's checks without a word.
        if FENCE.match(line) and "gate-evidence" in line and not BLOCK.match(line):
            raise PlanError(f"{doc.name}:{number}: an evidence fence must read exactly "
                            f"'```gate-evidence G<n>': {line}")
        if gate is not None:
            if line.startswith("```"):
                gate = None
            elif line.strip() and not line.lstrip().startswith("#"):
                match = ENTRY.match(line.strip())
                if not match:
                    raise PlanError(f"{doc.name}:{number}: expected '<run> <path> <name>': {line}")
                entries.append((gate, number, *match.groups()))
            continue
        block = BLOCK.match(line)
        if block:
            gate = block.group(1)
            if gate in blocks:
                raise PlanError(f"{doc.name}:{number}: {gate} has a second evidence block "
                                f"(the first is at line {blocks[gate]})")
            blocks[gate] = number
            continue
        row = ROW.match(line)
        if row:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 3:
                raise PlanError(f"{doc.name}:{number}: a gate row needs a status column")
            name = f"G{row.group(1)}"
            if name in statuses:
                raise PlanError(f"{doc.name}:{number}: {name} has two rows")
            status = cells[2].strip("*").strip().lower()
            if status not in STATUSES:
                raise PlanError(f"{doc.name}:{number}: {name} status '{cells[2]}' is not one of "
                                f"{', '.join(sorted(STATUSES))}")
            statuses[name] = status
    if gate is not None:
        raise PlanError(f"{doc.name}: the evidence block for {gate} is not closed")
    for name, status in statuses.items():
        if status != "review" and name not in blocks:
            raise PlanError(f"{doc.name}: {name} is {status} but has no evidence block")
    return statuses, entries


def package(root, crate):
    """Package name and the selector for unit tests in `crate/src`."""
    manifest = tomllib.loads((root / crate / "Cargo.toml").read_text(encoding="utf-8"))
    name = manifest["package"]["name"]
    if (root / crate / "src/lib.rs").exists():
        return name, ["--lib"]
    bins = [b["name"] for b in manifest.get("bin", []) if b.get("path", "src/main.rs") == "src/main.rs"]
    return name, ["--bin", bins[0] if bins else name]


def rust_check(root, path, name, where):
    if not RUST_NAME.fullmatch(name):
        raise PlanError(f"{where}: '{name}' is not a Rust test path")
    source = (root / path).read_text(encoding="utf-8")
    if not re.search(rf"\bfn\s+{re.escape(name.rsplit('::', 1)[-1])}\s*\(", source):
        raise PlanError(f"{where}: {path} has no test function for '{name}'")


CHECK_FILE = r"""\s+(?:"[^"\n]*"|'[^'\n]*'|[^\s;&|]+)"""
LOOP_CHECK = re.compile(r'grep\s+-qx\s+"test\s+\$\{?test\}?\s+\.\.\.\s+ok"' + CHECK_FILE)
NAMED_CHECK = re.compile(r"""grep\s+-qx\s+(['"])test\s+(\w+)\s+\.\.\.\s+ok\1""" + CHECK_FILE)
LOOP = re.compile(r"^for\s+test\s+in\s+([^;\n]*);\s*do\b", re.M)
DONE = re.compile(r"(?:^|;)[ \t]*done\b([^\n]*)", re.M)
EXIT_CODE = r"(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])"
END_OF_COMMAND = r"[ \t]*(?:[;#]|$)"


def errexit_changes(text):
    """[(offset, on)] for each `set` line that turns `-e` on or off. Only an unindented line
    turns it on, since an indented one may sit in a function or subshell; any line turns it
    off."""
    changes = []
    for line in re.finditer(r"^([ \t]*)set\s+([^;\n]*)", text, flags=re.M):
        words = line.group(2).split()
        for index, word in enumerate(words):
            if word in {"-", "--"}:
                break
            if word in {"-o", "+o"}:
                on = word[0] == "-" and words[index + 1:index + 2] == ["errexit"]
                off = word[0] == "+" and words[index + 1:index + 2] == ["errexit"]
            elif re.fullmatch(r"[-+][A-Za-z]+", word) and "e" in word[1:]:
                on, off = word[0] == "-", word[0] == "+"
            else:
                continue
            if off or (on and not line.group(1)):
                changes.append((line.start(), on))
    return changes


def failure_end(text, match, errexit, end):
    """Where the failure handling of the `grep` at `match` ends, if a failed grep stops the script
    with a non-zero status; else None. That handling is `|| exit [N]`, a `|| { ... }` block
    whose last command is `exit N`, or nothing at all under `set -e`; N is 1 to 255. A block
    with `continue`, `break` or `return`, or whose `exit` is conditional, does not count, nor do
    `|| true`, `|| :`, `&&` or a pipe."""
    after = text[match.end():end]
    direct = re.match(rf"[ \t]*\|\|[ \t]*exit(?:[ \t]+{EXIT_CODE})?(?={END_OF_COMMAND})", after,
                      flags=re.M)
    if direct:
        return match.end() + direct.end()
    group = re.match(r"[ \t]*\|\|[ \t]*\{(.*?)(?:^|;)[ \t]*\}", after, flags=re.M | re.S)
    if group:
        commands = [c.strip() for c in re.split(r"[;\n]", group.group(1)) if c.strip()]
        if commands and re.fullmatch(rf"exit[ \t]+{EXIT_CODE}", commands[-1]) and \
                not any(re.match(r"(?:continue|break|return)\b", c) for c in commands):
            return match.end() + group.end()
        return None
    if errexit and re.match(r"[ \t]*(?:;[ \t]*(?!then\b|do\b)|#|$)", after, flags=re.M):
        return match.end()
    return None


def release_requirements(script):
    """{(binary, name)} for each test the release script requires by name to have passed, each
    paired with the `--test` binary the script ran last above it:
    - the names of an unindented `for test in ...; do` loop whose body is exactly
      `grep -qx "test $test ... ok" FILE` and its failure handling (see `failure_end`), the loop
      not piped or part of a list;
    - the name in an unindented `grep -qx 'test NAME ... ok' FILE` check with failure handling,
      nothing after it on its line.
    An unindented line is taken to be at the top level of the script, since the script indents
    what a function, `if` or loop holds. A name anywhere else, a comment included, requires
    nothing."""
    logical, pending = [], ""
    for line in script.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        logical.append(pending + line)
        pending = ""
    text = "\n".join(logical)
    binaries = [(m.start(), m.group(1)) for m in re.finditer(r"--test\s+(\w+)", text)]
    changes = errexit_changes(text)

    def last(pairs, offset, default):
        return next((value for start, value in reversed(pairs) if start < offset), default)

    required = set()
    for loop in LOOP.finditer(text):
        binary = last(binaries, loop.start(), None)
        done = DONE.search(text, loop.end())
        # A loop that is piped or part of a list runs where a failure does not stop the script.
        if binary is None or done is None or not re.fullmatch(r"[ \t]*(?:[;#].*)?", done.group(1)):
            continue
        body = re.compile(r"\s*").match(text, loop.end()).end()
        check = LOOP_CHECK.match(text, body, done.start())
        stop = check and failure_end(text, check, last(changes, body, False), done.start())
        if stop and re.fullmatch(r"[\s;]*", text[stop:done.start()]):
            required.update((binary, name) for name in loop.group(1).split())
    for check in NAMED_CHECK.finditer(text):
        binary = last(binaries, check.start(), None)
        if binary is None or check.start() > 0 and text[check.start() - 1] != "\n":
            continue
        stop = failure_end(text, check, last(changes, check.start(), False), len(text))
        if stop is not None and re.match(END_OF_COMMAND, text[stop:], flags=re.M):
            required.add((binary, check.group(2)))
    return required


def runs_line(text, command):
    """Whether a workflow runs `command` as a step or a line of a step's script, not a comment."""
    pattern = rf"^\s*(?:-\s*)?(?:run:\s*)?{re.escape(command)}\s*$"
    return re.search(pattern, text, flags=re.M) is not None


def wallet_titles(source):
    """The first argument of each `test(` call: literal titles, and template-literal ones as
    patterns in which each `${...}` stands for any text."""
    literals, patterns = set(), []
    for quote, body in re.findall(r"\btest\(\s*(['\"`])((?:\\.|(?!\1)[^\\])*)\1", source):
        if quote == "`" and "${" in body:
            parts = re.split(r"\$\{[^}]*\}", body)
            patterns.append(re.compile(".+".join(map(re.escape, parts))))
        else:
            literals.add(re.sub(r"\\(.)", r"\1", body))
    return literals, patterns


def wallet_title_exists(source, title):
    literals, patterns = wallet_titles(source)
    return title in literals or any(pattern.fullmatch(title) for pattern in patterns)


def plan(root, doc):
    count = architecture_gate_count(root)
    statuses, entries = read_document(doc)
    expected = [f"G{i}" for i in range(1, count + 1)]
    if list(statuses) != expected:
        raise PlanError(f"{doc.name}: architecture §10 lists {count} gates; the table must have "
                        f"rows {expected[0]}..{expected[-1]} in order, found {list(statuses)}")
    release_required = release_requirements((root / RELEASE_SCRIPT).read_text(encoding="utf-8"))
    ci = (root / CI_WORKFLOW).read_text(encoding="utf-8")

    checks, evidence_per_gate, parts = {}, {g: 0 for g in statuses}, set()
    run_in_ci = {g: 0 for g in statuses}
    for gate, number, run, path, name in entries:
        where = f"{doc.name}:{number} ({gate})"
        if gate not in statuses:
            raise PlanError(f"{where}: no table row for {gate}")
        if not (root / path).is_file():
            raise PlanError(f"{where}: {path} does not exist")
        evidence_per_gate[gate] += 1
        if run in {"ci", "ci-step"}:
            run_in_ci[gate] += 1
        if run == "ci-step":
            if not path.startswith(".github/workflows/") or \
                    not runs_line((root / path).read_text(encoding="utf-8"), name):
                raise PlanError(f"{where}: {path} does not run '{name}'")
            key = ("step", path, name)
        elif run == "release":
            match = re.fullmatch(r"contracts/differential/tests/(\w+)\.rs", path)
            if not match:
                raise PlanError(f"{where}: release tests are the pinned-account suites in "
                                f"contracts/differential/tests, not {path}")
            rust_check(root, path, name, where)
            if (match.group(1), name) not in release_required:
                raise PlanError(f"{where}: {RELEASE_SCRIPT} does not require '{name}' from "
                                f"--test {match.group(1)} to run and pass")
            key = ("release", path, name)
        elif run == "ci":
            if path.startswith("wallet/tests/") and path.endswith(".test.mjs"):
                if re.search(r"[#\\\t]", name):
                    raise PlanError(f"{where}: a wallet title with '#' or '\\' is escaped in TAP; "
                                    "name another test")
                if not wallet_title_exists((root / path).read_text(encoding="utf-8"), name):
                    raise PlanError(f"{where}: {path} has no test titled '{name}'")
                key = ("node", path, name)
                parts.add("wallet")
            else:
                crate = re.fullmatch(r"(crates/[\w-]+)/(src/[\w/]+|tests/(\w+))\.rs", path)
                contract = re.fullmatch(r"(contracts/[\w-]+)/tests/(\w+)\.rs", path)
                if not crate and not contract:
                    raise PlanError(f"{where}: {path} is not a host crate source or test file, "
                                    "a contracts test file, or a wallet test file")
                rust_check(root, path, name, where)
                key = ("rust", path, name)
                parts.add("host" if crate else "contracts")
        else:
            raise PlanError(f"{where}: run '{run}' is not ci, release or ci-step")
        checks.setdefault(key, []).append(gate)

    for gate, status in statuses.items():
        if status in {"closed", "narrowed"} and evidence_per_gate[gate] == 0:
            raise PlanError(f"{doc.name}: {gate} is {status} but names no evidence")
        if status == "closed" and run_in_ci[gate] == 0:
            raise PlanError(f"{doc.name}: {gate} is closed but nothing it names runs in CI")
    if not runs_line(ci, SELF_TEST):
        raise PlanError(f"{CI_WORKFLOW} does not run '{SELF_TEST}'")
    for part in sorted(parts):
        if not runs_line(ci, f"{CHECKER} {part}"):
            raise PlanError(f"{CI_WORKFLOW} does not run '{CHECKER} {part}'")
    if any(kind == "release" for kind, _, _ in checks):
        workflow = root / RELEASE_WORKFLOW
        if not workflow.is_file() or \
                not runs_line(workflow.read_text(encoding="utf-8"), f"bash {RELEASE_SCRIPT}"):
            raise PlanError(f"{RELEASE_WORKFLOW} does not run 'bash {RELEASE_SCRIPT}'")
    if not checks:
        raise PlanError(f"{doc.name}: names no evidence at all")

    lines = []
    for (kind, path, name), gates in checks.items():
        gates = ",".join(sorted(set(gates), key=lambda g: int(g[1:])))
        if kind == "rust":
            crate = re.fullmatch(r"(crates/[\w-]+)/(src/[\w/]+|tests/(\w+))\.rs", path)
            if crate:
                pkg, selector = package(root, crate.group(1))
                if crate.group(3):
                    selector = ["--test", crate.group(3)]
                arguments, part = ["-p", pkg, *selector], "host"
            else:
                directory, binary = re.fullmatch(r"(contracts/[\w-]+)/tests/(\w+)\.rs", path).groups()
                pkg, _ = package(root, directory)
                arguments = ["--manifest-path", "contracts/Cargo.toml", "-p", pkg, "--test", binary]
                part = "contracts"
            lines.append(["rust", gates, part, name, *arguments])
        elif kind == "node":
            pattern = "^" + re.sub(r"[\\^$.*+?()[\]{}|/]", lambda m: "\\" + m.group(0), name) + "$"
            lines.append(["node", gates, "wallet", path.removeprefix("wallet/"), pattern, name])
        elif kind == "release":
            lines.append(["release", gates, path, name])
        else:
            lines.append(["step", gates, path, name])
    return lines


def main():
    scripts = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=scripts.parent)
    parser.add_argument("--doc", type=Path)
    arguments = parser.parse_args()
    doc = arguments.doc or arguments.root / "docs/MAINNET-GATES.md"
    try:
        for line in plan(arguments.root, doc):
            print("\t".join(line))
    except (PlanError, OSError, KeyError, tomllib.TOMLDecodeError) as error:
        print(f"mainnet gates: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
