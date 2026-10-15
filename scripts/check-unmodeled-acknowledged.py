#!/usr/bin/env python3
"""Check a local reference-suite report and its exact coverage acknowledgements.

Usage:
  check-unmodeled-acknowledged.py --run <ack-file> <spec-name>=<spec-path>...
  reference-suite-json | check-unmodeled-acknowledged.py <spec-name> <ack-file>
  check-unmodeled-acknowledged.py --known-specs <ack-file> <spec-name>...

Use --run for a complete gate: it executes and checks every declared spec. The stdin
and --known-specs modes are lower-level report inspection helpers, not a complete gate.
An acknowledgement documents a layer-1 limitation; it does not test that
policy or turn reference agreement into evidence of on-chain behavior. This checks
locally generated report consistency, not the authenticity of imported evidence.
"""

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


def entries(path: str) -> list[tuple[str, str]]:
    rows = []
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9_-]+", parts[0]):
                raise ValueError(f"{path}:{number}: expected '<spec>|rule[<index>]: <kind>'")
            name, entry = parts
            if not re.fullmatch(r"rule\[(0|[1-9][0-9]*)\]: [^\s|]+", entry):
                raise ValueError(f"{path}:{number}: malformed policy entry {entry!r}")
            # Repeated kinds are valid: one acknowledgement per policy instance.
            rows.append((name, entry))
    return rows


def unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def string_list(report: dict, key: str, unique=True) -> list[str]:
    value = report.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{key} must be an array of nonempty strings")
    if unique and len(value) != len(set(value)):
        raise ValueError(f"{key} contains duplicate entries")
    return value


def class_name(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", value):
        raise ValueError("invalid evidence mutation class")
    return value


def class_label(rule: int, kind: str) -> str:
    return f"rule[{rule}]: {''.join(part.capitalize() for part in kind.split('_'))}"


def rule_index(value: object, rules: dict) -> int:
    if type(value) is not int or value < 0 or str(value) not in rules:
        raise ValueError("evidence references an undeclared or invalid rule_index")
    return value


def coverage_counts(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("evidence coverage must map classes to positive counts")
    for kind, count in value.items():
        class_name(kind)
        if type(count) is not int or count <= 0:
            raise ValueError("evidence coverage must contain positive integer counts")
    return value


def spec_requirements(path: Path) -> tuple[set[str], Counter]:
    """Read only the input shape needed to catch whole-rule or policy omissions.

    The CLI still performs full PolicySpec validation. Unknown policy variants fail
    here rather than silently disappearing from this gate's reviewed-policy list.
    """
    with path.open(encoding="utf-8") as handle:
        spec = json.load(handle, object_pairs_hook=unique_object)
    rules = spec.get("rules") if isinstance(spec, dict) else None
    if not isinstance(rules, list) or not rules:
        raise ValueError("input spec must contain a nonempty rules array")
    policies = Counter()
    for index, rule in enumerate(rules):
        refs = rule.get("policies") if isinstance(rule, dict) else None
        if not isinstance(refs, list):
            raise ValueError("input spec rule must contain a policies array")
        for ref in refs:
            if not isinstance(ref, dict) or len(ref) != 1 or next(iter(ref)) not in ("reviewed", "generated"):
                raise ValueError("input spec contains an unsupported policy variant")
            variant, details = next(iter(ref.items()))
            if not isinstance(details, dict):
                raise ValueError("input spec policy must be an object")
            if variant == "reviewed":
                kind = details.get("kind")
                if not isinstance(kind, str) or not re.fullmatch(r"[^\s|]+", kind):
                    raise ValueError("input spec reviewed policy has an invalid kind")
                policies[f"rule[{index}]: {kind}"] += 1
    return {str(index) for index in range(len(rules))}, policies


def check_report(report: object, requirements=None) -> Counter:
    if not isinstance(report, dict):
        raise ValueError("reference-suite output must be a JSON object")
    if report.get("all_agree") is not True:
        raise ValueError("reference suite does not report all_agree: true")
    total = report.get("total")
    if type(total) is not int or total <= 0:
        raise ValueError("reference suite must exercise a positive number of cases")
    if type(report.get("disagreements")) is not int or report["disagreements"] != 0:
        raise ValueError("reference suite must report zero disagreements")
    missing = set(string_list(report, "missing_classes"))
    unmodeled = Counter(string_list(report, "unmodeled_reviewed_policies", unique=False))
    permit_only = set(string_list(report, "permit_only_classes"))

    evidence = report.get("report")
    if not isinstance(evidence, dict) or evidence.get("layer") != "layer1-reference-evaluator":
        raise ValueError("expected labeled layer1-reference-evaluator evidence")
    outcomes = evidence.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != total:
        raise ValueError("reported case count differs from the evidence outcomes")
    for key, expected in [("total", total), ("agreements", total), ("disagreements", 0)]:
        if type(evidence.get(key)) is not int or evidence[key] != expected:
            raise ValueError(f"evidence {key} contradicts the summary/outcomes")
    rules = evidence.get("expected_classes")
    if not isinstance(rules, dict) or not rules:
        raise ValueError("expected_classes must declare a nonempty set of rules")
    if requirements is not None and set(rules) != requirements[0]:
        raise ValueError("evidence rule set differs from the input spec")
    for rule, classes in rules.items():
        if not re.fullmatch(r"0|[1-9][0-9]*", rule):
            raise ValueError("expected_classes has an invalid rule index")
        for kind in string_list({"classes": classes}, "classes"):
            class_name(kind)
        if not classes:
            raise ValueError("expected_classes must declare required classes for every rule")

    coverage = Counter()
    by_rule = {rule: Counter() for rule in rules}
    original_rules, denial_rules, denial_classes = set(), set(), set()
    for outcome in outcomes:
        if not isinstance(outcome, dict) or outcome.get("agree") is not True:
            raise ValueError("evidence contains a missing or disagreeing outcome")
        expected, actual = outcome.get("expected"), outcome.get("actual")
        if not ((expected == "permit" and actual == "permit") or
                (expected == "deny" and isinstance(actual, str) and
                 re.fullmatch(r"deny\([A-Za-z][A-Za-z0-9_]*\)", actual))):
            raise ValueError("evidence outcome contradicts its expected verdict")
        rule = rule_index(outcome.get("rule_index"), rules)
        kind = class_name(outcome.get("class"))
        coverage[kind] += 1
        by_rule[str(rule)][kind] += 1
        if kind == "original" and actual == "permit":
            original_rules.add(rule)
        if expected == "deny":
            denial_rules.add(rule)
            denial_classes.add((rule, kind))
    for rule in rules:
        if int(rule) not in original_rules:
            raise ValueError(f"rule[{rule}] has no passing original control")
        if int(rule) not in denial_rules:
            raise ValueError(f"rule[{rule}] has no passing denial control")

    computed_missing = {class_label(int(rule), kind) for rule, classes in rules.items()
                        for kind in classes if kind not in by_rule[rule]}
    if missing != computed_missing:
        raise ValueError(f"missing_classes contradicts evidence: expected {sorted(computed_missing)}")
    if computed_missing:
        raise ValueError(f"reference suite is missing required boundary classes: {sorted(computed_missing)}")
    computed_permit_only = {class_label(int(rule), kind) for rule, classes in by_rule.items()
                           for kind in classes if kind != "original" and (int(rule), kind) not in denial_classes}
    if permit_only != computed_permit_only:
        raise ValueError(f"permit_only_classes contradicts evidence: expected {sorted(computed_permit_only)}")
    if permit_only:
        print(f"  permit-only classes (no denial demonstrated): {sorted(permit_only)}")

    declared_by_rule = evidence.get("coverage_by_rule")
    if not isinstance(declared_by_rule, dict) or set(declared_by_rule) != set(rules):
        raise ValueError("coverage_by_rule does not cover the declared rules")
    if {rule: coverage_counts(counts) for rule, counts in declared_by_rule.items()} != by_rule:
        raise ValueError("coverage_by_rule contradicts evidence outcomes")
    pairs = evidence.get("coverage")
    if not isinstance(pairs, list) or any(not isinstance(pair, list) or len(pair) != 2 for pair in pairs):
        raise ValueError("evidence coverage must be an array of class/count pairs")
    declared_coverage = {}
    for kind, count in pairs:
        kind = class_name(kind)
        if kind in declared_coverage:
            raise ValueError("evidence coverage contains duplicate classes")
        declared_coverage[kind] = count
    if coverage_counts(declared_coverage) != coverage:
        raise ValueError("evidence coverage contradicts outcomes")
    summary_coverage = {f"{''.join(part.capitalize() for part in kind.split('_'))}: {count}"
                        for kind, count in coverage.items()}
    if set(string_list(report, "coverage")) != summary_coverage:
        raise ValueError("summary coverage contradicts evidence outcomes")

    policies = evidence.get("unmodeled_policies")
    if not isinstance(policies, list):
        raise ValueError("unmodeled_policies must be an array")
    computed_unmodeled = Counter()
    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("unmodeled_policies must contain policy objects")
        rule = rule_index(policy.get("rule_index"), rules)
        kind = policy.get("kind")
        if not isinstance(kind, str) or not re.fullmatch(r"[^\s|]+", kind):
            raise ValueError("unmodeled_policies contains an invalid kind")
        computed_unmodeled[f"rule[{rule}]: {kind}"] += 1
    if unmodeled != computed_unmodeled:
        raise ValueError("unmodeled_reviewed_policies contradicts evidence unmodeled_policies")
    if requirements is not None and computed_unmodeled != requirements[1]:
        raise ValueError("evidence reviewed-policy counts differ from the input spec")
    return unmodeled


def check_acknowledgements(spec: str, rows: list, report: object, requirements=None) -> None:
    acknowledged = Counter(entry for name, entry in rows if name == spec)
    reported = check_report(report, requirements)
    unacknowledged = sorted((reported - acknowledged).elements())
    stale = sorted((acknowledged - reported).elements())
    if unacknowledged or stale:
        raise ValueError(
            f"{spec}: unacknowledged policies={unacknowledged}; stale acknowledgements={stale}"
        )
    print(f"{spec}: layer-1 agreement and coverage checks passed; "
          f"{sum(reported.values())} reviewed policy gap(s) explicitly acknowledged")
    for policy in sorted(reported.elements()):
        print(f"  NOT MODELED BY LAYER 1: {policy}")


def check_names(rows: list, names: list) -> None:
    if len(names) != len(set(names)) or any(not re.fullmatch(r"[A-Za-z0-9_-]+", name) for name in names):
        raise ValueError("checked spec names must be unique, nonempty identifiers")
    unknown = sorted({name for name, _ in rows} - set(names))
    if unknown:
        raise ValueError(f"acknowledgements name unchecked specs: {unknown}")


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] in ("--run", "--known-specs"):
        if len(sys.argv) < 4:
            raise ValueError(__doc__)
        mode, ack_file, *arguments = sys.argv[1:]
        rows = entries(ack_file)
        if mode == "--known-specs":
            check_names(rows, arguments)
            print(f"acknowledgements name only declared specs ({len(arguments)}); reports not checked")
            return 0
        specs = [argument.partition("=") for argument in arguments]
        if any(not separator or not path for _, separator, path in specs):
            raise ValueError("--run expects <spec-name>=<spec-path> pairs")
        check_names(rows, [name for name, _, _ in specs])
        for name, _, path in specs:
            # Both the ack file and spec paths resolve from the caller's directory.
            # Cargo itself runs at the repository root to select the right workspace.
            path = str(Path(path).resolve())
            requirements = spec_requirements(Path(path))
            output = subprocess.run(
                ["cargo", "run", "--locked", "-q", "-p", "ozpb-cli", "--", "reference-suite", "--spec", path],
                cwd=Path(__file__).resolve().parent.parent, stdout=subprocess.PIPE, text=True, check=True,
            )
            check_acknowledgements(name, rows, json.loads(output.stdout, object_pairs_hook=unique_object), requirements)
        print(f"All {len(specs)} declared reference suites ran and passed")
        return 0
    if len(sys.argv) != 3:
        raise ValueError(__doc__)
    spec, ack_file = sys.argv[1:]
    check_acknowledgements(spec, entries(ack_file), json.load(sys.stdin, object_pairs_hook=unique_object))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"reference coverage check failed: {error}", file=sys.stderr)
        sys.exit(1)
