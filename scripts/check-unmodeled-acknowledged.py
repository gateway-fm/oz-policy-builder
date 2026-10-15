#!/usr/bin/env python3
"""Check a local reference-suite report and its exact coverage acknowledgements.

Usage:
  reference-suite-json | check-unmodeled-acknowledged.py <spec-name> <ack-file>
  check-unmodeled-acknowledged.py --known-specs <ack-file> <spec-name>...

Run --known-specs with the complete set checked by the calling gate, then check each
report. An acknowledgement documents a layer-1 limitation; it does not test that
policy or turn reference agreement into evidence of on-chain behavior. This checks
locally generated report consistency, not the authenticity of imported evidence.
"""

import json
import re
import sys


def entries(path: str) -> list[tuple[str, str]]:
    rows = []
    seen = set()
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
            row = (name, entry)
            if row in seen:
                raise ValueError(f"{path}:{number}: duplicate acknowledgement {line!r}")
            seen.add(row)
            rows.append(row)
    return rows


def unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def string_list(report: dict, key: str) -> list[str]:
    value = report.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{key} must be an array of nonempty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{key} contains duplicate entries")
    return value


def check_report(report: object) -> set[str]:
    if not isinstance(report, dict):
        raise ValueError("reference-suite output must be a JSON object")
    if report.get("all_agree") is not True:
        raise ValueError("reference suite does not report all_agree: true")
    total = report.get("total")
    if type(total) is not int or total <= 0:
        raise ValueError("reference suite must exercise a positive number of cases")
    if type(report.get("disagreements")) is not int or report["disagreements"] != 0:
        raise ValueError("reference suite must report zero disagreements")
    missing = string_list(report, "missing_classes")
    if missing:
        raise ValueError(f"reference suite is missing required boundary classes: {missing}")
    unmodeled = set(string_list(report, "unmodeled_reviewed_policies"))
    permit_only = string_list(report, "permit_only_classes")
    if permit_only:
        print(f"  permit-only classes (no denial demonstrated): {permit_only}")

    evidence = report.get("report")
    if not isinstance(evidence, dict) or evidence.get("layer") != "layer1-reference-evaluator":
        raise ValueError("expected labeled layer1-reference-evaluator evidence")
    outcomes = evidence.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != total:
        raise ValueError("reported case count differs from the evidence outcomes")
    for outcome in outcomes:
        if not isinstance(outcome, dict) or outcome.get("agree") is not True:
            raise ValueError("evidence contains a missing or disagreeing outcome")
        expected, actual = outcome.get("expected"), outcome.get("actual")
        if not ((expected == "permit" and actual == "permit") or
                (expected == "deny" and isinstance(actual, str) and
                 re.fullmatch(r"deny\([A-Za-z][A-Za-z0-9_]*\)", actual))):
            raise ValueError("evidence outcome contradicts its expected verdict")
    if not any(row.get("class") == "original" and row["actual"] == "permit" for row in outcomes):
        raise ValueError("reference suite has no passing original control")
    if not any(row["expected"] == "deny" for row in outcomes):
        raise ValueError("reference suite has no passing denial control")
    return unmodeled


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--known-specs":
        if len(sys.argv) < 4:
            raise ValueError(__doc__)
        ack_file, *names = sys.argv[2:]
        if len(names) != len(set(names)):
            raise ValueError("checked spec names must be unique")
        unknown = sorted({name for name, _ in entries(ack_file)} - set(names))
        if unknown:
            raise ValueError(f"acknowledgements name unchecked specs: {unknown}")
        print(f"acknowledgements name only checked specs ({len(names)})")
        return 0
    if len(sys.argv) != 3:
        raise ValueError(__doc__)
    spec, ack_file = sys.argv[1:]
    acknowledged = {entry for name, entry in entries(ack_file) if name == spec}
    reported = check_report(json.load(sys.stdin, object_pairs_hook=unique_object))
    unacknowledged = sorted(reported - acknowledged)
    stale = sorted(acknowledged - reported)
    if unacknowledged or stale:
        raise ValueError(
            f"{spec}: unacknowledged policies={unacknowledged}; stale acknowledgements={stale}"
        )
    print(f"{spec}: layer-1 agreement and coverage checks passed; "
          f"{len(reported)} reviewed policy gap(s) explicitly acknowledged")
    for policy in sorted(reported):
        print(f"  NOT MODELED BY LAYER 1: {policy}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"reference coverage check failed: {error}", file=sys.stderr)
        sys.exit(1)
