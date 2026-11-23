#!/usr/bin/env python3
"""Validate cert-observation-set JSON files against schema/cert-observation.schema.json.

Usage: cor_validate.py FILE [FILE ...]     ('-' reads stdin)
Exit status 0 if all files are valid.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = Path(__file__).resolve().parents[2] / "schema" / "cert-observation.schema.json"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()), format_checker=FormatChecker())
    failed = 0
    for name in argv:
        data = json.load(sys.stdin) if name == "-" else json.loads(Path(name).read_text())
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        if errors:
            failed += 1
            for err in errors:
                where = "/".join(str(p) for p in err.path) or "(root)"
                print(f"{name}: {where}: {err.message}")
        else:
            print(f"{name}: valid ({len(data['records'])} record(s))")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
