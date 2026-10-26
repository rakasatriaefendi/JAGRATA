#!/usr/bin/env python3
"""Read-only entry point; negative cases are in test_cs00_r1.py."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from fixture_policy import validate_fixtures


if __name__ == '__main__':
    try:
        counts = validate_fixtures(Path(__file__).resolve().parents[1])
        print('[PASS] Strict UTF-8/LF, IP, structure, count and SHA-256 checks: ' + str(counts))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('[FAIL] ' + str(error), file=sys.stderr)
        sys.exit(1)
