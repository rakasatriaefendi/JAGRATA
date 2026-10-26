# CS-00 R1 validation

Read-only fixture validation: python -B tests/test_validate_fixtures.py.

For adversarial unit/mocked tests, create a NEW, uniquely named directory below
runtime/qa-cs00-r1 and set CS00_R1_QA_DIR to that absolute directory. Then run
python -B tests/test_cs00_r1.py. The suite creates a fresh unit-UUID child and leaves
it for inspection; it never reuses customer runtime paths or accesses real Docker.
Do not point it at an existing installation or global temporary directory.

Tests cover fixture corruption, missing/extra content, encoding/IP/line endings,
ownership/collisions, native failures/timeouts, rejected remote/shim runtimes,
preserved logs/backups, locks, bind-mode resource selection, blocked recovery,
structured detection assertions and real launcher argument/exit propagation using
fake interpreters. Wrapper tests may skip if their host executable is unavailable.

Compose rendering and PowerShell/Bash syntax are static checks only. Successful
unit tests do not prove upstream JSON compatibility, detection, backup/restore,
native Linux/macOS support or live Docker isolation. See the R2 plan.
