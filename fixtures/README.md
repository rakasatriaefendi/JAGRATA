# Reviewed synthetic fixtures

fixtures/logs contains exactly ssh/auth.log and web/access.log. They were reconstructed
from valid synthetic SSH and nginx-combined structures in R1, not repaired by global
character replacement. All source IPs are documentation-only IPv4 addresses.

SSH contains 10 events: eight rapid failures from 203.0.113.50 and two benign events.
Web contains 14 events: twelve distinct 404 paths from 198.51.100.77 and two benign
events. Timestamps are fixed UTC-context examples. They are not live replay evidence.

fixtures/manifest.json records reviewed SHA-256 byte hashes. The offline validator
requires exact files, strict UTF-8 without BOM, LF-only final-newline content, valid
IP ranges, complete event structures/counts and matching hashes. Any intended edit
requires a reviewed specification and manifest update; do not silently recalculate
the manifest during validation. Hashes detect changes, not malicious co-editing of
both source and manifest.

Init copies fixtures only into a NEW installation's working log paths. Up does not
overwrite working logs. The old runtime/logs files were left untouched. R2 must use
fresh current-UTC bursts after readiness; EOF acquisition does not replay baseline files.
