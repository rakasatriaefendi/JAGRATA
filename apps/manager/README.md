# CrowdSec Guard Manager

Node 24+ TypeScript run directly with Node's type stripping. Standard library only;
no compile build required. [Root setup and operations](../../docs/CS03_INSTALLATION_GUIDE.md)
run locked npm ci and manage the application process without controlling Docker.

Server binds 127.0.0.1 only and requires explicit administrator, adapter and TLS files.
GET /api/session, /api/snapshot, /api/alerts/:id and /api/sources require a server-side
administrator session. POST /api/sources/validate, /api/sources/save and
/api/sources/remove additionally require exact Origin, JSON and session CSRF.
The source endpoints inspect selected file metadata or change private project-local
configuration only. There is no engine apply, restart, shell or raw-YAML route.
Static files are an explicit allowlist, not a filesystem server.

CS-05 adds authenticated GET /api/remediation and /api/remediation/decisions,
and same-origin JSON + CSRF protected POST /api/remediation/preview and
/api/remediation/confirm. Confirmation applies only Guard-local protection policy
or reverses its exact Guard-owned entry. Decision changes and enforcement have no
execution route. Local protection is not a CrowdSec AllowList. See the
[remediation guide](../../docs/CS05_REMEDIATION_GUIDE.md).

The Docker CLI adapter verifies one exact local QA container and ownership labels,
then permits fixed cscli alert/metrics/scenario reads; CS-05 additionally reads the
bounded decisions list after the same ownership verification. Docker authorization is
broader than the application's reads; run only as the trusted local operator.

Run `node --test apps/manager/tests/*.test.ts` from the repository root.
Use `npm test` for the expanded source/installer regression suite. See the
[source guide](../../docs/CS04_SOURCE_INTEGRATION_GUIDE.md) for plan generation,
status semantics, privacy and the operator deployment boundary.
