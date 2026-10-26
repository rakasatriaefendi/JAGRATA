# CrowdSec Guard — local Security Console

Independent, self-hosted security console with local administrator login and a bounded,
read-only CrowdSec adapter. CS-04 adds administrator-managed SSH/Nginx file
configurations and explicit operator deployment planning to the Obsidian Kinetic
Console. Saving configuration never changes the engine. Runtime ingestion acceptance
and remaining approval gates are recorded in the [CS-04 report](docs/CS04_IMPLEMENTATION_REPORT.md).
No remediation is enabled. This is a local MVP, not commercial certification.

CS-05 adds the [Remediation Center](docs/CS05_REMEDIATION_GUIDE.md): real decision
observations, dry-run proposals and confirmed Guard-local protection policy with an
audit trail and owned local rollback. Engine decision writes and network enforcement
remain disabled. See the [CS-05 report](docs/CS05_IMPLEMENTATION_REPORT.md) and
[security review](docs/CS05_SECURITY_REVIEW.md) for tested scope and limitations.

JAGRATA also supports local English/Bahasa Indonesia UI preferences and fluid
desktop/tablet/mobile layouts. The EN/ID controls update text without replacing
forms or changing security data. `Always Awake.` is the tagline in both languages.
See the [responsive/localization report](docs/JAGRATA_RESPONSIVE_I18N_REPORT.md)
for tests, local i18next delivery and the separately approved source-receipt boundary.

Install and run from this directory. Node 24+, npm 9+, Docker CLI, a local Linux Docker
engine, Compose 2.20+, and an explicitly selected registered QA engine are required.
Existing OpenSSL generates localhost TLS, or you supply a certificate/key. Nothing is
installed globally. Setup never provisions, starts, stops or deletes Docker resources.

```powershell
.\setup.ps1
.\guard.ps1 start
.\guard.ps1 status
.\guard.ps1 doctor
.\guard.ps1 stop
```

```bash
bash ./setup.sh
bash ./guard.sh start
bash ./guard.sh status
bash ./guard.sh doctor
bash ./guard.sh stop
```

Read the [installation guide](docs/CS03_INSTALLATION_GUIDE.md) first, including the
process-only PowerShell execution-policy option if scripts are blocked, explicit
engine selection, private project-local state and certificate verification.
[CS-03 implementation evidence](docs/CS03_IMPLEMENTATION_REPORT.md) and
[security review](docs/CS03_SECURITY_REVIEW.md) record the tested scope. Windows local
MVP is validated; native Linux/macOS/ARM remain unverified. No Python is needed by
this installer. The older lab lifecycle tools below still have separate prerequisites.

The authenticated Console uses the [CS-02 implementation](docs/CS02_IMPLEMENTATION_REPORT.md).
Setup creates only a new Console identity and read-only binding; it never reassigns
ownership of an existing engine. Runtime state stays under runtime/console by default.
Stop the application before removal. Docker images/volumes remain outside the folder;
deleting the repository does not remove them. This is not a commercial release.

For selected file sources, read the [source integration guide](docs/CS04_SOURCE_INTEGRATION_GUIDE.md).
The Sources page offers add/edit, path validation, disable/remove confirmation,
configuration persistence and authoritative observation states. Path validation is
metadata-only. New mounts/deployments remain explicit operator actions; neither
normal application startup nor a browser action starts or restarts Docker.

`npm test` runs backend, installer and source-management unit/regression checks.
Live append ingestion tests require a separate, explicitly approved CS-04 QA engine.

## Historical CS-00 R1 lifecycle reference

The following describes the earlier foundation. Current acceptance evidence is in
[CS-00 acceptance](docs/CS00_ACCEPTANCE.md) and [CS-01 detection](docs/CS01_DETECTION_REPORT.md).

R1 replaces unsafe lifecycle paths with installation ownership checks and explicit
unsupported errors. Existing legacy Docker resources, deploy/docker/.env and
runtime/logs are not adopted, migrated, overwritten or removed.

Prerequisites: Python 3.8+ (standard library only), PowerShell 5.1+ on Windows or
Bash 3.2+ on Linux/macOS, and an operator-provided local Linux Docker engine with
Docker Compose >=2.20. No prerequisite is automatically installed. Python was
already used for validation; R1 makes it required for lifecycle operations to
share structured JSON and native-command failure checks across platforms.

Read-only source validation, with no Docker daemon required:

```powershell
.\scripts\lab.ps1 validate
```

```bash
bash scripts/lab.sh validate
```

Future runtime evaluation must use a NEW installation, never the historical lab:

```powershell
# Examples only: not executed during R1. Choose your explicit local context.
.\scripts\lab.ps1 init -InstallationId qa-example -DockerContext desktop-linux
.\scripts\lab.ps1 preflight
.\scripts\lab.ps1 up
.\scripts\lab.ps1 status
.\scripts\lab.ps1 down
```

The Bash equivalent is `bash scripts/lab.sh init --installation-id qa-example
--docker-context default`. Init creates folder-local state without contacting
Docker. A generated ID is used if omitted. IDs lab/crowdsec-guard-lab are reserved.
Changing an existing identity or moving a registered folder is not a migration.

Current operations:

| Command | R1 behavior |
|---|---|
| init | Exclusively create a new identity, configuration and initial synthetic working logs |
| validate | Strict fixture integrity and Compose rendering; no write probe |
| preflight | Distinguish CLI, local daemon, Compose and candidate host capability; read-only |
| up/status | Check ownership, LAPI readiness and loaded scenarios; runtime validation pending |
| down/uninstall | Only verified container/network IDs; preserve all data, backups, images and configuration |
| detect --evidence FILE | Offline normalized-evidence assertions only; not a live test |
| detect without evidence | Disabled until R2 collector validation |
| backup/restore/update/reset | Unsupported, nonzero, before any Docker operation or archive access |
| --purge / --remove-image | Rejected; no global cleanup or data deletion |

Installation registration is config/installation.json; per-installation host
configuration is config/installations/ID; working data is runtime/installations/ID.
These locations are ignored by Git. Named volumes and images live in Docker's
managed storage, outside the folder. Copying the folder does not copy those volumes.
The bind persistence option keeps engine files under runtime/installations/ID but
does not make images, filesystem permissions or database migration automatically portable.

Base Compose publishes no ports, mounts logs/configuration files read-only, disables
CAPI and includes no bouncer. Decisions can still be generated by upstream profiles;
they are not enforced blocking. Outbound Hub/GeoIP downloads remain possible.
There is no verified offline Hub bundle, ARM64 manifest or commercial redistribution package.

See [operations](docs/operations.md), [R1 report](docs/CS00_R1_REMEDIATION_REPORT.md),
[R2 validation plan](docs/CS00_R2_VALIDATION_PLAN.md), [platform status](docs/platform-compatibility.md),
[backup contract](docs/backup-format.md), [detection evidence](docs/detection-evidence.md),
[commercial review](docs/commercial-readiness.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
