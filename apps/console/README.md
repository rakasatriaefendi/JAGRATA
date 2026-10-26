# CrowdSec Guard Console

Functional CS-02 browser application. Served by the Manager over loopback HTTPS;
opening index.html directly is unsupported. No npm dependencies or build step.
Use the [root-level installer](../../docs/CS03_INSTALLATION_GUIDE.md).
The earlier [manual developer setup](../../docs/CS02_LOCAL_DEVELOPMENT.md) is retained
as CS-02 reference; ordinary users should run setup/guard from the repository root.

The browser has no Docker or CrowdSec credentials. Four pages consume authenticated,
normalized Manager observations. No demo fallback or remediation controls exist.
The approved prototype remains separate; only its shared design stylesheet is served
as /design.css. Keep that stylesheet with the app when packaging.

CS-04 extends Data Sources with an authenticated configuration list, add/edit drawer,
explicit file consent, metadata validation and disable/remove confirmation. Current
engine evidence is separate from saved configuration. File validation never claims
parsing or recent activity. The existing theme, navigation, alerts and dialogs remain;
spacing, technical typography, mobile layout and modal keyboard focus were refined.
See [CS-04 source setup](../../docs/CS04_SOURCE_INTEGRATION_GUIDE.md).
