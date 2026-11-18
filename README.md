# AEGIS
### Active Directory Attack Path Discovery & Intelligence Engine

AEGIS is an offline, read-only analysis platform. It ingests BloodHound CE / SharpHound collection output
and custom inventories, rebuilds the Active Directory graph and finds privilege-escalation paths
with its own algorithms. It then scores each path transparently, simulates remediation in an isolated copy, compares
assessment snapshots over time and produces penetration-test reports.

> **Status:** early development. The environment is ready and the backend foundation is next.
> See [docs/DEVELOPMENT_ROADMAP.md](docs/DEVELOPMENT_ROADMAP.md).

AEGIS never connects to, collects from, or modifies a live directory. It only analyses data you supply.
Use it only on environments you are authorised to assess.

## Documentation
* [System assessment](docs/SYSTEM_ASSESSMENT.md): the hardware the defaults are tuned for
* [Architecture](docs/ARCHITECTURE.md)
* [Dependencies](docs/DEPENDENCIES.md) and the [installation report](docs/DEPENDENCY_INSTALLATION_REPORT.md)

## Quick setup (Windows)
```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_backend.ps1 -Dev
cd frontend; npm ci
copy ..\.env.example ..\.env   # then set AEGIS_SECRET_KEY
```
