# AEGIS — HTTP API

The interactive OpenAPI documentation is at `http://127.0.0.1:8000/api/docs` (disabled when `AEGIS_ENV=production`).
This page summarises the conventions and the endpoints.

## Conventions
* **Authentication:** `POST /api/auth/login` sets the `aegis_session` cookie and returns a `csrf_token`.
* **CSRF:** every POST, PUT, PATCH or DELETE must send the header `X-CSRF-Token: <token>`.
  `GET /api/auth/csrf` issues a fresh token, for example after a page reload.
* **Roles:** V = viewer, A = analyst, D = administrator. Each role includes those below it.
* **Errors:** `{"error": {"code", "message", "request_id", "details?"}}`. Codes include `not_authenticated` (401),
  `forbidden` (403), `not_found` (404), `conflict` (409), `limit_exceeded` (413), `unsupported_format` (415),
  `validation_failed` (422), `rate_limited` (429, with `Retry-After`) and `insufficient_resources` (503).
* **Pagination:** `offset` (≥ 0) and `limit` (1–500). Responses are `{"total", "items"}`.
* **Long-running work** (imports, analyses) returns `202 {"job": {...}}`. Poll `GET /api/jobs/{id}` until `status` is
  `succeeded`, `failed`, `cancelled` or `timed_out`. A successful job includes `result`.
* **Request bodies** other than uploads are limited to 1 MB.

## Endpoints

| Method & path | Role | Purpose |
|---|---|---|
| `GET /api/health` | public | Liveness: `{"status", "version"}` only |
| `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/auth/me` · `GET /api/auth/csrf` | – / V | Session lifecycle |
| `GET /api/auth/setup-status` | public | `{"needs_setup": bool}`: true only while no account exists |
| `POST /api/auth/setup` | public, one-time | First run only: `{"setup_code", "username", "password"}` creates the first admin and signs in. `403 invalid_setup_code` for a wrong code; `409` once any user exists. |
| `POST /api/auth/change-password` | V | Change own password (revokes other sessions) |
| `GET /api/system/health` | V | Resources, limits, job queue, graph cache, database, warnings |
| `GET /api/dashboard?snapshot_id=` | V | Headline statistics from imported data and the latest analysis |
| `GET /api/snapshots` · `POST /api/snapshots` · `GET /api/snapshots/{id}` · `DELETE /api/snapshots/{id}` | V / A / V / D | Assessment snapshots (detail includes import history) |
| `POST /api/snapshots/{id}/imports?filename=corp.zip` | A | Upload a `.zip`, `.json` or `.csv` **as the raw body** (`application/octet-stream`). The size limit is enforced while streaming. Returns a job. |
| `GET /api/snapshots/{id}/objects?q=&kind=&tier0=` | V | Identity explorer search |
| `GET /api/objects/{id}` · `GET /api/objects/{id}/relationships?direction=in\|out` | V | Object detail, relationships with evidence |
| `GET /api/jobs` · `GET /api/jobs/{id}` · `POST /api/jobs/{id}/cancel` | V / V / A | Background jobs |
| `POST /api/snapshots/{id}/analyses` | A | Start an analysis (optional body: `max_depth`, `alternatives_per_source`, `max_paths`, capped by server settings). Returns a job. |
| `GET /api/snapshots/{id}/analyses` · `GET /api/analyses/{id}` | V | Analyses. The detail includes the full summary: environment risk, targets, choke points, minimum cut, centrality. |
| `GET /api/analyses/{id}/paths?severity=&classification=&source=&target=` | V | Scored paths, highest risk first |
| `GET /api/paths/{id}` · `GET /api/paths/{id}/evidence` · `GET /api/paths/{id}/graph` | V | Explanation and score breakdown, per-step evidence records, Cytoscape elements |
| `POST /api/paths/{id}/validate` `{"note"}` | A | Mark a path as a validated security exposure and rescore it |
| `GET /api/snapshots/{id}/graph/neighborhood?node=&depth=1-3&traversable_only=` | V | Cytoscape elements around an object, capped at `AEGIS_UI_MAX_ELEMENTS` (`truncated` flag) |
| `POST /api/analyses/{id}/simulations` `{"actions": [...]}` · `GET /api/analyses/{id}/simulations` · `GET /api/simulations/{id}` | A / V / V | Remediation what-ifs (remove relationship, step, membership, ACL, admin right or session; disable identity; apply minimum cut). Never modifies data. |
| `GET /api/comparisons?old_snapshot=&new_snapshot=` | V | Historical comparison (objects, relationships, privilege, paths, exposure, risk) |
| `POST /api/analyses/{id}/reports` `{"formats": ["pdf","html","json"], "simulation_ids"?, "previous_snapshot_id"?}` | A | Generate a report (job) with all 13 sections, plus the change section when a previous snapshot is given |
| `GET /api/reports?snapshot_id=` · `GET /api/reports/{id}/download` | V | List reports, download one (always an attachment, with an `X-Report-SHA256` header) |
| `GET /api/settings/analysis` · `PUT /api/settings/analysis` | A / D | Tier-0 categories, custom tier-0 objects, trust traversal |
| `GET /api/settings/risk` · `PUT /api/settings/risk` | A / D | Risk model parameters ([RISK_SCORING.md](RISK_SCORING.md)) |
| `GET /api/users` · `POST /api/users` · `PATCH /api/users/{id}` · `POST /api/users/{id}/reset-password` | D | User administration |
| `GET /api/audit?action=` | D | Audit log |

## Example (PowerShell, using `curl.exe`)
```powershell
$B = "http://127.0.0.1:8000"
$login = curl.exe -s -c jar.txt -H "Content-Type: application/json" `
  -d '{"username":"analyst1","password":"<password>"}' "$B/api/auth/login" | ConvertFrom-Json
$h = @("-b", "jar.txt", "-H", "X-CSRF-Token: $($login.csrf_token)")
$snap = curl.exe -s @h -H "Content-Type: application/json" -d '{"name":"Lab AD"}' "$B/api/snapshots" | ConvertFrom-Json
curl.exe -s @h -H "Content-Type: application/octet-stream" --data-binary "@lab.zip" `
  "$B/api/snapshots/$($snap.id)/imports?filename=lab.zip"
```
