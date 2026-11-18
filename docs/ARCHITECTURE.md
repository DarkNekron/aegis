# AEGIS — Architecture

AEGIS is an **offline analysis platform**. It ingests Active Directory collection output that someone
else has already gathered, such as BloodHound CE or SharpHound JSON/ZIP files or custom inventories.
From that data it rebuilds the directory graph, finds attack paths with its own algorithms, scores
them, simulates remediation, compares snapshots over time and produces reports.

AEGIS never connects to a live directory, never runs collectors and never modifies any directory.

The constraints come from [SYSTEM_ASSESSMENT.md](SYSTEM_ASSESSMENT.md). The machine is a 16 GB
laptop with about 2 GB of RAM free during normal work, so memory is the budget every design decision
is checked against.

---

## 1. Runtime topology

```
 Browser (React SPA, Cytoscape.js)
        │  HTTPS/HTTP on localhost, session cookie + CSRF header
        ▼
 ┌──────────────────────── single Python process ─────────────────────────┐
 │ FastAPI (Uvicorn, 1 worker)                                            │
 │  ├── api/            routers, authN/authZ dependencies, rate limiter   │
 │  ├── core/           settings, security, resource manager, job runner  │
 │  ├── ingestion/      streaming parsers, safe ZIP, normaliser           │
 │  ├── graph_engine/   graph builder, traversal rules, path algorithms   │
 │  ├── risk_engine/    transparent scoring model                         │
 │  ├── simulation/     what-if engine on filtered graph views            │
 │  ├── comparison/     snapshot diffing                                  │
 │  ├── reporting/      HTML (Jinja2), PDF (ReportLab), JSON              │
 │  └── static/         built frontend (served in "single-process" mode)  │
 │                                                                        │
 │  JobRunner: 1 heavy-analysis thread + small light-job pool             │
 │  GraphCache: LRU of in-memory graphs (default capacity 1)              │
 └───────────────┬────────────────────────────────────────────────────────┘
                 ▼
          SQLite (WAL) — data/aegis.db      (PostgreSQL-compatible schema)
```

**Why one process?** A separate worker process, queue such as Celery/Redis, or Docker stack would
add 300 MB to 2 GB of resident memory without benefiting a single-analyst tool. The job runner is
an in-process, bounded, cancellable executor (§6).

**Two run modes:**
* *Dev mode:* Vite dev server on `:5173` proxies `/api` to Uvicorn on `:8000`. Use it only while editing the UI.
* *Single-process mode (default):* `npm run build` once. FastAPI then serves `frontend/dist`. Nothing else runs.

## 2. Technology decisions

| Concern | Choice | Reason / alternatives rejected |
|---|---|---|
| Language | Python 3.12 | Broadest wheel coverage on Windows. The Store 3.13 build is avoided (§5 of assessment). |
| API | FastAPI + Pydantic v2 | Typed validation at the boundary and auto OpenAPI docs |
| ORM | SQLAlchemy 2.x | Portable between SQLite and PostgreSQL |
| Migrations | Alembic | Makes the PostgreSQL move a configuration change, not a rewrite |
| Database | SQLite, WAL mode | No service to run, about 0 MB idle. PostgreSQL is **postponed** until multi-user deployment. |
| Graph | NetworkX `MultiDiGraph` | Pure Python and well understood. AEGIS uses it as a **data structure**. Path, cut and centrality algorithms are implemented in `graph_engine/algorithms/`. |
| Graph DB | **None** | Neo4j would cost 1–2 GB of JVM heap and add nothing a 150k-node in-memory graph needs |
| Streaming JSON | ijson (C backend) | SharpHound files can be hundreds of MB. Streaming keeps parse memory flat. |
| Password hashing | argon2-cffi (Argon2id) | Current OWASP recommendation |
| Resource monitoring | psutil | RAM, CPU and disk checks before heavy jobs, plus the System Health page |
| Reports | Jinja2 (HTML), ReportLab (PDF) | ReportLab is pure Python with no headless browser. WeasyPrint was rejected because it needs GTK on Windows. |
| Frontend | React + TypeScript + Vite | |
| Styling | Tailwind CSS v4 (`@tailwindcss/vite`) | No PostCSS config files |
| Graph UI | Cytoscape.js | Canvas renderer that handles a few thousand elements well |
| Charts | Recharts | Covers the dashboard's bar, area and donut charts |
| Testing | pytest, httpx (TestClient), pytest-cov | |
| Lint/format | ruff | One fast tool instead of flake8 + isort + black |
| Containers | Dockerfile + compose (optional) | Docker is not installed here and is **not required** |

## 3. Data model (relational, persisted)

```
users(id, username, password_hash, role, is_active, failed_attempts, locked_until, created_at)
auth_sessions(id, token_hash, user_id, csrf_token_hash, created_at, expires_at, last_seen, ip)
audit_log(id, ts, user_id, action, target_type, target_id, outcome, ip, detail_json)

snapshots(id, name, description, created_at, collected_at, source_kind, is_sample, status, stats_json)
import_jobs(id, snapshot_id, filename, sha256, size_bytes, detected_format, status, summary_json, errors_json)

ad_objects(id, snapshot_id, object_id, kind, name, domain, enabled, is_tier0, tier0_reason,
           properties_json)                      UNIQUE(snapshot_id, object_id)
ad_edges(id, snapshot_id, src_object_pk, dst_object_pk, kind, data_source, collected_at,
         is_inherited, confidence, evidence_json, conditions_json)

analyses(id, snapshot_id, params_json, status, started_at, finished_at, error, summary_json)
attack_paths(id, analysis_id, source_pk, target_pk, hops, edge_ids_json, classification,
             confidence, score, score_breakdown_json, signature)
simulations(id, analysis_id, removed_json, result_json, created_by, created_at)
reports(id, snapshot_id, analysis_id, format, path, created_by, created_at)
settings(key, value_json)                         -- scoring weights, target categories
```

`object_id` is the directory identifier: the SID for security principals, or the GUID for OUs, GPOs and containers.
`ad_objects.id` is a compact integer. That integer is also the node key in the in-memory graph.

## 4. Graph model

### 4.1 Nodes
`User, Group, Computer, Domain, OU, GPO, Container, ServiceAccount, CertTemplate, EnterpriseCA,
Unknown`. A `ServiceAccount` is a User with SPNs, or a gMSA/MSA, and it keeps `base_kind=User`.
An `Unknown` node is a principal referenced by an ACE or membership but missing from the export. Unknown nodes are
kept because they are often evidence of a collection gap.

In-memory node attributes are limited to `kind, name, tier0, enabled, owned`. Everything else is loaded
from SQLite on demand.

### 4.2 Edges: direction always means "source can affect destination"

| Edge | Direction | Traversable | Conditions recorded |
|---|---|---|---|
| MemberOf | member → group | yes | none (group rights inherited) |
| AdminTo | principal → computer | yes | local admin rights need valid credentials and network reach |
| HasSession | **computer → user** | yes | point-in-time observation. The session may have ended, and credential theft needs admin on the host. |
| GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, AllExtendedRights | principal → object | yes, by target kind | e.g. GenericWrite on a user means a targeted Kerberoast or shadow credentials, which depend on the domain functional level / ADCS |
| AddMember, AddSelf | principal → group | yes | |
| ForceChangePassword | principal → user | yes | disruptive to the target and will be noticed |
| ReadLAPSPassword, ReadGMSAPassword | principal → computer/account | yes | LAPS deployed / gMSA |
| AllowedToDelegate | principal → computer | yes | constrained delegation (S4U), needs control of the principal |
| AllowedToAct | principal → computer | yes | RBCD |
| CanRDP, CanPSRemote, ExecuteDCOM | principal → computer | **conditional** | gives code execution as the user, not necessarily privileged |
| DCSync (GetChanges + GetChangesAll) | principal → domain | yes | both rights must be present. Derived by AEGIS, not trusted from input. |
| Contains, GPLink | OU/GPO → children | yes | GPO edit rights propagate to linked OUs |
| HasSIDHistory | principal → principal | yes | |
| TrustedBy / SameForestTrust / CrossForestTrust | domain → domain | **not traversed by default** | trust abuse depends on SID filtering. It is informational unless enabled. |

Traversal rules live in **one table** (`graph_engine/rules.py`). For each `(edge kind, target kind)` pair the
table defines `traversable`, `base_cost`, `severity`, `conditions[]` and `technique` (the explanation text).
An edge kind that is unknown to the rules is stored and shown but **never traversed**. AEGIS does not treat
every relationship as exploitable.

### 4.3 Tier-0 (privileged destination) identification
These come from well-known RIDs and SIDs, such as -512 Domain Admins, -519 Enterprise Admins,
-518 Schema Admins, S-1-5-32-544 Administrators, -516 Domain Controllers, DC computer objects, the domain
object, krbtgt and Account/Backup/Server Operators. AEGIS also uses the input's `highvalue` and
`isTierZero` flags, but only as supporting evidence, and analyst-configured objects or categories. Every tier-0
node records *why* it is tier-0.

## 5. Attack-path engine (`graph_engine/algorithms/`)

All of these are implemented in AEGIS. None of them delegates to `networkx.algorithms` or to BloodHound queries.

1. **Reverse multi-source Dijkstra from the tier-0 set.** One pass over the reversed graph, using only traversable edges and
   rule costs, gives every node its distance to the nearest privileged target and its next hop.
   It costs O((V+E) log V) for *all* sources at once. This is the reachability map.
2. **Shortest path per source.** Read off the next-hop tree in O(hops).
3. **Alternative paths: Yen's k-shortest loopless paths**, bounded by `max_depth`,
   `max_alternatives`, a deadline and a cancellation token.
4. **Multi-hop enumeration** for a specific source→target pair: a depth-bounded DFS with pruning.
   A branch is dropped when the remaining distance from the reachability map shows it cannot finish within the depth bound.
5. **Deduplication.** A canonical signature is the edge-id tuple. A path is also dropped if it fully contains a
   shorter path to the same target.
6. **Ranking** by risk score (§7). Hop count and confidence break ties.
7. **Dependency / choke-point analysis.** This counts how many source→target optimal paths each edge carries.
   The **minimum edge cut** between "ordinary principals" and tier-0 uses an Edmonds–Karp max-flow with unit capacities.
   The result is the smallest set of relationships that would disconnect every ordinary user from tier-0.
   It feeds straight into remediation recommendations.
8. **Centrality.** Sampled Brandes betweenness runs only on the *attack-relevant subgraph*, meaning nodes that can reach
   tier-0. The sample size is configurable. In-degree and out-degree of control edges are also computed.

**Path classification** (never stated as "exploited"):

| Class | Meaning |
|---|---|
| Observed relationship | A single edge present in collected data |
| Potential privilege escalation | Every edge on the path is unconditionally traversable under the rules |
| Conditional attack path | One or more edges carry conditions that need validation, such as a session that may be stale or a delegation prerequisite |
| Validated security exposure | **Only** set manually by an analyst who confirmed it in an authorised lab or test |

Each path result carries the start, the destination, the ordered node and edge list, the hop count, the relationship kinds,
the rights involved, evidence per edge (source file, collection timestamp, ACE inheritance), confidence, the conditions to validate,
and a generated explanation of *why it matters*.

## 6. Resource management (`core/resources.py`, `core/jobs.py`)

* `ResourceManager` reads limits from settings. Before a heavy job it checks free RAM (psutil)
  against `AEGIS_MIN_FREE_RAM_MB` and checks the graph size against the node and edge limits. If a check fails,
  it raises a typed error that the API returns as `503` with a readable reason.
* `JobRunner`: a bounded `ThreadPoolExecutor` with one heavy slot and two light slots, a job registry, status polling,
  `CancellationToken` objects and deadlines. Algorithms call `token.check()` inside their loops, every N iterations,
  so cancellation and timeouts take effect promptly.
* Threads are used instead of processes because a process pool would need its own copy of the graph,
  which would double memory. Analysis is CPU-bound, but only one heavy job runs at a time, and Uvicorn's
  event loop stays responsive through GIL switching.
* `GraphCache`: an LRU of built graphs keyed by snapshot ID, with a default capacity of 1, so only one graph is in memory.
  It is rebuilt from SQLite on demand.
* **Ingestion streams.** ijson iterates `data[]` items. Objects are written to SQLite in batches of 2,000 rows,
  and the raw file is never held in memory as a whole.
* **The API paginates every list endpoint** (`limit` ≤ 500). Graph endpoints return *neighbourhoods* or
  *path subgraphs* capped at `AEGIS_UI_MAX_ELEMENTS`, never the whole graph.

## 7. Risk engine (summary; full method in `RISK_SCORING.md` at Module 4)

`score = 100 × Σ wᵢ·fᵢ` over normalised factors in [0,1]: destination privilege, the maximum relationship
severity on the path, hop penalty (shorter scores higher), alternative-path count (more paths are harder to fix),
exposure of the source population (how many principals can start this path), evidence completeness, confidence,
and asset criticality. The weights are stored in `settings` and can be edited by an Administrator. Every score is stored with
its factor breakdown. Severity bands are fixed thresholds (Critical ≥ 85, High ≥ 65, Medium ≥ 40, Low otherwise),
so "Critical" has to be earned.

## 8. Remediation simulation

A simulation never mutates the cached graph or the database snapshot. It builds a
**filtered read-only view** (`nx.subgraph_view` with edge and node filter predicates) that hides the removed edges
or disabled principals, and then runs the same algorithms against that view. The memory cost is the size of the removal
set, not a graph copy. Supported actions are removing an edge, removing a group membership, removing an ACL edge,
removing admin rights, disabling an identity (hiding its outbound edges) and removing sessions. The output shows paths before and after,
eliminated paths, surviving alternatives, tier-0 targets still reachable and the change in risk score.

## 9. Historical comparison
Snapshots are compared through **stable keys**: `object_id` for objects and `(src object_id, kind, dst object_id)` for edges.
The comparison uses set differences in SQL over indexed columns rather than loading both graphs. Path comparison uses path signatures
built from object IDs, which are stable across snapshots, rather than from database primary keys.

## 10. Security architecture

* **Authentication:** username and password, hashed with Argon2id. Accounts lock out after repeated failures. Sessions are server-side. The cookie is a
  random 256-bit token, stored as a SHA-256 hash, with `HttpOnly`, `SameSite=Strict`, `Secure` when HTTPS is used and idle plus absolute expiry.
* **CSRF:** a per-session token is returned at login. Every state-changing request needs a matching
  `X-CSRF-Token` header, and SameSite=Strict adds a second layer of protection.
* **RBAC:** `admin` > `analyst` > `viewer`, enforced by FastAPI dependencies on every route and covered by tests.
* **Rate limiting:** in-process token buckets per IP and per user, with a stricter limit on `/auth/login`.
* **Input:** Pydantic models on every body and query. The ORM uses only bound parameters and never builds SQL from strings.
* **Uploads:** extension and magic-byte checks, a size cap enforced *while streaming*, and SHA-256 hashing. ZIP handling checks
  member names (no absolute paths, `..`, drive letters or symlinks), member count, the per-member ratio and the total
  uncompressed size. Members are read in memory and streamed without extraction to disk.
* **Imported data is untrusted.** Strings are length-capped and control characters are stripped, the UI escapes output (React default
  plus no `dangerouslySetInnerHTML`), reports autoescape in Jinja2, and imported flags like `highvalue` are only *hints*.
* **Errors:** a generic message plus a correlation ID goes to the client, and details go to the server log. Secrets never appear in logs.
* **Audit log** covers logins, imports, analyses, simulations, report generation, settings changes and user management.
* **Secrets** come from `.env` (`AEGIS_SECRET_KEY`). The first admin is created with `scripts/create_admin.py`,
  which prompts for the password interactively. There are no default credentials.
* **Security headers:** a strict CSP that allows self and data: images, X-Content-Type-Options, X-Frame-Options DENY and Referrer-Policy.

## 11. What is postponed and why

| Item | Status |
|---|---|
| PostgreSQL | Postponed. SQLite is sufficient for a single analyst, and the schema is portable. |
| Docker | Files provided, but not required and not tested on this machine (no Docker or WSL) |
| Neo4j or any graph DB | Not planned (§2) |
| Live LDAP collection | Out of scope. AEGIS stays offline and read-only by design. |
| ADCS (ESC1–ESC8) analysis | Parsed and stored as nodes. Traversal rules are a later enhancement. |
| GPU acceleration | Not needed |

## 12. Decisions revised during implementation

| Area | Original plan | What was built, and why |
|---|---|---|
| Environment risk | 50% worst path, 30% *mean* identity score, 20% breadth | The mean **rose** when low-scoring identities were secured (found by the simulation tests). It was replaced by a capped **exposure mass**, so every component is monotone. A property test guards it ([RISK_SCORING.md](RISK_SCORING.md) §4). |
| Graph memory estimate | 700 B/node, 500 B/edge | Measured 87 MB for 28k nodes / 96k edges, 35% higher than estimated. Now 1,100 / 700 B with headroom. |
| Bulk allocation speed | – | CPython's cyclic GC dominated index and graph builds. GC is paused during acyclic bulk allocation (`gc_paused()`): 2.2 s → 0.6 s. |
| SPA serving | Static mount plus catch-all route | A catch-all shadows routes registered later. The UI is served from the **404 handler** instead, so route order never matters and `/api/*` 404s stay JSON. |
| Uploads | Multipart `UploadFile` | Multipart spools the whole file to disk before the handler runs. Uploads are now the **raw request body**, so the size limit is enforced while streaming. |
| SQLAlchemy | Binary wheel | Smart App Control blocks its unsigned Cython extension. The same version is installed as pure Python, automatically by setup. |
| Parallel edges | One path per edge | Collapsed into one step that records the alternatives, to avoid near-duplicate paths |
