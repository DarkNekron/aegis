# AEGIS — Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ImportError: DLL load failed … An Application Control policy has blocked this file` | Windows **Smart App Control** blocks unsigned compiled extensions (seen with SQLAlchemy and coverage) | Rerun `scripts\setup.ps1`. It reinstalls SQLAlchemy as pure Python. Coverage falls back automatically. Do **not** disable Smart App Control. |
| `pytest.exe` / `uvicorn.exe` / `alembic.exe` "Permission denied" or blocked | Smart App Control blocks pip's unsigned launcher executables | Run them as modules: `python -m pytest`, `python -m uvicorn`, `python -m alembic` (the scripts already do) |
| Antivirus warns about PowerShell scripts | The scripts use `-ExecutionPolicy Bypass` (one process only). Behaviour monitors flag this pattern, especially for scripts in Temp folders. | Run the scripts from the project folder. Read them first; they are short. Scanning the project with Kaspersky and Defender found no threats. |
| `insufficient_resources` (HTTP 503) when analysing | Free RAM is below `AEGIS_MIN_FREE_RAM_MB` plus the graph estimate | Close memory-heavy applications, or narrow the data. Do not simply lower the reserve on a busy laptop. |
| `limit_exceeded` on import | The snapshot exceeds `AEGIS_MAX_GRAPH_NODES` / `_EDGES`, or the upload exceeds `AEGIS_MAX_UPLOAD_MB` | Raise the limit only if RAM allows (about 1.1 KB per node and 0.7 KB per relationship) |
| Import `partial` with errors | Malformed records or truncated files | Check the import's error list (file and location). Valid records were kept. |
| Many "placeholders" / collection gaps | Referenced objects were not collected (e.g. a partial SharpHound run) | Re-collect with full coverage. Placeholders are replaced automatically by a later import. |
| `unsafe_archive` | Traversal paths, symlinks, encryption, too many members, or a suspicious compression ratio | Extract a password-protected SharpHound ZIP and upload the JSON files. Never weaken the ZIP limits for untrusted files. |
| "This exact file has already been imported" | The same SHA-256 was already imported into that snapshot | Expected behaviour. Create a new snapshot for a new assessment. |
| UI shows "No snapshots" or a blank page after login | The UI was not built | `cd frontend; npm run build`, then restart. AEGIS serves `frontend\dist`. |
| Sessions end after every restart | `AEGIS_SECRET_KEY` is unset, so an ephemeral key is used (System Health warns) | Set it in `.env`. Setup does this. |
| `403 Missing or invalid CSRF token` from scripts | State-changing requests need the `X-CSRF-Token` header from the login response | See [API.md](API.md) |
| PDF shows `->` instead of `→` | No Unicode TrueType font was found (Arial or Consolas on Windows, DejaVu on Linux) | Install `fonts-dejavu-core` (Linux). The text is still correct. |
| Port 8000 already in use | Another process is listening on it | `scripts\run_backend.ps1 -Port 8001` |
